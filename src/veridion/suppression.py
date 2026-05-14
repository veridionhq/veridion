"""Repo-local finding suppressions for accepted-risk workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from veridion.normalize import NormalizedFinding
from veridion.util import optional_string, strict_string

SUPPORTED_SUPPRESSION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class SuppressionRule:
    """Rule describing a finding that should be treated as accepted risk."""

    reason: str
    owner: str | None = None
    approved_by: str | None = None
    ticket: str | None = None
    created_at: str | None = None
    fingerprint: str | None = None
    dedup_key: str | None = None
    rule_id: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    finding_type: str | None = None
    path_prefix: str | None = None
    expires_on: str | None = None

    def is_expired(self, *, reference_date: date | None = None) -> bool:
        if not self.expires_on:
            return False
        resolved_date = reference_date or date.today()
        try:
            expiry = date.fromisoformat(self.expires_on)
        except ValueError as exc:
            raise ValueError(f"invalid suppression expiry date: {self.expires_on}") from exc
        return expiry < resolved_date

    def matches(self, finding: NormalizedFinding) -> bool:
        selectors = 0

        if self.fingerprint:
            selectors += 1
            if finding.fingerprint != self.fingerprint:
                return False
        if self.dedup_key:
            selectors += 1
            if finding.dedup_key != self.dedup_key:
                return False
        if self.rule_id:
            selectors += 1
            if finding.rule_id != self.rule_id:
                return False
        if self.package_name:
            selectors += 1
            if finding.package_name != self.package_name:
                return False
        if self.package_version:
            selectors += 1
            if finding.package_version != self.package_version:
                return False
        if self.finding_type:
            selectors += 1
            if finding.finding_type != self.finding_type:
                return False
        if self.path_prefix:
            selectors += 1
            location_path = finding.location.path or ""
            if not location_path.startswith(self.path_prefix):
                return False

        return True


@dataclass(frozen=True)
class SuppressedFinding:
    """Lightweight current-run record for a suppressed finding."""

    fingerprint: str
    rule_id: str
    title: str
    severity: str
    reason: str
    owner: str | None = None
    approved_by: str | None = None
    ticket: str | None = None
    created_at: str | None = None
    expires_on: str | None = None


@dataclass(frozen=True)
class SuppressionReport:
    """Result of applying accepted-risk suppressions."""

    suppressed_findings: tuple[SuppressedFinding, ...] = ()
    suppressed_baseline_findings: int = 0
    expired_rules: int = 0
    governance_gaps: tuple[str, ...] = ()


def parse_suppressions_payload(payload: dict[str, object]) -> tuple[SuppressionRule, ...]:
    """Parse and validate a suppressions payload."""

    if not payload:
        return ()

    if "schema_version" not in payload:
        raise ValueError("suppression schema_version must be 1")
    schema_version = payload.get("schema_version")
    if schema_version != SUPPORTED_SUPPRESSION_SCHEMA_VERSION:
        raise ValueError(f"unsupported suppression schema_version: {schema_version}")

    suppressions = payload.get("suppressions", [])
    if not isinstance(suppressions, list):
        raise ValueError("suppressions must be a list")

    rules: list[SuppressionRule] = []
    for raw_rule in suppressions:
        if not isinstance(raw_rule, dict):
            raise ValueError("each suppression rule must be an object")
        reason = strict_string(raw_rule.get("reason"))
        if not reason:
            raise ValueError("suppression rule reason is required")
        rule = SuppressionRule(
            reason=reason,
            owner=optional_string(raw_rule.get("owner")),
            approved_by=optional_string(raw_rule.get("approved_by")),
            ticket=optional_string(raw_rule.get("ticket")),
            created_at=optional_string(raw_rule.get("created_at")),
            fingerprint=optional_string(raw_rule.get("fingerprint")),
            dedup_key=optional_string(raw_rule.get("dedup_key")),
            rule_id=optional_string(raw_rule.get("rule_id")),
            package_name=optional_string(raw_rule.get("package_name")),
            package_version=optional_string(raw_rule.get("package_version")),
            finding_type=optional_string(raw_rule.get("finding_type")),
            path_prefix=optional_string(raw_rule.get("path_prefix")),
            expires_on=optional_string(raw_rule.get("expires_on")),
        )
        if not any(
            (
                rule.fingerprint,
                rule.dedup_key,
                rule.rule_id,
                rule.package_name,
                rule.package_version,
                rule.finding_type,
                rule.path_prefix,
            )
        ):
            raise ValueError("suppression rule must contain at least one match selector")
        rules.append(rule)

    return tuple(rules)


def apply_suppressions(
    *,
    current_findings: list[NormalizedFinding],
    baseline_findings: list[NormalizedFinding],
    rules: tuple[SuppressionRule, ...],
    reference_date: date | None = None,
) -> tuple[list[NormalizedFinding], list[NormalizedFinding], SuppressionReport]:
    """Filter suppressed findings from current and baseline pools."""

    active_rules: list[SuppressionRule] = []
    expired_rules = 0
    for rule in rules:
        if rule.is_expired(reference_date=reference_date):
            expired_rules += 1
        else:
            active_rules.append(rule)

    filtered_current: list[NormalizedFinding] = []
    filtered_baseline: list[NormalizedFinding] = []
    suppressed_current: list[SuppressedFinding] = []
    suppressed_baseline_count = 0
    governance_gaps: set[str] = set()

    for finding in current_findings:
        matched_rule = _match_rule(finding, active_rules)
        if matched_rule is None:
            filtered_current.append(finding)
            continue
        governance_gaps.update(_governance_gaps_for_rule(matched_rule))
        suppressed_current.append(
            SuppressedFinding(
                fingerprint=finding.fingerprint,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                reason=matched_rule.reason,
                owner=matched_rule.owner,
                approved_by=matched_rule.approved_by,
                ticket=matched_rule.ticket,
                created_at=matched_rule.created_at,
                expires_on=matched_rule.expires_on,
            )
        )

    for finding in baseline_findings:
        if _match_rule(finding, active_rules) is None:
            filtered_baseline.append(finding)
            continue
        suppressed_baseline_count += 1

    return filtered_current, filtered_baseline, SuppressionReport(
        suppressed_findings=tuple(suppressed_current),
        suppressed_baseline_findings=suppressed_baseline_count,
        expired_rules=expired_rules,
        governance_gaps=tuple(sorted(governance_gaps)),
    )


def _match_rule(finding: NormalizedFinding, rules: list[SuppressionRule]) -> SuppressionRule | None:
    for rule in rules:
        if rule.matches(finding):
            return rule
    return None


def _governance_gaps_for_rule(rule: SuppressionRule) -> tuple[str, ...]:
    gaps: list[str] = []
    if not rule.owner:
        gaps.append("owner missing")
    if not rule.approved_by:
        gaps.append("approval metadata missing")
    if not rule.ticket:
        gaps.append("tracking ticket missing")
    return tuple(gaps)
