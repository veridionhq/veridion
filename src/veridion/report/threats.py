"""Structured threat explanations for introduced release risk."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from veridion.analysis import AnalysisBundle
from veridion.normalize.models import NormalizedFinding


@dataclass(frozen=True)
class ThreatExplanation:
    """Concrete, human-readable explanation for an introduced threat."""

    source: str
    threat_type: str
    severity: str
    subject: str
    location: str | None
    summary: str
    why_not_safe: str
    advisory_count: int = 1

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def explain_introduced_threats(bundle: AnalysisBundle) -> tuple[ThreatExplanation, ...]:
    """Build deterministic threat explanations from introduced findings."""

    introduced = sorted(
        bundle.baseline_comparison.introduced,
        key=lambda finding: (
            _severity_rank(finding.severity),
            finding.finding_type,
            finding.title.lower(),
            finding.location.path or "",
        ),
    )
    explanations: list[ThreatExplanation] = []
    grouped_dependencies: dict[tuple[str, str, str, str | None], list[NormalizedFinding]] = {}

    for finding in introduced:
        if finding.finding_type == "dependency":
            location = _normalize_location(finding.location.path)
            severity = finding.severity.replace("-", " ")
            package = " ".join(part for part in (finding.package_name, finding.package_version) if part)
            subject = package or finding.rule_id
            # Keep severities separate so the rendered threat lines preserve the highest-risk grouping.
            # advisory_count is therefore per (package, location, severity), not a package-wide total.
            key = (severity, "dependency", subject, location)
            grouped_dependencies.setdefault(key, []).append(finding)
            continue
        explanation = _explain_finding(finding)
        explanations.append(explanation)

    for (severity, _, subject, location), findings in grouped_dependencies.items():
        explanations.append(_merge_dependency_explanations(findings, severity=severity, subject=subject, location=location))

    return tuple(
        sorted(
            explanations,
            key=lambda item: (
                _severity_rank(item.severity),
                item.threat_type,
                item.location or "",
                item.subject,
            ),
        )
    )


def render_threat_line(explanation: ThreatExplanation) -> str:
    """Render a short threat line for comment output."""

    if explanation.location:
        return (
            f"{explanation.severity} {explanation.threat_type} risk in "
            f"{explanation.location}: {explanation.summary}"
        )
    return f"{explanation.severity} {explanation.threat_type} risk: {explanation.summary}"


def _explain_finding(finding: NormalizedFinding) -> ThreatExplanation:
    location = _normalize_location(finding.location.path)
    severity = finding.severity.replace("-", " ")

    if finding.finding_type == "dependency":
        package = " ".join(part for part in (finding.package_name, finding.package_version) if part)
        subject = package or finding.rule_id
        summary = _summarize_dependency_title(finding)
        why_not_safe = "the change introduces a vulnerable package version"
        return ThreatExplanation(
            source=finding.source,
            threat_type="dependency",
            severity=severity,
            subject=subject,
            location=location,
            summary=f"{subject}" + (f" ({summary})" if summary else ""),
            why_not_safe=why_not_safe,
        )

    summary, why_not_safe = _summarize_code_or_config_finding(finding)
    return ThreatExplanation(
        source=finding.source,
        threat_type=finding.finding_type,
        severity=severity,
        subject=finding.rule_id,
        location=location,
        summary=summary,
        why_not_safe=why_not_safe,
    )


def _summarize_dependency_title(finding: NormalizedFinding) -> str:
    title = (finding.title or finding.rule_id).strip()
    return _shorten_title(title)


def _summarize_code_or_config_finding(finding: NormalizedFinding) -> tuple[str, str]:
    title = (finding.title or finding.rule_id).strip()
    lowered = title.lower()
    rule_id = finding.rule_id.lower()

    if "shell=true" in lowered:
        return (
            "uses subprocess with shell=True",
            "shell execution can allow command injection or unsafe command expansion",
        )
    if "allowprivilegeescalation" in lowered or "allowprivilegeescalation" in rule_id:
        return (
            "container can allow privilege escalation",
            "a compromised process may be able to gain elevated privileges inside the container",
        )
    if "runasnonroot" in lowered or "runasnonroot" in rule_id:
        return (
            "container may run as root",
            "running as root increases the impact of a container compromise",
        )
    if "privileged: true" in lowered or "privileged" in rule_id:
        return (
            "container is configured as privileged",
            "a privileged container has broad host-level access if it is compromised",
        )
    if "no-iam-admin-privileges" in rule_id or "no-iam-star-actions" in rule_id:
        return (
            "adds overly broad IAM permissions",
            "overly broad IAM permissions can allow privilege escalation and violate least privilege",
        )

    summary = _shorten_title(title)
    return summary, "the change introduces new application or configuration risk"


def _merge_dependency_explanations(
    findings: list[NormalizedFinding],
    *,
    severity: str,
    subject: str,
    location: str | None,
) -> ThreatExplanation:
    ordered_titles = []
    seen_titles: set[str] = set()
    for finding in findings:
        title = _summarize_dependency_title(finding)
        if title and title not in seen_titles:
            seen_titles.add(title)
            ordered_titles.append(title)

    if len(ordered_titles) <= 1:
        summary = f"{subject}" + (f" ({ordered_titles[0]})" if ordered_titles else "")
    elif len(ordered_titles) == 2:
        summary = f"{subject} ({ordered_titles[0]}; {ordered_titles[1]})"
    else:
        summary = f"{subject} ({ordered_titles[0]}; {len(ordered_titles) - 1} more advisories)"

    return ThreatExplanation(
        source=findings[0].source,
        threat_type="dependency",
        severity=severity,
        subject=subject,
        location=location,
        summary=summary,
        why_not_safe="the change introduces vulnerable package versions",
        advisory_count=len(findings),
    )


def _shorten_title(text: str) -> str:
    shortened = _first_sentence(text)
    if len(shortened) > 90:
        shortened = shortened[:87].rstrip() + "..."
    return shortened


def _first_sentence(text: str) -> str:
    for delimiter in (". ", "\n"):
        if delimiter in text:
            return text.split(delimiter, 1)[0].strip().rstrip(".")
    return text.strip().rstrip(".")


def _normalize_location(path: str | None) -> str | None:
    if not path:
        return None
    normalized = path.removeprefix("/workspace/").lstrip("/")
    return normalized or None


def _severity_rank(severity: str) -> int:
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "unknown": 5,
    }
    return order.get(severity, 6)
