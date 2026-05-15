"""Versioned machine-facing release decision contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from veridion.analysis import AnalysisBundle
from veridion.normalize.common import severity_rank
from veridion.policy import PolicyDecision
from veridion.policy.pack import PolicyPackMetadata
from veridion.policy.text import (
    SEVERITY_ISSUE_REASON_RE,
    filter_approval_echo_recommendations,
    format_approval_label,
)
from veridion.report import ThreatExplanation

SUPPORTED_DECISION_SCHEMA_VERSION = 1

_REQUIRED_NEXT_STEP_PREFIXES = (
    "Block release",
    "Run ",
    "Review ",
    "Prioritize ",
    "Validate ",
    "Verify ",
    "Define ",
    "Remove ",
    "Restore ",
    "Avoid ",
    "Confirm ",
    "Use ",
    "Treat ",
    "Increase ",
    "Coordinate ",
    "Schedule ",
    "Require ",
)


@dataclass(frozen=True)
class GateEvaluation:
    """Workflow-facing gate interpretation of a release decision."""

    status: str
    decision_allowed: bool
    allowed_decisions: tuple[str, ...]

    @property
    def exit_code(self) -> int:
        return 0 if self.decision_allowed else 1


def evaluate_gate(decision: str, *, allowed_decisions: tuple[str, ...]) -> GateEvaluation:
    """Map a verdict to a stable gate status and allowed/blocked result."""

    normalized_allowed = tuple(dict.fromkeys(item.strip() for item in allowed_decisions if item.strip()))
    return GateEvaluation(
        status=_gate_status(decision),
        decision_allowed=decision in normalized_allowed,
        allowed_decisions=normalized_allowed,
    )


def build_decision_contract(
    *,
    bundle: AnalysisBundle,
    decision: PolicyDecision,
    threats: tuple[ThreatExplanation, ...],
    comment_identifier: str,
    comment_summary: dict[str, str],
    gate: GateEvaluation,
    policy_pack_metadata: PolicyPackMetadata | None = None,
) -> dict[str, object]:
    """Build the stable decision artifact consumed by downstream automation."""

    required_next_steps, advisory_guidance = _split_recommendations(
        filter_approval_echo_recommendations(decision.recommendations, decision.required_approvals)
    )
    blocking_reasons = tuple(reason for reason in decision.reasons if _is_blocking_reason(reason, decision.decision))
    operational_signals = _operational_signals(bundle)

    return {
        "schema_version": SUPPORTED_DECISION_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "source": "veridion/action",
        "contract_version_source": "veridion.decision_contract@1",
        "decision": {
            "verdict": decision.decision,
            "score": decision.score,
            "confidence": decision.confidence.upper(),
            "gate_status": gate.status,
            "decision_allowed": gate.decision_allowed,
            "allowed_decisions": list(gate.allowed_decisions),
            "blocking_categories": _blocking_categories(bundle, decision),
        },
        "reasons": {
            "blocking": list(blocking_reasons),
            "all": list(decision.reasons),
            "score_adjustments": list(decision.score_adjustments),
        },
        "actions": {
            "required_approvals": list(decision.required_approvals),
            "required_approval_labels": [_format_approval(value) for value in decision.required_approvals],
            "required_next_steps": list(required_next_steps),
            "advisory_guidance": list(advisory_guidance),
            "all_recommendations": list(decision.recommendations),
        },
        "threats": _normalize_threats(threats),
        "signals": operational_signals,
        "accepted_risk": {
            "present": bool(bundle.summary.suppressed_findings),
            "suppressed_findings_count": bundle.summary.suppressed_findings,
            "expired_suppressions": bundle.summary.expired_suppressions,
            "pending_review": bundle.suppression_report.pending_review,
            "renewal_pending": bundle.suppression_report.renewal_pending,
            "expiring_soon": bundle.suppression_report.expiring_soon,
            "governance_gaps": list(bundle.suppression_report.governance_gaps),
            "lifecycle_events": list(bundle.suppression_report.lifecycle_events),
            "exceptions": [
                {
                    "exception_id": item.exception_id,
                    "status": item.status,
                    "reason": item.reason,
                    "owner": item.owner or "",
                    "approved_by": item.approved_by or "",
                    "ticket": item.ticket or "",
                    "created_at": item.created_at or "",
                    "reviewed_at": item.reviewed_at or "",
                    "renewal_of": item.renewal_of or "",
                    "expires_on": item.expires_on or "",
                    "expired": item.expired,
                    "expiring_soon": item.expiring_soon,
                    "active": item.active,
                }
                for item in bundle.suppression_report.exceptions
            ],
            "suppressed_findings": [
                {
                    "fingerprint": item.fingerprint,
                    "rule_id": item.rule_id,
                    "title": item.title,
                    "severity": item.severity,
                    "exception_id": item.exception_id or "",
                    "status": item.status,
                    "reason": item.reason,
                    "owner": item.owner or "",
                    "approved_by": item.approved_by or "",
                    "ticket": item.ticket or "",
                    "created_at": item.created_at or "",
                    "reviewed_at": item.reviewed_at or "",
                    "renewal_of": item.renewal_of or "",
                    "expires_on": item.expires_on or "",
                }
                for item in bundle.suppression_report.suppressed_findings
            ],
        },
        "automation": {
            "comment_identifier": comment_identifier,
            "comment_summary": comment_summary,
            "requires_human_review": decision.decision in {"NO GO", "CONDITIONAL GO"} or bool(decision.required_approvals),
            "requires_approvals": bool(decision.required_approvals),
            "requires_exception_review": bool(
                bundle.summary.suppressed_findings
                or bundle.suppression_report.pending_review
                or bundle.suppression_report.renewal_pending
                or bundle.suppression_report.governance_gaps
                or bundle.summary.expired_suppressions
            ),
        },
        "policy": {
            "pack_id": (policy_pack_metadata.pack_id if policy_pack_metadata else ""),
            "pack_name": (policy_pack_metadata.display_name if policy_pack_metadata else ""),
            "pack_version": (policy_pack_metadata.version if policy_pack_metadata else ""),
            "pack_owner": (policy_pack_metadata.owner if policy_pack_metadata else ""),
            "rollout_stage": (policy_pack_metadata.rollout_stage if policy_pack_metadata else ""),
            "max_severity": decision.policy.max_severity,
            "allow_conditional": decision.policy.allow_conditional,
            "no_go_below_score": decision.policy.no_go_below_score,
            "conditional_go_below_score": decision.policy.conditional_go_below_score,
        },
    }


def _gate_status(decision: str) -> str:
    if decision == "NO GO":
        return "block"
    if decision == "CONDITIONAL GO":
        return "review"
    return "pass"


def _split_recommendations(recommendations: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    required: list[str] = []
    advisory: list[str] = []

    for recommendation in recommendations:
        if recommendation.startswith(_REQUIRED_NEXT_STEP_PREFIXES):
            required.append(recommendation)
        else:
            advisory.append(recommendation)

    return tuple(required), tuple(advisory)


def _is_blocking_reason(reason: str, decision: str) -> bool:
    if decision == "GO":
        return False
    if SEVERITY_ISSUE_REASON_RE.match(reason):
        return True
    return reason.startswith(
        (
            "policy ",
            "the change includes infrastructure updates",
            "the change introduces vulnerable dependencies",
            "accepted risk is present in the current change",
            "accepted risk governance metadata is incomplete",
        )
    )


def _format_approval(value: str) -> str:
    return format_approval_label(value)


def _operational_signals(bundle: AnalysisBundle) -> dict[str, object]:
    historical = bundle.historical_signals
    runtime = bundle.runtime_signals
    ownership = bundle.ownership_signals
    trust = bundle.trust_baseline
    trust_memory = bundle.trust_memory_signals
    change_context = bundle.change_context

    runtime_safety_checks: list[str] = []
    if change_context.has_healthcheck_risk_changes:
        runtime_safety_checks.append("health-check coverage changed")
    if change_context.has_resource_limit_risk_changes:
        runtime_safety_checks.append("resource limits changed")
    if change_context.has_privileged_container_changes:
        runtime_safety_checks.append("privileged container settings changed")
    if change_context.has_direct_rollout_changes:
        runtime_safety_checks.append("direct rollout settings changed")

    return {
        "history": {
            "repo_criticality": historical.repo_criticality,
            "service_criticality": historical.service_criticality,
            "rollback_rate_30d": historical.rollback_rate_30d,
            "change_failure_rate_30d": historical.change_failure_rate_30d,
            "incident_count_30d": historical.incident_count_30d,
            "flaky_service": historical.flaky_service,
            "sensitive_repo": historical.sensitive_repo,
            "elevated": list(historical.elevated_signals),
        },
        "runtime": {
            "environment": runtime.environment,
            "deployment_window": runtime.deployment_window,
            "public_exposure": runtime.public_exposure,
            "blast_radius": runtime.blast_radius,
            "rollout_strategy": runtime.rollout_strategy,
            "deployment_freeze_active": runtime.deployment_freeze_active,
            "active_incident": runtime.active_incident,
            "active_incident_severity": runtime.active_incident_severity,
            "alert_state": runtime.alert_state,
            "canary_health": runtime.canary_health,
            "rollback_viability": runtime.rollback_viability,
            "runtime_safety_checks": runtime_safety_checks,
            "active_runtime_gates": _active_runtime_gates(runtime),
            "elevated": list(runtime.elevated_signals),
        },
        "ownership": {
            "service_owner": ownership.service_owner,
            "owning_team": ownership.owning_team,
            "review_coverage": ownership.review_coverage,
            "team_trust_level": ownership.team_trust_level,
            "oncall_defined": ownership.oncall_defined,
            "elevated": list(ownership.elevated_signals),
        },
        "trust_baseline": {
            "repo_stability": trust.repo_stability,
            "service_stability": trust.service_stability,
            "team_deploy_safety": trust.team_deploy_safety,
            "test_coverage_level": trust.test_coverage_level,
            "rollback_readiness": trust.rollback_readiness,
            "dependency_reputation_risk": trust.dependency_reputation_risk,
            "elevated": list(trust.elevated_signals),
        },
        "trust_memory": {
            "recent_decisions_30d": trust_memory.recent_decisions_30d,
            "conditional_go_count_30d": trust_memory.conditional_go_count_30d,
            "no_go_count_30d": trust_memory.no_go_count_30d,
            "policy_override_count_30d": trust_memory.policy_override_count_30d,
            "accepted_risk_exception_count": trust_memory.accepted_risk_exception_count,
            "mean_rdi_score_30d": trust_memory.mean_rdi_score_30d,
            "elevated": list(trust_memory.elevated_signals),
        },
    }


def _normalize_threats(threats: tuple[ThreatExplanation, ...]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str | None, str, str], dict[str, object]] = {}

    for threat in threats:
        key = (
            threat.severity,
            threat.threat_type,
            threat.location,
            threat.summary,
            threat.why_not_safe,
        )
        existing = grouped.get(key)
        if existing is None:
            existing = {
                "severity": threat.severity,
                "threat_type": threat.threat_type,
                "location": threat.location,
                "summary": threat.summary,
                "why_not_safe": threat.why_not_safe,
                "advisory_count": 0,
                "subjects": [],
                "sources": [],
            }
            grouped[key] = existing
        existing["advisory_count"] += threat.advisory_count
        if threat.subject not in existing["subjects"]:
            existing["subjects"].append(threat.subject)
        if threat.source not in existing["sources"]:
            existing["sources"].append(threat.source)

    return sorted(
        grouped.values(),
        key=lambda item: (
            severity_rank(str(item["severity"])),
            str(item["threat_type"]),
            str(item["location"] or ""),
            str(item["summary"]),
        ),
    )


def _blocking_categories(bundle: AnalysisBundle, decision: PolicyDecision) -> list[str]:
    categories: list[str] = []
    features = decision.risk.features

    if features.introduced_critical:
        categories.append("introduced_critical_findings")
    if features.introduced_high:
        categories.append("introduced_high_findings")
    if features.introduced_medium:
        categories.append("introduced_medium_findings")
    if bundle.summary.infrastructure_changes:
        categories.append("infrastructure_risk")
    if features.introduced_dependency_findings:
        categories.append("dependency_risk")
    if bundle.runtime_signals.public_exposure:
        categories.append("public_exposure")
    if bundle.runtime_signals.blast_radius in {"high", "critical"}:
        categories.append("large_blast_radius")
    if bundle.runtime_signals.deployment_freeze_active:
        categories.append("deployment_freeze_active")
    if bundle.runtime_signals.active_incident:
        categories.append("active_incident")
    if bundle.runtime_signals.alert_state == "firing":
        categories.append("firing_alerts")
    if bundle.runtime_signals.canary_health in {"degraded", "failing"}:
        categories.append("degraded_canary_health")
    if bundle.runtime_signals.rollback_viability == "blocked":
        categories.append("runtime_rollback_blocked")
    if bundle.change_context.has_shared_platform_changes:
        categories.append("shared_platform_surface")
    if bundle.summary.suppressed_findings:
        categories.append("accepted_risk_present")
    if bundle.summary.suppression_governance_gaps:
        categories.append("accepted_risk_governance_gap")
    if bundle.suppression_report.pending_review:
        categories.append("accepted_risk_pending_review")
    if bundle.suppression_report.renewal_pending:
        categories.append("accepted_risk_renewal_pending")
    if bundle.suppression_report.expiring_soon:
        categories.append("accepted_risk_expiring_soon")
    if bundle.summary.expired_suppressions:
        categories.append("expired_accepted_risk")
    if bundle.trust_memory_signals.policy_override_count_30d >= 2:
        categories.append("policy_override_burden")
    if bundle.trust_memory_signals.accepted_risk_exception_count >= 5:
        categories.append("accepted_risk_burden")
    if any(reason.startswith("policy max_severity") for reason in decision.reasons):
        categories.append("policy_max_severity_exceeded")
    if any(reason.startswith("policy no_go threshold") for reason in decision.reasons):
        categories.append("policy_no_go_threshold")

    return categories


def _active_runtime_gates(runtime) -> list[str]:
    gates: list[str] = []

    if runtime.deployment_freeze_active:
        gates.append("deployment_freeze_active")
    if runtime.active_incident:
        gates.append("active_incident")
    if runtime.alert_state in {"elevated", "firing"}:
        gates.append(f"alert_state:{runtime.alert_state}")
    if runtime.canary_health in {"degraded", "failing"}:
        gates.append(f"canary_health:{runtime.canary_health}")
    if runtime.rollback_viability in {"unverified", "blocked"}:
        gates.append(f"rollback_viability:{runtime.rollback_viability}")

    return gates


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
