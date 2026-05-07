"""Policy-aware release decision evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.analysis import AnalysisBundle
from veridion.normalize.common import SEVERITY_ORDER
from veridion.policy.model import PolicyConfig
from veridion.risk import RdiResult, score_analysis_bundle


@dataclass(frozen=True)
class PolicyDecision:
    """Final policy-aware release outcome."""

    score: int
    decision: str
    confidence: str
    reasons: tuple[str, ...]
    recommendations: tuple[str, ...]
    required_approvals: tuple[str, ...]
    policy: PolicyConfig
    risk: RdiResult


def evaluate_release(bundle: AnalysisBundle, policy: PolicyConfig | None = None) -> PolicyDecision:
    """Apply policy constraints and recommendations to the scored risk result."""

    resolved_policy = policy or PolicyConfig()
    risk = score_analysis_bundle(bundle)

    reasons = list(risk.reasons)
    decision = _apply_policy_decision(risk, bundle, resolved_policy, reasons)
    required_approvals = _required_approvals(bundle, resolved_policy)
    recommendations = _recommendations(bundle, risk, decision, required_approvals)

    return PolicyDecision(
        score=risk.score,
        decision=decision,
        confidence=risk.confidence,
        reasons=tuple(reasons),
        recommendations=recommendations,
        required_approvals=required_approvals,
        policy=resolved_policy,
        risk=risk,
    )


def _apply_policy_decision(
    risk: RdiResult,
    bundle: AnalysisBundle,
    policy: PolicyConfig,
    reasons: list[str],
) -> str:
    max_allowed_index = SEVERITY_ORDER.index(policy.max_severity)
    strongest_introduced = _strongest_introduced_severity(bundle)

    if strongest_introduced is not None and SEVERITY_ORDER.index(strongest_introduced) <= max_allowed_index:
        reasons.append(f"policy max_severity exceeded by introduced {strongest_introduced} finding(s)")
        return "NO GO"

    if risk.score < policy.no_go_below_score:
        reasons.append(f"policy no_go threshold triggered at score {policy.no_go_below_score}")
        return "NO GO"

    if risk.decision == "CONDITIONAL GO" and not policy.allow_conditional:
        reasons.append("policy does not allow conditional releases")
        return "NO GO"

    if risk.decision == "NO GO":
        return "NO GO"

    if risk.score < policy.conditional_go_below_score:
        return "CONDITIONAL GO"

    return risk.decision


def _strongest_introduced_severity(bundle: AnalysisBundle) -> str | None:
    severities = {finding.severity for finding in bundle.baseline_comparison.introduced}
    for severity in SEVERITY_ORDER:
        if severity in severities:
            return severity
    return None


def _required_approvals(bundle: AnalysisBundle, policy: PolicyConfig) -> tuple[str, ...]:
    approvals: list[str] = []

    if "production_iac" in policy.require_approval_for and bundle.summary.infrastructure_changes:
        approvals.append("platform_owner")

    if "dependency_changes" in policy.require_approval_for and (
        bundle.summary.dependency_changes or bundle.summary.lockfile_changes
    ):
        approvals.append("security_owner")

    return tuple(approvals)


def _recommendations(
    bundle: AnalysisBundle,
    risk: RdiResult,
    decision: str,
    required_approvals: tuple[str, ...],
) -> tuple[str, ...]:
    recommendations: list[str] = []

    if decision == "NO GO":
        recommendations.append("Block release until introduced risk is remediated or policy is adjusted")

    if "platform_owner" in required_approvals:
        recommendations.append("Require approval from the platform owner")

    if "security_owner" in required_approvals:
        recommendations.append("Require approval from the security owner")

    if bundle.summary.infrastructure_changes:
        recommendations.append("Run staging smoke tests for infrastructure-affecting changes")

    if bundle.summary.dependency_changes or bundle.summary.lockfile_changes:
        recommendations.append("Review newly introduced dependencies and lockfile updates")

    if risk.features.introduced_high or risk.features.introduced_critical:
        recommendations.append("Prioritize remediation for introduced high-severity findings")

    if not recommendations:
        recommendations.append("Proceed with normal review and deployment checks")

    return tuple(dict.fromkeys(recommendations))
