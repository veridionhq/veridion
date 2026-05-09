"""Policy-aware release decision evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.analysis import AnalysisBundle
from veridion.normalize.common import SEVERITY_ORDER
from veridion.policy.labels import APPROVAL_LABELS, VALID_POLICY_TRIGGERS
from veridion.policy.model import PolicyConfig
from veridion.risk import RdiResult, score_analysis_bundle


@dataclass(frozen=True)
class PolicyDecision:
    """Final policy-aware release outcome."""

    score: int
    decision: str
    confidence: str
    reasons: tuple[str, ...]
    score_adjustments: tuple[str, ...]
    recommendations: tuple[str, ...]
    required_approvals: tuple[str, ...]
    policy: PolicyConfig
    risk: RdiResult


def evaluate_release(bundle: AnalysisBundle, policy: PolicyConfig | None = None) -> PolicyDecision:
    """Apply policy constraints and recommendations to the scored risk result."""

    resolved_policy = policy or PolicyConfig()
    base_risk = score_analysis_bundle(bundle)
    risk, score_adjustments = _apply_policy_score_adjustments(base_risk, bundle, resolved_policy)

    reasons = list(risk.reasons)
    reasons.extend(_historical_context_reasons(bundle))
    reasons.extend(_runtime_context_reasons(bundle))
    reasons.extend(_ownership_context_reasons(bundle))
    reasons.extend(_trust_baseline_reasons(bundle))
    decision = _apply_policy_decision(risk, bundle, resolved_policy, reasons)
    required_approvals = _required_approvals(bundle, resolved_policy)
    recommendations = _recommendations(bundle, risk, decision, required_approvals)

    return PolicyDecision(
        score=risk.score,
        decision=decision,
        confidence=risk.confidence,
        reasons=tuple(reasons),
        score_adjustments=score_adjustments,
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

    if _matches_policy_trigger(policy.require_platform_owner_for, bundle):
        approvals.append("platform_owner")

    if _matches_policy_trigger(policy.require_service_owner_for, bundle):
        approvals.append("service_owner")

    if _matches_policy_trigger(policy.require_sre_owner_for, bundle):
        approvals.append("sre_owner")

    if _matches_policy_trigger(policy.require_security_owner_for, bundle):
        approvals.append("security_owner")

    return tuple(dict.fromkeys(approvals))


def _recommendations(
    bundle: AnalysisBundle,
    risk: RdiResult,
    decision: str,
    required_approvals: tuple[str, ...],
) -> tuple[str, ...]:
    recommendations: list[str] = []
    runtime = bundle.runtime_signals
    ownership = bundle.ownership_signals
    historical = bundle.historical_signals
    trust_baseline = bundle.trust_baseline
    ownership_present = _has_ownership_metadata(bundle)

    if decision == "NO GO":
        recommendations.append("Block release until introduced risk is remediated or policy is adjusted")

    for approval in required_approvals:
        recommendations.append(f"Require approval from the {_approval_label(approval)}")

    if bundle.summary.infrastructure_changes:
        recommendations.append("Run staging smoke tests for infrastructure-affecting changes")

    if bundle.summary.dependency_changes or bundle.summary.lockfile_changes:
        recommendations.append("Review newly introduced dependencies and lockfile updates")

    if risk.features.introduced_high or risk.features.introduced_critical:
        recommendations.append("Prioritize remediation for introduced high-severity findings")

    if historical.repo_criticality in {"high", "critical"}:
        recommendations.append("Use heightened review for this high-criticality repository")

    if historical.service_criticality in {"high", "critical"}:
        recommendations.append("Treat this change as high-impact for service operations and release planning")

    if (
        historical.rollback_rate_30d is not None
        and historical.rollback_rate_30d >= 0.10
    ) or (
        historical.change_failure_rate_30d is not None
        and historical.change_failure_rate_30d >= 0.15
    ):
        recommendations.append("Prefer a staged rollout or canary deployment for this historically unstable change surface")

    if historical.incident_count_30d >= 3:
        recommendations.append("Verify rollback ownership and on-call coverage before deployment")

    if historical.flaky_service or historical.sensitive_repo:
        recommendations.append("Schedule deployment during staffed hours with active operational monitoring")

    if runtime.environment == "production" and runtime.blast_radius in {"high", "critical"}:
        recommendations.append("Use a staged rollout with a validated rollback plan for this production deployment")

    if runtime.public_exposure:
        recommendations.append("Verify customer-facing monitoring and alerting before deployment")

    if runtime.rollout_strategy in {"direct", "all_at_once"} and (
        runtime.environment == "production" or runtime.blast_radius in {"high", "critical"}
    ):
        recommendations.append("Prefer canary, rolling, or blue-green rollout over a direct production release")

    if runtime.deployment_window == "after_hours":
        if ownership_present and not ownership.oncall_defined:
            recommendations.append("Avoid after-hours deployment until on-call coverage is defined")
        else:
            recommendations.append("Confirm staffed on-call coverage for this after-hours deployment")

    if ownership_present and ownership.review_coverage == "cross_team":
        recommendations.append("Coordinate sign-off across owning teams before deployment")

    if ownership_present and not ownership.service_owner:
        recommendations.append("Define a service owner before relying on this change path in production")

    if ownership_present and ownership.team_trust_level in {"low", "degrading"}:
        recommendations.append("Use an explicit deployment checklist and reviewer sign-off for this low-trust team surface")

    if trust_baseline.repo_stability in {"watch", "fragile"} or trust_baseline.service_stability in {"watch", "fragile"}:
        recommendations.append("Increase manual validation for this historically fragile change surface")

    if trust_baseline.test_coverage_level == "low":
        recommendations.append("Run targeted regression coverage because baseline test coverage is low")

    if trust_baseline.rollback_readiness in {"partial", "weak"}:
        recommendations.append("Require and verify a rollback path before deployment")

    if (
        trust_baseline.dependency_reputation_risk in {"medium", "high"}
        and (bundle.summary.dependency_changes or bundle.summary.lockfile_changes)
    ):
        recommendations.append("Review dependency reputation and maintenance signals before approving new packages")

    if trust_baseline.team_deploy_safety in {"low", "degrading"}:
        recommendations.append("Use an operator-assisted release path for this low-safety team baseline")

    if not recommendations:
        recommendations.append("Proceed with normal review and deployment checks")

    return tuple(dict.fromkeys(recommendations))


def _approval_label(value: str) -> str:
    return APPROVAL_LABELS.get(value, value.replace("_", " "))


def _historical_context_reasons(bundle: AnalysisBundle) -> tuple[str, ...]:
    historical = bundle.historical_signals
    reasons: list[str] = []

    if historical.repo_criticality in {"high", "critical"}:
        reasons.append(f"repository criticality is {historical.repo_criticality}")

    if historical.service_criticality in {"high", "critical"}:
        reasons.append(f"service criticality is {historical.service_criticality}")

    if historical.rollback_rate_30d is not None and historical.rollback_rate_30d >= 0.10:
        reasons.append(f"30d rollback rate is elevated at {historical.rollback_rate_30d:.0%}")

    if historical.change_failure_rate_30d is not None and historical.change_failure_rate_30d >= 0.15:
        reasons.append(f"30d change failure rate is elevated at {historical.change_failure_rate_30d:.0%}")

    if historical.incident_count_30d >= 3:
        reasons.append(f"service recorded {historical.incident_count_30d} incidents in the last 30 days")

    if historical.flaky_service:
        reasons.append("service is marked flaky in operational metadata")

    if historical.sensitive_repo:
        reasons.append("repository is marked sensitive in operational metadata")

    return tuple(reasons)


def _runtime_context_reasons(bundle: AnalysisBundle) -> tuple[str, ...]:
    runtime = bundle.runtime_signals
    reasons: list[str] = []

    if runtime.environment == "production":
        reasons.append("deployment target is production")
    if runtime.public_exposure:
        reasons.append("service is publicly exposed")
    if runtime.blast_radius in {"high", "critical"}:
        reasons.append(f"blast radius is {runtime.blast_radius}")
    if runtime.deployment_window == "after_hours":
        reasons.append("deployment is planned for after-hours window")
    if runtime.rollout_strategy in {"direct", "all_at_once"}:
        reasons.append(f"rollout strategy is {runtime.rollout_strategy}")

    return tuple(reasons)


def _ownership_context_reasons(bundle: AnalysisBundle) -> tuple[str, ...]:
    ownership = bundle.ownership_signals
    if not _has_ownership_metadata(bundle):
        return ()
    reasons: list[str] = []

    if not ownership.service_owner:
        reasons.append("service ownership metadata is missing")
    if ownership.review_coverage == "cross_team":
        reasons.append("change requires cross-team review coverage")
    if ownership.team_trust_level in {"low", "degrading"}:
        reasons.append(f"team trust level is {ownership.team_trust_level}")
    if not ownership.oncall_defined:
        reasons.append("on-call coverage is not defined for this service")

    return tuple(reasons)


def _matches_policy_trigger(triggers: tuple[str, ...], bundle: AnalysisBundle) -> bool:
    if not triggers:
        return False

    for trigger in triggers:
        if _trigger_matches(trigger, bundle):
            return True
    return False


def _trust_baseline_reasons(bundle: AnalysisBundle) -> tuple[str, ...]:
    trust_baseline = bundle.trust_baseline
    reasons: list[str] = []

    if trust_baseline.repo_stability in {"watch", "fragile"}:
        reasons.append(f"repository stability baseline is {trust_baseline.repo_stability}")
    if trust_baseline.service_stability in {"watch", "fragile"}:
        reasons.append(f"service stability baseline is {trust_baseline.service_stability}")
    if trust_baseline.team_deploy_safety in {"low", "degrading"}:
        reasons.append(f"team deployment safety baseline is {trust_baseline.team_deploy_safety}")
    if trust_baseline.test_coverage_level == "low":
        reasons.append("test coverage baseline is low")
    if trust_baseline.rollback_readiness in {"partial", "weak"}:
        reasons.append(f"rollback readiness baseline is {trust_baseline.rollback_readiness}")
    if trust_baseline.dependency_reputation_risk in {"medium", "high"}:
        reasons.append(f"dependency reputation baseline is {trust_baseline.dependency_reputation_risk} risk")

    return tuple(reasons)


def _trigger_matches(trigger: str, bundle: AnalysisBundle) -> bool:
    historical = bundle.historical_signals
    ownership_present = _has_ownership_metadata(bundle)

    checks = {
        "repo_criticality_high": historical.repo_criticality in {"high", "critical"},
        "service_criticality_high": historical.service_criticality in {"high", "critical"},
        "historical_instability": (
            (historical.rollback_rate_30d is not None and historical.rollback_rate_30d >= 0.10)
            or (historical.change_failure_rate_30d is not None and historical.change_failure_rate_30d >= 0.15)
            or historical.incident_count_30d >= 3
        ),
        "flaky_service": historical.flaky_service,
        "sensitive_repo": historical.sensitive_repo,
        "production_deployment": bundle.runtime_signals.environment == "production",
        "public_exposure": bundle.runtime_signals.public_exposure,
        "large_blast_radius": bundle.runtime_signals.blast_radius in {"high", "critical"},
        "after_hours_deploy": bundle.runtime_signals.deployment_window == "after_hours",
        "low_team_trust": ownership_present and bundle.ownership_signals.team_trust_level in {"low", "degrading"},
        "unowned_service": ownership_present and not bundle.ownership_signals.service_owner,
        "missing_oncall": ownership_present and not bundle.ownership_signals.oncall_defined,
        "cross_team_change": ownership_present and bundle.ownership_signals.review_coverage == "cross_team",
    }
    return checks.get(trigger, False) if trigger in VALID_POLICY_TRIGGERS else False


def _has_ownership_metadata(bundle: AnalysisBundle) -> bool:
    ownership = bundle.ownership_signals
    return any(
        (
            ownership.service_owner,
            ownership.owning_team,
            ownership.review_coverage,
            ownership.team_trust_level,
            ownership.oncall_defined,
        )
    )


def _apply_policy_score_adjustments(
    risk: RdiResult,
    bundle: AnalysisBundle,
    policy: PolicyConfig,
) -> tuple[RdiResult, tuple[str, ...]]:
    adjusted_score = risk.score
    adjustments: list[str] = []

    if policy.historical_instability_score_penalty and _trigger_matches("historical_instability", bundle):
        adjusted_score -= policy.historical_instability_score_penalty
        adjustments.append(
            f"historical instability: -{policy.historical_instability_score_penalty}"
        )

    if policy.service_criticality_score_penalty and _trigger_matches("service_criticality_high", bundle):
        adjusted_score -= policy.service_criticality_score_penalty
        adjustments.append(
            f"service criticality: -{policy.service_criticality_score_penalty}"
        )

    if policy.sensitive_repo_score_penalty and _trigger_matches("sensitive_repo", bundle):
        adjusted_score -= policy.sensitive_repo_score_penalty
        adjustments.append(f"sensitive repository: -{policy.sensitive_repo_score_penalty}")

    if policy.ai_signal_score_penalty and bundle.summary.ai_change_signals:
        adjusted_score -= policy.ai_signal_score_penalty
        adjustments.append(f"AI-origin signals: -{policy.ai_signal_score_penalty}")

    if policy.ai_authored_commit_score_penalty and bundle.summary.ai_authored_commits:
        adjusted_score -= policy.ai_authored_commit_score_penalty
        adjustments.append(f"AI-attributed commits: -{policy.ai_authored_commit_score_penalty}")

    if policy.production_deployment_score_penalty and _trigger_matches("production_deployment", bundle):
        adjusted_score -= policy.production_deployment_score_penalty
        adjustments.append(f"production deployment: -{policy.production_deployment_score_penalty}")

    if policy.after_hours_deploy_score_penalty and _trigger_matches("after_hours_deploy", bundle):
        adjusted_score -= policy.after_hours_deploy_score_penalty
        adjustments.append(f"after-hours deployment: -{policy.after_hours_deploy_score_penalty}")

    if policy.public_exposure_score_penalty and _trigger_matches("public_exposure", bundle):
        adjusted_score -= policy.public_exposure_score_penalty
        adjustments.append(f"public exposure: -{policy.public_exposure_score_penalty}")

    if policy.large_blast_radius_score_penalty and _trigger_matches("large_blast_radius", bundle):
        adjusted_score -= policy.large_blast_radius_score_penalty
        adjustments.append(f"large blast radius: -{policy.large_blast_radius_score_penalty}")

    if policy.low_team_trust_score_penalty and _trigger_matches("low_team_trust", bundle):
        adjusted_score -= policy.low_team_trust_score_penalty
        adjustments.append(f"low team trust: -{policy.low_team_trust_score_penalty}")

    if policy.unowned_service_score_penalty and _trigger_matches("unowned_service", bundle):
        adjusted_score -= policy.unowned_service_score_penalty
        adjustments.append(f"unowned service: -{policy.unowned_service_score_penalty}")

    if policy.missing_oncall_score_penalty and _trigger_matches("missing_oncall", bundle):
        adjusted_score -= policy.missing_oncall_score_penalty
        adjustments.append(f"missing on-call coverage: -{policy.missing_oncall_score_penalty}")

    if policy.cross_team_change_score_penalty and _trigger_matches("cross_team_change", bundle):
        adjusted_score -= policy.cross_team_change_score_penalty
        adjustments.append(f"cross-team change surface: -{policy.cross_team_change_score_penalty}")

    adjusted_score = max(0, min(100, adjusted_score))

    return (
        RdiResult(
            score=adjusted_score,
            decision=risk.decision,
            confidence=risk.confidence,
            reasons=risk.reasons,
            features=risk.features,
        ),
        tuple(adjustments),
    )
