"""Deterministic risk feature extraction and scoring for release decisions."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.analysis import AnalysisBundle


@dataclass(frozen=True)
class RiskFeatures:
    """Explainable risk features derived from the analysis bundle."""

    introduced_findings: int
    introduced_critical: int
    introduced_high: int
    introduced_medium: int
    introduced_low: int
    introduced_code_findings: int
    introduced_dependency_findings: int
    changed_files: int
    has_dependency_changes: bool
    has_lockfile_changes: bool
    has_infrastructure_changes: bool
    public_exposure: bool
    high_blast_radius: bool
    after_hours_deploy: bool
    weak_rollback_readiness: bool
    low_test_coverage: bool
    broad_iam_changes: bool
    privileged_container_changes: bool
    direct_rollout_changes: bool
    healthcheck_risk_changes: bool
    resource_limit_risk_changes: bool
    autoscaling_changes: bool


@dataclass(frozen=True)
class RdiResult:
    """Scored release outcome for the current analysis bundle."""

    score: int
    decision: str
    confidence: str
    reasons: tuple[str, ...]
    features: RiskFeatures


def extract_risk_features(bundle: AnalysisBundle) -> RiskFeatures:
    """Extract scoring features from the deterministic analysis bundle."""

    introduced = bundle.baseline_comparison.introduced

    return RiskFeatures(
        introduced_findings=len(introduced),
        introduced_critical=_count_introduced_with_severity(bundle, "critical"),
        introduced_high=_count_introduced_with_severity(bundle, "high"),
        introduced_medium=_count_introduced_with_severity(bundle, "medium"),
        introduced_low=_count_introduced_with_severity(bundle, "low"),
        introduced_code_findings=_count_introduced_with_type(bundle, "code"),
        introduced_dependency_findings=_count_introduced_with_type(bundle, "dependency"),
        changed_files=bundle.summary.changed_files,
        has_dependency_changes=bundle.summary.dependency_changes,
        has_lockfile_changes=bundle.summary.lockfile_changes,
        has_infrastructure_changes=bundle.summary.infrastructure_changes,
        public_exposure=bundle.runtime_signals.public_exposure,
        high_blast_radius=bundle.runtime_signals.blast_radius in {"high", "critical"},
        after_hours_deploy=bundle.runtime_signals.deployment_window == "after_hours",
        weak_rollback_readiness=bundle.trust_baseline.rollback_readiness in {"partial", "weak"},
        low_test_coverage=bundle.trust_baseline.test_coverage_level == "low",
        broad_iam_changes=bundle.change_context.has_broad_iam_changes,
        privileged_container_changes=bundle.change_context.has_privileged_container_changes,
        direct_rollout_changes=bundle.change_context.has_direct_rollout_changes,
        healthcheck_risk_changes=bundle.change_context.has_healthcheck_risk_changes,
        resource_limit_risk_changes=bundle.change_context.has_resource_limit_risk_changes,
        autoscaling_changes=bundle.change_context.has_autoscaling_changes,
    )


def score_analysis_bundle(bundle: AnalysisBundle) -> RdiResult:
    """Assign an explainable RDI score and release decision.

    CVSS and EPSS are captured in the normalized model but not yet applied in scoring.
    """

    features = extract_risk_features(bundle)
    score = 100

    score -= features.introduced_critical * 35
    score -= features.introduced_high * 20
    score -= features.introduced_medium * 8
    score -= features.introduced_low * 3

    if features.has_infrastructure_changes and features.introduced_findings:
        score -= 10
    elif features.has_infrastructure_changes:
        score -= 5

    if features.has_dependency_changes and features.introduced_dependency_findings:
        score -= 8

    if features.has_lockfile_changes and features.introduced_dependency_findings:
        score -= 4

    if features.public_exposure and features.introduced_findings:
        score -= 5
    if features.high_blast_radius and features.introduced_findings:
        score -= 7
    if features.after_hours_deploy and features.introduced_findings:
        score -= 4
    if features.weak_rollback_readiness and features.introduced_findings:
        score -= 6
    if features.low_test_coverage and features.introduced_findings:
        score -= 4
    if features.broad_iam_changes:
        score -= 6
    if features.privileged_container_changes:
        score -= 6
    if features.direct_rollout_changes:
        score -= 5
    if features.healthcheck_risk_changes:
        score -= 5
    if features.resource_limit_risk_changes:
        score -= 4
    if features.autoscaling_changes:
        score -= 3

    score = max(0, min(100, score))

    decision = _derive_decision(score, features)
    confidence = _derive_confidence(bundle, features)
    reasons = _derive_reasons(features)

    return RdiResult(
        score=score,
        decision=decision,
        confidence=confidence,
        reasons=reasons,
        features=features,
    )


def _count_introduced_with_severity(bundle: AnalysisBundle, severity: str) -> int:
    return sum(1 for finding in bundle.baseline_comparison.introduced if finding.severity == severity)


def _count_introduced_with_type(bundle: AnalysisBundle, finding_type: str) -> int:
    return sum(1 for finding in bundle.baseline_comparison.introduced if finding.finding_type == finding_type)


def _derive_decision(score: int, features: RiskFeatures) -> str:
    if features.introduced_critical:
        return "NO GO"
    if score < 60:
        return "NO GO"
    if features.has_infrastructure_changes and features.introduced_findings:
        return "CONDITIONAL GO"
    if features.introduced_high:
        return "CONDITIONAL GO"
    if score < 85:
        return "CONDITIONAL GO"
    return "GO"


def _derive_confidence(bundle: AnalysisBundle, features: RiskFeatures) -> str:
    evidence_count = 0

    if features.changed_files:
        evidence_count += 1
    if features.changed_files >= 5:
        evidence_count += 1
    if bundle.summary.total_findings or bundle.summary.inventory_packages:
        evidence_count += 1
    if features.has_dependency_changes or features.has_lockfile_changes or features.has_infrastructure_changes:
        evidence_count += 1
    if bundle.baseline_comparison.existing or bundle.baseline_comparison.introduced or bundle.baseline_comparison.unattributed:
        evidence_count += 1
    if bundle.summary.ai_change_signals or bundle.summary.historical_risk_signals:
        evidence_count += 1

    if evidence_count >= 3:
        return "high"
    if evidence_count >= 2:
        return "medium"
    return "low"


def _derive_reasons(features: RiskFeatures) -> tuple[str, ...]:
    reasons: list[str] = []

    if features.introduced_critical:
        reasons.append(_issue_count_reason(features.introduced_critical, "critical"))
    if features.introduced_high:
        reasons.append(_issue_count_reason(features.introduced_high, "high-severity"))
    if features.introduced_medium:
        reasons.append(_issue_count_reason(features.introduced_medium, "medium-severity"))
    if features.introduced_low:
        reasons.append(_issue_count_reason(features.introduced_low, "low-severity"))
    if features.has_infrastructure_changes and features.introduced_findings:
        reasons.append("the change includes infrastructure updates")
    if features.introduced_dependency_findings:
        reasons.append("the change introduces vulnerable dependencies")
    if not reasons and features.introduced_findings == 0:
        reasons.append("no introduced findings detected")

    return tuple(reasons)


def _issue_count_reason(count: int, severity: str) -> str:
    noun = "issue" if count == 1 else "issues"
    return f"{count} new {severity} {noun} detected"
