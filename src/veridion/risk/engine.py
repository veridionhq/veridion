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
