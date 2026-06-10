"""Shared decision-basis language for human and machine release decisions."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.analysis import AnalysisBundle
from veridion.policy import PolicyDecision
from veridion.policy.text import format_approval_label


@dataclass(frozen=True)
class DecisionBasis:
    """Compact explanation of the governance decision, separate from raw findings."""

    decision_question: str
    action_type: str
    policy_rule: str
    evidence_quality: str
    control_path: str


def build_decision_basis(bundle: AnalysisBundle, decision: PolicyDecision) -> DecisionBasis:
    return DecisionBasis(
        decision_question="Should this PR proceed through the release gate?",
        action_type="release_gate",
        policy_rule=_policy_rule_summary(bundle, decision),
        evidence_quality=_evidence_quality_summary(bundle, decision),
        control_path=_control_path_summary(decision),
    )


def decision_basis_input_scope(bundle: AnalysisBundle) -> dict[str, int]:
    return {
        "introduced_findings": bundle.summary.introduced_findings,
        "change_relevant_findings": bundle.summary.change_relevant_findings,
        "existing_findings": bundle.summary.existing_findings,
        "suppressed_findings": bundle.summary.suppressed_findings,
        "evidence_items": bundle.summary.evidence_items,
        "blocking_evidence": bundle.summary.blocking_evidence,
        "review_evidence": bundle.summary.review_evidence,
        "changed_files": bundle.summary.changed_files,
    }


def _policy_rule_summary(bundle: AnalysisBundle, decision: PolicyDecision) -> str:
    if not bundle.summary.baseline_attribution_trusted and bundle.summary.change_relevant_findings:
        return "baseline attribution must be repaired before changed-file findings can be treated as proven introduced risk"
    if decision.decision == "NO GO":
        if bundle.summary.blocking_evidence:
            return "required release evidence failed or blocked the release gate"
        return "introduced critical dependency risk blocks release unless remediated or governed by policy"
    if decision.decision == "CONDITIONAL GO":
        if bundle.summary.review_evidence or _has_required_evidence_review_reason(decision):
            return "required release evidence needs human review before release"
        if bundle.summary.suppressed_findings:
            return "accepted risk requires explicit human review even when no unsuppressed introduced findings remain"
        if decision.risk.features.introduced_high:
            return "introduced high dependency risk requires review before release"
        return "release controls require human verification before this action proceeds"
    return "no introduced severe dependency risk was detected"


def _evidence_quality_summary(bundle: AnalysisBundle, decision: PolicyDecision) -> str:
    if decision.risk.confidence_ceiling_reason == "missing_baseline":
        return "confidence is capped because baseline scanner evidence is unavailable"
    if decision.risk.confidence_ceiling_reason == "suspicious_baseline":
        return "confidence is capped because baseline comparison appears unreliable"
    if bundle.summary.suppressed_findings:
        return f"{bundle.summary.suppressed_findings} finding(s) are governed by accepted-risk metadata"
    if bundle.summary.blocking_evidence:
        return f"{bundle.summary.blocking_evidence} required evidence item(s) failed release readiness"
    if bundle.summary.review_evidence:
        return f"{bundle.summary.review_evidence} required evidence item(s) need release review"
    if _has_required_evidence_review_reason(decision):
        return "required release evidence is missing or needs review"
    if bundle.summary.introduced_findings:
        return f"{bundle.summary.introduced_findings} introduced finding(s) were attributed to this change"
    return "baseline comparison found no introduced findings"


def _control_path_summary(decision: PolicyDecision) -> str:
    if decision.decision == "NO GO":
        return "block until remediation or approved policy change"
    if decision.required_approvals:
        labels = ", ".join(format_approval_label(role) for role in decision.required_approvals)
        return f"require {labels} approval"
    if decision.decision == "CONDITIONAL GO":
        return "manual review required before release"
    return "release gate passed"


def _has_required_evidence_review_reason(decision: PolicyDecision) -> bool:
    return any(
        reason.startswith(("required evidence needs review", "required evidence is missing"))
        for reason in decision.reasons
    )
