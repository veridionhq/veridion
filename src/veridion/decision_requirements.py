"""Structured release requirements derived from a policy decision."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.analysis import AnalysisBundle
from veridion.policy import PolicyDecision
from veridion.policy.text import filter_approval_echo_recommendations, format_approval_label


@dataclass(frozen=True)
class DecisionRequirements:
    """Machine-readable control path for a release decision."""

    required_approvals: tuple[str, ...]
    approval_triggers: dict[str, tuple[str, ...]]
    remediation: tuple[str, ...]
    baseline_repair: tuple[str, ...]
    accepted_risk: tuple[str, ...]
    release_validation: tuple[str, ...]
    advisory: tuple[str, ...]
    all_required: tuple[str, ...]

    @property
    def has_requirements(self) -> bool:
        return bool(
            self.required_approvals
            or self.remediation
            or self.baseline_repair
            or self.accepted_risk
            or self.release_validation
        )


_REQUIRED_PREFIXES = (
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

_REMEDIATION_PREFIXES = (
    "Block release",
    "Prioritize remediation",
    "Review newly introduced dependencies",
    "Restore or validate container resource limits",
    "Review privileged container settings",
    "Review broad IAM permission changes",
)

_BASELINE_REPAIR_PREFIXES = (
    "Repair or refresh baseline scanner outputs",
    "Review change-relevant findings manually",
)

_ACCEPTED_RISK_PREFIXES = (
    "Remove or renew expired accepted-risk suppressions",
    "Fill suppression owner",
    "Review pending accepted-risk proposals",
    "Approve or reject accepted-risk renewal requests",
    "Renew or close accepted-risk exceptions expiring soon",
)

_RELEASE_VALIDATION_PREFIXES = (
    "Run staging smoke tests",
    "Validate migration safety",
    "Verify payment-impact",
    "Run authentication and access-control",
    "Validate data-handling",
    "Verify rollback ownership",
    "Require and verify a rollback path",
    "Confirm an explicit deployment-freeze exception",
    "Resolve the active incident",
    "Resolve firing alerts",
    "Review elevated alert state",
    "Stop rollout and restore canary health",
    "Stabilize degraded canary health",
    "Restore rollback viability",
    "Verify the live rollback path",
    "Avoid direct rollout settings",
    "Validate autoscaling thresholds",
    "Coordinate staged validation",
    "Coordinate sign-off",
    "Use a staged rollout",
    "Prefer canary",
    "Confirm staffed on-call coverage",
    "Schedule deployment during staffed hours",
    "Define a service owner",
    "Run targeted regression coverage",
    "Increase manual validation",
)

_V1_ALLOWED_PREFIXES = (
    "Block release",
    "Repair or refresh baseline scanner outputs",
    "Review change-relevant findings manually",
    "Review newly introduced dependencies",
    "Prioritize remediation",
    "Remove or renew expired accepted-risk suppressions",
    "Fill suppression owner",
    "Review pending accepted-risk proposals",
    "Approve or reject accepted-risk renewal requests",
    "Renew or close accepted-risk exceptions expiring soon",
)


def build_decision_requirements(bundle: AnalysisBundle, decision: PolicyDecision) -> DecisionRequirements:
    recommendations = filter_approval_echo_recommendations(decision.recommendations, decision.required_approvals)
    if not decision.policy.condition_on_release_controls:
        recommendations = (
            ()
            if _is_v1_clean_dependency_go(bundle, decision)
            else tuple(item for item in recommendations if item.startswith(_V1_ALLOWED_PREFIXES))
        )

    remediation: list[str] = []
    baseline_repair: list[str] = []
    accepted_risk: list[str] = []
    release_validation: list[str] = []
    advisory: list[str] = []

    for item in recommendations:
        if item.startswith(_BASELINE_REPAIR_PREFIXES):
            baseline_repair.append(item)
        elif item.startswith(_ACCEPTED_RISK_PREFIXES):
            accepted_risk.append(item)
        elif item.startswith(_REMEDIATION_PREFIXES):
            remediation.append(item)
        elif item.startswith(_RELEASE_VALIDATION_PREFIXES):
            release_validation.append(item)
        elif item.startswith(_REQUIRED_PREFIXES):
            release_validation.append(item)
        else:
            advisory.append(item)

    return DecisionRequirements(
        required_approvals=decision.required_approvals,
        approval_triggers=dict(decision.required_approval_triggers),
        remediation=tuple(dict.fromkeys(remediation)),
        baseline_repair=tuple(dict.fromkeys(baseline_repair)),
        accepted_risk=_accepted_risk_requirements(bundle, tuple(dict.fromkeys(accepted_risk))),
        release_validation=tuple(dict.fromkeys(release_validation)),
        advisory=tuple(dict.fromkeys(advisory)),
        all_required=_all_required(
            remediation=tuple(dict.fromkeys(remediation)),
            baseline_repair=tuple(dict.fromkeys(baseline_repair)),
            accepted_risk=_accepted_risk_requirements(bundle, tuple(dict.fromkeys(accepted_risk))),
            release_validation=tuple(dict.fromkeys(release_validation)),
        ),
    )


def approval_label(role: str, triggers_by_role: dict[str, tuple[str, ...]]) -> str:
    label = format_approval_label(role)
    triggers = triggers_by_role.get(role, ())
    if not triggers:
        return label
    trigger_text = ", ".join(trigger.replace("_", " ") for trigger in triggers)
    return f"{label} (required: {trigger_text})"


def requirements_to_dict(requirements: DecisionRequirements) -> dict[str, object]:
    return {
        "required_approvals": list(requirements.required_approvals),
        "required_approval_labels": [
            format_approval_label(role)
            for role in requirements.required_approvals
        ],
        "required_approval_details": [
            approval_label(role, requirements.approval_triggers)
            for role in requirements.required_approvals
        ],
        "required_approval_triggers": {
            role: list(triggers)
            for role, triggers in requirements.approval_triggers.items()
        },
        "remediation": list(requirements.remediation),
        "baseline_repair": list(requirements.baseline_repair),
        "accepted_risk": list(requirements.accepted_risk),
        "release_validation": list(requirements.release_validation),
        "advisory": list(requirements.advisory),
        "all_required": list(requirements.all_required),
        "has_requirements": requirements.has_requirements,
    }


def _accepted_risk_requirements(bundle: AnalysisBundle, current: tuple[str, ...]) -> tuple[str, ...]:
    items = list(current)
    if bundle.summary.suppressed_findings and not items:
        items.append("Review accepted-risk exception scope, owner, approval, ticket, and expiry before release")
    return tuple(dict.fromkeys(items))


def _all_required(
    *,
    remediation: tuple[str, ...],
    baseline_repair: tuple[str, ...],
    accepted_risk: tuple[str, ...],
    release_validation: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(dict.fromkeys(remediation + baseline_repair + accepted_risk + release_validation))


def _is_v1_clean_dependency_go(bundle: AnalysisBundle, decision: PolicyDecision) -> bool:
    return (
        decision.decision == "GO"
        and not decision.policy.condition_on_release_controls
        and bundle.summary.baseline_attribution_trusted
        and bundle.summary.change_relevant_findings == 0
        and bundle.summary.introduced_findings == 0
        and bundle.summary.suppressed_findings == 0
        and bundle.summary.expired_suppressions == 0
    )
