"""Render policy decisions into PR-facing markdown."""

from __future__ import annotations

from veridion.analysis import AnalysisBundle
from veridion.policy.engine import PolicyDecision
from veridion.policy.labels import APPROVAL_LABELS

COMMENT_MARKER_START = "<!-- veridion:rdi:start -->"
COMMENT_MARKER_END = "<!-- veridion:rdi:end -->"
MAX_AI_ITEMS = 3
MAX_PRIMARY_DRIVER_ITEMS = 6
MAX_CONTEXTUAL_RISK_ITEMS = 5
MAX_REQUIRED_NEXT_STEP_ITEMS = 6
MAX_ADVISORY_GUIDANCE_ITEMS = 6
REQUIRED_NEXT_STEP_PREFIXES = (
    "Block release",
    "Run staging smoke tests",
    "Prioritize remediation",
    "Review newly introduced dependencies",
    "Verify rollback ownership and on-call coverage",
    "Require and verify a rollback path",
    "Define a service owner",
    "Validate migration safety",
    "Verify payment-impact",
    "Run authentication and access-control",
)


def render_pr_comment(bundle: AnalysisBundle, decision: PolicyDecision) -> str:
    """Render a deterministic PR comment for the current release decision."""

    lines: list[str] = []

    lines.append("## Release Decision Intelligence")
    lines.append("")
    lines.append(f"**Decision:** {decision.decision}")
    lines.append(f"**RDI Score:** {decision.score}")
    lines.append(f"**Confidence:** {decision.confidence.upper()}")
    lines.append("")

    summary_parts = [
        f"Introduced findings: {bundle.summary.introduced_findings}",
        f"Existing findings: {bundle.summary.existing_findings}",
        f"Unattributed findings: {bundle.summary.unattributed_findings}",
        f"Changed files: {bundle.summary.changed_files}",
    ]
    lines.append("**Summary:** " + " | ".join(summary_parts))
    lines.append("")

    if bundle.ai_attribution.detected:
        lines.extend(_section("AI Attribution", _truncate_items(_format_ai_attribution(bundle), MAX_AI_ITEMS, "detail")))
    if bundle.historical_signals.elevated_signals:
        lines.extend(_section("Historical Trust Signals", _format_historical_signals(bundle)))
    if bundle.runtime_signals.elevated_signals:
        lines.extend(_section("Runtime Context", _format_runtime_signals(bundle)))
    if bundle.ownership_signals.elevated_signals:
        lines.extend(_section("Ownership Context", _format_ownership_signals(bundle)))
    if bundle.trust_baseline.elevated_signals:
        lines.extend(_section("Operational Baseline", _format_trust_baseline(bundle)))

    primary_drivers, contextual_risk = _split_reasons(decision.reasons)
    lines.extend(_section("Primary Drivers", _truncate_items(primary_drivers, MAX_PRIMARY_DRIVER_ITEMS, "driver")))
    if contextual_risk:
        lines.extend(
            _section(
                "Contextual Risk",
                _truncate_items(contextual_risk, MAX_CONTEXTUAL_RISK_ITEMS, "contextual risk"),
            )
        )

    if decision.score_adjustments:
        lines.extend(_section("Policy Score Adjustments", decision.score_adjustments))

    if decision.required_approvals:
        approvals = tuple(_format_approval(name) for name in decision.required_approvals)
        lines.extend(_section("Required Approvals", approvals))

    required_next_steps, advisory_guidance = _split_recommendations(
        _filter_recommendations(decision.recommendations, decision.required_approvals)
    )
    lines.extend(
        _section(
            "Required Next Steps",
            _truncate_items(required_next_steps, MAX_REQUIRED_NEXT_STEP_ITEMS, "required step"),
        )
    )
    if advisory_guidance:
        lines.extend(
            _section(
                "Advisory Guidance",
                _truncate_items(advisory_guidance, MAX_ADVISORY_GUIDANCE_ITEMS, "guidance item"),
            )
        )
    lines.extend(_section("Introduced Severity", _format_counts(bundle.summary.introduced_by_severity)))
    lines.extend(_section("Introduced Finding Types", _format_counts(bundle.summary.introduced_by_finding_type)))

    return wrap_pr_comment("\n".join(lines).rstrip() + "\n")


def wrap_pr_comment(body: str) -> str:
    """Wrap a rendered PR comment with stable Veridion markers."""

    return f"{COMMENT_MARKER_START}\n{body.rstrip()}\n{COMMENT_MARKER_END}\n"


def _section(title: str, items: tuple[str, ...] | list[str]) -> list[str]:
    rendered = [f"### {title}", ""]
    if items:
        rendered.extend(f"- {item}" for item in items)
    else:
        rendered.append("- None")
    rendered.append("")
    return rendered


def _format_approval(value: str) -> str:
    return APPROVAL_LABELS.get(value, value.replace("_", " "))


def _format_counts(counts: dict[str, int]) -> tuple[str, ...]:
    return tuple(f"{key}: {value}" for key, value in counts.items())


def _truncate_items(items: tuple[str, ...], limit: int, noun: str) -> tuple[str, ...]:
    if len(items) <= limit:
        return items
    remaining = len(items) - limit
    suffix = noun if remaining == 1 else noun + "s"
    return items[:limit] + (f"... {remaining} more {suffix}",)


def _format_ai_attribution(bundle: AnalysisBundle) -> tuple[str, ...]:
    items = [f"AI-origin signals detected: {bundle.ai_attribution.signal_count}"]

    if bundle.ai_attribution.ai_authored_commits:
        items.append(f"AI-attributed commits: {bundle.ai_attribution.ai_authored_commits}")
    if bundle.ai_attribution.sources:
        items.append("Sources: " + ", ".join(bundle.ai_attribution.sources))
    if bundle.ai_attribution.indicators:
        items.append("Indicators: " + ", ".join(bundle.ai_attribution.indicators))

    return tuple(items)


def _format_historical_signals(bundle: AnalysisBundle) -> tuple[str, ...]:
    historical = bundle.historical_signals
    items: list[str] = []

    criticality_parts: list[str] = []
    if historical.repo_criticality:
        criticality_parts.append(f"repo criticality: {historical.repo_criticality}")
    if historical.service_criticality:
        criticality_parts.append(f"service criticality: {historical.service_criticality}")
    if criticality_parts:
        items.append(" | ".join(criticality_parts))

    instability_parts: list[str] = []
    if historical.rollback_rate_30d is not None:
        instability_parts.append(f"30d rollback rate: {historical.rollback_rate_30d:.0%}")
    if historical.change_failure_rate_30d is not None:
        instability_parts.append(f"30d change failure rate: {historical.change_failure_rate_30d:.0%}")
    if historical.incident_count_30d:
        instability_parts.append(f"30d incidents: {historical.incident_count_30d}")
    if instability_parts:
        items.append("Historical instability: " + " | ".join(instability_parts))

    flags: list[str] = []
    if historical.flaky_service:
        flags.append("service marked flaky")
    if historical.sensitive_repo:
        flags.append("repository marked sensitive")
    if flags:
        items.append("Operational flags: " + " | ".join(flags))

    return tuple(items)


def _format_runtime_signals(bundle: AnalysisBundle) -> tuple[str, ...]:
    runtime = bundle.runtime_signals
    items: list[str] = []

    surface_parts: list[str] = []
    if runtime.environment:
        surface_parts.append(f"deployment target: {runtime.environment}")
    if runtime.public_exposure:
        surface_parts.append("service is publicly exposed")
    if runtime.blast_radius:
        surface_parts.append(f"blast radius: {runtime.blast_radius}")
    if surface_parts:
        items.append(" | ".join(surface_parts))

    execution_parts: list[str] = []
    if runtime.deployment_window:
        execution_parts.append("deployment window: " + runtime.deployment_window.replace("_", " "))
    if runtime.rollout_strategy:
        execution_parts.append("rollout strategy: " + runtime.rollout_strategy.replace("_", " "))
    if execution_parts:
        items.append("Execution plan: " + " | ".join(execution_parts))

    return tuple(items)


def _format_ownership_signals(bundle: AnalysisBundle) -> tuple[str, ...]:
    ownership = bundle.ownership_signals
    items: list[str] = []

    identity_parts: list[str] = []
    if "service owner missing" in ownership.elevated_signals:
        identity_parts.append("service owner missing")
    elif ownership.service_owner:
        identity_parts.append("service owner: " + ownership.service_owner)
    if ownership.owning_team:
        identity_parts.append("owning team: " + ownership.owning_team)
    if identity_parts:
        items.append(" | ".join(identity_parts))

    coordination_parts: list[str] = []
    if ownership.review_coverage:
        coordination_parts.append("review coverage: " + ownership.review_coverage.replace("_", " "))
    if ownership.team_trust_level:
        coordination_parts.append("team trust: " + ownership.team_trust_level)
    if coordination_parts:
        items.append("Coordination: " + " | ".join(coordination_parts))

    if "on-call coverage missing" in ownership.elevated_signals:
        items.append("Operational readiness: on-call coverage missing")

    return tuple(items)


def _format_trust_baseline(bundle: AnalysisBundle) -> tuple[str, ...]:
    baseline = bundle.trust_baseline
    items: list[str] = []

    stability_parts: list[str] = []
    if baseline.repo_stability:
        stability_parts.append("repository stability: " + baseline.repo_stability)
    if baseline.service_stability:
        stability_parts.append("service stability: " + baseline.service_stability)
    if stability_parts:
        items.append(" | ".join(stability_parts))

    execution_parts: list[str] = []
    if baseline.team_deploy_safety:
        execution_parts.append("team deploy safety: " + baseline.team_deploy_safety)
    if baseline.test_coverage_level:
        execution_parts.append("test coverage: " + baseline.test_coverage_level)
    if baseline.rollback_readiness:
        execution_parts.append("rollback readiness: " + baseline.rollback_readiness)
    if baseline.dependency_reputation_risk:
        execution_parts.append("dependency reputation risk: " + baseline.dependency_reputation_risk)
    if execution_parts:
        items.append("Execution baseline: " + " | ".join(execution_parts))

    profile_parts: list[str] = []
    if bundle.trust_profile_metadata.repo_id:
        profile_parts.append(bundle.trust_profile_metadata.repo_id)
    if bundle.trust_profile_metadata.service_id:
        profile_parts.append(bundle.trust_profile_metadata.service_id)
    if bundle.trust_profile_metadata.team_id:
        profile_parts.append(bundle.trust_profile_metadata.team_id)
    if profile_parts:
        items.append("Trust profile: " + " | ".join(profile_parts))

    return tuple(items)


def _split_reasons(reasons: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    primary: list[str] = []
    contextual: list[str] = []

    for reason in reasons:
        if _is_primary_driver(reason):
            primary.append(reason)
        else:
            contextual.append(reason)

    return tuple(primary), tuple(contextual)


def _is_primary_driver(reason: str) -> bool:
    if " introduced " in reason:
        return True

    primary_markers = (
        "infrastructure changes",
        "new dependency vulnerability",
        "policy max_severity",
        "policy no_go threshold",
        "policy does not allow conditional releases",
    )
    return reason.startswith(primary_markers)


def _filter_recommendations(
    recommendations: tuple[str, ...],
    required_approvals: tuple[str, ...],
) -> tuple[str, ...]:
    blocked = {f"Require approval from the {_format_approval(value)}" for value in required_approvals}
    return tuple(item for item in recommendations if item not in blocked)


def _split_recommendations(recommendations: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    required: list[str] = []
    advisory: list[str] = []

    for recommendation in recommendations:
        if _is_required_next_step(recommendation):
            required.append(recommendation)
        else:
            advisory.append(recommendation)

    return tuple(required), tuple(advisory)


def _is_required_next_step(recommendation: str) -> bool:
    return recommendation.startswith(REQUIRED_NEXT_STEP_PREFIXES)
