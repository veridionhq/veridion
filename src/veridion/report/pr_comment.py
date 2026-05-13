"""Render policy decisions into PR-facing markdown."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.analysis import AnalysisBundle
from veridion.policy.engine import PolicyDecision
from veridion.policy.labels import APPROVAL_LABELS
from veridion.report.threats import ThreatExplanation, explain_introduced_threats, render_threat_line
from veridion.summarization import CommentSummarizer, SummarizationRequest, SummarizationTrace, summarize_comment_request

COMMENT_MARKER_START = "<!-- veridion:rdi:start -->"
COMMENT_MARKER_END = "<!-- veridion:rdi:end -->"
MAX_AI_ITEMS = 3
MAX_PRIMARY_DRIVER_ITEMS = 3
MAX_THREAT_ITEMS = 3
MAX_CONTEXTUAL_RISK_ITEMS = 4
MAX_REQUIRED_NEXT_STEP_ITEMS = 6
MAX_ADVISORY_GUIDANCE_ITEMS = 4
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


@dataclass(frozen=True)
class RenderedComment:
    """Rendered PR comment plus wording telemetry."""

    markdown: str
    summary_trace: SummarizationTrace


def render_pr_comment(
    bundle: AnalysisBundle,
    decision: PolicyDecision,
    *,
    summarizer: CommentSummarizer | None = None,
    summary_style: str = "terse",
) -> str:
    return render_pr_comment_result(
        bundle,
        decision,
        summarizer=summarizer,
        summary_style=summary_style,
    ).markdown


def render_pr_comment_result(
    bundle: AnalysisBundle,
    decision: PolicyDecision,
    *,
    summarizer: CommentSummarizer | None = None,
    summary_style: str = "terse",
) -> RenderedComment:
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
        f"Suppressed findings: {bundle.summary.suppressed_findings}",
        f"Changed files: {bundle.summary.changed_files}",
    ]
    lines.append("**Summary:** " + " | ".join(summary_parts))
    lines.append("")

    primary_drivers, contextual_risk = _split_reasons(decision.reasons)
    compact_render = _should_use_compact_render(bundle, decision, primary_drivers, contextual_risk)
    introduced_threat_explanations = explain_introduced_threats(bundle)
    required_next_steps, advisory_guidance = _split_recommendations(
        _filter_recommendations(decision.recommendations, decision.required_approvals)
    )
    next_steps = required_next_steps or advisory_guidance or ("Proceed with normal review and deployment checks",)
    summarized_primary_drivers, summarized_threats, _summarized_contextual, summary_trace = _summarize_comment_sections(
        summarizer=summarizer,
        decision=decision,
        primary_drivers=primary_drivers,
        introduced_threats=introduced_threat_explanations,
        contextual_risk=contextual_risk,
        required_next_steps=required_next_steps,
        summary_style=summary_style,
    )

    key_context = _format_key_context(bundle, compact=compact_render)
    if key_context:
        lines.extend(_section("Key Context", key_context))
    if bundle.summary.suppressed_findings or bundle.summary.expired_suppressions:
        lines.extend(_section("Accepted Risk", _format_suppressions(bundle)))

    rendered_primary_drivers = _merge_headline_summary(
        bundle=bundle,
        decision=decision,
        introduced_threats=introduced_threat_explanations,
        rendered_primary_drivers=summarized_primary_drivers or primary_drivers,
    )
    if rendered_primary_drivers:
        lines.extend(
            _section(
                _drivers_title(decision.decision),
                rendered_primary_drivers[:MAX_PRIMARY_DRIVER_ITEMS],
            )
        )
    introduced_threats = summarized_threats or tuple(render_threat_line(item) for item in introduced_threat_explanations)
    if introduced_threats:
        lines.extend(
            _section(
                _threats_title(decision.decision),
                _truncate_items(introduced_threats, MAX_THREAT_ITEMS, "threat"),
            )
        )

    if decision.score_adjustments:
        lines.extend(_section("Policy Score Adjustments", decision.score_adjustments))

    if decision.required_approvals:
        approvals = tuple(_format_approval(name) for name in decision.required_approvals)
        lines.extend(_section("Required Approvals", approvals))

    lines.extend(
        _section(
            "What must happen next",
            _truncate_items(next_steps, MAX_REQUIRED_NEXT_STEP_ITEMS, "required step"),
        )
    )

    return RenderedComment(
        markdown=wrap_pr_comment("\n".join(lines).rstrip() + "\n"),
        summary_trace=summary_trace,
    )


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


def _drivers_title(decision: str) -> str:
    if decision == "NO GO":
        return "Why this is blocked"
    if decision == "CONDITIONAL GO":
        return "Why this needs review"
    return "Why this is allowed"


def _threats_title(decision: str) -> str:
    return "Key threats"


def _default_driver_summary(
    bundle: AnalysisBundle,
    decision: PolicyDecision,
    introduced_threats: tuple[ThreatExplanation, ...],
) -> tuple[str, ...]:
    if "no introduced findings detected" in decision.reasons:
        return ("no introduced findings detected",)
    if "release still requires explicit approvals or operational checks" in decision.reasons:
        return ("release still requires explicit approvals or operational checks",)
    if decision.decision == "NO GO" and introduced_threats:
        return (_headline_blocker_summary(bundle, introduced_threats),) + tuple(
            item
            for item in (
                _severity_summary(bundle),
                "the change includes infrastructure updates" if bundle.summary.infrastructure_changes else "",
                "the change introduces vulnerable dependencies" if bundle.summary.introduced_by_finding_type.get("dependency") else "",
            )
            if item
        )
    if decision.decision == "CONDITIONAL GO" and introduced_threats:
        return (_headline_review_summary(bundle, introduced_threats),) + tuple(
            item
            for item in (
                _severity_summary(bundle),
                "the change includes infrastructure updates" if bundle.summary.infrastructure_changes else "",
            )
            if item
        )
    return ()


def _merge_headline_summary(
    *,
    bundle: AnalysisBundle,
    decision: PolicyDecision,
    introduced_threats: tuple[ThreatExplanation, ...],
    rendered_primary_drivers: tuple[str, ...],
) -> tuple[str, ...]:
    fallback = _default_driver_summary(bundle, decision, introduced_threats)
    if not fallback:
        return rendered_primary_drivers or fallback
    if not rendered_primary_drivers:
        return fallback
    headline = fallback[0]
    merged = [headline]
    headline_key = _normalize_driver_line(headline)
    for line in rendered_primary_drivers:
        if _normalize_driver_line(line) == headline_key:
            continue
        if line not in merged:
            merged.append(line)
    return tuple(merged)


def _summarize_comment_sections(
    *,
    summarizer: CommentSummarizer | None,
    decision: PolicyDecision,
    primary_drivers: tuple[str, ...],
    introduced_threats,
    contextual_risk: tuple[str, ...],
    required_next_steps: tuple[str, ...],
    summary_style: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], SummarizationTrace]:
    if summarizer is None or not introduced_threats:
        return primary_drivers, (), (), SummarizationTrace(mode="deterministic", provider="none", model="")
    result, trace = summarize_comment_request(
        SummarizationRequest(
            decision=decision.decision,
            score=decision.score,
            confidence=decision.confidence,
            primary_drivers=primary_drivers,
            threats=tuple(introduced_threats),
            contextual_risk=contextual_risk,
            required_approvals=decision.required_approvals,
            required_next_steps=required_next_steps,
            style=summary_style,
        ),
        summarizer,
    )
    if result is None:
        return primary_drivers, (), (), trace
    rendered_primary = result.driver_summary or primary_drivers
    return rendered_primary, result.threat_summaries, result.contextual_summary, trace


def _headline_blocker_summary(bundle: AnalysisBundle, threats: tuple[ThreatExplanation, ...]) -> str:
    top = threats[0]
    if top.threat_type == "dependency":
        summary = f"this change cannot ship because it introduces {top.severity} vulnerable dependencies"
    else:
        location = f" in {top.location}" if top.location else ""
        summary = f"this change cannot ship because it introduces {top.severity} {top.threat_type} risk{location}"
    if bundle.runtime_signals.public_exposure:
        summary += " into a public-facing service"
    elif bundle.runtime_signals.blast_radius in {"high", "critical"}:
        summary += " in a high-blast-radius path"
    return summary


def _headline_review_summary(bundle: AnalysisBundle, threats: tuple[ThreatExplanation, ...]) -> str:
    top = threats[0]
    if top.location:
        summary = f"this change needs review because {top.location} {top.summary}"
    else:
        summary = f"this change needs review because it introduces {top.severity} {top.threat_type} risk"
    if bundle.summary.infrastructure_changes:
        summary += " and it also changes infrastructure"
    return summary


def _severity_summary(bundle: AnalysisBundle) -> str:
    parts: list[str] = []
    severities = bundle.summary.introduced_by_severity
    if severities.get("critical"):
        count = severities["critical"]
        parts.append(f"{count} critical issue" + ("" if count == 1 else "s"))
    if severities.get("high"):
        count = severities["high"]
        parts.append(f"{count} high-severity issue" + ("" if count == 1 else "s"))
    if severities.get("medium"):
        count = severities["medium"]
        parts.append(f"{count} medium-severity issue" + ("" if count == 1 else "s"))
    if not parts:
        return ""
    return "new risk includes " + ", ".join(parts)


def _should_use_compact_render(
    bundle: AnalysisBundle,
    decision: PolicyDecision,
    primary_drivers: tuple[str, ...],
    contextual_risk: tuple[str, ...],
) -> bool:
    contextual_domains = sum(
        (
            bool(bundle.historical_signals.elevated_signals),
            bool(bundle.runtime_signals.elevated_signals),
            bool(bundle.ownership_signals.elevated_signals),
            bool(bundle.trust_baseline.elevated_signals),
        )
    )
    return all(
        (
            bundle.summary.introduced_findings == 0,
            bundle.summary.suppressed_findings == 0,
            bundle.summary.expired_suppressions == 0,
            not decision.score_adjustments,
            primary_drivers == ("no introduced findings detected",),
            contextual_domains >= 3,
            len(contextual_risk) >= 5,
        )
    )


def _format_release_context(bundle: AnalysisBundle) -> tuple[str, ...]:
    items: list[str] = []

    historical_parts: list[str] = []
    if bundle.historical_signals.repo_criticality:
        historical_parts.append(f"repo criticality: {bundle.historical_signals.repo_criticality}")
    if bundle.historical_signals.service_criticality:
        historical_parts.append(f"service criticality: {bundle.historical_signals.service_criticality}")
    if bundle.historical_signals.rollback_rate_30d is not None:
        historical_parts.append(f"rollback rate: {bundle.historical_signals.rollback_rate_30d:.0%}")
    if historical_parts:
        items.append("historical: " + " | ".join(historical_parts))

    runtime_parts: list[str] = []
    if bundle.runtime_signals.environment:
        runtime_parts.append(f"target: {bundle.runtime_signals.environment}")
    if bundle.runtime_signals.public_exposure:
        runtime_parts.append("public exposure")
    if bundle.runtime_signals.blast_radius:
        runtime_parts.append(f"blast radius: {bundle.runtime_signals.blast_radius}")
    if runtime_parts:
        items.append("runtime: " + " | ".join(runtime_parts))

    ownership_parts: list[str] = []
    if bundle.ownership_signals.service_owner:
        ownership_parts.append(f"service owner: {bundle.ownership_signals.service_owner}")
    if bundle.ownership_signals.owning_team:
        ownership_parts.append(f"team: {bundle.ownership_signals.owning_team}")
    if bundle.ownership_signals.review_coverage:
        ownership_parts.append(
            "review coverage: " + bundle.ownership_signals.review_coverage.replace("_", " ")
        )
    if ownership_parts:
        items.append("ownership: " + " | ".join(ownership_parts))

    baseline_parts: list[str] = []
    if bundle.trust_baseline.service_stability:
        baseline_parts.append(f"service stability: {bundle.trust_baseline.service_stability}")
    if bundle.trust_baseline.rollback_readiness:
        baseline_parts.append(f"rollback readiness: {bundle.trust_baseline.rollback_readiness}")
    if bundle.trust_baseline.test_coverage_level:
        baseline_parts.append(f"test coverage: {bundle.trust_baseline.test_coverage_level}")
    if baseline_parts:
        items.append("baseline: " + " | ".join(baseline_parts))

    return tuple(items)


def _format_key_context(bundle: AnalysisBundle, *, compact: bool) -> tuple[str, ...]:
    if compact:
        return _format_release_context(bundle)

    items: list[str] = []

    history_parts: list[str] = []
    if bundle.historical_signals.repo_criticality:
        history_parts.append(f"repo criticality: {bundle.historical_signals.repo_criticality}")
    if bundle.historical_signals.service_criticality:
        history_parts.append(f"service criticality: {bundle.historical_signals.service_criticality}")
    if bundle.historical_signals.rollback_rate_30d is not None:
        history_parts.append(f"rollback rate: {bundle.historical_signals.rollback_rate_30d:.0%}")
    if bundle.historical_signals.change_failure_rate_30d is not None:
        history_parts.append(f"failure rate: {bundle.historical_signals.change_failure_rate_30d:.0%}")
    if bundle.historical_signals.incident_count_30d:
        history_parts.append(f"incidents: {bundle.historical_signals.incident_count_30d}")
    if bundle.historical_signals.flaky_service:
        history_parts.append("flaky service")
    if bundle.historical_signals.sensitive_repo:
        history_parts.append("sensitive repo")
    if history_parts:
        items.append("history: " + " | ".join(history_parts))

    runtime_parts: list[str] = []
    if bundle.runtime_signals.environment:
        runtime_parts.append(f"target: {bundle.runtime_signals.environment}")
    if bundle.runtime_signals.public_exposure:
        runtime_parts.append("public exposure")
    if bundle.runtime_signals.blast_radius:
        runtime_parts.append(f"blast radius: {bundle.runtime_signals.blast_radius}")
    if bundle.runtime_signals.deployment_window:
        runtime_parts.append("window: " + bundle.runtime_signals.deployment_window.replace("_", " "))
    if bundle.runtime_signals.rollout_strategy:
        runtime_parts.append("rollout: " + bundle.runtime_signals.rollout_strategy.replace("_", " "))
    if runtime_parts:
        items.append("runtime: " + " | ".join(runtime_parts))

    ownership_parts: list[str] = []
    if bundle.ownership_signals.service_owner:
        ownership_parts.append(f"owner: {bundle.ownership_signals.service_owner}")
    if bundle.ownership_signals.owning_team:
        ownership_parts.append(f"team: {bundle.ownership_signals.owning_team}")
    if bundle.ownership_signals.review_coverage:
        ownership_parts.append("review: " + bundle.ownership_signals.review_coverage.replace("_", " "))
    if bundle.ownership_signals.team_trust_level:
        ownership_parts.append("team trust: " + bundle.ownership_signals.team_trust_level)
    if ownership_parts:
        items.append("ownership: " + " | ".join(ownership_parts))

    baseline_parts: list[str] = []
    if bundle.trust_baseline.repo_stability:
        baseline_parts.append("repo stability: " + bundle.trust_baseline.repo_stability)
    if bundle.trust_baseline.service_stability:
        baseline_parts.append("service stability: " + bundle.trust_baseline.service_stability)
    if bundle.trust_baseline.test_coverage_level:
        baseline_parts.append("test coverage: " + bundle.trust_baseline.test_coverage_level)
    if bundle.trust_baseline.rollback_readiness:
        baseline_parts.append("rollback: " + bundle.trust_baseline.rollback_readiness)
    if bundle.trust_baseline.dependency_reputation_risk:
        baseline_parts.append("dependency risk: " + bundle.trust_baseline.dependency_reputation_risk)
    if baseline_parts:
        items.append("baseline: " + " | ".join(baseline_parts))

    return tuple(items)


def _format_suppressions(bundle: AnalysisBundle) -> tuple[str, ...]:
    items: list[str] = []
    if bundle.summary.suppressed_findings:
        items.append(f"suppressed findings: {bundle.summary.suppressed_findings}")
        items.extend(_aggregate_suppression_reasons(bundle))
    if bundle.summary.expired_suppressions:
        items.append(f"expired suppression rules: {bundle.summary.expired_suppressions}")
    return tuple(items)


def _aggregate_suppression_reasons(bundle: AnalysisBundle) -> tuple[str, ...]:
    counts: dict[tuple[str, str | None], int] = {}
    for suppressed in bundle.suppression_report.suppressed_findings:
        key = (suppressed.reason, suppressed.expires_on)
        counts[key] = counts.get(key, 0) + 1

    items: list[str] = []
    for (reason, expires_on), count in counts.items():
        suffix = f" (expires {expires_on})" if expires_on else ""
        items.append(f"{reason} ({count} finding(s)){suffix}")
    return tuple(items)


def _truncate_items(items: tuple[str, ...], limit: int, noun: str) -> tuple[str, ...]:
    if len(items) <= limit:
        return items
    remaining = len(items) - limit
    suffix = noun if remaining == 1 else noun + "s"
    return items[:limit] + (f"... {remaining} more {suffix}",)


def _normalize_driver_line(line: str) -> str:
    normalized = line.strip().lower().rstrip(".")
    replacements = (
        (" into a public-facing path", ""),
        (" into a public-facing service", ""),
        (" in a high-blast-radius path", ""),
        ("this change cannot ship because ", ""),
        ("this change needs review because ", ""),
    )
    for old, new in replacements:
        normalized = normalized.replace(old, new)
    return " ".join(normalized.split())


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
    if " new " in reason and " issue" in reason:
        return True

    primary_markers = (
        "no introduced findings detected",
        "release still requires explicit approvals or operational checks",
        "the change includes infrastructure updates",
        "the change introduces vulnerable dependencies",
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
