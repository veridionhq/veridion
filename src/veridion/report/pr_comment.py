"""Render policy decisions into PR-facing markdown."""

from __future__ import annotations

from veridion.analysis import AnalysisBundle
from veridion.policy.engine import PolicyDecision
from veridion.policy.labels import APPROVAL_LABELS

COMMENT_MARKER_START = "<!-- veridion:rdi:start -->"
COMMENT_MARKER_END = "<!-- veridion:rdi:end -->"


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
        lines.extend(_section("AI Attribution", _format_ai_attribution(bundle)))
    if bundle.historical_signals.elevated_signals:
        lines.extend(_section("Historical Trust Signals", _format_historical_signals(bundle)))

    lines.extend(_section("Why", decision.reasons))

    if decision.score_adjustments:
        lines.extend(_section("Policy Score Adjustments", decision.score_adjustments))

    if decision.required_approvals:
        approvals = tuple(_format_approval(name) for name in decision.required_approvals)
        lines.extend(_section("Required Approvals", approvals))

    lines.extend(_section("Recommendations", decision.recommendations))
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
    items = list(bundle.historical_signals.elevated_signals)

    if bundle.historical_signals.repo_criticality not in {"", "high", "critical"}:
        items.append("Repository criticality: " + bundle.historical_signals.repo_criticality)
    if bundle.historical_signals.service_criticality not in {"", "high", "critical"}:
        items.append("Service criticality: " + bundle.historical_signals.service_criticality)

    return tuple(dict.fromkeys(items))
