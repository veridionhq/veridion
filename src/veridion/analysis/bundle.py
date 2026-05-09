"""Compose normalized findings and change context into a deterministic analysis bundle."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from veridion.attribution import AiAttribution, detect_ai_attribution, PullRequestMetadata
from veridion.baseline import BaselineComparison, compare_findings_against_baseline
from veridion.change_context import ParsedChangeContext
from veridion.context import HistoricalSignals
from veridion.normalize.models import NormalizedFinding
from veridion.util import plain
from veridion.analysis.dedup import deduplicate_findings


@dataclass(frozen=True)
class AnalysisSummary:
    """Compact summary of the analysis inputs for scoring and reporting."""

    total_findings: int
    introduced_findings: int
    existing_findings: int
    unattributed_findings: int
    changed_files: int
    dependency_changes: bool
    lockfile_changes: bool
    infrastructure_changes: bool
    inventory_packages: int
    ai_change_signals: int
    ai_authored_commits: int
    historical_risk_signals: int
    by_severity: dict[str, int]
    introduced_by_severity: dict[str, int]
    by_finding_type: dict[str, int]
    introduced_by_finding_type: dict[str, int]


@dataclass(frozen=True)
class AnalysisBundle:
    """Single object consumed by downstream scoring and decision layers."""

    current_findings: tuple[NormalizedFinding, ...]
    baseline_findings: tuple[NormalizedFinding, ...]
    current_inventory: tuple[NormalizedFinding, ...]
    baseline_inventory: tuple[NormalizedFinding, ...]
    ai_attribution: AiAttribution
    historical_signals: HistoricalSignals
    change_context: ParsedChangeContext
    baseline_comparison: BaselineComparison
    summary: AnalysisSummary

    def to_dict(self) -> dict[str, object]:
        """Convert the bundle into plain Python objects for testing and serialization."""

        return plain(asdict(self))


def build_analysis_bundle(
    current_findings: list[NormalizedFinding],
    baseline_findings: list[NormalizedFinding],
    change_context: ParsedChangeContext,
    metadata: PullRequestMetadata | None = None,
    historical_signals: HistoricalSignals | None = None,
) -> AnalysisBundle:
    """Assemble the deterministic analysis object used by the decision engine."""

    current_inventory = [finding for finding in current_findings if finding.is_inventory_only]
    baseline_inventory = [finding for finding in baseline_findings if finding.is_inventory_only]
    scored_current_findings = deduplicate_findings([finding for finding in current_findings if not finding.is_inventory_only])
    scored_baseline_findings = deduplicate_findings(
        [finding for finding in baseline_findings if not finding.is_inventory_only]
    )

    baseline_comparison = compare_findings_against_baseline(
        current_findings=scored_current_findings,
        baseline_findings=scored_baseline_findings,
        change_context=change_context,
    )
    ai_attribution = detect_ai_attribution(metadata)
    resolved_historical_signals = historical_signals or HistoricalSignals()
    summary = _build_summary(
        current_findings=scored_current_findings,
        current_inventory=current_inventory,
        change_context=change_context,
        baseline_comparison=baseline_comparison,
        ai_attribution=ai_attribution,
        historical_signals=resolved_historical_signals,
    )

    return AnalysisBundle(
        current_findings=tuple(scored_current_findings),
        baseline_findings=tuple(scored_baseline_findings),
        current_inventory=tuple(current_inventory),
        baseline_inventory=tuple(baseline_inventory),
        ai_attribution=ai_attribution,
        historical_signals=resolved_historical_signals,
        change_context=change_context,
        baseline_comparison=baseline_comparison,
        summary=summary,
    )


def _build_summary(
    *,
    current_findings: list[NormalizedFinding],
    current_inventory: list[NormalizedFinding],
    change_context: ParsedChangeContext,
    baseline_comparison: BaselineComparison,
    ai_attribution: AiAttribution,
    historical_signals: HistoricalSignals,
) -> AnalysisSummary:
    return AnalysisSummary(
        total_findings=len(current_findings),
        introduced_findings=len(baseline_comparison.introduced),
        existing_findings=len(baseline_comparison.existing),
        unattributed_findings=len(baseline_comparison.unattributed),
        changed_files=len(change_context.files),
        dependency_changes=change_context.has_dependency_changes,
        lockfile_changes=change_context.has_lockfile_changes,
        infrastructure_changes=change_context.has_iac_changes,
        inventory_packages=len(current_inventory),
        ai_change_signals=ai_attribution.signal_count,
        ai_authored_commits=ai_attribution.ai_authored_commits,
        historical_risk_signals=len(historical_signals.elevated_signals),
        by_severity=_count_by_severity(current_findings),
        introduced_by_severity=_count_by_severity(list(baseline_comparison.introduced)),
        by_finding_type=_count_by_finding_type(current_findings),
        introduced_by_finding_type=_count_by_finding_type(list(baseline_comparison.introduced)),
    )


def _count_by_severity(findings: list[NormalizedFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return dict(sorted(counts.items()))


def _count_by_finding_type(findings: list[NormalizedFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.finding_type] = counts.get(finding.finding_type, 0) + 1
    return dict(sorted(counts.items()))
