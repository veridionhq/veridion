"""Compose normalized findings and change context into a deterministic analysis bundle."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from veridion.baseline import BaselineComparison, compare_findings_against_baseline
from veridion.change_context import ParsedChangeContext
from veridion.normalize.models import NormalizedFinding


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
    by_severity: dict[str, int]
    introduced_by_severity: dict[str, int]
    by_finding_type: dict[str, int]
    introduced_by_finding_type: dict[str, int]


@dataclass(frozen=True)
class AnalysisBundle:
    """Single object consumed by downstream scoring and decision layers."""

    current_findings: tuple[NormalizedFinding, ...]
    baseline_findings: tuple[NormalizedFinding, ...]
    change_context: ParsedChangeContext
    baseline_comparison: BaselineComparison
    summary: AnalysisSummary

    def to_dict(self) -> dict[str, object]:
        """Convert the bundle into plain Python objects for testing and serialization."""

        return _plain(asdict(self))


def build_analysis_bundle(
    current_findings: list[NormalizedFinding],
    baseline_findings: list[NormalizedFinding],
    change_context: ParsedChangeContext,
) -> AnalysisBundle:
    """Assemble the deterministic analysis object used by the decision engine."""

    baseline_comparison = compare_findings_against_baseline(
        current_findings=current_findings,
        baseline_findings=baseline_findings,
        change_context=change_context,
    )
    summary = _build_summary(
        current_findings=current_findings,
        change_context=change_context,
        baseline_comparison=baseline_comparison,
    )

    return AnalysisBundle(
        current_findings=tuple(current_findings),
        baseline_findings=tuple(baseline_findings),
        change_context=change_context,
        baseline_comparison=baseline_comparison,
        summary=summary,
    )


def _build_summary(
    *,
    current_findings: list[NormalizedFinding],
    change_context: ParsedChangeContext,
    baseline_comparison: BaselineComparison,
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


def _plain(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value
