"""Compare normalized findings against baseline state and change context."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.change_context import ParsedChangeContext
from veridion.normalize.models import NormalizedFinding


@dataclass(frozen=True)
class BaselineComparison:
    """Partition findings into introduced and pre-existing groups."""

    introduced: tuple[NormalizedFinding, ...]
    existing: tuple[NormalizedFinding, ...]
    change_relevant: tuple[NormalizedFinding, ...]
    unattributed: tuple[NormalizedFinding, ...]
    attribution_trusted: bool
    attribution_mode: str
    attribution_likely_cause: str


def compare_findings_against_baseline(
    current_findings: list[NormalizedFinding],
    baseline_findings: list[NormalizedFinding],
    change_context: ParsedChangeContext,
    baseline_available: bool | None = None,
) -> BaselineComparison:
    """Identify findings that are newly introduced by the current change."""

    baseline_fingerprints = {finding.fingerprint for finding in baseline_findings}
    baseline_dedup_keys = {finding.dedup_key for finding in baseline_findings}
    resolved_baseline_available = bool(baseline_findings) if baseline_available is None else baseline_available
    attribution_trusted = resolved_baseline_available or not current_findings
    attribution_mode = "trusted"
    attribution_likely_cause = ""
    changed_paths = set(change_context.changed_paths)
    changed_paths.update(file.previous_path for file in change_context.files if file.previous_path)
    has_dependency_surface_change = change_context.has_dependency_changes or change_context.has_lockfile_changes

    introduced: list[NormalizedFinding] = []
    existing: list[NormalizedFinding] = []
    change_relevant: list[NormalizedFinding] = []
    unattributed: list[NormalizedFinding] = []

    for finding in current_findings:
        if finding.fingerprint in baseline_fingerprints or finding.dedup_key in baseline_dedup_keys:
            existing.append(finding)
            continue

        if _is_finding_relevant_to_change(finding, changed_paths, has_dependency_surface_change):
            if attribution_trusted:
                introduced.append(finding)
            else:
                change_relevant.append(finding)
        else:
            unattributed.append(finding)

    if _is_suspicious_baseline_attribution(
        baseline_findings=baseline_findings,
        changed_paths=changed_paths,
        introduced=introduced,
        existing=existing,
        unattributed=unattributed,
    ):
        attribution_trusted = False
        attribution_mode = "suspicious_present_baseline"
        attribution_likely_cause = "base_ref_or_normalization_mismatch"
        change_relevant = [*change_relevant, *introduced]
        introduced = []
    elif not attribution_trusted:
        attribution_mode = "missing_baseline"
        attribution_likely_cause = "baseline_reports_missing_or_empty"

    return BaselineComparison(
        introduced=tuple(introduced),
        existing=tuple(existing),
        change_relevant=tuple(change_relevant),
        unattributed=tuple(unattributed),
        attribution_trusted=attribution_trusted,
        attribution_mode=attribution_mode,
        attribution_likely_cause=attribution_likely_cause,
    )


def _is_finding_relevant_to_change(
    finding: NormalizedFinding,
    changed_paths: set[str],
    has_dependency_surface_change: bool,
) -> bool:
    location_path = finding.location.path
    if location_path:
        normalized_path = location_path.removeprefix("/workspace/")
        if normalized_path in changed_paths:
            return True
        if location_path in changed_paths:
            return True

    if finding.finding_type == "dependency" and has_dependency_surface_change:
        return True

    return False


def _is_suspicious_baseline_attribution(
    *,
    baseline_findings: list[NormalizedFinding],
    changed_paths: set[str],
    introduced: list[NormalizedFinding],
    existing: list[NormalizedFinding],
    unattributed: list[NormalizedFinding],
) -> bool:
    if not baseline_findings:
        return False
    if existing:
        return False
    if not introduced:
        return False
    if not unattributed:
        return False
    return len(changed_paths) >= 50 or len(unattributed) >= len(introduced)
