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
    unattributed: tuple[NormalizedFinding, ...]


def compare_findings_against_baseline(
    current_findings: list[NormalizedFinding],
    baseline_findings: list[NormalizedFinding],
    change_context: ParsedChangeContext,
) -> BaselineComparison:
    """Identify findings that are newly introduced by the current change."""

    baseline_fingerprints = {finding.fingerprint for finding in baseline_findings}
    changed_paths = set(change_context.changed_paths)
    changed_paths.update(file.previous_path for file in change_context.files if file.previous_path)
    has_dependency_surface_change = change_context.has_dependency_changes or change_context.has_lockfile_changes

    introduced: list[NormalizedFinding] = []
    existing: list[NormalizedFinding] = []
    unattributed: list[NormalizedFinding] = []

    for finding in current_findings:
        if finding.fingerprint in baseline_fingerprints:
            existing.append(finding)
            continue

        if _is_finding_relevant_to_change(finding, changed_paths, has_dependency_surface_change):
            introduced.append(finding)
        else:
            unattributed.append(finding)

    return BaselineComparison(
        introduced=tuple(introduced),
        existing=tuple(existing),
        unattributed=tuple(unattributed),
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

    if finding.finding_type in {"dependency", "package"} and has_dependency_surface_change:
        return True

    return False
