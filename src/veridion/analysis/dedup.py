"""Cross-scanner deduplication for normalized findings."""

from __future__ import annotations

from veridion.normalize.models import NormalizedFinding


def deduplicate_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Deduplicate equivalent findings while preserving deterministic order."""

    deduped: list[NormalizedFinding] = []
    seen: dict[str, NormalizedFinding] = {}

    for finding in findings:
        key = finding.dedup_key
        existing = seen.get(key)
        if existing is None:
            seen[key] = finding
            deduped.append(finding)
            continue

        preferred = _prefer_finding(existing, finding)
        if preferred is finding:
            seen[key] = finding
            deduped[deduped.index(existing)] = finding

    return deduped


def _prefer_finding(left: NormalizedFinding, right: NormalizedFinding) -> NormalizedFinding:
    left_score = _preference_score(left)
    right_score = _preference_score(right)
    if right_score > left_score:
        return right
    return left


def _preference_score(finding: NormalizedFinding) -> tuple[int, float, float]:
    reference_count = len(finding.references)
    cvss_score = finding.cvss_score or 0.0
    epss_score = finding.epss_score or 0.0
    return (reference_count, cvss_score, epss_score)
