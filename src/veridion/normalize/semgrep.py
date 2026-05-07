"""Normalize Semgrep scanner output."""

from __future__ import annotations

from veridion.normalize.common import as_int, as_string, flatten_first, normalize_confidence, normalize_severity, stable_text_hash
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def normalize_semgrep_report(report: dict[str, object]) -> list[NormalizedFinding]:
    """Convert a Semgrep JSON report into the unified finding schema."""

    findings: list[NormalizedFinding] = []

    for result in report.get("results", []):
        if not isinstance(result, dict):
            continue

        extra = result.get("extra", {})
        extra = extra if isinstance(extra, dict) else {}
        metadata = extra.get("metadata", {})
        metadata = metadata if isinstance(metadata, dict) else {}
        start = result.get("start", {})
        start = start if isinstance(start, dict) else {}
        end = result.get("end", {})
        end = end if isinstance(end, dict) else {}
        match_lines = as_string(extra.get("lines"))

        findings.append(
            NormalizedFinding(
                source="semgrep",
                finding_type=_classify_semgrep_result(metadata),
                rule_id=as_string(result.get("check_id"), default="unknown-rule"),
                title=as_string(extra.get("message"), default="Untitled Semgrep finding"),
                severity=normalize_severity(as_string(extra.get("severity"))),
                confidence=normalize_confidence(as_string(metadata.get("confidence"))),
                description=as_string(metadata.get("shortlink")),
                location=NormalizedLocation(
                    path=as_string(result.get("path")),
                    start_line=as_int(start.get("line")),
                    end_line=as_int(end.get("line")),
                ),
                references=_build_references(metadata),
                categories=_build_categories(metadata),
                metadata=_build_metadata(metadata, match_lines),
            )
        )

    return findings


def _classify_semgrep_result(metadata: dict[str, object]) -> str:
    category = as_string(metadata.get("category"))
    if category in {"security", "security-audit", "correctness", "performance"}:
        return "code"
    if category == "supply-chain":
        return "dependency"
    return "code"


def _build_references(metadata: dict[str, object]) -> tuple[str, ...]:
    references: list[str] = []

    source = metadata.get("source")
    if isinstance(source, str):
        references.append(source)

    shortlink = metadata.get("shortlink")
    if isinstance(shortlink, str):
        references.append(shortlink)

    return tuple(references)


def _build_categories(metadata: dict[str, object]) -> tuple[str, ...]:
    categories: list[str] = []

    category = metadata.get("category")
    if isinstance(category, str):
        categories.append(category)

    technology = metadata.get("technology")
    if isinstance(technology, list):
        categories.extend(item for item in technology if isinstance(item, str))

    return tuple(categories)


def _build_metadata(metadata: dict[str, object], match_lines: str | None) -> dict[str, str]:
    fields = {
        "cwe": flatten_first(metadata.get("cwe")),
        "owasp": flatten_first(metadata.get("owasp")),
        "impact": as_string(metadata.get("impact")),
        "likelihood": as_string(metadata.get("likelihood")),
        "match_sha256": stable_text_hash(match_lines),
    }
    return {key: value for key, value in fields.items() if value}
