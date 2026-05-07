"""Normalize Grype scanner output."""

from __future__ import annotations

from veridion.normalize.common import as_float, as_string, flatten_first, location_path_from_locations, normalize_severity
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def normalize_grype_report(report: dict[str, object]) -> list[NormalizedFinding]:
    """Convert a Grype JSON report into the unified finding schema."""

    findings: list[NormalizedFinding] = []

    for match in report.get("matches", []):
        if not isinstance(match, dict):
            continue

        vulnerability = match.get("vulnerability", {})
        vulnerability = vulnerability if isinstance(vulnerability, dict) else {}
        artifact = match.get("artifact", {})
        artifact = artifact if isinstance(artifact, dict) else {}

        findings.append(
            NormalizedFinding(
                source="grype",
                finding_type="dependency",
                rule_id=as_string(vulnerability.get("id"), default="unknown-rule"),
                title=as_string(vulnerability.get("description"), default="Untitled vulnerability"),
                severity=normalize_severity(as_string(vulnerability.get("severity"))),
                description=as_string(vulnerability.get("dataSource")),
                package_name=as_string(artifact.get("name")),
                package_version=as_string(artifact.get("version")),
                fixed_version=_fix_version(match.get("fix", {})),
                cvss_score=_extract_grype_cvss(vulnerability),
                epss_score=_extract_grype_epss(vulnerability),
                location=NormalizedLocation(path=location_path_from_locations(artifact.get("locations"))),
                references=_build_references(vulnerability),
                categories=("dependency",),
                metadata=_build_metadata(artifact, vulnerability),
            )
        )

    return findings


def _build_references(vulnerability: dict[str, object]) -> tuple[str, ...]:
    references = vulnerability.get("urls")
    if not isinstance(references, list):
        return ()
    return tuple(item for item in references if isinstance(item, str))


def _build_metadata(artifact: dict[str, object], vulnerability: dict[str, object]) -> dict[str, str]:
    fields = {
        "package_type": as_string(artifact.get("type")),
        "purl": as_string(artifact.get("purl")),
        "namespace": as_string(vulnerability.get("namespace")),
    }
    return {key: value for key, value in fields.items() if value}


def _fix_version(container: object) -> str | None:
    if not isinstance(container, dict):
        return None

    return flatten_first(container.get("versions"))


def _extract_grype_cvss(vulnerability: dict[str, object]) -> float | None:
    cvss = vulnerability.get("cvss")
    if not isinstance(cvss, list):
        return None

    scores: list[float] = []
    for entry in cvss:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics")
        if not isinstance(metrics, dict):
            continue
        score = as_float(metrics.get("baseScore"))
        if score is not None:
            scores.append(score)

    if not scores:
        return None
    return max(scores)


def _extract_grype_epss(vulnerability: dict[str, object]) -> float | None:
    epss = vulnerability.get("epss")
    if not isinstance(epss, list):
        return None

    for entry in epss:
        if not isinstance(entry, dict):
            continue
        probability = as_float(entry.get("probability"))
        if probability is not None:
            return probability

    return None
