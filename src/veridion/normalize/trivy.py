"""Normalize Trivy scanner output."""

from __future__ import annotations

from veridion.normalize.common import as_float, as_string, normalize_severity
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def normalize_trivy_report(report: dict[str, object]) -> list[NormalizedFinding]:
    """Convert a Trivy JSON report into the unified finding schema."""

    findings: list[NormalizedFinding] = []

    for result in report.get("Results", []):
        if not isinstance(result, dict):
            continue

        target = as_string(result.get("Target"))
        finding_class = _classify_target(target)

        for vulnerability in result.get("Vulnerabilities", []):
            if not isinstance(vulnerability, dict):
                continue

            findings.append(
                NormalizedFinding(
                    source="trivy",
                    finding_type=finding_class,
                    rule_id=as_string(vulnerability.get("VulnerabilityID"), default="unknown-rule"),
                    title=as_string(vulnerability.get("Title"), default="Untitled vulnerability"),
                    severity=normalize_severity(as_string(vulnerability.get("Severity"))),
                    description=as_string(vulnerability.get("Description")),
                    package_name=as_string(vulnerability.get("PkgName")),
                    package_version=as_string(vulnerability.get("InstalledVersion")),
                    fixed_version=as_string(vulnerability.get("FixedVersion")),
                    cvss_score=_extract_trivy_cvss(vulnerability),
                    epss_score=as_float(vulnerability.get("EPSS")),
                    location=NormalizedLocation(path=target),
                    references=_string_tuple(vulnerability.get("References")),
                    categories=("dependency",),
                    metadata=_compact_metadata(
                        class_name=as_string(result.get("Class")),
                        type_name=as_string(result.get("Type")),
                    ),
                )
            )

    return findings


def _classify_target(target: str | None) -> str:
    if not target:
        return "dependency"

    if ".tf" in target or target.endswith((".yaml", ".yml", ".json")):
        return "infrastructure"

    return "dependency"


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _compact_metadata(**values: str | None) -> dict[str, str]:
    return {key: value for key, value in values.items() if value}


def _extract_trivy_cvss(vulnerability: dict[str, object]) -> float | None:
    cvss = vulnerability.get("CVSS")
    if not isinstance(cvss, dict):
        return None

    scores: list[float] = []
    for source_data in cvss.values():
        if not isinstance(source_data, dict):
            continue
        score = as_float(source_data.get("V3Score"))
        if score is None:
            score = as_float(source_data.get("V2Score"))
        if score is not None:
            scores.append(score)

    if not scores:
        return None
    return max(scores)
