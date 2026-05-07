"""Normalize Syft SBOM output."""

from __future__ import annotations

from veridion.normalize.common import as_string, location_path_from_locations, normalize_severity
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def normalize_syft_report(report: dict[str, object]) -> list[NormalizedFinding]:
    """Convert a Syft JSON report into normalized package observations."""

    findings: list[NormalizedFinding] = []

    for artifact in report.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue

        findings.append(
            NormalizedFinding(
                source="syft",
                finding_type="package",
                rule_id=as_string(artifact.get("purl"), default=_artifact_identity(artifact)),
                title=f"Discovered package: {as_string(artifact.get('name'), default='unknown-package')}",
                severity=normalize_severity(None),
                description=as_string(artifact.get("description")),
                package_name=as_string(artifact.get("name")),
                package_version=as_string(artifact.get("version")),
                location=NormalizedLocation(path=location_path_from_locations(artifact.get("locations"))),
                references=_artifact_references(artifact),
                categories=("dependency", "inventory"),
                metadata=_artifact_metadata(artifact),
            )
        )

    return findings


def _artifact_identity(artifact: dict[str, object]) -> str:
    name = as_string(artifact.get("name"), default="unknown-package")
    version = as_string(artifact.get("version"), default="unknown-version")
    return f"{name}@{version}"


def _artifact_references(artifact: dict[str, object]) -> tuple[str, ...]:
    purl = artifact.get("purl")
    if isinstance(purl, str):
        return (purl,)
    return ()


def _artifact_metadata(artifact: dict[str, object]) -> dict[str, str]:
    licenses = artifact.get("licenses")
    license_name = _flatten_license(licenses)

    fields = {
        "package_type": as_string(artifact.get("type")),
        "language": as_string(artifact.get("language")),
        "license": license_name,
    }
    return {key: value for key, value in fields.items() if value}


def _flatten_license(value: object) -> str | None:
    if not isinstance(value, list):
        return None

    for item in value:
        if isinstance(item, dict):
            spdx = item.get("spdxExpression")
            if isinstance(spdx, str):
                return spdx
            name = item.get("value")
            if isinstance(name, str):
                return name
        if isinstance(item, str):
            return item

    return None
