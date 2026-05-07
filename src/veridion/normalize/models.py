"""Normalized schema used by downstream risk and decision engines."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class NormalizedLocation:
    """File or package location associated with a finding."""

    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None


@dataclass(frozen=True)
class NormalizedFinding:
    """Scanner-agnostic representation of a finding."""

    source: str
    finding_type: str
    rule_id: str
    title: str
    severity: str
    confidence: str | None = None
    description: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    location: NormalizedLocation = field(default_factory=NormalizedLocation)
    references: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)
    schema_version: str = "1"

    def to_dict(self) -> dict[str, object]:
        """Convert the model to plain Python objects for tests and serialization."""

        return asdict(self)

    @property
    def fingerprint(self) -> str:
        """Stable identifier used for baseline comparisons."""

        location = self.location.path or ""
        package = _package_identity(self.package_name, self.package_version)
        evidence = self.metadata.get("match_sha256", "")
        return "|".join(
            (
                self.schema_version,
                self.source,
                self.finding_type,
                self.rule_id,
                package,
                location,
                evidence,
            )
        )


def _package_identity(name: str | None, version: str | None) -> str:
    if name and version:
        return f"{name}@{version}"
    if name:
        return name
    if version:
        return version
    return ""
