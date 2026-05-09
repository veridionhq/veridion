"""Learned trust baselines parsed from optional PR metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TrustProfileMetadata:
    """Metadata about the trust-profile artifact itself."""

    schema_version: int = 0
    repo_id: str = ""
    service_id: str = ""
    team_id: str = ""
    source: str = ""
    generated_at: str = ""
    precedence: str = ""


@dataclass(frozen=True)
class TrustBaseline:
    """Persistent repo, service, and team trust posture."""

    repo_stability: str = ""
    service_stability: str = ""
    team_deploy_safety: str = ""
    test_coverage_level: str = ""
    rollback_readiness: str = ""
    dependency_reputation_risk: str = ""

    @property
    def elevated_signals(self) -> tuple[str, ...]:
        signals: list[str] = []

        if self.repo_stability in {"watch", "fragile"}:
            signals.append(f"repository stability: {self.repo_stability}")
        if self.service_stability in {"watch", "fragile"}:
            signals.append(f"service stability: {self.service_stability}")
        if self.team_deploy_safety in {"low", "degrading"}:
            signals.append(f"team deploy safety: {self.team_deploy_safety}")
        if self.test_coverage_level == "low":
            signals.append("test coverage: low")
        if self.rollback_readiness in {"partial", "weak"}:
            signals.append(f"rollback readiness: {self.rollback_readiness}")
        if self.dependency_reputation_risk in {"medium", "high"}:
            signals.append(f"dependency reputation risk: {self.dependency_reputation_risk}")

        return tuple(signals)


def parse_trust_baseline(payload: dict[str, object]) -> TrustBaseline:
    """Parse learned trust baselines from a permissive metadata payload."""

    raw = payload.get("trust_baseline")
    if not isinstance(raw, dict):
        return TrustBaseline()

    return TrustBaseline(
        repo_stability=_normalize_value(raw.get("repo_stability"), {"stable", "watch", "fragile"}),
        service_stability=_normalize_value(raw.get("service_stability"), {"stable", "watch", "fragile"}),
        team_deploy_safety=_normalize_value(raw.get("team_deploy_safety"), {"high", "medium", "low", "degrading"}),
        test_coverage_level=_normalize_value(raw.get("test_coverage_level"), {"high", "medium", "low"}),
        rollback_readiness=_normalize_value(raw.get("rollback_readiness"), {"strong", "partial", "weak"}),
        dependency_reputation_risk=_normalize_value(raw.get("dependency_reputation_risk"), {"low", "medium", "high"}),
    )


def parse_trust_profile_metadata(payload: dict[str, object]) -> TrustProfileMetadata:
    """Parse trust-profile artifact metadata from a permissive payload."""

    raw = payload.get("trust_profile_metadata")
    if not isinstance(raw, dict):
        return TrustProfileMetadata()

    return TrustProfileMetadata(
        schema_version=_as_int(raw.get("schema_version")),
        repo_id=_as_string(raw.get("repo_id")),
        service_id=_as_string(raw.get("service_id")),
        team_id=_as_string(raw.get("team_id")),
        source=_as_string(raw.get("source")),
        generated_at=_as_string(raw.get("generated_at")),
        precedence=_as_string(raw.get("precedence")),
    )


def _normalize_value(value: object, allowed: set[str]) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    return normalized if normalized in allowed else ""


def _as_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _as_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0
