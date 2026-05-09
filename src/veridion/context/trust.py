"""Learned trust baselines parsed from optional PR metadata."""

from __future__ import annotations

from dataclasses import dataclass


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


def _normalize_value(value: object, allowed: set[str]) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    return normalized if normalized in allowed else ""
