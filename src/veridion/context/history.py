"""Historical trust signals parsed from optional PR metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HistoricalSignals:
    """Lightweight historical and operational trust inputs."""

    repo_criticality: str = ""
    service_criticality: str = ""
    rollback_rate_30d: float | None = None
    incident_count_30d: int = 0
    change_failure_rate_30d: float | None = None
    flaky_service: bool = False
    sensitive_repo: bool = False

    @property
    def elevated_signals(self) -> tuple[str, ...]:
        signals: list[str] = []

        if self.repo_criticality in {"high", "critical"}:
            signals.append(f"repo criticality: {self.repo_criticality}")
        if self.service_criticality in {"high", "critical"}:
            signals.append(f"service criticality: {self.service_criticality}")
        if self.rollback_rate_30d is not None and self.rollback_rate_30d >= 0.10:
            signals.append(f"30d rollback rate: {self.rollback_rate_30d:.0%}")
        if self.change_failure_rate_30d is not None and self.change_failure_rate_30d >= 0.15:
            signals.append(f"30d change failure rate: {self.change_failure_rate_30d:.0%}")
        if self.incident_count_30d >= 3:
            signals.append(f"30d incidents: {self.incident_count_30d}")
        if self.flaky_service:
            signals.append("service marked flaky")
        if self.sensitive_repo:
            signals.append("repository marked sensitive")

        return tuple(signals)


def parse_historical_signals(payload: dict[str, object]) -> HistoricalSignals:
    """Parse historical trust signals from a permissive metadata payload."""

    raw = payload.get("historical")
    if not isinstance(raw, dict):
        return HistoricalSignals()

    return HistoricalSignals(
        repo_criticality=_normalize_level(raw.get("repo_criticality")),
        service_criticality=_normalize_level(raw.get("service_criticality")),
        rollback_rate_30d=_as_float(raw.get("rollback_rate_30d")),
        incident_count_30d=_as_int(raw.get("incident_count_30d")),
        change_failure_rate_30d=_as_float(raw.get("change_failure_rate_30d")),
        flaky_service=_as_bool(raw.get("flaky_service")),
        sensitive_repo=_as_bool(raw.get("sensitive_repo")),
    )


def _normalize_level(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    return normalized if normalized in {"low", "medium", "high", "critical"} else ""


def _as_float(value: object) -> float | None:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _as_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False
