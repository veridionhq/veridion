"""Runtime and deployment context parsed from optional PR metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeSignals:
    """Deployment-time context that can influence trust decisions."""

    environment: str = ""
    deployment_window: str = ""
    public_exposure: bool = False
    blast_radius: str = ""
    rollout_strategy: str = ""

    @property
    def elevated_signals(self) -> tuple[str, ...]:
        signals: list[str] = []

        if self.environment == "production":
            signals.append("deployment target: production")
        if self.public_exposure:
            signals.append("service is publicly exposed")
        if self.blast_radius in {"high", "critical"}:
            signals.append(f"blast radius: {self.blast_radius}")
        if self.deployment_window == "after_hours":
            signals.append("deployment window: after hours")
        if self.rollout_strategy in {"direct", "all_at_once"}:
            signals.append(f"rollout strategy: {self.rollout_strategy}")

        return tuple(signals)


def parse_runtime_signals(payload: dict[str, object]) -> RuntimeSignals:
    """Parse runtime/deployment context from a permissive metadata payload."""

    raw = payload.get("runtime")
    if not isinstance(raw, dict):
        return RuntimeSignals()

    return RuntimeSignals(
        environment=_normalize_value(raw.get("environment"), {"development", "staging", "production"}),
        deployment_window=_normalize_value(raw.get("deployment_window"), {"business_hours", "after_hours"}),
        public_exposure=_as_bool(raw.get("public_exposure")),
        blast_radius=_normalize_value(raw.get("blast_radius"), {"low", "medium", "high", "critical"}),
        rollout_strategy=_normalize_value(raw.get("rollout_strategy"), {"rolling", "canary", "blue_green", "direct", "all_at_once"}),
    )


def _normalize_value(value: object, allowed: set[str]) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    return normalized if normalized in allowed else ""


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False
