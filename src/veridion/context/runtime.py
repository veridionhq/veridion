"""Runtime and deployment context parsed from optional PR metadata."""

from __future__ import annotations

from dataclasses import dataclass

from veridion.change_context import ParsedChangeContext


@dataclass(frozen=True)
class RuntimeSignals:
    """Deployment-time context that can influence trust decisions."""

    environment: str = ""
    deployment_window: str = ""
    public_exposure: bool = False
    blast_radius: str = ""
    rollout_strategy: str = ""
    deployment_freeze_active: bool = False
    active_incident: bool = False
    active_incident_severity: str = ""
    alert_state: str = ""
    canary_health: str = ""
    rollback_viability: str = ""

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
        if self.deployment_freeze_active:
            signals.append("deployment freeze is active")
        if self.active_incident:
            if self.active_incident_severity:
                signals.append(f"active incident: {self.active_incident_severity}")
            else:
                signals.append("active incident is open")
        if self.alert_state in {"elevated", "firing"}:
            signals.append(f"alert state: {self.alert_state}")
        if self.canary_health in {"degraded", "failing"}:
            signals.append(f"canary health: {self.canary_health}")
        if self.rollback_viability in {"unverified", "blocked"}:
            signals.append(f"runtime rollback viability: {self.rollback_viability}")

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
        rollout_strategy=_normalize_value(
            raw.get("rollout_strategy"),
            {"rolling", "canary", "blue_green", "direct", "all_at_once"},
        ),
        deployment_freeze_active=_as_bool(raw.get("deployment_freeze_active")),
        active_incident=_as_bool(raw.get("active_incident")),
        active_incident_severity=_normalize_value(raw.get("active_incident_severity"), {"low", "medium", "high", "critical"}),
        alert_state=_normalize_value(raw.get("alert_state"), {"clear", "elevated", "firing"}),
        canary_health=_normalize_value(raw.get("canary_health"), {"healthy", "degraded", "failing"}),
        rollback_viability=_normalize_value(raw.get("rollback_viability"), {"ready", "unverified", "blocked"}),
    )


def derive_runtime_signals(
    change_context: ParsedChangeContext,
    runtime_signals: RuntimeSignals | None = None,
) -> RuntimeSignals:
    """Augment runtime context using inferred blast-radius signals from the diff."""

    runtime = runtime_signals or RuntimeSignals()
    environment = runtime.environment or _derive_environment(change_context)
    public_exposure = runtime.public_exposure or change_context.has_public_exposure_changes
    blast_radius = runtime.blast_radius or _derive_blast_radius(change_context, environment, public_exposure)

    return RuntimeSignals(
        environment=environment,
        deployment_window=runtime.deployment_window,
        public_exposure=public_exposure,
        blast_radius=blast_radius,
        rollout_strategy=runtime.rollout_strategy,
        deployment_freeze_active=runtime.deployment_freeze_active,
        active_incident=runtime.active_incident,
        active_incident_severity=runtime.active_incident_severity,
        alert_state=runtime.alert_state,
        canary_health=runtime.canary_health,
        rollback_viability=runtime.rollback_viability,
    )


def _derive_environment(change_context: ParsedChangeContext) -> str:
    if change_context.has_production_surface_changes:
        return "production"
    return ""


def _derive_blast_radius(
    change_context: ParsedChangeContext,
    environment: str,
    public_exposure: bool,
) -> str:
    high_conditions = (
        change_context.has_shared_platform_changes,
        change_context.has_database_migration_changes,
        change_context.touches_payments_surface,
        change_context.touches_auth_surface,
        change_context.touches_data_surface,
        environment == "production" and public_exposure,
    )
    if any(high_conditions):
        return "high"

    medium_conditions = (
        change_context.has_iac_changes,
        change_context.has_dependency_changes,
        change_context.has_lockfile_changes,
        environment == "production",
        public_exposure,
    )
    if any(medium_conditions):
        return "medium"

    return ""


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
