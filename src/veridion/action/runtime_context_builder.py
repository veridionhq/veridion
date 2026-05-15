"""Build normalized runtime context from provider-neutral source payloads."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from veridion.context.runtime import RuntimeSignals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build normalized Veridion runtime context from live source payloads")
    parser.add_argument("--output-path", required=True, help="Where to write the normalized runtime JSON")
    parser.add_argument("--incident-path", help="Path to incident source JSON")
    parser.add_argument("--freeze-path", help="Path to deployment-freeze source JSON")
    parser.add_argument("--alerts-path", help="Path to alerts source JSON")
    parser.add_argument("--canary-path", help="Path to canary-health source JSON")
    parser.add_argument("--rollback-path", help="Path to rollback-readiness source JSON")
    parser.add_argument("--environment", help="Optional normalized environment value")
    parser.add_argument("--deployment-window", help="Optional normalized deployment window")
    parser.add_argument("--public-exposure", help="Optional boolean public exposure override")
    parser.add_argument("--blast-radius", help="Optional normalized blast radius")
    parser.add_argument("--rollout-strategy", help="Optional normalized rollout strategy")
    args = parser.parse_args(argv)

    runtime = build_runtime_context(
        incident_payload=_load_optional_json(args.incident_path),
        freeze_payload=_load_optional_json(args.freeze_path),
        alerts_payload=_load_optional_json(args.alerts_path),
        canary_payload=_load_optional_json(args.canary_path),
        rollback_payload=_load_optional_json(args.rollback_path),
        environment=args.environment or "",
        deployment_window=args.deployment_window or "",
        public_exposure=_parse_bool_flag(args.public_exposure),
        blast_radius=args.blast_radius or "",
        rollout_strategy=args.rollout_strategy or "",
    )
    Path(args.output_path).write_text(json.dumps({"runtime": runtime}, indent=2) + "\n")
    return 0


def build_runtime_context(
    *,
    incident_payload: dict[str, object],
    freeze_payload: dict[str, object],
    alerts_payload: dict[str, object],
    canary_payload: dict[str, object],
    rollback_payload: dict[str, object],
    environment: str,
    deployment_window: str,
    public_exposure: bool | None,
    blast_radius: str,
    rollout_strategy: str,
) -> dict[str, object]:
    incident = _incident_state(incident_payload)
    freeze_active = _freeze_active(freeze_payload)
    alert_state = _alert_state(alerts_payload)
    canary_health = _canary_health(canary_payload)
    rollback_viability = _rollback_viability(rollback_payload)

    runtime = RuntimeSignals(
        environment=_normalize_value(environment, {"development", "staging", "production"}),
        deployment_window=_normalize_value(deployment_window, {"business_hours", "after_hours"}),
        public_exposure=public_exposure if public_exposure is not None else False,
        blast_radius=_normalize_value(blast_radius, {"low", "medium", "high", "critical"}),
        rollout_strategy=_normalize_value(rollout_strategy, {"rolling", "canary", "blue_green", "direct", "all_at_once"}),
        deployment_freeze_active=freeze_active,
        active_incident=incident["active"],
        active_incident_severity=incident["severity"],
        alert_state=alert_state,
        canary_health=canary_health,
        rollback_viability=rollback_viability,
    )
    return {
        "environment": runtime.environment,
        "deployment_window": runtime.deployment_window,
        "public_exposure": runtime.public_exposure,
        "blast_radius": runtime.blast_radius,
        "rollout_strategy": runtime.rollout_strategy,
        "deployment_freeze_active": runtime.deployment_freeze_active,
        "active_incident": runtime.active_incident,
        "active_incident_severity": runtime.active_incident_severity,
        "alert_state": runtime.alert_state,
        "canary_health": runtime.canary_health,
        "rollback_viability": runtime.rollback_viability,
    }


def _load_optional_json(path: str | None) -> dict[str, object]:
    if not path:
        return {}
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return payload


def _incident_state(payload: dict[str, object]) -> dict[str, object]:
    active = _boolish(payload.get("active")) or _status_in(payload.get("status"), {"active", "open", "triggered"})
    severity = _normalize_value(payload.get("severity"), {"low", "medium", "high", "critical"})
    return {"active": active, "severity": severity}


def _freeze_active(payload: dict[str, object]) -> bool:
    return _boolish(payload.get("active")) or _status_in(payload.get("status"), {"active", "frozen", "enabled"})


def _alert_state(payload: dict[str, object]) -> str:
    direct = _normalize_value(payload.get("state"), {"clear", "elevated", "firing"})
    if direct:
        return direct
    if _boolish(payload.get("firing")):
        return "firing"
    if _boolish(payload.get("elevated")):
        return "elevated"
    return ""


def _canary_health(payload: dict[str, object]) -> str:
    direct = _normalize_value(payload.get("health"), {"healthy", "degraded", "failing"})
    if direct:
        return direct
    return _normalize_value(payload.get("status"), {"healthy", "degraded", "failing"})


def _rollback_viability(payload: dict[str, object]) -> str:
    direct = _normalize_value(payload.get("viability"), {"ready", "unverified", "blocked"})
    if direct:
        return direct
    if _boolish(payload.get("blocked")):
        return "blocked"
    if _boolish(payload.get("ready")):
        verified = payload.get("verified")
        if verified is False:
            return "unverified"
        return "ready"
    if payload.get("verified") is False:
        return "unverified"
    return ""


def _status_in(value: object, allowed: set[str]) -> bool:
    normalized = _normalize_value(value, allowed)
    return bool(normalized)


def _normalize_value(value: object, allowed: set[str]) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    return normalized if normalized in allowed else ""


def _boolish(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _parse_bool_flag(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    return value.strip().lower() == "true"


if __name__ == "__main__":
    raise SystemExit(main())
