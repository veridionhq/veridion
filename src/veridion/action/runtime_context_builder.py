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
    parser.add_argument("--incident-provider", default="generic", help="Incident source provider: generic, pagerduty, opsgenie, or incident-io")
    parser.add_argument("--freeze-path", help="Path to deployment-freeze source JSON")
    parser.add_argument("--freeze-provider", default="generic", help="Freeze source provider: generic or google-calendar")
    parser.add_argument("--alerts-path", help="Path to alerts source JSON")
    parser.add_argument("--alerts-provider", default="generic", help="Alerts source provider: generic, datadog, statuspage, or cloudwatch")
    parser.add_argument("--canary-path", help="Path to canary-health source JSON")
    parser.add_argument("--canary-provider", default="generic", help="Canary source provider: generic, argo-rollouts, spinnaker, or harness")
    parser.add_argument("--rollback-path", help="Path to rollback-readiness source JSON")
    parser.add_argument("--rollback-provider", default="generic", help="Rollback source provider: generic, argo-rollouts, spinnaker, or harness")
    parser.add_argument("--environment", help="Optional normalized environment value")
    parser.add_argument("--deployment-window", help="Optional normalized deployment window")
    parser.add_argument("--public-exposure", help="Optional boolean public exposure override")
    parser.add_argument("--blast-radius", help="Optional normalized blast radius")
    parser.add_argument("--rollout-strategy", help="Optional normalized rollout strategy")
    args = parser.parse_args(argv)

    runtime = build_runtime_context(
        incident_payload=_load_optional_json(args.incident_path),
        incident_provider=args.incident_provider,
        freeze_payload=_load_optional_json(args.freeze_path),
        freeze_provider=args.freeze_provider,
        alerts_payload=_load_optional_json(args.alerts_path),
        alerts_provider=args.alerts_provider,
        canary_payload=_load_optional_json(args.canary_path),
        canary_provider=args.canary_provider,
        rollback_payload=_load_optional_json(args.rollback_path),
        rollback_provider=args.rollback_provider,
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
    incident_provider: str,
    freeze_payload: dict[str, object],
    freeze_provider: str,
    alerts_payload: dict[str, object],
    alerts_provider: str,
    canary_payload: dict[str, object],
    canary_provider: str,
    rollback_payload: dict[str, object],
    rollback_provider: str,
    environment: str,
    deployment_window: str,
    public_exposure: bool | None,
    blast_radius: str,
    rollout_strategy: str,
) -> dict[str, object]:
    incident = _incident_state(incident_payload, provider=incident_provider)
    freeze_active = _freeze_active(freeze_payload, provider=freeze_provider)
    alert_state = _alert_state(alerts_payload, provider=alerts_provider)
    canary_health = _canary_health(canary_payload, provider=canary_provider)
    rollback_viability = _rollback_viability(rollback_payload, provider=rollback_provider)

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


def _incident_state(payload: dict[str, object], *, provider: str) -> dict[str, object]:
    if provider == "pagerduty":
        incident = _first_object(payload.get("incidents")) or payload
        status = _normalize_value(incident.get("status"), {"triggered", "acknowledged", "resolved"})
        urgency = _normalize_value(incident.get("urgency"), {"low", "high"})
        severity = "high" if urgency == "high" else "medium" if status in {"triggered", "acknowledged"} else ""
        return {"active": status in {"triggered", "acknowledged"}, "severity": severity}
    if provider == "opsgenie":
        data = _first_object(payload.get("data")) or payload
        status = _normalize_value(data.get("status"), {"open", "closed"})
        priority = _normalize_value(data.get("priority"), {"p1", "p2", "p3", "p4", "p5"})
        severity = {"p1": "critical", "p2": "high", "p3": "medium", "p4": "low", "p5": "low"}.get(priority, "")
        return {"active": status == "open", "severity": severity}
    if provider == "incident-io":
        incident = _first_object(payload.get("incident")) or payload
        mode = _normalize_value(incident.get("mode"), {"real", "test"})
        status = _normalize_value(incident.get("status"), {"active", "closed", "resolved"})
        severity = _normalize_value(incident.get("severity"), {"low", "medium", "high", "critical"})
        return {"active": mode == "real" and status == "active", "severity": severity}
    active = _boolish(payload.get("active")) or _status_in(payload.get("status"), {"active", "open", "triggered"})
    severity = _normalize_value(payload.get("severity"), {"low", "medium", "high", "critical"})
    return {"active": active, "severity": severity}


def _freeze_active(payload: dict[str, object], *, provider: str) -> bool:
    if provider == "google-calendar":
        items = payload.get("items")
        if isinstance(items, list):
            return any(isinstance(item, dict) and str(item.get("status", "")).lower() == "confirmed" for item in items)
    return _boolish(payload.get("active")) or _status_in(payload.get("status"), {"active", "frozen", "enabled"})


def _alert_state(payload: dict[str, object], *, provider: str) -> str:
    if provider == "datadog":
        monitors = payload.get("monitors")
        if isinstance(monitors, list):
            states = {str(item.get("overall_state", "")).lower() for item in monitors if isinstance(item, dict)}
            if "alert" in states:
                return "firing"
            if "warn" in states:
                return "elevated"
    if provider == "statuspage":
        incidents = payload.get("incidents")
        if isinstance(incidents, list):
            impacts = {str(item.get("impact", "")).lower() for item in incidents if isinstance(item, dict)}
            if any(impact in {"critical", "major"} for impact in impacts):
                return "firing"
            if any(impact in {"minor", "maintenance"} for impact in impacts):
                return "elevated"
    if provider == "cloudwatch":
        alarms = payload.get("MetricAlarms") or payload.get("CompositeAlarms")
        if isinstance(alarms, list):
            states = {str(item.get("StateValue", "")).lower() for item in alarms if isinstance(item, dict)}
            if "alarm" in states:
                return "firing"
            if "insufficient_data" in states:
                return "elevated"
    direct = _normalize_value(payload.get("state"), {"clear", "elevated", "firing"})
    if direct:
        return direct
    if _boolish(payload.get("firing")):
        return "firing"
    if _boolish(payload.get("elevated")):
        return "elevated"
    return ""


def _canary_health(payload: dict[str, object], *, provider: str) -> str:
    if provider == "argo-rollouts":
        status = _first_object(payload.get("status"))
        phase = _normalize_value(status.get("phase") if status else payload.get("phase"), {"healthy", "degraded", "failing"})
        if phase:
            return phase
        conditions = status.get("conditions") if isinstance(status, dict) else payload.get("conditions")
        if isinstance(conditions, list):
            normalized = {str(item.get("status", "")).lower() for item in conditions if isinstance(item, dict)}
            if "degraded" in normalized:
                return "degraded"
    if provider == "spinnaker":
        status = _normalize_value(payload.get("status"), {"succeeded", "running", "terminal"})
        if status == "terminal":
            return "failing"
        if status == "running":
            return "degraded"
        if status == "succeeded":
            return "healthy"
    if provider == "harness":
        stage = _first_object(payload.get("stage")) or payload
        status = _normalize_value(stage.get("status"), {"success", "running", "failed", "aborted"})
        if status in {"failed", "aborted"}:
            return "failing"
        if status == "running":
            return "degraded"
        if status == "success":
            return "healthy"
    direct = _normalize_value(payload.get("health"), {"healthy", "degraded", "failing"})
    if direct:
        return direct
    return _normalize_value(payload.get("status"), {"healthy", "degraded", "failing"})


def _rollback_viability(payload: dict[str, object], *, provider: str) -> str:
    if provider == "argo-rollouts":
        status = _first_object(payload.get("status"))
        phase = _normalize_value(status.get("phase") if isinstance(status, dict) else payload.get("phase"), {"healthy", "degraded", "failing"})
        if phase == "failing":
            return "blocked"
        if phase == "degraded":
            return "unverified"
    if provider == "spinnaker":
        rollback = _normalize_value(payload.get("rollback"), {"available", "blocked", "unverified"})
        if rollback == "available":
            return "ready"
        if rollback:
            return rollback
    if provider == "harness":
        rollback = _first_object(payload.get("rollback")) or payload
        status = _normalize_value(rollback.get("status"), {"ready", "blocked", "unverified", "verified"})
        if status == "verified":
            return "ready"
        if status:
            return status
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


def _first_object(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                return item
    return {}


if __name__ == "__main__":
    raise SystemExit(main())
