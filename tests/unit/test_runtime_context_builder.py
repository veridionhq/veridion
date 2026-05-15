import json

from veridion.action.runtime_context_builder import build_runtime_context, main


def test_build_runtime_context_normalizes_live_source_payloads() -> None:
    runtime = build_runtime_context(
        incident_payload={"status": "open", "severity": "high"},
        incident_provider="generic",
        freeze_payload={"active": True},
        freeze_provider="generic",
        alerts_payload={"firing": True},
        alerts_provider="generic",
        canary_payload={"health": "degraded"},
        canary_provider="generic",
        rollback_payload={"ready": True, "verified": False},
        rollback_provider="generic",
        environment="production",
        deployment_window="after_hours",
        public_exposure=True,
        blast_radius="high",
        rollout_strategy="canary",
    )

    assert runtime["active_incident"] is True
    assert runtime["active_incident_severity"] == "high"
    assert runtime["deployment_freeze_active"] is True
    assert runtime["alert_state"] == "firing"
    assert runtime["canary_health"] == "degraded"
    assert runtime["rollback_viability"] == "unverified"


def test_runtime_context_builder_writes_normalized_runtime_json(tmp_path) -> None:
    incident_path = tmp_path / "incident.json"
    freeze_path = tmp_path / "freeze.json"
    alerts_path = tmp_path / "alerts.json"
    canary_path = tmp_path / "canary.json"
    rollback_path = tmp_path / "rollback.json"
    output_path = tmp_path / "runtime.json"

    incident_path.write_text(json.dumps({"active": True, "severity": "critical"}))
    freeze_path.write_text(json.dumps({"status": "active"}))
    alerts_path.write_text(json.dumps({"state": "elevated"}))
    canary_path.write_text(json.dumps({"status": "failing"}))
    rollback_path.write_text(json.dumps({"blocked": True}))

    exit_code = main(
        [
            "--incident-path",
            str(incident_path),
            "--incident-provider",
            "generic",
            "--freeze-path",
            str(freeze_path),
            "--freeze-provider",
            "generic",
            "--alerts-path",
            str(alerts_path),
            "--alerts-provider",
            "generic",
            "--canary-path",
            str(canary_path),
            "--canary-provider",
            "generic",
            "--rollback-path",
            str(rollback_path),
            "--rollback-provider",
            "generic",
            "--environment",
            "production",
            "--output-path",
            str(output_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    assert payload["runtime"]["active_incident"] is True
    assert payload["runtime"]["active_incident_severity"] == "critical"
    assert payload["runtime"]["deployment_freeze_active"] is True
    assert payload["runtime"]["alert_state"] == "elevated"
    assert payload["runtime"]["canary_health"] == "failing"
    assert payload["runtime"]["rollback_viability"] == "blocked"


def test_build_runtime_context_supports_provider_shaped_payloads() -> None:
    runtime = build_runtime_context(
        incident_payload={"incidents": [{"status": "triggered", "urgency": "high"}]},
        incident_provider="pagerduty",
        freeze_payload={"active": False},
        freeze_provider="generic",
        alerts_payload={"monitors": [{"overall_state": "Alert"}]},
        alerts_provider="datadog",
        canary_payload={"status": {"phase": "degraded"}},
        canary_provider="argo-rollouts",
        rollback_payload={"status": {"phase": "degraded"}},
        rollback_provider="argo-rollouts",
        environment="production",
        deployment_window="after_hours",
        public_exposure=True,
        blast_radius="high",
        rollout_strategy="canary",
    )

    assert runtime["active_incident"] is True
    assert runtime["active_incident_severity"] == "high"
    assert runtime["alert_state"] == "firing"
    assert runtime["canary_health"] == "degraded"
    assert runtime["rollback_viability"] == "unverified"
