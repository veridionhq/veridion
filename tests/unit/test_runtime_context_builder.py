import json

from veridion.action.runtime_context_builder import build_runtime_context, main


def test_build_runtime_context_normalizes_live_source_payloads() -> None:
    runtime = build_runtime_context(
        incident_payload={"status": "open", "severity": "high"},
        freeze_payload={"active": True},
        alerts_payload={"firing": True},
        canary_payload={"health": "degraded"},
        rollback_payload={"ready": True, "verified": False},
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
            "--freeze-path",
            str(freeze_path),
            "--alerts-path",
            str(alerts_path),
            "--canary-path",
            str(canary_path),
            "--rollback-path",
            str(rollback_path),
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
