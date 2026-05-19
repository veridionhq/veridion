from veridion.action import runtime_live_fetch


def test_fetch_and_build_runtime_context_uses_live_provider_fetches(monkeypatch) -> None:
    monkeypatch.setattr(
        runtime_live_fetch,
        "fetch_incident_payload",
        lambda **_: {"incidents": [{"status": "triggered", "urgency": "high"}]},
    )
    monkeypatch.setattr(
        runtime_live_fetch,
        "fetch_alerts_payload",
        lambda **_: {"MetricAlarms": [{"StateValue": "ALARM"}]},
    )
    monkeypatch.setattr(
        runtime_live_fetch,
        "fetch_canary_payload",
        lambda **_: {"stage": {"status": "running"}},
    )
    monkeypatch.setattr(
        runtime_live_fetch,
        "fetch_rollback_payload",
        lambda **_: {"rollback": {"status": "verified"}},
    )

    payload = runtime_live_fetch.fetch_and_build_runtime_context(
        incident_provider="pagerduty",
        incident_base_url="https://pagerduty.example",
        incident_token="token",
        alerts_provider="cloudwatch",
        alerts_base_url="",
        alerts_token="",
        cloudwatch_region="us-west-2",
        canary_provider="harness",
        canary_base_url="https://harness.example",
        canary_token="token",
        environment="production",
        deployment_window="after_hours",
        public_exposure="true",
        blast_radius="high",
        rollout_strategy="canary",
    )

    assert payload["runtime"]["active_incident"] is True
    assert payload["runtime"]["alert_state"] == "firing"
    assert payload["runtime"]["canary_health"] == "degraded"
    assert payload["runtime"]["rollback_viability"] == "ready"
