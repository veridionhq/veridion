import json

from veridion.action import decision_sinks


def test_parse_sink_spec_parses_kind_and_options() -> None:
    spec = decision_sinks.parse_sink_spec("s3:bucket=my-bucket,key=events/one.json,region=us-west-2")

    assert spec.kind == "s3"
    assert spec.options["bucket"] == "my-bucket"
    assert spec.options["key"] == "events/one.json"
    assert spec.options["region"] == "us-west-2"


def test_deliver_decision_event_writes_local_file_and_ndjson(tmp_path) -> None:
    event = {"decision": {"verdict": "GO"}}
    file_path = tmp_path / "event.json"
    history_path = tmp_path / "history.ndjson"

    results = decision_sinks.deliver_decision_event(
        event,
        sink_specs=(
            decision_sinks.SinkSpec(kind="local-file", options={"path": str(file_path)}),
            decision_sinks.SinkSpec(kind="local-ndjson", options={"path": str(history_path)}),
        ),
    )

    assert len(results) == 2
    assert json.loads(file_path.read_text())["decision"]["verdict"] == "GO"
    assert json.loads(history_path.read_text().strip())["decision"]["verdict"] == "GO"


def test_deliver_decision_event_uses_webhook_sink(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post_json(*, url: str, payload: dict[str, object], token: str):
        captured["url"] = url
        captured["payload"] = payload
        captured["token"] = token
        return {}

    monkeypatch.setattr(decision_sinks, "_post_json", fake_post_json)

    results = decision_sinks.deliver_decision_event(
        {"decision": {"verdict": "NO GO"}},
        sink_specs=(
            decision_sinks.SinkSpec(
                kind="webhook",
                options={"url": "https://example.test/sink", "token": "secret", "event_type": "veridion.event"},
            ),
        ),
    )

    assert results[0].status == "delivered"
    assert captured["url"] == "https://example.test/sink"
    assert captured["token"] == "secret"
    assert captured["payload"]["event_type"] == "veridion.event"
    assert captured["payload"]["decision_event"]["decision"]["verdict"] == "NO GO"


def test_deliver_decision_event_collects_failures_without_raising_by_default() -> None:
    results = decision_sinks.deliver_decision_event(
        {"decision": {"verdict": "GO"}},
        sink_specs=(decision_sinks.SinkSpec(kind="unsupported", options={}),),
        fail_on_error=False,
    )

    assert results[0].status == "failed"
    assert "unsupported sink kind" in results[0].error
