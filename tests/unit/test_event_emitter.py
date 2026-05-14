from veridion.action import event_emitter


def test_emit_decision_event_posts_contract(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post_json(*, url: str, payload: dict[str, object], token: str):
        captured["url"] = url
        captured["payload"] = payload
        captured["token"] = token
        return {}

    monkeypatch.setattr(event_emitter, "_post_json", fake_post_json)

    result = event_emitter.emit_decision_event(
        webhook_url="https://example.test/webhook",
        event_type="veridion.rdi.decision.v1",
        decision_contract={"decision": {"verdict": "NO GO"}},
        repository="acme/veridion",
        pull_request_number=7,
        token="secret",
    )

    assert result.status == "delivered"
    assert captured["url"] == "https://example.test/webhook"
    assert captured["token"] == "secret"
    assert captured["payload"] == {
        "event_type": "veridion.rdi.decision.v1",
        "repository": "acme/veridion",
        "pull_request_number": 7,
        "decision_contract": {"decision": {"verdict": "NO GO"}},
    }
