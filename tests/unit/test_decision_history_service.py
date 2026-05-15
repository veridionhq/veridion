import json

from veridion.action.decision_history_service import resolve_history_request


def test_decision_history_service_routes_health_and_analytics(tmp_path) -> None:
    history_path = tmp_path / "history.ndjson"
    history_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "generated_at": "2026-05-14T12:00:00Z",
                        "repository": "acme/service-a",
                        "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                        "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                        "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
                    }
                ),
                json.dumps(
                    {
                        "generated_at": "2026-05-14T13:00:00Z",
                        "repository": "acme/service-b",
                        "decision": {"verdict": "NO GO", "gate_status": "block", "blocking_categories": ["dependency_risk"]},
                        "automation": {"approval_gate_status": "blocked", "stale_approvals": []},
                        "policy": {"pack_id": "platform", "pack_version": "1", "rollout_stage": "general"},
                    }
                ),
            ]
        )
        + "\n"
    )
    history_paths = (str(history_path),)

    health_status, health = resolve_history_request("/healthz", history_paths=history_paths)
    analytics_status, analytics = resolve_history_request(
        "/analytics?repository=acme/service-b",
        history_paths=history_paths,
    )
    repositories_status, repositories = resolve_history_request("/repositories", history_paths=history_paths)

    assert health_status == 200
    assert health["status"] == "ok"
    assert analytics_status == 200
    assert analytics["summary"]["events"] == 1
    assert analytics["by_verdict"] == {"NO GO": 1}
    assert repositories_status == 200
    assert repositories["repositories"] == ["acme/service-a", "acme/service-b"]
