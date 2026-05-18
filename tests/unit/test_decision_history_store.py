import json

from veridion.action.decision_history_store import analyze_history_store, upsert_history_store


def test_decision_history_store_ingests_and_analyzes_by_tenant(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    acme_history = tmp_path / "acme.ndjson"
    beta_history = tmp_path / "beta.ndjson"
    acme_history.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-14T12:00:00Z",
                "repository": "acme/service-a",
                "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
            }
        )
        + "\n"
    )
    beta_history.write_text(
        json.dumps(
            {
                "generated_at": "2026-05-14T13:00:00Z",
                "repository": "beta/service-b",
                "decision": {"verdict": "NO GO", "gate_status": "block", "blocking_categories": ["dependency_risk"]},
                "automation": {"approval_gate_status": "blocked", "stale_approvals": []},
                "policy": {"pack_id": "platform", "pack_version": "1", "rollout_stage": "general"},
            }
        )
        + "\n"
    )

    assert upsert_history_store(sqlite_path=sqlite_path, tenant_id="acme", history_paths=(str(acme_history),)) == 1
    assert upsert_history_store(sqlite_path=sqlite_path, tenant_id="beta", history_paths=(str(beta_history),)) == 1

    acme = analyze_history_store(sqlite_path=sqlite_path, tenant_id="acme")
    beta = analyze_history_store(sqlite_path=sqlite_path, tenant_id="beta")

    assert acme["by_verdict"] == {"GO": 1}
    assert beta["by_verdict"] == {"NO GO": 1}
