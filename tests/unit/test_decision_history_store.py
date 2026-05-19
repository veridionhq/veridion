import json

from veridion.action.decision_history_store import (
    analyze_history_store,
    get_history_store_status,
    list_materialization_runs,
    record_materialization_run,
    upsert_history_store,
)


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


def test_decision_history_store_tracks_materialization_runs(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    upsert_history_store(sqlite_path=sqlite_path, tenant_id="acme", history_paths=())

    record_materialization_run(
        sqlite_path=sqlite_path,
        run_id="run-1",
        tenant_id="acme",
        generated_at="2026-05-18T12:00:00Z",
        output_root=tmp_path / "materialized",
        run_path=tmp_path / "materialized" / "runs" / "run-1",
        since="2026-05-01T00:00:00Z",
        until="2026-05-18T00:00:00Z",
        athena_database="analytics",
        athena_table="veridion_decision_events",
        athena_s3_location="s3://bucket/path",
    )

    runs = list_materialization_runs(sqlite_path=sqlite_path, tenant_id="acme")

    assert len(runs) == 1
    assert runs[0]["run_id"] == "run-1"
    assert runs[0]["athena_database"] == "analytics"


def test_decision_history_store_reports_schema_status(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    upsert_history_store(sqlite_path=sqlite_path, tenant_id="acme", history_paths=())

    status = get_history_store_status(sqlite_path=sqlite_path, tenant_id="acme")

    assert status["store"]["backend"] == "sqlite"
    assert status["store"]["schema_version"] >= 2
    assert len(status["store"]["migrations"]) >= 2
