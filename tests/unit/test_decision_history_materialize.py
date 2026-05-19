import json

from veridion.action.decision_history_materialize import materialize_decision_history
from veridion.action.decision_history_store import list_materialization_runs, upsert_history_store


def test_materialize_decision_history_writes_run_and_latest(tmp_path) -> None:
    history_path = tmp_path / "history.ndjson"
    history_path.write_text(
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

    run_dir = materialize_decision_history(
        history_paths=(str(history_path),),
        config_path=None,
        output_root=tmp_path / "materialized",
        run_id="run-1",
    )

    overall = json.loads((run_dir / "overall.json").read_text())
    latest = json.loads((tmp_path / "materialized" / "latest" / "overall.json").read_text())

    assert overall["by_verdict"] == {"GO": 1}
    assert latest["by_verdict"] == {"GO": 1}


def test_materialize_decision_history_writes_manifest_and_warehouse_queries(tmp_path) -> None:
    sqlite_path = tmp_path / "history.db"
    history_path = tmp_path / "history.ndjson"
    config_path = tmp_path / "config.json"
    history_path.write_text(
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
    upsert_history_store(sqlite_path=sqlite_path, tenant_id="acme", history_paths=(str(history_path),))
    config_path.write_text(
        json.dumps(
            {
                "sqlite_path": str(sqlite_path),
                "tenants": [{"tenant_id": "acme", "history_paths": []}],
            }
        )
    )

    run_dir = materialize_decision_history(
        history_paths=(),
        config_path=str(config_path),
        output_root=tmp_path / "materialized",
        run_id="run-2",
        athena_database="analytics",
        athena_s3_location_template="s3://bucket/veridion/events/repo={tenant_id}/",
    )

    manifest = json.loads((run_dir / "run-manifest.json").read_text())
    warehouse = json.loads((run_dir / "warehouse" / "acme.athena.json").read_text())
    runs = list_materialization_runs(sqlite_path=sqlite_path, tenant_id="acme")

    assert manifest["run_id"] == "run-2"
    assert warehouse["tenant_id"] == "acme"
    assert warehouse["athena"]["database"] == "analytics"
    assert runs[0]["run_id"] == "run-2"
