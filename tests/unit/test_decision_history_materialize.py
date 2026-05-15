import json

from veridion.action.decision_history_materialize import materialize_decision_history


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
