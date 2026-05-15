import json

from veridion.action.decision_history import main


def test_decision_history_aggregates_pack_and_gate_trends(tmp_path) -> None:
    history_path = tmp_path / "history.ndjson"
    history_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "repository": "acme/service-a",
                        "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                        "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                        "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
                    }
                ),
                json.dumps(
                    {
                        "repository": "acme/service-a",
                        "decision": {
                            "verdict": "CONDITIONAL GO",
                            "gate_status": "review",
                            "blocking_categories": ["public_exposure"],
                        },
                        "automation": {"approval_gate_status": "stale", "stale_approvals": ["platform_owner"]},
                        "policy": {"pack_id": "app", "pack_version": "2", "rollout_stage": "pilot"},
                    }
                ),
                json.dumps(
                    {
                        "repository": "acme/service-b",
                        "decision": {
                            "verdict": "NO GO",
                            "gate_status": "block",
                            "blocking_categories": ["dependency_risk", "public_exposure"],
                        },
                        "automation": {"approval_gate_status": "blocked", "stale_approvals": []},
                        "policy": {"pack_id": "platform", "pack_version": "1", "rollout_stage": "general"},
                    }
                ),
            ]
        )
        + "\n"
    )
    output_path = tmp_path / "analytics.json"

    exit_code = main(
        [
            "--history-path",
            str(history_path),
            "--output-path",
            str(output_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    assert payload["summary"]["events"] == 3
    assert payload["summary"]["policy_pack_variants"] == 3
    assert payload["by_verdict"] == {"CONDITIONAL GO": 1, "GO": 1, "NO GO": 1}
    assert payload["approval_freshness"]["stale_approval_events"] == 1
    assert payload["top_blocking_categories"][0]["name"] == "public_exposure"
    assert payload["by_policy_pack"][0]["pack_id"] == "app"


def test_decision_history_filters_by_repository_and_pack(tmp_path) -> None:
    history_path = tmp_path / "history.ndjson"
    history_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "repository": "acme/service-a",
                        "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                        "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                        "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "general"},
                    }
                ),
                json.dumps(
                    {
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
    output_path = tmp_path / "analytics.json"

    exit_code = main(
        [
            "--history-path",
            str(history_path),
            "--repository",
            "acme/service-b",
            "--policy-pack-id",
            "platform",
            "--output-path",
            str(output_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    assert payload["summary"]["events"] == 1
    assert payload["by_verdict"] == {"NO GO": 1}


def test_decision_history_reads_exported_event_directory_and_reports_rollout(tmp_path) -> None:
    history_dir = tmp_path / "events"
    history_dir.mkdir()
    (history_dir / "one.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-05-14T12:00:00Z",
                "repository": "acme/service-a",
                "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                "policy": {"pack_id": "app", "pack_version": "1", "rollout_stage": "pilot"},
            }
        )
        + "\n"
    )
    nested = history_dir / "nested"
    nested.mkdir()
    (nested / "two.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-05-15T12:00:00Z",
                "repository": "acme/service-a",
                "decision": {"verdict": "CONDITIONAL GO", "gate_status": "review", "blocking_categories": ["public_exposure"]},
                "automation": {"approval_gate_status": "blocked", "stale_approvals": ["platform_owner"]},
                "policy": {"pack_id": "app", "pack_version": "2", "rollout_stage": "general"},
            }
        )
        + "\n"
    )
    output_path = tmp_path / "analytics.json"

    exit_code = main(["--history-path", str(history_dir), "--output-path", str(output_path)])

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    assert payload["summary"]["events"] == 2
    assert payload["time_series"]["by_day"] == [
        {"day": "2026-05-14", "events": 1},
        {"day": "2026-05-15", "events": 1},
    ]
    assert payload["policy_rollout"]["latest_by_repository"][0]["pack_version"] == "2"
    assert payload["policy_rollout"]["transitions"][0]["from"] == "app@1:pilot"
    assert payload["policy_rollout"]["transitions"][0]["to"] == "app@2:general"
