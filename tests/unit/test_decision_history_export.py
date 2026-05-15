import json

from veridion.action.decision_history_export import export_configured_decision_history, export_decision_history


def test_export_decision_history_writes_overall_repository_and_pack_snapshots(tmp_path) -> None:
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
                        "policy": {"pack_id": "platform", "pack_version": "2", "rollout_stage": "pilot"},
                    }
                ),
            ]
        )
        + "\n"
    )
    output_dir = tmp_path / "exports"

    export_decision_history(history_paths=(str(history_path),), output_dir=output_dir)

    overall = json.loads((output_dir / "overall.json").read_text())
    repo = json.loads((output_dir / "repositories" / "acme_service-a.json").read_text())
    pack = json.loads((output_dir / "policy-packs" / "platform.json").read_text())

    assert overall["summary"]["events"] == 2
    assert repo["summary"]["events"] == 1
    assert repo["by_verdict"] == {"GO": 1}
    assert pack["by_verdict"] == {"NO GO": 1}


def test_export_configured_decision_history_writes_per_tenant_snapshots(tmp_path) -> None:
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
                "policy": {"pack_id": "platform", "pack_version": "2", "rollout_stage": "pilot"},
            }
        )
        + "\n"
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "tenants": [
                    {"tenant_id": "acme", "history_paths": [str(acme_history)]},
                    {"tenant_id": "beta", "history_paths": [str(beta_history)]},
                ]
            }
        )
    )

    output_dir = tmp_path / "exports"
    export_configured_decision_history(config_path=config_path, output_dir=output_dir)

    acme = json.loads((output_dir / "tenants" / "acme" / "overall.json").read_text())
    beta = json.loads((output_dir / "tenants" / "beta" / "overall.json").read_text())
    assert acme["by_verdict"] == {"GO": 1}
    assert beta["by_verdict"] == {"NO GO": 1}
