import json

from veridion.action.decision_event import append_decision_history, build_decision_event


def test_build_decision_event_preserves_final_contract_state() -> None:
    event = build_decision_event(
        {
            "decision": {
                "verdict": "CONDITIONAL GO",
                "score": 84,
                "confidence": "HIGH",
                "gate_status": "review",
                "decision_allowed": True,
                "blocking_categories": ["public_exposure"],
            },
            "actions": {
                "required_approvals": ["platform_owner"],
                "required_next_steps": ["Run staging smoke tests for infrastructure-affecting changes"],
            },
            "reasons": {"blocking": ["release still requires explicit approvals or operational checks"]},
            "accepted_risk": {"present": False, "pending_review": 0, "renewal_pending": 0, "expiring_soon": 0},
            "policy": {"pack_id": "platform-team", "pack_version": "1", "rollout_stage": "general"},
            "automation": {
                "approval_satisfaction_status": "pending",
                "approvals_satisfied": False,
                "satisfied_approvals": [],
                "unsatisfied_approvals": ["platform_owner"],
                "stale_approvals": [],
                "approval_head_sha": "abc123",
                "approval_gate_status": "blocked",
                "approval_gate_allowed": False,
            },
            "signals": {
                "history": {"repo_criticality": "high", "service_criticality": "critical"},
                "runtime": {"environment": "production", "public_exposure": True, "blast_radius": "high"},
                "ownership": {"service_owner": "owner", "owning_team": "team"},
            },
        },
        repository="acme/veridion",
        pull_request_number=42,
    )

    assert event["decision"]["verdict"] == "CONDITIONAL GO"
    assert event["automation"]["approval_gate_status"] == "blocked"
    assert event["automation"]["approval_head_sha"] == "abc123"
    assert event["policy"]["pack_id"] == "platform-team"
    assert event["repository"] == "acme/veridion"
    assert event["pull_request_number"] == 42


def test_append_decision_history_writes_ndjson(tmp_path) -> None:
    history_path = tmp_path / "decision-history.ndjson"
    append_decision_history(history_path, {"decision": {"verdict": "GO"}})
    append_decision_history(history_path, {"decision": {"verdict": "NO GO"}})

    lines = history_path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["decision"]["verdict"] == "GO"
    assert json.loads(lines[1])["decision"]["verdict"] == "NO GO"
