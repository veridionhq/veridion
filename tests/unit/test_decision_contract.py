import json

from veridion.action.runner import _parse_allowed_decisions, _write_github_outputs, run_action
from veridion.decision_contract import evaluate_gate


def test_evaluate_gate_maps_decisions_to_stable_statuses() -> None:
    blocked = evaluate_gate("NO GO", allowed_decisions=("GO", "CONDITIONAL GO"))
    review = evaluate_gate("CONDITIONAL GO", allowed_decisions=("GO", "CONDITIONAL GO"))
    passed = evaluate_gate("GO", allowed_decisions=("GO", "CONDITIONAL GO"))

    assert blocked.status == "block"
    assert blocked.decision_allowed is False
    assert blocked.exit_code == 1
    assert review.status == "review"
    assert review.decision_allowed is True
    assert passed.status == "pass"
    assert passed.exit_code == 0


def test_parse_allowed_decisions_rejects_empty_values() -> None:
    try:
        _parse_allowed_decisions(" , ")
    except RuntimeError as exc:
        assert "allowed-decisions must contain at least one decision" in str(exc)
    else:
        raise AssertionError("expected empty allowed-decisions to fail")


def test_write_github_outputs_emits_gate_and_contract_fields(tmp_path, monkeypatch) -> None:
    result = run_action(
        diff_text="diff --git a/README.md b/README.md\nindex 1111111..2222222 100644\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n hello\n+world\n",
        current_reports={},
        baseline_reports={},
        policy_text=None,
    )
    output_path = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    _write_github_outputs(
        result,
        comment_path="veridion-pr-comment.md",
        json_output_path="veridion-result.json",
        decision_contract_path="veridion-decision.json",
    )

    content = output_path.read_text()
    assert "gate_status=pass" in content
    assert "decision_allowed=true" in content
    assert "decision_contract_path=veridion-decision.json" in content
    assert "required_approvals_json=[]" in content
    assert "accepted_risk_present=false" in content

    blocking_line = next(line for line in content.splitlines() if line.startswith("blocking_reasons_json="))
    assert json.loads(blocking_line.split("=", maxsplit=1)[1]) == []
