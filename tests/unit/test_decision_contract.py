import json

from veridion.analysis import build_analysis_bundle
from veridion.action.runner import _parse_allowed_decisions, _write_github_outputs, run_action
from veridion.change_context.diff_parser import ParsedChangeContext
from veridion.decision_contract import build_decision_contract, evaluate_gate
from veridion.policy import PolicyConfig, evaluate_release
from veridion.report.threats import ThreatExplanation


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
    assert "blocking_categories_json=[]" in content

    blocking_line = next(line for line in content.splitlines() if line.startswith("blocking_reasons_json="))
    assert json.loads(blocking_line.split("=", maxsplit=1)[1]) == []


def test_run_action_decision_contract_includes_metadata_and_categories() -> None:
    result = run_action(
        diff_text="diff --git a/requirements.txt b/requirements.txt\nindex 1111111..2222222 100644\n--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-urllib3==2.2.2\n+urllib3==1.25.8\n",
        current_reports={},
        baseline_reports={},
        policy_text=None,
    )

    contract = result.decision_contract

    assert contract["schema_version"] == 1
    assert contract["source"] == "veridion/action"
    assert contract["contract_version_source"] == "veridion.decision_contract@1"
    assert isinstance(contract["generated_at"], str)
    assert "blocking_categories" in contract["decision"]


def test_build_decision_contract_deduplicates_equivalent_threats() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
    )
    decision = evaluate_release(bundle, PolicyConfig())
    contract = build_decision_contract(
        bundle=bundle,
        decision=decision,
        threats=(
            ThreatExplanation(
                source="semgrep",
                threat_type="code",
                severity="medium",
                subject="terraform.rule.one",
                location="infra/main.tf",
                summary="adds overly broad IAM permissions",
                why_not_safe="overly broad IAM permissions can allow privilege escalation and violate least privilege",
                advisory_count=1,
            ),
            ThreatExplanation(
                source="semgrep",
                threat_type="code",
                severity="medium",
                subject="terraform.rule.two",
                location="infra/main.tf",
                summary="adds overly broad IAM permissions",
                why_not_safe="overly broad IAM permissions can allow privilege escalation and violate least privilege",
                advisory_count=1,
            ),
        ),
        comment_identifier="veridion:rdi",
        comment_summary={"mode": "deterministic", "provider": "none", "model": "", "error": ""},
        gate=evaluate_gate("GO", allowed_decisions=("GO", "CONDITIONAL GO")),
    )

    threats = contract["threats"]
    assert len(threats) == 1
    assert threats[0]["advisory_count"] == 2
    assert threats[0]["subjects"] == ["terraform.rule.one", "terraform.rule.two"]
