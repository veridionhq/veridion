import json
from pathlib import Path

from veridion.action.runner import run_action


def test_run_action_executes_pipeline_and_renders_comment() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()
    current_reports = {
        "trivy": "tests/fixtures/scanners/trivy_report.json",
        "semgrep": "tests/fixtures/scanners/semgrep_report.json",
        "grype": "tests/fixtures/scanners/grype_report.json",
        "syft": "tests/fixtures/scanners/syft_report.json",
    }
    baseline_reports = {
        "semgrep": "tests/fixtures/scanners/semgrep_report.json",
    }
    policy_text = Path("tests/fixtures/policies/default_policy.yaml").read_text()

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
    )

    assert result.decision.decision == "NO GO"
    assert result.decision.score < 60
    assert result.bundle.summary.introduced_findings == 3
    assert result.comment_identifier == "veridion:rdi"
    assert "## Release Decision Intelligence" in result.comment_markdown
    assert "**Decision:** NO GO" in result.comment_markdown
    assert "Unattributed findings: 0" in result.comment_markdown
    assert result.comment_markdown.startswith("<!-- veridion:rdi:start -->\n")


def test_action_result_to_dict_is_json_serializable() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()
    result = run_action(
        diff_text=diff_text,
        current_reports={},
        baseline_reports={},
        policy_text=None,
    )

    rendered = json.dumps(result.to_dict())

    assert '"decision": "GO"' in rendered
    assert '"comment_identifier": "veridion:rdi"' in rendered
