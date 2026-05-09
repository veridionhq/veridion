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
    metadata_text = Path("tests/fixtures/pr/pr_metadata.json").read_text()

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
        metadata_text=metadata_text,
    )

    assert result.decision.decision == "NO GO"
    assert result.decision.score < 60
    assert result.bundle.summary.introduced_findings == 2
    assert result.bundle.summary.inventory_packages == 1
    assert result.bundle.summary.ai_change_signals == 4
    assert result.bundle.summary.ai_authored_commits == 1
    assert result.bundle.summary.historical_risk_signals == 7
    assert result.bundle.summary.runtime_risk_signals == 5
    assert result.bundle.summary.ownership_risk_signals == 3
    assert result.bundle.summary.trust_baseline_risk_signals == 6
    assert result.decision.required_approvals == (
        "platform_owner",
        "security_owner",
        "service_owner",
        "sre_owner",
    )
    assert result.comment_identifier == "veridion:rdi"
    assert result.decision.score_adjustments == ()
    assert "## Release Decision Intelligence" in result.comment_markdown
    assert "**Decision:** NO GO" in result.comment_markdown
    assert "### AI Attribution" in result.comment_markdown
    assert "### Historical Trust Signals" in result.comment_markdown
    assert "### Runtime Context" in result.comment_markdown
    assert "### Ownership Context" in result.comment_markdown
    assert "### Trust Baseline" in result.comment_markdown
    assert "- platform owner" in result.comment_markdown
    assert "- security owner" in result.comment_markdown
    assert "- service owner" in result.comment_markdown
    assert "- SRE owner" in result.comment_markdown
    assert "Use heightened review for this high-criticality repository" in result.comment_markdown
    assert "Prefer a staged rollout or canary deployment for this historically unstable change surface" in result.comment_markdown
    assert "Increase manual validation for this historically fragile change surface" in result.comment_markdown
    assert "Use a staged rollout with a validated rollback plan for this production deployment" in result.comment_markdown
    assert "Avoid after-hours deployment until on-call coverage is defined" in result.comment_markdown
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
