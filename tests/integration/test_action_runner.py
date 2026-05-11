import json
from pathlib import Path

from veridion.action.runner import run_action
from veridion.context import build_operational_context_artifact


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
    trust_profile_text = Path("tests/fixtures/pr/trust_profile.json").read_text()

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
        metadata_text=metadata_text,
        trust_profile_text=trust_profile_text,
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
    assert result.bundle.trust_profile_metadata.schema_version == 1
    assert result.bundle.trust_profile_metadata.repo_id == "veridionhq/veridion"
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
    assert "### AI Signals" in result.comment_markdown
    assert "### Key Context" in result.comment_markdown
    assert "### Why this is blocked" in result.comment_markdown
    assert "### Why this matters" in result.comment_markdown
    assert "- platform owner" in result.comment_markdown
    assert "- security owner" in result.comment_markdown
    assert "- service owner" in result.comment_markdown
    assert "- SRE owner" in result.comment_markdown
    assert "- ownership: owner: payments-owner | team: payments-platform | review: cross team | team trust: degrading" in result.comment_markdown
    assert "Block release until introduced risk is remediated or policy is adjusted" in result.comment_markdown
    assert "Run staging smoke tests for infrastructure-affecting changes" in result.comment_markdown
    assert "### What must happen next" in result.comment_markdown
    assert "### Recommended rollout" in result.comment_markdown
    assert "... " in result.comment_markdown
    assert "more contextual risks" in result.comment_markdown or "more contextual risk" in result.comment_markdown
    assert "more guidance items" in result.comment_markdown or "more guidance item" in result.comment_markdown
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


def test_run_action_accepts_versioned_operational_context_artifact() -> None:
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
    metadata_payload = json.loads(Path("tests/fixtures/pr/pr_metadata.json").read_text())
    trust_profile_payload = json.loads(Path("tests/fixtures/pr/trust_profile.json").read_text())
    operational_context = build_operational_context_artifact(
        metadata_payload=metadata_payload,
        trust_profile_payload=trust_profile_payload,
        source="integration-test",
        generated_at="2026-05-10T00:00:00Z",
    )

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
        operational_context_text=json.dumps(operational_context),
    )

    assert result.decision.decision == "NO GO"
    assert result.decision.score < 60
    assert result.bundle.summary.ai_change_signals == 4
    assert result.bundle.summary.historical_risk_signals == 7
    assert result.bundle.summary.runtime_risk_signals == 5
    assert result.bundle.summary.ownership_risk_signals == 3
    assert result.bundle.summary.trust_baseline_risk_signals == 6
    assert result.bundle.runtime_signals.environment == "production"
    assert result.bundle.trust_profile_metadata.repo_id == "veridionhq/veridion"
    assert result.decision.required_approvals == (
        "platform_owner",
        "security_owner",
        "service_owner",
        "sre_owner",
    )
    assert "### Key Context" in result.comment_markdown
    assert "### What must happen next" in result.comment_markdown
    assert "### Recommended rollout" in result.comment_markdown
    assert "### Why this is blocked" in result.comment_markdown
    assert "### Why this matters" in result.comment_markdown
    assert "- platform owner" in result.comment_markdown
    assert "- security owner" in result.comment_markdown
    assert "- service owner" in result.comment_markdown
    assert "- SRE owner" in result.comment_markdown


def test_run_action_applies_accepted_risk_suppressions() -> None:
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

    initial = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
    )

    dependency_finding = next(
        finding for finding in initial.bundle.baseline_comparison.introduced if finding.finding_type == "dependency"
    )
    suppression_text = json.dumps(
        {
            "schema_version": 1,
            "suppressions": [
                {
                    "dedup_key": dependency_finding.dedup_key,
                    "reason": "temporary vendor exception while upstream patch is pending",
                    "expires_on": "2026-12-31",
                }
            ],
        }
    )

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
        suppression_text=suppression_text,
    )

    assert result.bundle.summary.suppressed_findings == 1
    assert result.bundle.summary.introduced_findings == 1
    assert result.bundle.summary.expired_suppressions == 0
    assert result.decision.score > initial.decision.score
    assert result.decision.score < 100
    assert result.decision.decision == "NO GO"
    assert "accepted risk suppressions: -" in "\n".join(result.decision.score_adjustments)
    assert "1 finding(s) are suppressed as accepted risk" in result.decision.reasons
    assert "policy no_go threshold triggered at score 60" in result.decision.reasons
    assert "### Accepted Risk" in result.comment_markdown
    assert "- suppressed findings: 1" in result.comment_markdown
    assert "temporary vendor exception while upstream patch is pending (1 finding(s)) (expires 2026-12-31)" in result.comment_markdown
