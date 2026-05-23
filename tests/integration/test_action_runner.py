import json
from pathlib import Path

from veridion.action.bootstrap import build_bootstrap_files
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
    assert len(result.to_dict()["threats"]) == 2
    assert result.comment_summary_mode == "deterministic"
    assert result.comment_summary_provider == "none"
    assert result.comment_summary_model == ""
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
    assert result.gate_status == "block"
    assert result.decision_allowed is False
    assert result.allowed_decisions == ("GO", "CONDITIONAL GO")
    assert result.decision.score_adjustments == ()
    assert "## Release Decision Intelligence" in result.comment_markdown
    assert "### ❌ NO GO" in result.comment_markdown
    assert "### AI Signals" not in result.comment_markdown
    assert "### Key Context" in result.comment_markdown
    assert "### Why this is blocked" in result.comment_markdown
    assert "### Key threats" in result.comment_markdown
    assert "### Why this matters" not in result.comment_markdown
    assert "- platform owner" in result.comment_markdown
    assert "- security owner" in result.comment_markdown
    assert "- service owner" in result.comment_markdown
    assert "- SRE owner" in result.comment_markdown
    assert "- ownership: owner: payments-owner | team: payments-platform | review: cross team | team trust: degrading" in result.comment_markdown
    assert "Block release until introduced risk is remediated or policy is adjusted" in result.comment_markdown
    assert "Run staging smoke tests for infrastructure-affecting changes" in result.comment_markdown
    assert "### What must happen next" in result.comment_markdown
    assert "### Recommended rollout" not in result.comment_markdown
    assert "Unattributed findings: 0" in result.comment_markdown
    assert result.comment_markdown.startswith("<!-- veridion:rdi:start -->\n")
    assert result.to_dict()["comment_summary"]["mode"] == "deterministic"
    assert result.to_dict()["report_diagnostics"]["attribution_trusted"] is True
    assert result.to_dict()["report_diagnostics"]["attribution_mode"] == "trusted"
    decision_contract = result.to_dict()["decision_contract"]
    assert decision_contract["schema_version"] == 1
    assert decision_contract["source"] == "veridion/action"
    assert decision_contract["contract_version_source"] == "veridion.decision_contract@1"
    assert decision_contract["decision"]["verdict"] == "NO GO"
    assert decision_contract["decision"]["gate_status"] == "block"
    assert decision_contract["decision"]["blocking_categories"] == [
        "introduced_critical_findings",
        "introduced_high_findings",
        "infrastructure_risk",
        "dependency_risk",
        "public_exposure",
        "large_blast_radius",
        "policy_max_severity_exceeded",
    ]
    assert decision_contract["actions"]["required_approvals"] == [
        "platform_owner",
        "security_owner",
        "service_owner",
        "sre_owner",
    ]
    assert decision_contract["actions"]["required_approval_labels"] == [
        "platform owner",
        "security owner",
        "service owner",
        "SRE owner",
    ]
    triggers = decision_contract["actions"]["required_approval_triggers"]
    assert "platform_owner" in triggers
    assert "security_owner" in triggers
    assert "production_iac" in triggers["platform_owner"]
    assert "dependency_changes" in triggers["security_owner"]
    assert "rollback readiness" in " ".join(decision_contract["signals"]["trust_baseline"]["elevated"])


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
    assert '"decision_contract"' in rendered
    assert '"report_diagnostics"' in rendered


def test_run_action_surfaces_suspicious_baseline_diagnostics() -> None:
    diff_lines: list[str] = []
    for index in range(30):
        diff_lines.extend(
            [
                f"diff --git a/app/file_{index}.py b/app/file_{index}.py",
                f"--- a/app/file_{index}.py",
                f"+++ b/app/file_{index}.py",
                "@@ -1 +1 @@",
                "-pass",
                "+print('changed')",
            ]
        )
    diff_lines.extend(
        [
            "diff --git a/app/routes.py b/app/routes.py",
            "--- a/app/routes.py",
            "+++ b/app/routes.py",
            "@@ -1 +1 @@",
            "-pass",
            "+danger()",
        ]
    )
    diff_text = "\n".join(diff_lines)
    current_reports = {
        "semgrep": "tests/fixtures/scanners/semgrep_report.json",
    }
    baseline_reports = {
        "semgrep": "tests/fixtures/scanners/semgrep_baseline_empty.json",
    }

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=None,
    )

    diagnostics = result.to_dict()["report_diagnostics"]
    assert diagnostics["attribution_trusted"] is False
    assert diagnostics["attribution_mode"] == "missing_baseline"
    assert diagnostics["likely_cause"] == "baseline_reports_missing_or_empty"
    assert diagnostics["zero_finding_baseline_tools"] == ["semgrep"]
    assert "### Baseline Attribution" in result.comment_markdown
    assert "### Report Health" in result.comment_markdown
    assert "- attribution mode: missing_baseline" in result.comment_markdown
    assert "- baseline tools with zero normalized findings: semgrep" in result.comment_markdown
    assert "one or more baseline scanner reports were missing or normalized to zero findings" in result.comment_markdown


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
    assert "### Recommended rollout" not in result.comment_markdown
    assert "### Why this is blocked" in result.comment_markdown
    assert "### Why this matters" not in result.comment_markdown
    assert "### Key threats" in result.comment_markdown
    assert "- platform owner" in result.comment_markdown
    assert "- security owner" in result.comment_markdown
    assert "- service owner" in result.comment_markdown
    assert "- SRE owner" in result.comment_markdown


def test_run_action_produces_go_for_clean_change_with_trusted_baseline() -> None:
    """A change with no introduced findings and a trusted baseline should GO.

    This is the baseline-comparison happy path: the same finding appears in both
    current and baseline, so it is classified as 'existing' rather than
    'introduced', and the decision is GO.
    """
    diff_text = "\n".join([
        "diff --git a/app/routes.py b/app/routes.py",
        "--- a/app/routes.py",
        "+++ b/app/routes.py",
        "@@ -1,3 +1,4 @@",
        " from flask import Flask",
        "+app = Flask(__name__)",
        " ",
        " def index():",
    ])

    result = run_action(
        diff_text=diff_text,
        current_reports={"semgrep": "tests/fixtures/scanners/semgrep_report.json"},
        baseline_reports={"semgrep": "tests/fixtures/scanners/semgrep_report.json"},
        policy_text=None,
    )

    assert result.decision.decision == "GO"
    assert result.bundle.summary.introduced_findings == 0
    assert result.bundle.summary.existing_findings >= 1
    assert result.bundle.summary.baseline_attribution_trusted is True
    assert result.bundle.summary.baseline_attribution_mode == "trusted"
    assert result.gate_status == "pass"
    assert result.decision_allowed is True
    assert result.decision.confidence == "high"
    assert result.decision.risk.confidence_ceiling_reason == ""
    assert result.to_dict()["decision_contract"]["decision"]["confidence_ceiling_reason"] == ""
    assert "### ✅ GO" in result.comment_markdown
    assert "### Required Approvals" not in result.comment_markdown
    assert "no introduced findings detected" in result.comment_markdown


def test_run_action_comment_surfaces_approvals_and_next_steps_before_reasons() -> None:
    """For NO GO decisions, approvals and next steps must appear before the reasons section.

    Engineers reading a blocked PR comment should see the unblock path immediately
    rather than having to scroll through context, reasons, and threat details first.
    """
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()
    current_reports = {
        "trivy": "tests/fixtures/scanners/trivy_report.json",
        "semgrep": "tests/fixtures/scanners/semgrep_report.json",
        "grype": "tests/fixtures/scanners/grype_report.json",
        "syft": "tests/fixtures/scanners/syft_report.json",
    }
    baseline_reports = {"semgrep": "tests/fixtures/scanners/semgrep_report.json"}
    policy_text = Path("tests/fixtures/policies/default_policy.yaml").read_text()

    result = run_action(
        diff_text=diff_text,
        current_reports=current_reports,
        baseline_reports=baseline_reports,
        policy_text=policy_text,
    )

    comment = result.comment_markdown
    assert result.decision.decision == "NO GO"
    assert "### Required Approvals" in comment
    assert "### What must happen next" in comment
    assert "### Why this is blocked" in comment
    # The unblock path must appear before the reasons section
    assert comment.index("### Required Approvals") < comment.index("### Why this is blocked")
    assert comment.index("### What must happen next") < comment.index("### Why this is blocked")
    # And approvals before next steps
    assert comment.index("### Required Approvals") < comment.index("### What must happen next")


def test_run_action_caps_confidence_when_baseline_missing_with_findings() -> None:
    """When baseline reports are absent but current findings exist, confidence is capped.

    Without a baseline we cannot verify which findings are newly introduced,
    so the system must not claim high confidence in the decision.
    """
    diff_text = "\n".join([
        "diff --git a/app/routes.py b/app/routes.py",
        "--- a/app/routes.py",
        "+++ b/app/routes.py",
        "@@ -1 +1,2 @@",
        " from flask import Flask",
        "+app = Flask(__name__)",
    ])

    result = run_action(
        diff_text=diff_text,
        current_reports={"semgrep": "tests/fixtures/scanners/semgrep_report.json"},
        baseline_reports={},
        policy_text=None,
    )

    assert result.bundle.summary.baseline_attribution_trusted is False
    assert result.bundle.summary.baseline_attribution_mode == "missing_baseline"
    assert result.bundle.summary.total_findings >= 1
    assert result.decision.confidence == "medium"
    assert result.decision.risk.confidence_ceiling_reason == "missing_baseline"
    assert "### Baseline Attribution" in result.comment_markdown
    assert "MEDIUM (limited: baseline unavailable)" in result.comment_markdown
    assert result.to_dict()["decision_contract"]["decision"]["confidence_ceiling_reason"] == "missing_baseline"


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
    assert result.bundle.summary.suppression_governance_gaps == 6
    assert result.bundle.summary.introduced_findings == 1
    assert result.bundle.summary.expired_suppressions == 0
    assert result.decision.score > initial.decision.score
    assert result.decision.score < 100
    assert result.decision.decision == "NO GO"
    assert "accepted risk suppressions: -" in "\n".join(result.decision.score_adjustments)
    assert "1 finding(s) are suppressed as accepted risk" in result.decision.reasons
    assert "policy no_go threshold triggered at score 60" in result.decision.reasons
    assert "Fill suppression owner, approval, and ticket metadata before release" in result.decision.recommendations
    assert "### Accepted Risk" in result.comment_markdown
    assert "- suppressed findings: 1" in result.comment_markdown
    assert "temporary vendor exception while upstream patch is pending (1 finding(s)) (expires 2026-12-31)" in result.comment_markdown
    assert (
        "governance gaps: approval metadata missing, created timestamp missing, exception id missing, "
        "owner missing, review timestamp missing, tracking ticket missing"
    ) in result.comment_markdown
    assert result.to_dict()["decision_contract"]["accepted_risk"]["governance_gaps"] == [
        "approval metadata missing",
        "created timestamp missing",
        "exception id missing",
        "owner missing",
        "review timestamp missing",
        "tracking ticket missing",
    ]


def test_run_action_produces_conditional_go_for_introduced_high_severity() -> None:
    """A high-severity introduced finding with a matching baseline should yield CONDITIONAL GO.

    This covers the path where:
    - semgrep appears in both current and baseline (existing, not introduced)
    - grype appears only in current (high-severity dependency finding is introduced)
    - Policy requires security_owner approval for dependency_changes
    - Score lands between no_go and conditional_go thresholds
    """
    policy_text = "\n".join([
        "max_severity: critical",
        "allow_conditional: true",
        "no_go_below_score: 60",
        "conditional_go_below_score: 85",
        "require_approval_for:",
        "  - dependency_changes",
        "require_security_owner_for:",
        "  - dependency_reputation_risk",
    ])

    result = run_action(
        diff_text="\n".join([
            "diff --git a/requirements.txt b/requirements.txt",
            "--- a/requirements.txt",
            "+++ b/requirements.txt",
            "@@ -1 +1 @@",
            "-requests==2.0.0",
            "+requests==2.31.0",
        ]),
        current_reports={
            "semgrep": "tests/fixtures/scanners/semgrep_report.json",
            "grype": "tests/fixtures/scanners/grype_report.json",
        },
        baseline_reports={
            "semgrep": "tests/fixtures/scanners/semgrep_report.json",
        },
        policy_text=policy_text,
    )

    assert result.decision.decision == "CONDITIONAL GO"
    assert result.decision.score < 85
    assert result.decision.score >= 60
    assert result.bundle.summary.introduced_findings == 1
    assert result.bundle.summary.existing_findings >= 1
    assert result.bundle.summary.baseline_attribution_trusted is True
    assert result.decision.confidence == "high"
    assert result.decision.risk.confidence_ceiling_reason == ""
    assert result.gate_status == "review"
    assert result.decision_allowed is True
    assert result.decision.required_approvals == ("security_owner",)
    assert result.decision.required_approval_triggers["security_owner"] == ("dependency_changes",)
    # Action-first layout: approvals and next steps before reasons
    comment = result.comment_markdown
    assert "### 🟡 CONDITIONAL GO" in comment
    assert "### Required Approvals" in comment
    assert "### What must happen next" in comment
    assert "### Why this needs review" in comment
    assert "### Why this is blocked" not in comment
    assert comment.index("### Required Approvals") < comment.index("### Why this needs review")
    assert comment.index("### What must happen next") < comment.index("### Why this needs review")
    assert "- security owner (required: dependency changes)" in comment
    # Decision contract
    contract = result.to_dict()["decision_contract"]
    assert contract["decision"]["verdict"] == "CONDITIONAL GO"
    assert contract["decision"]["gate_status"] == "review"
    assert contract["decision"]["confidence_ceiling_reason"] == ""
    assert contract["actions"]["required_approval_triggers"]["security_owner"] == ["dependency_changes"]


def test_run_action_bootstrap_preset_produces_valid_pipeline_decision() -> None:
    """Bootstrap-generated policy packs must be accepted by the runner pipeline.

    This test ensures that the starter preset produced by 'veridion bootstrap' wires
    through the full pipeline without error and yields a recognizable release decision.
    Any schema drift between the bootstrap output and policy engine would surface here.
    """
    files = build_bootstrap_files(
        preset="application-team",
        repo_id="acme/payments",
        service_id="payments/api",
        team_id="platform-trust",
    )
    policy_text = files[".veridion/policy.yaml"]

    result = run_action(
        diff_text="\n".join([
            "diff --git a/requirements.txt b/requirements.txt",
            "--- a/requirements.txt",
            "+++ b/requirements.txt",
            "@@ -1 +1 @@",
            "-requests==2.0.0",
            "+requests==2.31.0",
        ]),
        current_reports={
            "semgrep": "tests/fixtures/scanners/semgrep_report.json",
            "grype": "tests/fixtures/scanners/grype_report.json",
        },
        baseline_reports={
            "semgrep": "tests/fixtures/scanners/semgrep_report.json",
        },
        policy_text=policy_text,
    )

    # application-team preset has no_go_below_score=60 and max_severity=critical;
    # grype introduces a high (not critical) finding → score should land above 60
    assert result.decision.decision in {"CONDITIONAL GO", "GO"}
    assert result.decision.score >= 60
    assert result.decision.confidence in {"low", "medium", "high"}
    # Dependency approval gating is wired in the preset
    assert "security_owner" in result.decision.required_approvals
    # Decision contract is well-formed
    contract = result.to_dict()["decision_contract"]
    assert contract["schema_version"] == 1
    assert contract["decision"]["verdict"] in {"CONDITIONAL GO", "GO"}
    assert "confidence_ceiling_reason" in contract["decision"]
    assert isinstance(contract["actions"]["required_approval_triggers"], dict)
    assert result.to_dict()["comment_summary"]["mode"] == "deterministic"
