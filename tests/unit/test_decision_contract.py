import json
from datetime import date, timedelta

from veridion.analysis import build_analysis_bundle
from veridion.action.runner import _parse_allowed_decisions, _write_github_outputs, run_action
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.decision_contract import build_decision_contract, evaluate_gate
from veridion.policy import PolicyConfig, evaluate_release
from veridion.report.threats import ThreatExplanation
from veridion.suppression import parse_suppressions_payload


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


def test_parse_allowed_decisions_rejects_unknown_values() -> None:
    try:
        _parse_allowed_decisions("SHIP IT,LGTM")
    except RuntimeError as exc:
        assert "allowed-decisions contains unsupported value(s): SHIP IT, LGTM" in str(exc)
    else:
        raise AssertionError("expected unsupported allowed-decisions to fail")


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
    assert "confidence_ceiling_reason=" in content

    blocking_line = next(line for line in content.splitlines() if line.startswith("blocking_reasons_json="))
    assert json.loads(blocking_line.split("=", maxsplit=1)[1]) == []


def test_clean_go_contract_keeps_required_next_steps_empty() -> None:
    result = run_action(
        diff_text="diff --git a/README.md b/README.md\nindex 1111111..2222222 100644\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n hello\n+world\n",
        current_reports={},
        baseline_reports={},
        policy_text=None,
    )

    assert result.decision_contract["decision"]["verdict"] == "GO"
    assert result.decision_contract["actions"]["required_next_steps"] == []
    assert result.decision_contract["actions"]["advisory_guidance"] == [
        "Proceed with normal review and deployment checks"
    ]


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
    assert contract["decision_basis"]["decision_question"] == "Should this PR proceed through the release gate?"
    assert contract["decision_basis"]["action_type"] == "release_gate"
    assert contract["decision_basis"]["control_path"] == "manual review required before release"
    assert contract["evidence"]["attribution"]["mode"] == "trusted"
    assert contract["evidence"]["reports"]["current_tools"] == []


def test_decision_contract_includes_policy_evidence_and_control_basis_for_no_go() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="trivy",
                finding_type="dependency",
                rule_id="CVE-2020-1747",
                title="PyYAML incomplete fix",
                severity="critical",
                package_name="PyYAML",
                package_version="5.3.1",
                location=NormalizedLocation(path="requirements.txt"),
            )
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="modified",
                    added_lines=1,
                    removed_lines=0,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
        baseline_available=True,
    )
    decision = evaluate_release(bundle, PolicyConfig(condition_on_release_controls=False))
    contract = build_decision_contract(
        bundle=bundle,
        decision=decision,
        threats=(),
        comment_identifier="veridion:rdi",
        comment_summary={"mode": "deterministic", "provider": "none", "model": "", "error": ""},
        gate=evaluate_gate(decision.decision, allowed_decisions=("GO", "CONDITIONAL GO")),
    )

    basis = contract["decision_basis"]

    assert basis["policy_rule"] == "introduced critical dependency risk blocks release unless remediated or governed by policy"
    assert basis["evidence_quality"] == "1 introduced finding(s) were attributed to this change"
    assert basis["control_path"] == "block until remediation or approved policy change"
    assert basis["input_scope"]["introduced_findings"] == 1


def test_run_action_decision_contract_surfaces_report_health() -> None:
    result = run_action(
        diff_text="diff --git a/requirements.txt b/requirements.txt\nindex 1111111..2222222 100644\n--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-urllib3==2.2.2\n+urllib3==1.25.8\n",
        current_reports={"semgrep": "tests/fixtures/scanners/semgrep_report.json"},
        baseline_reports={"semgrep": "tests/fixtures/scanners/semgrep_baseline_empty.json"},
        policy_text=None,
    )

    evidence = result.decision_contract["evidence"]

    assert evidence["attribution"]["trusted"] is True
    assert evidence["attribution"]["mode"] == "trusted"
    assert evidence["reports"]["current_tools"] == ["semgrep"]
    assert evidence["reports"]["baseline_tools"] == ["semgrep"]
    assert evidence["reports"]["zero_finding_baseline_tools"] == ["semgrep"]
    assert evidence["reports"]["current"]["semgrep"]["normalized_findings"] > 0
    assert "sha256" in evidence["reports"]["current"]["semgrep"]


def test_run_action_decision_contract_surfaces_scan_provenance_for_recheck() -> None:
    result = run_action(
        diff_text="diff --git a/README.md b/README.md\nindex 1111111..2222222 100644\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n hello\n+world\n",
        current_reports={},
        baseline_reports={},
        policy_text=None,
        scan_metadata_text=json.dumps(
            {
                "commit_hash": "abc123",
                "commit_short": "abc123",
                "branch": "feature/deps",
                "scan_timestamp": "2026-05-27T00:00:00Z",
                "scanner_versions": {
                    "trivy": "0.69.3",
                    "grype": "0.110.0",
                    "syft": "1.20.0",
                },
            }
        ),
        recheck_only=True,
        expected_commit="abc123",
    )

    scan = result.decision_contract["evidence"]["scan"]

    assert scan["recheck_only"] is True
    assert scan["metadata"]["commit_hash"] == "abc123"
    assert scan["metadata"]["scanner_versions"]["trivy"] == "0.69.3"


def test_decision_contract_surfaces_runtime_release_gates() -> None:
    result = run_action(
        diff_text="diff --git a/README.md b/README.md\nindex 1111111..2222222 100644\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n hello\n+world\n",
        current_reports={},
        baseline_reports={},
        policy_text=None,
        operational_context_text=json.dumps(
            {
                "schema_version": 1,
                "metadata": {},
                "historical": {},
                "runtime": {
                    "environment": "production",
                    "deployment_freeze_active": True,
                    "active_incident": True,
                    "active_incident_severity": "high",
                    "alert_state": "firing",
                    "canary_health": "failing",
                    "rollback_viability": "blocked",
                },
                "ownership": {},
                "trust_baseline": {},
                "trust_profile_metadata": {},
            }
        ),
    )

    contract = result.decision_contract

    assert contract["decision"]["verdict"] == "NO GO"
    assert "deployment_freeze_active" in contract["decision"]["blocking_categories"]
    assert "active_incident" in contract["decision"]["blocking_categories"]
    assert "firing_alerts" in contract["decision"]["blocking_categories"]
    assert "runtime_rollback_blocked" in contract["decision"]["blocking_categories"]
    assert contract["signals"]["runtime"]["deployment_freeze_active"] is True
    assert contract["signals"]["runtime"]["active_incident"] is True
    assert contract["signals"]["runtime"]["active_incident_severity"] == "high"
    assert contract["signals"]["runtime"]["alert_state"] == "firing"
    assert contract["signals"]["runtime"]["canary_health"] == "failing"
    assert contract["signals"]["runtime"]["rollback_viability"] == "blocked"
    assert "deployment_freeze_active" in contract["signals"]["runtime"]["active_runtime_gates"]


def test_decision_contract_surfaces_accepted_risk_lifecycle() -> None:
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="trivy",
                finding_type="dependency",
                rule_id="CVE-2025-99999",
                title="Temporary dependency issue",
                severity="high",
                package_name="urllib3",
                package_version="1.25.8",
                location=NormalizedLocation(path="requirements.txt"),
            )
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        suppression_rules=parse_suppressions_payload(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "exception_id": "AR-300",
                        "status": "renewal_requested",
                        "finding_type": "dependency",
                        "package_name": "urllib3",
                        "package_version": "1.25.8",
                        "reason_type": "risk_reduction",
                        "reduced_severity": "medium",
                        "reason": "renewal under review",
                        "owner": "platform-security",
                        "approved_by": "security-owner",
                        "ticket": "SEC-300",
                        "created_at": "2026-05-01T00:00:00Z",
                        "reviewed_at": "2026-05-02T00:00:00Z",
                        "renewal_of": "AR-100",
                        "expires_on": tomorrow,
                    }
                ],
            }
        ),
    )
    decision = evaluate_release(bundle, PolicyConfig())
    contract = build_decision_contract(
        bundle=bundle,
        decision=decision,
        threats=(),
        comment_identifier="veridion:rdi",
        comment_summary={"mode": "deterministic", "provider": "none", "model": "", "error": ""},
        gate=evaluate_gate(decision.decision, allowed_decisions=("GO", "CONDITIONAL GO")),
    )

    accepted_risk = contract["accepted_risk"]
    assert accepted_risk["present"] is True
    assert accepted_risk["renewal_pending"] == 1
    assert accepted_risk["expiring_soon"] == 1
    assert accepted_risk["exceptions"][0]["exception_id"] == "AR-300"
    assert accepted_risk["exceptions"][0]["status"] == "renewal_requested"
    assert accepted_risk["exceptions"][0]["reason_type"] == "risk_reduction"
    assert accepted_risk["exceptions"][0]["reduced_severity"] == "medium"
    assert accepted_risk["suppressed_findings"][0]["reason_type"] == "risk_reduction"
    assert accepted_risk["suppressed_findings"][0]["reduced_severity"] == "medium"
    assert "accepted-risk renewal pending review: AR-300" in accepted_risk["lifecycle_events"]
    assert contract["automation"]["requires_exception_review"] is True


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
