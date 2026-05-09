from pathlib import Path

from veridion.analysis import build_analysis_bundle
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.context import HistoricalSignals
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.policy import evaluate_release, parse_policy_yaml


DEFAULT_POLICY_PATH = Path("tests/fixtures/policies/default_policy.yaml")
STRICT_POLICY_PATH = Path("tests/fixtures/policies/strict_policy.yaml")


def test_parse_policy_yaml_builds_expected_config() -> None:
    policy = parse_policy_yaml(DEFAULT_POLICY_PATH.read_text())

    assert policy.max_severity == "critical"
    assert policy.allow_conditional is True
    assert policy.no_go_below_score == 60
    assert policy.conditional_go_below_score == 85
    assert policy.require_approval_for == ("production_iac", "dependency_changes")


def test_evaluate_release_applies_required_approvals_and_recommendations() -> None:
    bundle = _bundle_with_iac_and_dependency_risk()
    policy = parse_policy_yaml(DEFAULT_POLICY_PATH.read_text())

    decision = evaluate_release(bundle, policy)

    assert decision.score == 38
    assert decision.decision == "NO GO"
    assert decision.confidence == "high"
    assert decision.required_approvals == ("platform_owner", "security_owner")
    assert "policy no_go threshold triggered at score 60" in decision.reasons
    assert decision.recommendations == (
        "Block release until introduced risk is remediated or policy is adjusted",
        "Require approval from the platform owner",
        "Require approval from the security owner",
        "Run staging smoke tests for infrastructure-affecting changes",
        "Review newly introduced dependencies and lockfile updates",
        "Prioritize remediation for introduced high-severity findings",
    )


def test_evaluate_release_escalates_conditional_go_when_policy_disallows_it() -> None:
    bundle = _bundle_with_single_high_code_issue()
    policy = parse_policy_yaml(STRICT_POLICY_PATH.read_text())

    decision = evaluate_release(bundle, policy)

    assert decision.score == 80
    assert decision.decision == "NO GO"
    assert "policy does not allow conditional releases" in decision.reasons


def test_evaluate_release_blocks_when_max_severity_policy_is_exceeded() -> None:
    bundle = _bundle_with_single_high_code_issue()
    policy = parse_policy_yaml("max_severity: high\nallow_conditional: true\n")

    decision = evaluate_release(bundle, policy)

    assert decision.decision == "NO GO"
    assert "policy max_severity exceeded by introduced high finding(s)" in decision.reasons


def test_evaluate_release_adds_advisory_recommendations_for_historical_trust_signals() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        historical_signals=HistoricalSignals(
            repo_criticality="high",
            service_criticality="critical",
            rollback_rate_30d=0.18,
            incident_count_30d=4,
            change_failure_rate_30d=0.22,
            flaky_service=True,
            sensitive_repo=True,
        ),
    )

    decision = evaluate_release(bundle)

    assert decision.decision == "GO"
    assert decision.required_approvals == ("service_owner", "sre_owner", "security_owner")
    assert decision.recommendations == (
        "Require approval from the service owner",
        "Require approval from the SRE owner",
        "Require approval from the security owner",
        "Use heightened review for this high-criticality repository",
        "Treat this change as high-impact for service operations and release planning",
        "Prefer a staged rollout or canary deployment for this historically unstable change surface",
        "Verify rollback ownership and on-call coverage before deployment",
        "Schedule deployment during staffed hours with active operational monitoring",
    )


def _bundle_with_iac_and_dependency_risk():
    baseline = [
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.old",
            title="Existing issue",
            severity="medium",
            location=NormalizedLocation(path="app/routes.py", start_line=4, end_line=4),
        )
    ]
    current = [
        baseline[0],
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.new",
            title="New code issue",
            severity="high",
            location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
        ),
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2025-99999",
            title="New dependency issue",
            severity="high",
            package_name="urllib3",
            package_version="2.2.2",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
        NormalizedFinding(
            source="syft",
            finding_type="package",
            rule_id="pkg:pypi/flask@3.0.3",
            title="Discovered package: flask",
            severity="unknown",
            package_name="flask",
            package_version="3.0.3",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
    ]
    return build_analysis_bundle(
        current_findings=current,
        baseline_findings=baseline,
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="app/routes.py",
                    change_type="modified",
                    added_lines=2,
                    removed_lines=1,
                    signals=("application_code",),
                    previous_path="app/routes.py",
                ),
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="added",
                    added_lines=1,
                    removed_lines=0,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
                ParsedFileChange(
                    path="terraform/prod/main.tf",
                    change_type="added",
                    added_lines=2,
                    removed_lines=0,
                    signals=("infrastructure",),
                    previous_path="terraform/prod/main.tf",
                ),
                ParsedFileChange(
                    path="poetry.lock",
                    change_type="modified",
                    added_lines=1,
                    removed_lines=1,
                    signals=("lockfile",),
                    previous_path="poetry.lock",
                ),
            )
        ),
    )


def _bundle_with_single_high_code_issue():
    return build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="python.audit.new",
                title="New code issue",
                severity="high",
                location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
            )
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="app/routes.py",
                    change_type="modified",
                    added_lines=2,
                    removed_lines=1,
                    signals=("application_code",),
                    previous_path="app/routes.py",
                ),
            )
        ),
    )
