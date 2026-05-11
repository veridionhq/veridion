from veridion.analysis import build_analysis_bundle
from veridion.attribution import PullRequestMetadata
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.context import HistoricalSignals, OwnershipSignals, RuntimeSignals, TrustBaseline
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.policy import PolicyConfig, evaluate_release
from veridion.report import render_pr_comment
from veridion.report.pr_comment import _is_required_next_step


def test_render_pr_comment_renders_policy_decision_for_high_risk_change() -> None:
    bundle = _bundle_with_iac_and_dependency_risk()
    decision = evaluate_release(
        bundle,
        PolicyConfig(
            max_severity="critical",
            allow_conditional=True,
            no_go_below_score=60,
            conditional_go_below_score=85,
            require_approval_for=("production_iac", "dependency_changes"),
        ),
    )

    comment = render_pr_comment(bundle, decision)

    assert comment == """<!-- veridion:rdi:start -->
## Release Decision Intelligence

**Decision:** NO GO
**RDI Score:** 38
**Confidence:** HIGH

**Summary:** Introduced findings: 2 | Existing findings: 1 | Unattributed findings: 0 | Suppressed findings: 0 | Changed files: 4

### Primary Drivers

- 2 introduced high-severity finding(s)
- infrastructure changes are present in the current diff
- new dependency vulnerability findings were introduced
- policy no_go threshold triggered at score 60

### Required Approvals

- platform owner
- security owner

### Required Next Steps

- Block release until introduced risk is remediated or policy is adjusted
- Run staging smoke tests for infrastructure-affecting changes
- Review newly introduced dependencies and lockfile updates
- Prioritize remediation for introduced high-severity findings

### Introduced Severity

- high: 2

### Introduced Finding Types

- code: 1
- dependency: 1
<!-- veridion:rdi:end -->
"""


def test_render_pr_comment_handles_clean_change_without_approvals() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
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
    decision = evaluate_release(
        bundle,
        PolicyConfig(service_criticality_score_penalty=1),
    )

    comment = render_pr_comment(bundle, decision)

    assert "**Decision:** GO" in comment
    assert "**Summary:** Introduced findings: 0 | Existing findings: 0 | Unattributed findings: 0 | Suppressed findings: 0 | Changed files: 1" in comment
    assert "### Required Approvals" not in comment
    assert "- Proceed with normal review and deployment checks" in comment
    assert "### Introduced Severity" in comment
    assert "- None" in comment
    assert comment.startswith("<!-- veridion:rdi:start -->\n")
    assert comment.endswith("<!-- veridion:rdi:end -->\n")


def test_render_pr_comment_includes_ai_attribution_when_present() -> None:
    bundle_with_ai = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        metadata=PullRequestMetadata(
            body="Prepared with Cursor.",
        ),
    )
    decision = evaluate_release(bundle_with_ai)

    comment = render_pr_comment(bundle_with_ai, decision)

    assert "### AI Attribution" in comment
    assert "- AI-origin signals detected: 1" in comment
    assert "- Sources: pr_body" in comment
    assert "- Indicators: Cursor" in comment
    assert "### Primary Drivers" in comment


def test_render_pr_comment_includes_historical_trust_signals_when_present() -> None:
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
    decision = evaluate_release(
        bundle,
        PolicyConfig(service_criticality_score_penalty=1),
    )

    comment = render_pr_comment(bundle, decision)

    assert "### Historical Trust Signals" in comment
    assert "- repo criticality: high | service criticality: critical" in comment
    assert "- Historical instability: 30d rollback rate: 18% | 30d change failure rate: 22% | 30d incidents: 4" in comment
    assert "- Operational flags: service marked flaky | repository marked sensitive" in comment
    assert "### Contextual Risk" in comment
    assert "- repository criticality is high" in comment
    assert "- 30d change failure rate is elevated at 22%" in comment


def test_render_pr_comment_includes_policy_score_adjustments_when_present() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        historical_signals=HistoricalSignals(
            service_criticality="critical",
            rollback_rate_30d=0.18,
            incident_count_30d=4,
            change_failure_rate_30d=0.22,
            sensitive_repo=True,
        ),
    )
    decision = evaluate_release(
        bundle,
        PolicyConfig(
            historical_instability_score_penalty=7,
            service_criticality_score_penalty=5,
            sensitive_repo_score_penalty=3,
        ),
    )

    comment = render_pr_comment(bundle, decision)

    assert "### Policy Score Adjustments" in comment
    assert "- historical instability: -7" in comment
    assert "- service criticality: -5" in comment
    assert "- sensitive repository: -3" in comment


def test_render_pr_comment_includes_runtime_and_ownership_sections_when_present() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        runtime_signals=RuntimeSignals(
            environment="production",
            deployment_window="after_hours",
            public_exposure=True,
            blast_radius="high",
            rollout_strategy="direct",
        ),
        ownership_signals=OwnershipSignals(
            service_owner="",
            owning_team="payments-platform",
            review_coverage="cross_team",
            team_trust_level="degrading",
            oncall_defined=False,
            service_owner_provided=True,
            oncall_defined_provided=True,
        ),
    )
    decision = evaluate_release(bundle)

    comment = render_pr_comment(bundle, decision)

    assert "### Runtime Context" in comment
    assert "- deployment target: production | service is publicly exposed | blast radius: high" in comment
    assert "### Ownership Context" in comment
    assert "- service owner missing | owning team: payments-platform" in comment
    assert "- Coordination: review coverage: cross team | team trust: degrading" in comment


def test_render_pr_comment_includes_trust_baseline_section_when_present() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        trust_baseline=TrustBaseline(
            repo_stability="fragile",
            service_stability="watch",
            team_deploy_safety="degrading",
            test_coverage_level="low",
            rollback_readiness="partial",
            dependency_reputation_risk="high",
        ),
    )
    decision = evaluate_release(bundle)

    comment = render_pr_comment(bundle, decision)

    assert "### Operational Baseline" in comment
    assert "- repository stability: fragile | service stability: watch" in comment
    assert "- Execution baseline: team deploy safety: degrading | test coverage: low | rollback readiness: partial | dependency reputation risk: high" in comment


def test_render_pr_comment_truncates_verbose_sections() -> None:
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
        runtime_signals=RuntimeSignals(
            environment="production",
            deployment_window="after_hours",
            public_exposure=True,
            blast_radius="high",
            rollout_strategy="canary",
        ),
        ownership_signals=OwnershipSignals(
            service_owner="payments-owner",
            owning_team="payments-platform",
            review_coverage="cross_team",
            team_trust_level="degrading",
            oncall_defined=False,
            service_owner_provided=True,
            oncall_defined_provided=True,
        ),
        trust_baseline=TrustBaseline(
            repo_stability="watch",
            service_stability="fragile",
            team_deploy_safety="degrading",
            test_coverage_level="low",
            rollback_readiness="partial",
            dependency_reputation_risk="medium",
        ),
    )
    decision = evaluate_release(
        bundle,
        PolicyConfig(service_criticality_score_penalty=1),
    )

    comment = render_pr_comment(bundle, decision)

    assert "### Historical Trust Signals" in comment
    assert "- Operational flags: service marked flaky | repository marked sensitive" in comment
    assert "### Required Next Steps" in comment
    assert "### Advisory Guidance" in comment
    assert "### Primary Drivers" in comment
    assert "### Contextual Risk" in comment
    assert "- ... " in comment
    assert "more contextual risks" in comment
    assert "more guidance items" in comment


def test_render_pr_comment_compacts_clean_context_heavy_change() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        historical_signals=HistoricalSignals(
            repo_criticality="high",
            service_criticality="critical",
            rollback_rate_30d=0.12,
            incident_count_30d=3,
            change_failure_rate_30d=0.18,
            flaky_service=True,
            sensitive_repo=True,
        ),
        runtime_signals=RuntimeSignals(
            environment="production",
            deployment_window="after_hours",
            public_exposure=True,
            blast_radius="high",
            rollout_strategy="canary",
        ),
        ownership_signals=OwnershipSignals(
            service_owner="payments-owner",
            owning_team="payments-platform",
            review_coverage="cross_team",
            team_trust_level="degrading",
            oncall_defined=True,
            service_owner_provided=True,
            oncall_defined_provided=True,
        ),
        trust_baseline=TrustBaseline(
            repo_stability="watch",
            service_stability="fragile",
            team_deploy_safety="degrading",
            test_coverage_level="low",
            rollback_readiness="partial",
            dependency_reputation_risk="medium",
        ),
    )
    decision = evaluate_release(bundle)

    comment = render_pr_comment(bundle, decision)

    assert "### Release Context" in comment
    assert "- historical: repo criticality: high | service criticality: critical | rollback rate: 12%" in comment
    assert "- runtime: target: production | public exposure | blast radius: high" in comment
    assert "### Historical Trust Signals" not in comment
    assert "### Runtime Context" not in comment
    assert "### Ownership Context" not in comment
    assert "### Operational Baseline" not in comment
    assert "### Contextual Risk" not in comment
    assert "### Advisory Guidance" not in comment
    assert "### Required Next Steps" in comment
    assert "- Verify rollback ownership and on-call coverage before deployment" in comment


def test_required_next_step_classification_keeps_high_consequence_surface_checks_required() -> None:
    assert _is_required_next_step("Block release until introduced risk is remediated or policy is adjusted") is True
    assert _is_required_next_step("Validate migration safety and data rollback steps before deployment") is True
    assert _is_required_next_step("Verify payment-impact monitoring and rollback safeguards before release") is True
    assert _is_required_next_step("Run authentication and access-control regression checks before deployment") is True
    assert _is_required_next_step("Use heightened review for this high-criticality repository") is False


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
