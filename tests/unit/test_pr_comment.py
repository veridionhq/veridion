from veridion.analysis import build_analysis_bundle
from veridion.attribution import PullRequestMetadata
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.context import HistoricalSignals, OwnershipSignals, RuntimeSignals, TrustBaseline
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.policy import PolicyConfig, evaluate_release
from veridion.report import render_pr_comment, render_pr_comment_result
from veridion.report.pr_comment import _is_required_next_step
from veridion.summarization import SummarizationResult


class _StaticSummarizer:
    provider = "test"
    model_name = "stub"

    def summarize(self, summary_request):
        return SummarizationResult(
            driver_summary=("this change introduces release risk that still needs review",),
            threat_summaries=("app/main.py uses subprocess with shell=True, which can allow command injection",),
            contextual_summary=("this change also affects a production-facing path",),
        )


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

    assert comment.startswith("<!-- veridion:rdi:start -->\n## Release Decision Intelligence")
    assert "> ❌ **NO GO**" in comment
    assert "> RDI Score: 38 | Confidence: HIGH" in comment
    assert "### Why this is blocked" in comment
    assert "- this change cannot ship because it introduces high code risk in app/routes.py" in comment
    assert "- 2 new high-severity issues detected" in comment
    assert "- the change includes infrastructure updates" in comment
    assert "- the change introduces vulnerable dependencies" not in comment
    assert "### Key threats" in comment
    assert "- high code risk in app/routes.py: New code issue" in comment
    assert "- high dependency risk in requirements.txt: urllib3 2.2.2 (New dependency issue)" in comment
    assert "### Required Approvals" in comment
    assert "- platform owner" in comment
    assert "- security owner" in comment
    assert "### What must happen next" in comment
    assert "- Block release until introduced risk is remediated or policy is adjusted" in comment
    assert "### Recommended rollout" not in comment
    assert "### Why this matters" not in comment
    assert "### Introduced Severity" not in comment
    assert "### Introduced Finding Types" not in comment
    assert comment.endswith("<!-- veridion:rdi:end -->\n")


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

    assert "> ✅ **GO**" in comment
    assert "**Summary:** Introduced findings: 0 | Existing findings: 0 | Unattributed findings: 0 | Suppressed findings: 0 | Changed files: 1" in comment
    assert "### Required Approvals" not in comment
    assert "- Proceed with normal review and deployment checks" in comment
    assert "### Introduced Severity" not in comment
    assert "### Introduced Finding Types" not in comment
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

    assert "### AI Signals" not in comment
    assert "### Why this is allowed" in comment


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

    assert "### Key Context" in comment
    assert "- history: repo criticality: high | service criticality: critical | rollback rate: 18% | failure rate: 22% | incidents: 4 | flaky service | sensitive repo" in comment
    assert "### Why this matters" not in comment


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

    assert "### Key Context" in comment
    assert "- runtime: target: production | public exposure | blast radius: high | window: after hours | rollout: direct" in comment
    assert "- ownership: team: payments-platform | review: cross team | team trust: degrading" in comment


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

    assert "### Key Context" in comment
    assert "- baseline: repo stability: fragile | service stability: watch | test coverage: low | rollback: partial | dependency risk: high" in comment


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

    assert "### Key Context" in comment
    assert "### What must happen next" in comment
    assert "### Why this needs review" in comment
    assert "### Recommended rollout" not in comment


def test_render_pr_comment_surfaces_plain_english_threat_details() -> None:
    bundle = _bundle_with_iac_and_dependency_risk()
    decision = evaluate_release(bundle, PolicyConfig(allow_conditional=True))

    comment = render_pr_comment(bundle, decision)

    assert "### Key threats" in comment
    assert "- high code risk in app/routes.py: New code issue" in comment
    assert "- high dependency risk in requirements.txt: urllib3 2.2.2 (New dependency issue)" in comment


def test_render_pr_comment_can_use_optional_ai_wording_layer() -> None:
    bundle = _bundle_with_iac_and_dependency_risk()
    decision = evaluate_release(bundle, PolicyConfig(allow_conditional=True))

    comment = render_pr_comment(bundle, decision, summarizer=_StaticSummarizer())

    assert "### Key threats" in comment
    assert "- this change introduces release risk that still needs review" in comment
    assert "- app/main.py uses subprocess with shell=True, which can allow command injection" in comment
    assert "- this change also affects a production-facing path" not in comment


def test_render_pr_comment_result_exposes_deterministic_summary_trace() -> None:
    bundle = _bundle_with_iac_and_dependency_risk()
    decision = evaluate_release(bundle, PolicyConfig(allow_conditional=True))

    rendered = render_pr_comment_result(bundle, decision)

    assert rendered.summary_trace.mode == "deterministic"
    assert rendered.summary_trace.provider == "none"
    assert rendered.summary_trace.model == ""


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

    assert "### Key Context" in comment
    assert "- history: repo criticality: high | service criticality: critical | rollback rate: 12%" in comment
    assert "- runtime: target: production | public exposure | blast radius: high | window: after hours | rollout: canary" in comment
    assert "### Why this matters" not in comment
    assert "### Recommended rollout" not in comment
    assert "### What must happen next" in comment
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
