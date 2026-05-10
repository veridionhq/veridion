from veridion.analysis import build_analysis_bundle
from veridion.attribution import PullRequestMetadata, CommitMetadata
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.context import HistoricalSignals, OwnershipSignals, RuntimeSignals, TrustBaseline
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def test_build_analysis_bundle_assembles_deterministic_summary_and_partitions() -> None:
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
            title="New issue",
            severity="high",
            location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
        ),
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2025-99999",
            title="New dependency issue",
            severity="critical",
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
    change_context = ParsedChangeContext(
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
                path="poetry.lock",
                change_type="modified",
                added_lines=1,
                removed_lines=1,
                signals=("lockfile",),
                previous_path="poetry.lock",
            ),
        )
    )

    bundle = build_analysis_bundle(current, baseline, change_context)

    assert tuple(finding.rule_id for finding in bundle.baseline_comparison.introduced) == (
        "python.audit.new",
        "CVE-2025-99999",
    )
    assert tuple(finding.rule_id for finding in bundle.baseline_comparison.existing) == ("python.audit.old",)
    assert tuple(finding.rule_id for finding in bundle.current_inventory) == ("pkg:pypi/flask@3.0.3",)
    assert bundle.summary.total_findings == 3
    assert bundle.summary.introduced_findings == 2
    assert bundle.summary.existing_findings == 1
    assert bundle.summary.unattributed_findings == 0
    assert bundle.summary.changed_files == 3
    assert bundle.summary.dependency_changes is True
    assert bundle.summary.lockfile_changes is True
    assert bundle.summary.infrastructure_changes is False
    assert bundle.summary.inventory_packages == 1
    assert bundle.summary.suppressed_findings == 0
    assert bundle.summary.expired_suppressions == 0
    assert bundle.summary.ai_change_signals == 0
    assert bundle.summary.ai_authored_commits == 0
    assert bundle.summary.historical_risk_signals == 0
    assert bundle.summary.runtime_risk_signals == 0
    assert bundle.summary.ownership_risk_signals == 0
    assert bundle.summary.trust_baseline_risk_signals == 0
    assert bundle.summary.by_severity == {
        "critical": 1,
        "high": 1,
        "medium": 1,
    }
    assert bundle.summary.introduced_by_severity == {
        "critical": 1,
        "high": 1,
    }
    assert bundle.summary.by_finding_type == {
        "code": 2,
        "dependency": 1,
    }
    assert bundle.summary.introduced_by_finding_type == {
        "code": 1,
        "dependency": 1,
    }


def test_analysis_bundle_to_dict_is_plain_and_stable() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
    )

    assert bundle.to_dict() == {
        "current_findings": [],
        "baseline_findings": [],
        "current_inventory": [],
        "baseline_inventory": [],
        "ai_attribution": {
            "detected": False,
            "signal_count": 0,
            "ai_authored_commits": 0,
            "sources": [],
            "indicators": [],
        },
        "historical_signals": {
            "repo_criticality": "",
            "service_criticality": "",
            "rollback_rate_30d": None,
            "incident_count_30d": 0,
            "change_failure_rate_30d": None,
            "flaky_service": False,
            "sensitive_repo": False,
        },
        "runtime_signals": {
            "environment": "",
            "deployment_window": "",
            "public_exposure": False,
            "blast_radius": "",
            "rollout_strategy": "",
        },
        "ownership_signals": {
            "service_owner": "",
            "owning_team": "",
            "review_coverage": "",
            "team_trust_level": "",
            "oncall_defined": False,
            "service_owner_provided": False,
            "oncall_defined_provided": False,
        },
        "trust_profile_metadata": {
            "schema_version": 0,
            "repo_id": "",
            "service_id": "",
            "team_id": "",
            "source": "",
            "generated_at": "",
            "precedence": "",
        },
        "trust_baseline": {
            "repo_stability": "",
            "service_stability": "",
            "team_deploy_safety": "",
            "test_coverage_level": "",
            "rollback_readiness": "",
            "dependency_reputation_risk": "",
        },
        "suppression_report": {
            "suppressed_findings": [],
            "suppressed_baseline_findings": 0,
            "expired_rules": 0,
        },
        "change_context": {"files": []},
        "baseline_comparison": {
            "introduced": [],
            "existing": [],
            "unattributed": [],
        },
        "summary": {
            "total_findings": 0,
            "introduced_findings": 0,
            "existing_findings": 0,
            "unattributed_findings": 0,
            "changed_files": 0,
            "dependency_changes": False,
            "lockfile_changes": False,
            "infrastructure_changes": False,
            "production_surface_changes": False,
            "public_exposure_surface_changes": False,
            "shared_platform_changes": False,
            "database_migration_changes": False,
            "payments_surface_changes": False,
            "auth_surface_changes": False,
            "data_surface_changes": False,
            "inventory_packages": 0,
            "suppressed_findings": 0,
            "expired_suppressions": 0,
            "ai_change_signals": 0,
            "ai_authored_commits": 0,
            "historical_risk_signals": 0,
            "runtime_risk_signals": 0,
            "ownership_risk_signals": 0,
            "trust_baseline_risk_signals": 0,
            "by_severity": {},
            "introduced_by_severity": {},
            "by_finding_type": {},
            "introduced_by_finding_type": {},
        },
    }


def test_build_analysis_bundle_surfaces_ai_attribution_summary() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        metadata=PullRequestMetadata(
            body="This PR was prepared with ChatGPT.",
            commits=(
                CommitMetadata(
                    message="feat: generated with Claude",
                ),
            ),
        ),
    )

    assert bundle.ai_attribution.detected is True
    assert bundle.summary.ai_change_signals == 2
    assert bundle.summary.ai_authored_commits == 1


def test_build_analysis_bundle_surfaces_historical_trust_summary() -> None:
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

    assert bundle.summary.historical_risk_signals == 7
    assert bundle.historical_signals.elevated_signals[0] == "repo criticality: high"


def test_build_analysis_bundle_surfaces_runtime_and_ownership_summary() -> None:
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

    assert bundle.summary.runtime_risk_signals == 5
    assert bundle.summary.ownership_risk_signals == 4


def test_build_analysis_bundle_surfaces_trust_baseline_summary() -> None:
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

    assert bundle.summary.trust_baseline_risk_signals == 6
    assert bundle.trust_baseline.elevated_signals[0] == "repository stability: fragile"
