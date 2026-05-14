from pathlib import Path

from veridion.analysis import build_analysis_bundle
from veridion.change_context import parse_unified_diff
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.context import HistoricalSignals, RuntimeSignals, TrustBaseline, derive_runtime_signals
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.policy import evaluate_release, parse_policy_yaml
from veridion.suppression import parse_suppressions_payload


DEFAULT_POLICY_PATH = Path("tests/fixtures/policies/default_policy.yaml")
STRICT_POLICY_PATH = Path("tests/fixtures/policies/strict_policy.yaml")


def test_parse_policy_yaml_builds_expected_config() -> None:
    policy = parse_policy_yaml(DEFAULT_POLICY_PATH.read_text())

    assert policy.max_severity == "critical"
    assert policy.allow_conditional is True
    assert policy.no_go_below_score == 60
    assert policy.conditional_go_below_score == 85
    assert policy.require_approval_for == ("production_iac", "dependency_changes")
    assert policy.require_platform_owner_for == (
        "production_deployment",
        "large_blast_radius",
        "weak_rollback_readiness",
        "shared_platform_surface",
        "database_migration_surface",
    )
    assert policy.require_service_owner_for == (
        "repo_criticality_high",
        "service_criticality_high",
        "low_team_trust",
        "unowned_service",
        "low_test_coverage",
        "payments_surface",
        "auth_surface",
        "data_surface",
    )
    assert policy.require_sre_owner_for == (
        "historical_instability",
        "flaky_service",
        "after_hours_deploy",
        "missing_oncall",
        "service_fragility",
        "low_team_deploy_safety",
        "shared_platform_surface",
        "database_migration_surface",
        "data_surface",
    )
    assert policy.require_security_owner_for == (
        "sensitive_repo",
        "public_exposure",
        "dependency_reputation_risk",
        "payments_surface",
        "auth_surface",
        "data_surface",
    )
    assert policy.historical_instability_score_penalty == 0
    assert policy.service_criticality_score_penalty == 0
    assert policy.sensitive_repo_score_penalty == 0
    assert policy.ai_signal_score_penalty == 0
    assert policy.ai_authored_commit_score_penalty == 0
    assert policy.production_deployment_score_penalty == 0
    assert policy.after_hours_deploy_score_penalty == 0
    assert policy.public_exposure_score_penalty == 0
    assert policy.large_blast_radius_score_penalty == 0
    assert policy.low_team_trust_score_penalty == 0
    assert policy.unowned_service_score_penalty == 0
    assert policy.missing_oncall_score_penalty == 0
    assert policy.cross_team_change_score_penalty == 0
    assert policy.repo_fragility_score_penalty == 0
    assert policy.service_fragility_score_penalty == 0
    assert policy.low_test_coverage_score_penalty == 0
    assert policy.weak_rollback_readiness_score_penalty == 0
    assert policy.dependency_reputation_risk_score_penalty == 0
    assert policy.low_team_deploy_safety_score_penalty == 0
    assert policy.shared_platform_surface_score_penalty == 0
    assert policy.database_migration_surface_score_penalty == 0
    assert policy.payments_surface_score_penalty == 0
    assert policy.auth_surface_score_penalty == 0
    assert policy.data_surface_score_penalty == 0


def test_parse_policy_yaml_rejects_invalid_require_approval_for_values() -> None:
    with __import__("pytest").raises(ValueError, match=r"require_approval_for contains unsupported value\(s\): production_lac"):
        parse_policy_yaml(
            """
require_approval_for:
  - production_lac
"""
        )


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
        runtime_signals=__import__("veridion.context", fromlist=["RuntimeSignals"]).RuntimeSignals(
            environment="production",
            deployment_window="after_hours",
            public_exposure=True,
            blast_radius="high",
            rollout_strategy="direct",
        ),
        ownership_signals=__import__("veridion.context", fromlist=["OwnershipSignals"]).OwnershipSignals(
            service_owner="",
            owning_team="payments-platform",
            review_coverage="cross_team",
            team_trust_level="degrading",
            oncall_defined=False,
            service_owner_provided=True,
            oncall_defined_provided=True,
        ),
        trust_baseline=TrustBaseline(
            repo_stability="fragile",
            service_stability="watch",
            team_deploy_safety="degrading",
            test_coverage_level="low",
            rollback_readiness="partial",
            dependency_reputation_risk="high",
        ),
    )

    decision = evaluate_release(bundle, parse_policy_yaml(DEFAULT_POLICY_PATH.read_text()))

    assert decision.decision == "CONDITIONAL GO"
    assert decision.required_approvals == ("platform_owner", "service_owner", "sre_owner", "security_owner")
    assert "release still requires explicit approvals or operational checks" in decision.reasons
    assert "repository criticality is high" in decision.reasons
    assert "service criticality is critical" in decision.reasons
    assert "30d rollback rate is elevated at 18%" in decision.reasons
    assert "30d change failure rate is elevated at 22%" in decision.reasons
    assert "service recorded 4 incidents in the last 30 days" in decision.reasons
    assert "service is marked flaky in operational metadata" in decision.reasons
    assert "repository is marked sensitive in operational metadata" in decision.reasons
    assert "deployment target is production" in decision.reasons
    assert "service is publicly exposed" in decision.reasons
    assert "blast radius is high" in decision.reasons
    assert "change requires cross-team review coverage" in decision.reasons
    assert "team trust level is degrading" in decision.reasons
    assert "on-call coverage is not defined for this service" in decision.reasons
    assert "repository stability baseline is fragile" in decision.reasons
    assert "service stability baseline is watch" in decision.reasons
    assert "team deployment safety baseline is degrading" in decision.reasons
    assert "test coverage baseline is low" in decision.reasons
    assert "rollback readiness baseline is partial" in decision.reasons
    assert "dependency reputation baseline is high risk" in decision.reasons
    assert decision.score_adjustments == ()
    assert decision.recommendations == (
        "Require approval from the platform owner",
        "Require approval from the service owner",
        "Require approval from the SRE owner",
        "Require approval from the security owner",
        "Use heightened review for this high-criticality repository",
        "Treat this change as high-impact for service operations and release planning",
        "Prefer a staged rollout or canary deployment for this historically unstable change surface",
        "Verify rollback ownership and on-call coverage before deployment",
        "Schedule deployment during staffed hours with active operational monitoring",
        "Use a staged rollout with a validated rollback plan for this production deployment",
        "Verify customer-facing monitoring and alerting before deployment",
        "Prefer canary, rolling, or blue-green rollout over a direct production release",
        "Avoid after-hours deployment until on-call coverage is defined",
        "Coordinate sign-off across owning teams before deployment",
        "Define a service owner before relying on this change path in production",
        "Use an explicit deployment checklist and reviewer sign-off for this low-trust team surface",
        "Increase manual validation for this historically fragile change surface",
        "Run targeted regression coverage because baseline test coverage is low",
        "Require and verify a rollback path before deployment",
        "Use an operator-assisted release path for this low-safety team baseline",
    )


def test_evaluate_release_downgrades_clean_go_when_release_gates_exist() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        historical_signals=HistoricalSignals(
            repo_criticality="high",
        ),
    )

    decision = evaluate_release(
        bundle,
        parse_policy_yaml(
            """
allow_conditional: true
require_service_owner_for:
  - repo_criticality_high
"""
        ),
    )

    assert decision.decision == "CONDITIONAL GO"
    assert decision.required_approvals == ("service_owner",)
    assert "release still requires explicit approvals or operational checks" in decision.reasons


def test_evaluate_release_blocks_on_live_runtime_release_gates() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        runtime_signals=RuntimeSignals(
            environment="production",
            deployment_freeze_active=True,
            active_incident=True,
            active_incident_severity="critical",
            alert_state="firing",
            rollback_viability="blocked",
        ),
    )

    decision = evaluate_release(bundle, parse_policy_yaml(DEFAULT_POLICY_PATH.read_text()))

    assert decision.decision == "NO GO"
    assert "active deployment freeze blocks this release" in decision.reasons
    assert "Confirm an explicit deployment-freeze exception before release" in decision.recommendations
    assert "Resolve the active incident before continuing this release" in decision.recommendations
    assert "Resolve firing alerts or explicitly waive them before release" in decision.recommendations
    assert "Restore rollback viability before deployment" in decision.recommendations


def test_evaluate_release_marks_degraded_runtime_readiness_as_conditional() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        runtime_signals=RuntimeSignals(
            canary_health="degraded",
            rollback_viability="unverified",
            alert_state="elevated",
        ),
    )

    decision = evaluate_release(bundle, parse_policy_yaml("allow_conditional: true\n"))

    assert decision.decision == "CONDITIONAL GO"
    assert "release still requires explicit approvals or operational checks" in decision.reasons
    assert "Stabilize degraded canary health before expanding rollout" in decision.recommendations
    assert "Verify the live rollback path is executable before deployment" in decision.recommendations
    assert "Review elevated alert state before deployment" in decision.recommendations


def test_evaluate_release_only_requires_policy_configured_metadata_approvals() -> None:
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
        parse_policy_yaml(
            """
allow_conditional: true
require_service_owner_for:
  - repo_criticality_high
require_sre_owner_for: []
require_security_owner_for: []
"""
        ),
    )

    assert decision.required_approvals == ("service_owner",)
    assert "Require approval from the service owner" in decision.recommendations


def test_evaluate_release_uses_inferred_change_surface_for_runtime_and_guidance() -> None:
    change_context = parse_unified_diff(
        """\
diff --git a/terraform/prod/payments/ingress.tf b/terraform/prod/payments/ingress.tf
--- a/terraform/prod/payments/ingress.tf
+++ b/terraform/prod/payments/ingress.tf
@@ -1 +1 @@
-enabled = false
+enabled = true
diff --git a/alembic/versions/20260508_add_index.py b/alembic/versions/20260508_add_index.py
--- a/alembic/versions/20260508_add_index.py
+++ b/alembic/versions/20260508_add_index.py
@@ -1 +1 @@
-pass
+print("migrate")
diff --git a/platform/shared/auth/gateway.py b/platform/shared/auth/gateway.py
--- a/platform/shared/auth/gateway.py
+++ b/platform/shared/auth/gateway.py
@@ -1 +1 @@
-allow = false
+allow = true
diff --git a/services/data/tenant_mapper.py b/services/data/tenant_mapper.py
--- a/services/data/tenant_mapper.py
+++ b/services/data/tenant_mapper.py
@@ -1 +1 @@
-tenant = None
+tenant = "acme"
"""
    )

    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=change_context,
        runtime_signals=derive_runtime_signals(change_context),
    )

    decision = evaluate_release(bundle)

    assert bundle.runtime_signals.environment == "production"
    assert bundle.runtime_signals.public_exposure is True
    assert bundle.runtime_signals.blast_radius == "high"
    assert "change touches a shared platform surface" in decision.reasons
    assert "change includes a database migration surface" in decision.reasons
    assert "change touches a payments-sensitive surface" in decision.reasons
    assert "change touches an authentication-sensitive surface" in decision.reasons
    assert "Coordinate staged validation for this shared platform change surface before release" in decision.recommendations


def test_evaluate_release_uses_content_aware_operational_risk_signals() -> None:
    change_context = parse_unified_diff(
        """\
diff --git a/k8s/deployment.yaml b/k8s/deployment.yaml
--- a/k8s/deployment.yaml
+++ b/k8s/deployment.yaml
@@ -1,10 +1,11 @@
-        livenessProbe:
-          httpGet:
-            path: /healthz
-        readinessProbe:
-          httpGet:
-            path: /ready
-        resources:
-          limits:
-            cpu: "500m"
+        securityContext:
+          privileged: true
+        strategy:
+          type: Recreate
diff --git a/k8s/hpa.yaml b/k8s/hpa.yaml
--- a/k8s/hpa.yaml
+++ b/k8s/hpa.yaml
@@ -1 +1 @@
-maxReplicas: 5
+maxReplicas: 20
diff --git a/terraform/prod/iam/policy.tf b/terraform/prod/iam/policy.tf
--- a/terraform/prod/iam/policy.tf
+++ b/terraform/prod/iam/policy.tf
@@ -1 +1 @@
-Action = ["s3:GetObject"]
+Action = "*"
"""
    )

    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=change_context,
        runtime_signals=derive_runtime_signals(change_context),
    )

    decision = evaluate_release(bundle)

    assert "change weakens or removes health-check coverage" in decision.reasons
    assert "change introduces direct rollout behavior" in decision.reasons
    assert "change modifies autoscaling behavior" in decision.reasons
    assert "change introduces privileged container settings" in decision.reasons
    assert "change expands IAM permissions broadly" in decision.reasons
    assert "change weakens or removes container resource limits" in decision.reasons
    assert "Verify liveness, readiness, or health-check coverage before deployment" in decision.recommendations
    assert "Avoid direct rollout settings for this change and use a staged release" in decision.recommendations
    assert "Validate autoscaling thresholds and capacity behavior before deployment" in decision.recommendations
    assert "Review privileged container settings before release" in decision.recommendations
    assert "Review broad IAM permission changes before deployment" in decision.recommendations
    assert "Restore or validate container resource limits before deployment" in decision.recommendations


def test_evaluate_release_downgrades_clean_go_when_accepted_risk_is_present() -> None:
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
        suppression_rules=parse_suppressions_payload(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "finding_type": "dependency",
                        "package_name": "urllib3",
                        "package_version": "1.25.8",
                        "reason": "temporary vendor exception while upstream patch is pending",
                        "expires_on": "2026-12-31",
                    }
                ],
            }
        ),
    )

    decision = evaluate_release(bundle, parse_policy_yaml(DEFAULT_POLICY_PATH.read_text()))

    assert decision.decision == "CONDITIONAL GO"
    assert decision.score == 96
    assert "1 finding(s) are suppressed as accepted risk" in decision.reasons
    assert decision.score_adjustments == ("accepted risk suppressions: -4",)
    assert decision.required_approvals == ("security_owner",)
    assert "Review newly introduced dependencies and lockfile updates" in decision.recommendations


def test_evaluate_release_can_block_when_policy_requires_complete_accepted_risk_metadata() -> None:
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
        suppression_rules=parse_suppressions_payload(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "finding_type": "dependency",
                        "package_name": "urllib3",
                        "package_version": "1.25.8",
                        "reason": "temporary vendor exception while upstream patch is pending",
                        "expires_on": "2026-12-31",
                    }
                ],
            }
        ),
    )

    decision = evaluate_release(
        bundle,
        parse_policy_yaml(
            DEFAULT_POLICY_PATH.read_text()
            + "\nrequire_complete_accepted_risk_metadata: true\n"
        ),
    )

    assert decision.decision == "NO GO"
    assert "policy requires complete accepted-risk governance metadata" in decision.reasons


def test_parse_policy_yaml_accepts_accepted_risk_triggers() -> None:
    policy = parse_policy_yaml(
        """
require_security_owner_for:
  - accepted_risk_present
  - accepted_risk_governance_gap
  - accepted_risk_pending_review
  - accepted_risk_renewal_pending
  - accepted_risk_expiring_soon
"""
    )

    assert policy.require_security_owner_for == (
        "accepted_risk_present",
        "accepted_risk_governance_gap",
        "accepted_risk_pending_review",
        "accepted_risk_renewal_pending",
        "accepted_risk_expiring_soon",
    )


def test_evaluate_release_can_apply_policy_to_inferred_change_surfaces() -> None:
    change_context = parse_unified_diff(
        """\
diff --git a/terraform/prod/payments/ingress.tf b/terraform/prod/payments/ingress.tf
--- a/terraform/prod/payments/ingress.tf
+++ b/terraform/prod/payments/ingress.tf
@@ -1 +1 @@
-enabled = false
+enabled = true
diff --git a/alembic/versions/20260508_add_index.py b/alembic/versions/20260508_add_index.py
--- a/alembic/versions/20260508_add_index.py
+++ b/alembic/versions/20260508_add_index.py
@@ -1 +1 @@
-pass
+print("migrate")
diff --git a/platform/shared/auth/gateway.py b/platform/shared/auth/gateway.py
--- a/platform/shared/auth/gateway.py
+++ b/platform/shared/auth/gateway.py
@@ -1 +1 @@
-allow = false
+allow = true
diff --git a/services/data/tenant_mapper.py b/services/data/tenant_mapper.py
--- a/services/data/tenant_mapper.py
+++ b/services/data/tenant_mapper.py
@@ -1 +1 @@
-tenant = None
+tenant = "acme"
"""
    )

    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=change_context,
        runtime_signals=derive_runtime_signals(change_context),
    )

    decision = evaluate_release(
        bundle,
        parse_policy_yaml(
            """
allow_conditional: true
require_platform_owner_for:
  - shared_platform_surface
  - database_migration_surface
require_service_owner_for:
  - payments_surface
  - auth_surface
require_sre_owner_for:
  - data_surface
require_security_owner_for:
  - payments_surface
  - auth_surface
shared_platform_surface_score_penalty: 4
database_migration_surface_score_penalty: 5
payments_surface_score_penalty: 6
auth_surface_score_penalty: 3
data_surface_score_penalty: 2
"""
        ),
    )

    assert decision.required_approvals == (
        "platform_owner",
        "service_owner",
        "sre_owner",
        "security_owner",
    )
    assert decision.score_adjustments == (
        "shared platform surface: -4",
        "database migration surface: -5",
        "payments-sensitive surface: -6",
        "authentication-sensitive surface: -3",
        "data-sensitive surface: -2",
    )


def test_evaluate_release_can_require_approvals_from_trust_baseline_triggers() -> None:
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

    decision = evaluate_release(
        bundle,
        parse_policy_yaml(
            """
allow_conditional: true
require_platform_owner_for:
  - repo_fragility
  - weak_rollback_readiness
require_service_owner_for:
  - low_test_coverage
require_sre_owner_for:
  - service_fragility
  - low_team_deploy_safety
require_security_owner_for:
  - dependency_reputation_risk
"""
        ),
    )

    assert decision.required_approvals == (
        "platform_owner",
        "service_owner",
        "sre_owner",
        "security_owner",
    )


def test_evaluate_release_can_apply_policy_controlled_score_penalties() -> None:
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
        parse_policy_yaml(
            """
allow_conditional: true
historical_instability_score_penalty: 7
service_criticality_score_penalty: 5
sensitive_repo_score_penalty: 3
"""
        ),
    )

    assert decision.score == 85
    assert decision.score_adjustments == (
        "historical instability: -7",
        "service criticality: -5",
        "sensitive repository: -3",
    )


def test_evaluate_release_can_apply_policy_controlled_ai_score_penalties() -> None:
    from veridion.attribution import PullRequestMetadata, CommitMetadata

    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        metadata=PullRequestMetadata(
            body="Prepared with Cursor.",
            commits=(
                CommitMetadata(
                    message="feat: generated with Claude",
                ),
            ),
        ),
    )

    decision = evaluate_release(
        bundle,
        parse_policy_yaml(
            """
allow_conditional: true
ai_signal_score_penalty: 4
ai_authored_commit_score_penalty: 6
"""
        ),
    )

    assert decision.score == 90
    assert decision.score_adjustments == (
        "AI-origin signals: -4",
        "AI-attributed commits: -6",
    )


def test_evaluate_release_can_apply_runtime_and_team_score_penalties() -> None:
    from veridion.context import OwnershipSignals, RuntimeSignals

    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        runtime_signals=RuntimeSignals(
            environment="production",
            deployment_window="after_hours",
            public_exposure=True,
            blast_radius="high",
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

    decision = evaluate_release(
        bundle,
        parse_policy_yaml(
            """
allow_conditional: true
production_deployment_score_penalty: 4
after_hours_deploy_score_penalty: 2
public_exposure_score_penalty: 3
large_blast_radius_score_penalty: 5
low_team_trust_score_penalty: 6
unowned_service_score_penalty: 4
missing_oncall_score_penalty: 3
cross_team_change_score_penalty: 2
"""
        ),
    )

    assert decision.score == 71
    assert decision.score_adjustments == (
        "production deployment: -4",
        "after-hours deployment: -2",
        "public exposure: -3",
        "large blast radius: -5",
        "low team trust: -6",
        "unowned service: -4",
        "missing on-call coverage: -3",
        "cross-team change surface: -2",
    )


def test_evaluate_release_can_apply_trust_baseline_score_penalties() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="modified",
                    added_lines=2,
                    removed_lines=1,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
        trust_baseline=TrustBaseline(
            repo_stability="fragile",
            service_stability="watch",
            team_deploy_safety="degrading",
            test_coverage_level="low",
            rollback_readiness="partial",
            dependency_reputation_risk="high",
        ),
    )

    decision = evaluate_release(
        bundle,
        parse_policy_yaml(
            """
allow_conditional: true
repo_fragility_score_penalty: 4
service_fragility_score_penalty: 3
low_test_coverage_score_penalty: 5
weak_rollback_readiness_score_penalty: 6
dependency_reputation_risk_score_penalty: 2
low_team_deploy_safety_score_penalty: 7
"""
        ),
    )

    assert decision.score == 73
    assert decision.score_adjustments == (
        "repository fragility baseline: -4",
        "service fragility baseline: -3",
        "low test coverage baseline: -5",
        "weak rollback readiness baseline: -6",
        "dependency reputation baseline: -2",
        "low team deploy safety baseline: -7",
    )


def test_evaluate_release_adds_dependency_reputation_guidance_when_dependency_surface_changes() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="modified",
                    added_lines=2,
                    removed_lines=1,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
        trust_baseline=TrustBaseline(
            dependency_reputation_risk="high",
        ),
    )

    decision = evaluate_release(bundle)

    assert "Review dependency reputation and maintenance signals before approving new packages" in decision.recommendations


def test_evaluate_release_clamps_policy_adjusted_score_at_zero() -> None:
    from veridion.context import OwnershipSignals, RuntimeSignals

    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
        runtime_signals=RuntimeSignals(
            environment="production",
            public_exposure=True,
            blast_radius="critical",
        ),
        ownership_signals=OwnershipSignals(
            service_owner="payments-owner",
            team_trust_level="low",
            oncall_defined=True,
        ),
    )

    decision = evaluate_release(
        bundle,
        parse_policy_yaml(
            """
allow_conditional: true
production_deployment_score_penalty: 60
after_hours_deploy_score_penalty: 60
public_exposure_score_penalty: 60
large_blast_radius_score_penalty: 60
low_team_trust_score_penalty: 60
"""
        ),
    )

    assert decision.score == 0


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
