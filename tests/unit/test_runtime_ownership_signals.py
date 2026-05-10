from veridion.context import (
    OwnershipSignals,
    RuntimeSignals,
    TrustBaseline,
    derive_runtime_signals,
    parse_ownership_signals,
    parse_runtime_signals,
    parse_trust_baseline,
)
from veridion.change_context import parse_unified_diff


def test_parse_runtime_signals_extracts_elevated_deployment_context() -> None:
    signals = parse_runtime_signals(
        {
            "runtime": {
                "environment": "production",
                "deployment_window": "after_hours",
                "public_exposure": True,
                "blast_radius": "high",
                "rollout_strategy": "direct",
            }
        }
    )

    assert signals == RuntimeSignals(
        environment="production",
        deployment_window="after_hours",
        public_exposure=True,
        blast_radius="high",
        rollout_strategy="direct",
    )
    assert signals.elevated_signals == (
        "deployment target: production",
        "service is publicly exposed",
        "blast radius: high",
        "deployment window: after hours",
        "rollout strategy: direct",
    )


def test_derive_runtime_signals_uses_change_surface_when_metadata_is_missing() -> None:
    context = parse_unified_diff(
        """\
diff --git a/terraform/prod/payments/ingress.tf b/terraform/prod/payments/ingress.tf
--- a/terraform/prod/payments/ingress.tf
+++ b/terraform/prod/payments/ingress.tf
@@ -1 +1 @@
-enabled = false
+enabled = true
"""
    )

    signals = derive_runtime_signals(context)

    assert signals == RuntimeSignals(
        environment="production",
        public_exposure=True,
        blast_radius="high",
    )


def test_derive_runtime_signals_preserves_explicit_metadata_over_inference() -> None:
    context = parse_unified_diff(
        """\
diff --git a/platform/shared/auth/gateway.py b/platform/shared/auth/gateway.py
--- a/platform/shared/auth/gateway.py
+++ b/platform/shared/auth/gateway.py
@@ -1 +1 @@
-allow = false
+allow = true
"""
    )

    signals = derive_runtime_signals(
        context,
        RuntimeSignals(
            environment="staging",
            public_exposure=False,
            blast_radius="medium",
            rollout_strategy="canary",
        ),
    )

    assert signals == RuntimeSignals(
        environment="staging",
        public_exposure=True,
        blast_radius="medium",
        rollout_strategy="canary",
    )


def test_parse_ownership_signals_extracts_elevated_team_context() -> None:
    signals = parse_ownership_signals(
        {
            "ownership": {
                "service_owner": "",
                "owning_team": "payments-platform",
                "review_coverage": "cross_team",
                "team_trust_level": "degrading",
                "oncall_defined": False,
            }
        }
    )

    assert signals == OwnershipSignals(
        service_owner="",
        owning_team="payments-platform",
        review_coverage="cross_team",
        team_trust_level="degrading",
        oncall_defined=False,
        service_owner_provided=True,
        oncall_defined_provided=True,
    )
    assert signals.elevated_signals == (
        "service owner missing",
        "review coverage: cross team",
        "team trust: degrading",
        "on-call coverage missing",
    )


def test_parse_ownership_signals_does_not_infer_missing_fields_from_absent_keys() -> None:
    signals = parse_ownership_signals(
        {
            "ownership": {
                "owning_team": "payments-platform",
                "review_coverage": "cross_team",
            }
        }
    )

    assert signals == OwnershipSignals(
        owning_team="payments-platform",
        review_coverage="cross_team",
        service_owner_provided=False,
        oncall_defined_provided=False,
    )
    assert signals.elevated_signals == ("review coverage: cross team",)


def test_parse_trust_baseline_extracts_elevated_posture_context() -> None:
    signals = parse_trust_baseline(
        {
            "trust_baseline": {
                "repo_stability": "fragile",
                "service_stability": "watch",
                "team_deploy_safety": "degrading",
                "test_coverage_level": "low",
                "rollback_readiness": "partial",
                "dependency_reputation_risk": "high",
            }
        }
    )

    assert signals == TrustBaseline(
        repo_stability="fragile",
        service_stability="watch",
        team_deploy_safety="degrading",
        test_coverage_level="low",
        rollback_readiness="partial",
        dependency_reputation_risk="high",
    )
    assert signals.elevated_signals == (
        "repository stability: fragile",
        "service stability: watch",
        "team deploy safety: degrading",
        "test coverage: low",
        "rollback readiness: partial",
        "dependency reputation risk: high",
    )
