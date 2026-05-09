from veridion.context import (
    OwnershipSignals,
    RuntimeSignals,
    TrustBaseline,
    parse_ownership_signals,
    parse_runtime_signals,
    parse_trust_baseline,
)


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
