from veridion.context import (
    OwnershipSignals,
    RuntimeSignals,
    parse_ownership_signals,
    parse_runtime_signals,
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
    )
    assert signals.elevated_signals == (
        "service owner missing",
        "review coverage: cross team",
        "team trust: degrading",
        "on-call coverage missing",
    )
