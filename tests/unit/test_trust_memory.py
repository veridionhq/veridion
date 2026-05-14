from veridion.context import TrustMemorySignals, parse_trust_memory_signals


def test_parse_trust_memory_signals_extracts_elevated_memory_context() -> None:
    signals = parse_trust_memory_signals(
        {
            "trust_memory": {
                "recent_decisions_30d": 14,
                "conditional_go_count_30d": 6,
                "no_go_count_30d": 3,
                "policy_override_count_30d": 2,
                "accepted_risk_exception_count": 5,
                "mean_rdi_score_30d": 68,
            }
        }
    )

    assert signals == TrustMemorySignals(
        recent_decisions_30d=14,
        conditional_go_count_30d=6,
        no_go_count_30d=3,
        policy_override_count_30d=2,
        accepted_risk_exception_count=5,
        mean_rdi_score_30d=68,
    )
    assert signals.elevated_signals == (
        "recent no-go decisions: 3",
        "recent conditional-go decisions: 6",
        "policy overrides in 30d: 2",
        "accepted-risk exceptions in 30d: 5",
        "mean 30d RDI score: 68",
    )
