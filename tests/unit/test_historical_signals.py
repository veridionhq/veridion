from veridion.context import HistoricalSignals, parse_historical_signals


def test_parse_historical_signals_extracts_elevated_operational_context() -> None:
    signals = parse_historical_signals(
        {
            "historical": {
                "repo_criticality": "high",
                "service_criticality": "critical",
                "rollback_rate_30d": 0.18,
                "incident_count_30d": 4,
                "change_failure_rate_30d": 0.22,
                "flaky_service": True,
                "sensitive_repo": True,
            }
        }
    )

    assert signals.repo_criticality == "high"
    assert signals.service_criticality == "critical"
    assert signals.rollback_rate_30d == 0.18
    assert signals.incident_count_30d == 4
    assert signals.change_failure_rate_30d == 0.22
    assert signals.flaky_service is True
    assert signals.sensitive_repo is True
    assert signals.elevated_signals == (
        "repo criticality: high",
        "service criticality: critical",
        "30d rollback rate: 18%",
        "30d change failure rate: 22%",
        "30d incidents: 4",
        "service marked flaky",
        "repository marked sensitive",
    )


def test_parse_historical_signals_defaults_when_payload_is_missing() -> None:
    signals = parse_historical_signals({})

    assert signals == HistoricalSignals()
    assert signals.elevated_signals == ()
