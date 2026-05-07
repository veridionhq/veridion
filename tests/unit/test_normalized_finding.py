from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def test_normalized_finding_fingerprint_is_stable_for_baseline_matching() -> None:
    finding = NormalizedFinding(
        source="semgrep",
        finding_type="code",
        rule_id="python.audit.rule",
        title="Unsafe pattern",
        severity="high",
        location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
        metadata={"match_sha256": "abc123"},
    )

    assert finding.fingerprint == "1|semgrep|code|python.audit.rule||app/routes.py|abc123"


def test_normalized_finding_fingerprint_ignores_line_drift_when_match_hash_is_stable() -> None:
    first = NormalizedFinding(
        source="semgrep",
        finding_type="code",
        rule_id="python.audit.rule",
        title="Unsafe pattern",
        severity="high",
        location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
        metadata={"match_sha256": "abc123"},
    )
    shifted = NormalizedFinding(
        source="semgrep",
        finding_type="code",
        rule_id="python.audit.rule",
        title="Unsafe pattern",
        severity="high",
        location=NormalizedLocation(path="app/routes.py", start_line=22, end_line=22),
        metadata={"match_sha256": "abc123"},
    )

    assert first.fingerprint == shifted.fingerprint
