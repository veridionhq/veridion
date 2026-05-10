from datetime import date

import pytest

from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.suppression import apply_suppressions, parse_suppressions_payload


def test_parse_suppressions_payload_and_apply_by_rule_id() -> None:
    finding = NormalizedFinding(
        source="semgrep",
        finding_type="code",
        rule_id="python.lang.security.audit.dangerous-subprocess-use",
        title="Dangerous subprocess use",
        severity="high",
        location=NormalizedLocation(path="app/main.py", start_line=12, end_line=12),
    )

    rules = parse_suppressions_payload(
        {
            "schema_version": 1,
            "suppressions": [
                {
                    "rule_id": "python.lang.security.audit.dangerous-subprocess-use",
                    "reason": "accepted temporarily while refactor is in progress",
                    "expires_on": "2026-12-31",
                }
            ],
        }
    )

    current, baseline, report = apply_suppressions(
        current_findings=[finding],
        baseline_findings=[],
        rules=rules,
        reference_date=date(2026, 5, 10),
    )

    assert current == []
    assert baseline == []
    assert report.expired_rules == 0
    assert report.suppressed_baseline_findings == 0
    assert report.suppressed_findings[0].reason == "accepted temporarily while refactor is in progress"
    assert report.suppressed_findings[0].expires_on == "2026-12-31"


def test_apply_suppressions_ignores_expired_rules() -> None:
    finding = NormalizedFinding(
        source="trivy",
        finding_type="dependency",
        rule_id="CVE-2025-99999",
        title="Temporary dependency issue",
        severity="critical",
        package_name="urllib3",
        package_version="2.2.2",
        location=NormalizedLocation(path="requirements.txt"),
    )

    rules = parse_suppressions_payload(
        {
            "schema_version": 1,
            "suppressions": [
                {
                    "rule_id": "CVE-2025-99999",
                    "package_name": "urllib3",
                    "package_version": "2.2.2",
                    "reason": "expired exception",
                    "expires_on": "2026-01-01",
                }
            ],
        }
    )

    current, baseline, report = apply_suppressions(
        current_findings=[finding],
        baseline_findings=[],
        rules=rules,
        reference_date=date(2026, 5, 10),
    )

    assert current == [finding]
    assert baseline == []
    assert report.suppressed_findings == ()
    assert report.expired_rules == 1


def test_parse_suppressions_payload_rejects_missing_reason() -> None:
    with pytest.raises(ValueError, match="suppression rule reason is required"):
        parse_suppressions_payload(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "rule_id": "CVE-2025-99999",
                    }
                ],
            }
        )
