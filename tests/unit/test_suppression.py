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
                    "exception_id": "AR-123",
                    "status": "approved",
                    "rule_id": "python.lang.security.audit.dangerous-subprocess-use",
                    "reason": "accepted temporarily while refactor is in progress",
                    "owner": "platform-security",
                    "approved_by": "security-owner",
                    "ticket": "SEC-123",
                    "created_at": "2026-05-10T00:00:00Z",
                    "reviewed_at": "2026-05-10T01:00:00Z",
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
    assert report.suppressed_findings[0].exception_id == "AR-123"
    assert report.suppressed_findings[0].status == "approved"
    assert report.suppressed_findings[0].owner == "platform-security"
    assert report.suppressed_findings[0].approved_by == "security-owner"
    assert report.suppressed_findings[0].ticket == "SEC-123"
    assert report.suppressed_findings[0].created_at == "2026-05-10T00:00:00Z"
    assert report.suppressed_findings[0].reviewed_at == "2026-05-10T01:00:00Z"
    assert report.suppressed_findings[0].expires_on == "2026-12-31"
    assert report.governance_gaps == ()
    assert report.pending_review == 0
    assert report.renewal_pending == 0
    assert report.expiring_soon == 0
    assert report.exceptions[0].exception_id == "AR-123"
    assert report.exceptions[0].active is True


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


def test_parse_suppressions_payload_rejects_missing_schema_version() -> None:
    with pytest.raises(ValueError, match="suppression schema_version must be 1"):
        parse_suppressions_payload(
            {
                "suppressions": [
                    {
                        "rule_id": "CVE-2025-99999",
                        "reason": "temporary exception",
                    }
                ],
            }
        )


def test_parse_suppressions_payload_rejects_rule_without_selectors() -> None:
    with pytest.raises(ValueError, match="suppression rule must contain at least one match selector"):
        parse_suppressions_payload(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "reason": "temporary exception",
                    }
                ],
            }
        )


def test_apply_suppressions_counts_suppressed_baseline_findings() -> None:
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
                    "package_name": "urllib3",
                    "package_version": "2.2.2",
                    "finding_type": "dependency",
                    "reason": "baseline accepted risk",
                }
            ],
        }
    )

    current, baseline, report = apply_suppressions(
        current_findings=[],
        baseline_findings=[finding],
        rules=rules,
        reference_date=date(2026, 5, 10),
    )

    assert current == []
    assert baseline == []
    assert report.suppressed_baseline_findings == 1


def test_apply_suppressions_matches_path_prefix() -> None:
    finding = NormalizedFinding(
        source="semgrep",
        finding_type="code",
        rule_id="python.lang.security.audit.dangerous-subprocess-use",
        title="Dangerous subprocess use",
        severity="high",
        location=NormalizedLocation(path="app/admin/tasks.py", start_line=12, end_line=12),
    )
    rules = parse_suppressions_payload(
        {
            "schema_version": 1,
            "suppressions": [
                {
                    "path_prefix": "app/admin/",
                    "reason": "temporary admin path exception",
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
    assert report.suppressed_findings[0].reason == "temporary admin path exception"
    assert report.governance_gaps == (
        "approval metadata missing",
        "created timestamp missing",
        "exception id missing",
        "expiry missing",
        "owner missing",
        "review timestamp missing",
        "tracking ticket missing",
    )


def test_apply_suppressions_tracks_proposals_renewals_and_expiring_exceptions() -> None:
    rules = parse_suppressions_payload(
        {
            "schema_version": 1,
            "suppressions": [
                {
                    "exception_id": "AR-200",
                    "status": "proposed",
                    "rule_id": "rule.pending",
                    "reason": "proposal pending approval",
                    "owner": "platform-security",
                    "ticket": "SEC-200",
                    "created_at": "2026-05-01T00:00:00Z",
                },
                {
                    "exception_id": "AR-201",
                    "status": "renewal_requested",
                    "rule_id": "rule.renewal",
                    "reason": "renewal pending approval",
                    "owner": "platform-security",
                    "approved_by": "security-owner",
                    "ticket": "SEC-201",
                    "created_at": "2026-05-01T00:00:00Z",
                    "reviewed_at": "2026-05-02T00:00:00Z",
                    "renewal_of": "AR-101",
                    "expires_on": "2026-05-20",
                },
            ],
        }
    )

    _, _, report = apply_suppressions(
        current_findings=[],
        baseline_findings=[],
        rules=rules,
        reference_date=date(2026, 5, 10),
    )

    assert report.pending_review == 1
    assert report.renewal_pending == 1
    assert report.expiring_soon == 1
    assert report.lifecycle_events == (
        "accepted-risk proposal pending review: AR-200",
        "accepted-risk renewal pending review: AR-201",
        "accepted-risk exception expiring soon: AR-201",
    )


def test_parse_suppressions_payload_rejects_unsupported_status() -> None:
    with pytest.raises(ValueError, match="unsupported suppression status: paused"):
        parse_suppressions_payload(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "exception_id": "AR-999",
                        "status": "paused",
                        "rule_id": "CVE-2025-99999",
                        "reason": "invalid status",
                    }
                ],
            }
        )
