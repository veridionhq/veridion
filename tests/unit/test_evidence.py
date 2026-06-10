import json
from pathlib import Path

from veridion.evidence import parse_evidence_payload, parse_evidence_text
from veridion.evidence.catalog import evidence_catalog
from veridion.evidence.producer import validate_evidence_against_producer, validate_producer_manifest
from veridion.evidence.translate import (
    ingest_evidence,
    main,
    translate_github_checks,
    translate_junit_xml,
    validate_evidence_files,
)


def test_parse_evidence_bundle_applies_bundle_subject() -> None:
    evidence = parse_evidence_payload(
        {
            "schema_version": 1,
            "subject": {
                "repo": "acme/payments-api",
                "commit": "abc123",
            },
            "evidence": [
                {
                    "evidence_type": "test_result",
                    "category": "test",
                    "name": "checkout e2e",
                    "status": "failed",
                    "severity": "high",
                    "required": True,
                    "source": {"provider": "github_actions", "run_id": "123"},
                    "summary": "Checkout flow failed",
                }
            ],
        }
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.evidence_id == "github_actions:test_result:checkout e2e"
    assert item.is_blocking is True
    assert item.requires_review is False
    assert item.subject["repo"] == "acme/payments-api"
    assert item.source["provider"] == "github_actions"


def test_parse_evidence_text_accepts_single_evidence_item() -> None:
    evidence = parse_evidence_text(
        json.dumps(
            {
                "evidence_type": "runtime_signal",
                "name": "canary health",
                "status": "degraded",
                "required": True,
            }
        )
    )

    assert evidence[0].requires_review is True
    assert evidence[0].category == "release_readiness"
    assert evidence[0].severity == "info"


def test_parse_evidence_rejects_unknown_status() -> None:
    try:
        parse_evidence_payload(
            {
                "evidence_type": "test_result",
                "name": "unit tests",
                "status": "maybe",
            }
        )
    except RuntimeError as exc:
        assert "unsupported evidence status" in str(exc)
    else:
        raise AssertionError("expected unknown evidence status to fail")


def test_translate_junit_xml_outputs_required_failed_test_evidence(tmp_path) -> None:
    junit_path = tmp_path / "junit.xml"
    junit_path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="checkout" tests="3" failures="1" errors="0" skipped="1">
    <testcase classname="CheckoutTest" name="test_success" />
    <testcase classname="CheckoutTest" name="test_failure">
      <failure message="expected success" />
    </testcase>
    <testcase classname="CheckoutTest" name="test_skip">
      <skipped />
    </testcase>
  </testsuite>
</testsuites>
"""
    )

    payload = translate_junit_xml(
        paths=(junit_path,),
        subject={"repo": "acme/payments-api", "commit": "abc123"},
        name="checkout e2e",
        required=True,
    )
    evidence = parse_evidence_payload(payload)

    assert evidence[0].evidence_type == "test_result"
    assert evidence[0].status == "failed"
    assert evidence[0].severity == "high"
    assert evidence[0].required is True
    assert evidence[0].is_blocking is True
    assert evidence[0].attributes["tests"] == 3
    assert evidence[0].attributes["failures"] == 1


def test_translate_github_checks_maps_pending_required_checks_to_review() -> None:
    payload = translate_github_checks(
        payload={
            "check_runs": [
                {"name": "unit", "status": "completed", "conclusion": "success"},
                {"name": "load", "status": "in_progress", "conclusion": None},
            ]
        },
        subject={"repo": "acme/payments-api"},
        name="required checks",
        required=True,
    )
    evidence = parse_evidence_payload(payload)

    assert evidence[0].evidence_type == "ci_check"
    assert evidence[0].status == "unknown"
    assert evidence[0].requires_review is True
    assert evidence[0].attributes["check_run_count"] == 2


def test_evidence_translate_cli_writes_native_evidence_json(tmp_path) -> None:
    junit_path = tmp_path / "junit.xml"
    output_path = tmp_path / "veridion-evidence.json"
    junit_path.write_text('<testsuite name="unit" tests="1" failures="0" errors="0" skipped="0" />')

    exit_code = main(
        [
            "translate",
            "junit",
            "--input",
            str(junit_path),
            "--output",
            str(output_path),
            "--required",
            "--repo",
            "acme/payments-api",
            "--commit",
            "abc123",
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    evidence = parse_evidence_payload(payload)
    assert evidence[0].status == "passed"
    assert evidence[0].subject["repo"] == "acme/payments-api"
    assert evidence[0].subject["commit"] == "abc123"


def test_validate_evidence_files_returns_contract_summary(tmp_path) -> None:
    evidence_path = tmp_path / "veridion-evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "evidence": [
                    {
                        "evidence_type": "test_result",
                        "name": "checkout e2e",
                        "status": "failed",
                        "required": True,
                    },
                    {
                        "evidence_type": "runtime_signal",
                        "name": "canary health",
                        "status": "degraded",
                        "required": True,
                    },
                ],
            }
        )
    )

    summary = validate_evidence_files((evidence_path,))

    assert summary == {
        "valid": True,
        "files": 1,
        "evidence_items": 2,
        "blocking_required": 1,
        "review_required": 1,
        "by_status": {
            "degraded": 1,
            "failed": 1,
        },
        "by_type": {
            "runtime_signal": 1,
            "test_result": 1,
        },
    }


def test_evidence_validate_cli_rejects_invalid_evidence_json(tmp_path) -> None:
    evidence_path = tmp_path / "veridion-evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "evidence_type": "test_result",
                "name": "unit tests",
                "status": "maybe",
            }
        )
    )

    try:
        main(["validate", "--input", str(evidence_path)])
    except RuntimeError as exc:
        assert "unsupported evidence status" in str(exc)
    else:
        raise AssertionError("expected invalid evidence to fail validation")


def test_evidence_catalog_defines_release_signal_meanings() -> None:
    catalog = evidence_catalog()

    assert catalog["schema_version"] == 1
    assert catalog["statuses"]["failed"]["decision_effect_when_required"] == "block"
    assert catalog["statuses"]["missing"]["decision_effect_when_required"] == "review"
    assert catalog["statuses"]["passed"]["decision_effect_when_required"] == "none"
    assert catalog["evidence_types"]["test_result"]["category"] == "test"
    assert catalog["evidence_types"]["runtime_signal"]["category"] == "runtime"


def test_evidence_catalog_cli_writes_json(tmp_path) -> None:
    output_path = tmp_path / "evidence-catalog.json"

    exit_code = main(["catalog", "--output", str(output_path)])

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    assert payload["statuses"]["unsatisfied"]["decision_effect_when_required"] == "block"
    assert payload["evidence_types"]["approval_state"]["category"] == "approval"


def test_validate_producer_manifest_accepts_supported_signal_vocabulary() -> None:
    summary = validate_producer_manifest(
        {
            "schema_version": 1,
            "producer": {
                "id": "github-actions",
                "display_name": "GitHub Actions",
                "version": "1.0.0",
                "owner": "platform",
            },
            "emits": [
                {
                    "evidence_type": "test_result",
                    "statuses": ["passed", "failed", "skipped"],
                    "subject_keys": ["repo", "commit", "pull_request"],
                },
                {
                    "evidence_type": "ci_check",
                    "statuses": ["passed", "failed", "unknown"],
                    "subject_keys": ["repo", "commit"],
                },
            ],
        }
    )

    assert summary == {
        "valid": True,
        "producer_id": "github-actions",
        "display_name": "GitHub Actions",
        "emits": 2,
        "evidence_types": ["ci_check", "test_result"],
        "statuses": ["failed", "passed", "skipped", "unknown"],
    }


def test_validate_producer_manifest_rejects_unsupported_vocabulary() -> None:
    try:
        validate_producer_manifest(
            {
                "schema_version": 1,
                "producer": {
                    "id": "internal-release-system",
                    "display_name": "Internal Release System",
                },
                "emits": [
                    {
                        "evidence_type": "vibes",
                        "statuses": ["looks_good"],
                    }
                ],
            }
        )
    except RuntimeError as exc:
        assert "unsupported evidence_type" in str(exc)
    else:
        raise AssertionError("expected unsupported producer vocabulary to fail")


def test_validate_producer_cli_reads_manifest_file(tmp_path) -> None:
    manifest_path = tmp_path / "producer.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "producer": {
                    "id": "datadog",
                    "display_name": "Datadog",
                },
                "emits": [
                    {
                        "evidence_type": "runtime_signal",
                        "statuses": ["healthy", "degraded", "unhealthy"],
                    }
                ],
            }
        )
    )

    assert main(["validate-producer", "--input", str(manifest_path), "--summary"]) == 0


def test_evidence_conformance_rejects_undeclared_status() -> None:
    evidence = parse_evidence_payload(
        {
            "evidence_type": "test_result",
            "name": "checkout e2e",
            "status": "failed",
            "required": True,
        }
    )

    try:
        validate_evidence_against_producer(
            evidence,
            {
                "schema_version": 1,
                "producer": {
                    "id": "junit",
                    "display_name": "JUnit",
                },
                "emits": [
                    {
                        "evidence_type": "test_result",
                        "statuses": ["passed"],
                    }
                ],
            },
        )
    except RuntimeError as exc:
        assert "producer emitted undeclared evidence signal" in str(exc)
    else:
        raise AssertionError("expected undeclared evidence status to fail conformance")


def test_evidence_conformance_enforces_subject_keys() -> None:
    evidence = parse_evidence_payload(
        {
            "evidence_type": "test_result",
            "name": "checkout e2e",
            "status": "passed",
            "subject": {
                "repo": "acme/payments-api",
            },
        }
    )

    try:
        validate_evidence_against_producer(
            evidence,
            {
                "schema_version": 1,
                "producer": {
                    "id": "junit",
                    "display_name": "JUnit",
                },
                "emits": [
                    {
                        "evidence_type": "test_result",
                        "statuses": ["passed", "failed"],
                        "subject_keys": ["repo", "commit"],
                    }
                ],
            },
        )
    except RuntimeError as exc:
        assert "missing required subject key(s): commit" in str(exc)
    else:
        raise AssertionError("expected missing subject key to fail conformance")


def test_ingest_evidence_translates_validates_and_checks_conformance(tmp_path) -> None:
    manifest_path = tmp_path / "producer.json"
    junit_path = tmp_path / "junit.xml"
    output_path = tmp_path / "veridion-evidence.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "producer": {
                    "id": "junit",
                    "display_name": "JUnit",
                },
                "emits": [
                    {
                        "evidence_type": "test_result",
                        "statuses": ["passed", "failed", "skipped", "unknown"],
                    }
                ],
            }
        )
    )
    junit_path.write_text('<testsuite name="unit" tests="1" failures="0" errors="0" skipped="0" />')

    summary = ingest_evidence(
        producer_path=manifest_path,
        source_format="junit",
        input_paths=(junit_path,),
        output_path=output_path,
        subject={"repo": "acme/payments-api", "commit": "abc123"},
        name="unit tests",
        required=True,
    )

    assert summary["valid"] is True
    assert summary["producer"]["producer_id"] == "junit"
    assert summary["evidence"]["evidence_items"] == 1
    assert summary["conformance"]["evidence_items"] == 1
    evidence = parse_evidence_text(output_path.read_text())
    assert evidence[0].status == "passed"
    assert evidence[0].subject["commit"] == "abc123"


def test_ingest_cli_runs_full_lifecycle(tmp_path) -> None:
    manifest_path = tmp_path / "producer.json"
    junit_path = tmp_path / "junit.xml"
    output_path = tmp_path / "veridion-evidence.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "producer": {
                    "id": "junit",
                    "display_name": "JUnit",
                },
                "emits": [
                    {
                        "evidence_type": "test_result",
                        "statuses": ["passed", "failed", "skipped", "unknown"],
                    }
                ],
            }
        )
    )
    junit_path.write_text('<testsuite name="unit" tests="0" failures="0" errors="0" skipped="0" />')

    exit_code = main(
        [
            "ingest",
            "--producer",
            str(manifest_path),
            "--format",
            "junit",
            "--input",
            str(junit_path),
            "--output",
            str(output_path),
            "--required",
            "--summary",
        ]
    )

    assert exit_code == 0
    assert parse_evidence_text(output_path.read_text())[0].status == "unknown"


def test_example_producer_manifests_are_valid() -> None:
    paths = tuple(sorted(Path("examples/evidence/producers").glob("*.json")))

    assert paths
    summaries = [validate_producer_manifest(json.loads(path.read_text())) for path in paths]
    assert {summary["producer_id"] for summary in summaries} == {
        "datadog-runtime",
        "github-checks",
        "junit",
        "pagerduty-incidents",
    }
