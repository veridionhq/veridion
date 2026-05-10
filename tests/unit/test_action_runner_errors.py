from pathlib import Path

import pytest

from veridion.action.runner import run_action
from veridion.context import build_operational_context_artifact


def test_run_action_wraps_report_loading_failures_with_tool_and_path() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()

    with pytest.raises(RuntimeError, match=r"failed to load trivy report from missing\.json"):
        run_action(
            diff_text=diff_text,
            current_reports={"trivy": "missing.json"},
            baseline_reports={},
            policy_text=None,
        )


def test_run_action_rejects_non_object_trust_profile_json() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()

    with pytest.raises(RuntimeError, match=r"trust profile JSON input must contain an object at the top level"):
        run_action(
            diff_text=diff_text,
            current_reports={},
            baseline_reports={},
            policy_text=None,
            trust_profile_text="[]",
        )


def test_run_action_rejects_invalid_metadata_json() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()

    with pytest.raises(RuntimeError, match=r"metadata JSON is not valid JSON"):
        run_action(
            diff_text=diff_text,
            current_reports={},
            baseline_reports={},
            policy_text=None,
            metadata_text="{",
        )


def test_run_action_rejects_invalid_trust_profile_json() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()

    with pytest.raises(RuntimeError, match=r"trust profile JSON is not valid JSON"):
        run_action(
            diff_text=diff_text,
            current_reports={},
            baseline_reports={},
            policy_text=None,
            trust_profile_text="{",
        )


def test_run_action_rejects_unsupported_trust_profile_schema_version() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()

    with pytest.raises(RuntimeError, match=r"trust profile schema_version must be 1"):
        run_action(
            diff_text=diff_text,
            current_reports={},
            baseline_reports={},
            policy_text=None,
            trust_profile_text='{"schema_version": 2}',
        )


def test_run_action_rejects_non_object_operational_context_json() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()

    with pytest.raises(RuntimeError, match=r"operational context JSON input must contain an object at the top level"):
        run_action(
            diff_text=diff_text,
            current_reports={},
            baseline_reports={},
            policy_text=None,
            operational_context_text="[]",
        )


def test_run_action_rejects_invalid_operational_context_json() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()

    with pytest.raises(RuntimeError, match=r"operational context JSON is not valid JSON"):
        run_action(
            diff_text=diff_text,
            current_reports={},
            baseline_reports={},
            policy_text=None,
            operational_context_text="{",
        )


def test_run_action_rejects_unsupported_operational_context_schema_version() -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()

    with pytest.raises(RuntimeError, match=r"operational context schema_version must be 1"):
        run_action(
            diff_text=diff_text,
            current_reports={},
            baseline_reports={},
            policy_text=None,
            operational_context_text='{"schema_version": 2}',
        )


def test_run_action_warns_when_operational_context_overrides_legacy_inputs(capsys: pytest.CaptureFixture[str]) -> None:
    diff_text = Path("tests/fixtures/diffs/sample_pr.diff").read_text()
    operational_context = build_operational_context_artifact(
        metadata_payload={"title": "feat: override"},
        trust_profile_payload={},
        source="test",
        generated_at="2026-05-10T00:00:00Z",
    )

    run_action(
        diff_text=diff_text,
        current_reports={},
        baseline_reports={},
        policy_text=None,
        operational_context_text=__import__("json").dumps(operational_context),
        metadata_text='{"title": "legacy"}',
        trust_profile_text='{"schema_version": 1}',
    )

    captured = capsys.readouterr()
    assert "operational-context-path provided; metadata-path and trust-profile-path are ignored" in captured.err
