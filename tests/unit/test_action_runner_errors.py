from pathlib import Path

import pytest

from veridion.action.runner import run_action


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
