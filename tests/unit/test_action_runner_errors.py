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
