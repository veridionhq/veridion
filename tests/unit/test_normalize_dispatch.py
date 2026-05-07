import json
from pathlib import Path

import pytest

from veridion.normalize import normalize_report


def test_normalize_report_dispatches_by_tool_name() -> None:
    report = json.loads(Path("tests/fixtures/scanners/trivy_report.json").read_text())

    findings = normalize_report("trivy", report)

    assert len(findings) == 1
    assert findings[0].source == "trivy"


def test_normalize_report_rejects_unknown_tools() -> None:
    with pytest.raises(ValueError, match="unsupported normalization tool"):
        normalize_report("unknown-tool", {})
