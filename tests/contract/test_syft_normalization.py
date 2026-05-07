import json
from pathlib import Path

from veridion.normalize import normalize_syft_report


FIXTURE_PATH = Path("tests/fixtures/scanners/syft_report.json")


def test_syft_report_normalizes_to_package_observations() -> None:
    report = json.loads(FIXTURE_PATH.read_text())

    findings = normalize_syft_report(report)

    assert [finding.to_dict() for finding in findings] == [
        {
            "schema_version": "1",
            "source": "syft",
            "finding_type": "package",
            "rule_id": "pkg:pypi/flask@3.0.3",
            "title": "Discovered package: flask",
            "severity": "unknown",
            "confidence": None,
            "description": None,
            "package_name": "flask",
            "package_version": "3.0.3",
            "fixed_version": None,
            "cvss_score": None,
            "epss_score": None,
            "location": {
                "path": "/workspace/requirements.txt",
                "start_line": None,
                "end_line": None,
            },
            "references": ("pkg:pypi/flask@3.0.3",),
            "categories": ("dependency", "inventory"),
            "metadata": {
                "package_type": "python",
                "language": "python",
                "license": "BSD-3-Clause",
            },
        }
    ]
