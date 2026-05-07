import json
from pathlib import Path

from veridion.normalize import normalize_trivy_report


FIXTURE_PATH = Path("tests/fixtures/scanners/trivy_report.json")


def test_trivy_report_normalizes_to_unified_finding_schema() -> None:
    report = json.loads(FIXTURE_PATH.read_text())

    findings = normalize_trivy_report(report)

    assert [finding.to_dict() for finding in findings] == [
        {
            "schema_version": "1",
            "source": "trivy",
            "finding_type": "dependency",
            "rule_id": "CVE-2024-10000",
            "title": "urllib3 vulnerable to crafted request smuggling",
            "severity": "critical",
            "confidence": None,
            "description": "A crafted request can trigger unsafe proxy handling in affected versions.",
            "package_name": "urllib3",
            "package_version": "1.26.0",
            "fixed_version": "2.2.2",
            "cvss_score": None,
            "epss_score": None,
            "location": {
                "path": "requirements.txt",
                "start_line": None,
                "end_line": None,
            },
            "references": ("https://avd.aquasec.com/nvd/cve-2024-10000",),
            "categories": ("dependency",),
            "metadata": {
                "class_name": "lang-pkgs",
                "type_name": "pip",
            },
        }
    ]
