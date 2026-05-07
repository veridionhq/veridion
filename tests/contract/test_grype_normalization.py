import json
from pathlib import Path

from veridion.normalize import normalize_grype_report


FIXTURE_PATH = Path("tests/fixtures/scanners/grype_report.json")


def test_grype_report_normalizes_to_unified_finding_schema() -> None:
    report = json.loads(FIXTURE_PATH.read_text())

    findings = normalize_grype_report(report)

    assert [finding.to_dict() for finding in findings] == [
        {
            "schema_version": "1",
            "source": "grype",
            "finding_type": "dependency",
            "rule_id": "CVE-2025-20001",
            "title": "Requests vulnerable to header confusion in specific proxy chains.",
            "severity": "high",
            "confidence": None,
            "description": "https://grype.example/db/vulnerability/CVE-2025-20001",
            "package_name": "requests",
            "package_version": "2.31.0",
            "fixed_version": "2.32.3",
            "cvss_score": 8.8,
            "epss_score": 0.42,
            "location": {
                "path": "/workspace/requirements.txt",
                "start_line": None,
                "end_line": None,
            },
            "references": ("https://nvd.nist.gov/vuln/detail/CVE-2025-20001",),
            "categories": ("dependency",),
            "metadata": {
                "package_type": "python",
                "purl": "pkg:pypi/requests@2.31.0",
                "namespace": "nvd:cpe",
            },
        }
    ]
