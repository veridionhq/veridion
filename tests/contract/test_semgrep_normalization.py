import json
from pathlib import Path

from veridion.normalize import normalize_semgrep_report


FIXTURE_PATH = Path("tests/fixtures/scanners/semgrep_report.json")


def test_semgrep_report_normalizes_to_unified_finding_schema() -> None:
    report = json.loads(FIXTURE_PATH.read_text())

    findings = normalize_semgrep_report(report)

    assert [finding.to_dict() for finding in findings] == [
        {
            "schema_version": "1",
            "source": "semgrep",
            "finding_type": "code",
            "rule_id": "python.flask.security.audit.render-template-string.render-template-string",
            "title": "Untrusted input flows into render_template_string.",
            "severity": "high",
            "confidence": "high",
            "description": "https://sg.run/abc123",
            "package_name": None,
            "package_version": None,
            "fixed_version": None,
            "cvss_score": None,
            "epss_score": None,
            "location": {
                "path": "app/routes.py",
                "start_line": 12,
                "end_line": 12,
            },
            "references": (
                "https://semgrep.dev/r/python.flask.security.audit.render-template-string.render-template-string",
                "https://sg.run/abc123",
            ),
            "categories": ("security", "python", "flask"),
            "metadata": {
                "cwe": "CWE-94: Code Injection",
                "owasp": "A03:2021 - Injection",
                "impact": "high",
                "likelihood": "medium",
                "match_sha256": "9d9d99e2dfe18034a113cca514fd690ead64b5bab4e72fa3b9299da0a73d19c3",
            },
        }
    ]
