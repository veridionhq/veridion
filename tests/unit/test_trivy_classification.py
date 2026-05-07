from veridion.normalize.trivy import normalize_trivy_report


def test_trivy_does_not_treat_plain_yaml_or_json_as_infrastructure_without_iac_path_hints() -> None:
    report = {
        "Results": [
            {
                "Target": "config/app_config.yaml",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-20001",
                        "Title": "Example issue",
                        "Severity": "HIGH",
                    }
                ],
            },
            {
                "Target": "config/schema.json",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-20002",
                        "Title": "Example issue",
                        "Severity": "HIGH",
                    }
                ],
            },
        ]
    }

    findings = normalize_trivy_report(report)

    assert tuple(finding.finding_type for finding in findings) == ("dependency", "dependency")
