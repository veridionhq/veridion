from veridion.analysis import deduplicate_findings
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def test_deduplicate_findings_collapses_equivalent_dependency_vulnerabilities() -> None:
    trivy_finding = NormalizedFinding(
        source="trivy",
        finding_type="dependency",
        rule_id="CVE-2025-99999",
        title="Trivy record",
        severity="high",
        package_name="requests",
        package_version="2.31.0",
        cvss_score=8.0,
        location=NormalizedLocation(path="requirements.txt"),
    )
    grype_finding = NormalizedFinding(
        source="grype",
        finding_type="dependency",
        rule_id="CVE-2025-99999",
        title="Grype record",
        severity="high",
        package_name="requests",
        package_version="2.31.0",
        cvss_score=8.8,
        references=("https://nvd.nist.gov/vuln/detail/CVE-2025-99999",),
        location=NormalizedLocation(path="/workspace/requirements.txt"),
    )

    deduped = deduplicate_findings([trivy_finding, grype_finding])

    assert len(deduped) == 1
    assert deduped[0].source == "grype"
