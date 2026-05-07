from veridion.analysis import deduplicate_findings
from veridion.baseline import compare_findings_against_baseline
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def test_baseline_comparison_treats_cross_source_dedup_match_as_existing() -> None:
    baseline_findings = deduplicate_findings(
        [
            NormalizedFinding(
                source="trivy",
                finding_type="dependency",
                rule_id="CVE-2026-22222",
                title="Trivy baseline",
                severity="high",
                package_name="requests",
                package_version="2.31.0",
                references=("https://example.com/a", "https://example.com/b"),
                cvss_score=7.5,
                location=NormalizedLocation(path="requirements.txt"),
            ),
            NormalizedFinding(
                source="grype",
                finding_type="dependency",
                rule_id="CVE-2026-22222",
                title="Grype baseline",
                severity="high",
                package_name="requests",
                package_version="2.31.0",
                references=("https://example.com/a",),
                cvss_score=8.1,
                location=NormalizedLocation(path="/workspace/requirements.txt"),
            ),
        ]
    )
    current_findings = deduplicate_findings(
        [
            NormalizedFinding(
                source="trivy",
                finding_type="dependency",
                rule_id="CVE-2026-22222",
                title="Trivy current",
                severity="high",
                package_name="requests",
                package_version="2.31.0",
                references=("https://example.com/a",),
                cvss_score=7.2,
                location=NormalizedLocation(path="requirements.txt"),
            ),
            NormalizedFinding(
                source="grype",
                finding_type="dependency",
                rule_id="CVE-2026-22222",
                title="Grype current",
                severity="high",
                package_name="requests",
                package_version="2.31.0",
                references=("https://example.com/a",),
                cvss_score=9.0,
                location=NormalizedLocation(path="/workspace/requirements.txt"),
            ),
        ]
    )
    change_context = ParsedChangeContext(
        files=(
            ParsedFileChange(
                path="requirements.txt",
                change_type="modified",
                added_lines=1,
                removed_lines=1,
                signals=("dependency_manifest",),
                previous_path="requirements.txt",
            ),
        )
    )

    comparison = compare_findings_against_baseline(current_findings, baseline_findings, change_context)

    assert tuple(finding.source for finding in baseline_findings) == ("trivy",)
    assert tuple(finding.source for finding in current_findings) == ("grype",)
    assert tuple(finding.rule_id for finding in comparison.existing) == ("CVE-2026-22222",)
    assert comparison.introduced == ()
