from veridion.baseline import compare_findings_against_baseline
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def test_compare_findings_against_baseline_partitions_introduced_existing_and_unattributed() -> None:
    baseline = [
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.old",
            title="Existing issue",
            severity="medium",
            location=NormalizedLocation(path="app/routes.py", start_line=4, end_line=4),
        )
    ]
    current = [
        baseline[0],
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.new",
            title="New issue",
            severity="high",
            location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
        ),
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2025-99999",
            title="New dependency issue",
            severity="critical",
            package_name="urllib3",
            package_version="2.2.2",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.unrelated",
            title="Unrelated issue",
            severity="high",
            location=NormalizedLocation(path="scripts/maintenance.py", start_line=8, end_line=8),
        ),
    ]
    context = ParsedChangeContext(
        files=(
            ParsedFileChange(
                path="app/routes.py",
                change_type="modified",
                added_lines=2,
                removed_lines=1,
                signals=("application_code",),
                previous_path="app/routes.py",
            ),
            ParsedFileChange(
                path="requirements.txt",
                change_type="added",
                added_lines=1,
                removed_lines=0,
                signals=("dependency_manifest",),
                previous_path="requirements.txt",
            ),
        )
    )

    comparison = compare_findings_against_baseline(current, baseline, context)

    assert tuple(finding.rule_id for finding in comparison.existing) == ("python.audit.old",)
    assert tuple(finding.rule_id for finding in comparison.introduced) == (
        "python.audit.new",
        "CVE-2025-99999",
    )
    assert tuple(finding.rule_id for finding in comparison.unattributed) == ("python.audit.unrelated",)
