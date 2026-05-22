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
    assert comparison.change_relevant == ()
    assert tuple(finding.rule_id for finding in comparison.unattributed) == ("python.audit.unrelated",)
    assert comparison.attribution_trusted is True
    assert comparison.attribution_mode == "trusted"
    assert comparison.attribution_likely_cause == ""


def test_compare_findings_against_baseline_marks_changed_file_findings_as_change_relevant_without_baseline() -> None:
    current = [
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.new",
            title="New issue",
            severity="high",
            location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
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
        )
    )

    comparison = compare_findings_against_baseline(current, [], context)

    assert comparison.introduced == ()
    assert tuple(finding.rule_id for finding in comparison.change_relevant) == ("python.audit.new",)
    assert tuple(finding.rule_id for finding in comparison.unattributed) == ("python.audit.unrelated",)
    assert comparison.attribution_trusted is False
    assert comparison.attribution_mode == "missing_baseline"
    assert comparison.attribution_likely_cause == "baseline_reports_missing_or_empty"


def test_compare_findings_against_baseline_downgrades_suspicious_present_baseline_to_change_relevant() -> None:
    baseline = [
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.baseline",
            title="Existing issue elsewhere",
            severity="low",
            location=NormalizedLocation(path="legacy/unused.py", start_line=1, end_line=1),
        )
    ]
    current = [
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.new",
            title="New issue",
            severity="high",
            location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
        ),
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.unrelated",
            title="Unrelated issue",
            severity="medium",
            location=NormalizedLocation(path="scripts/maintenance.py", start_line=8, end_line=8),
        ),
    ]
    context = ParsedChangeContext(
        files=tuple(
            ParsedFileChange(
                path=f"app/file_{index}.py",
                change_type="modified",
                added_lines=2,
                removed_lines=1,
                signals=("application_code",),
                previous_path=f"app/file_{index}.py",
            )
            for index in range(60)
        )
        + (
            ParsedFileChange(
                path="app/routes.py",
                change_type="modified",
                added_lines=2,
                removed_lines=1,
                signals=("application_code",),
                previous_path="app/routes.py",
            ),
        )
    )

    comparison = compare_findings_against_baseline(current, baseline, context)

    assert comparison.introduced == ()
    assert tuple(finding.rule_id for finding in comparison.change_relevant) == ("python.audit.new",)
    assert tuple(finding.rule_id for finding in comparison.unattributed) == ("python.audit.unrelated",)
    assert comparison.attribution_trusted is False
    assert comparison.attribution_mode == "suspicious_present_baseline"
    assert comparison.attribution_likely_cause == "base_ref_or_normalization_mismatch"
