from veridion.analysis import build_analysis_bundle
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.normalize.models import NormalizedFinding, NormalizedLocation


def test_build_analysis_bundle_assembles_deterministic_summary_and_partitions() -> None:
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
            source="syft",
            finding_type="package",
            rule_id="pkg:pypi/flask@3.0.3",
            title="Discovered package: flask",
            severity="unknown",
            package_name="flask",
            package_version="3.0.3",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
    ]
    change_context = ParsedChangeContext(
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
            ParsedFileChange(
                path="poetry.lock",
                change_type="modified",
                added_lines=1,
                removed_lines=1,
                signals=("lockfile",),
                previous_path="poetry.lock",
            ),
        )
    )

    bundle = build_analysis_bundle(current, baseline, change_context)

    assert tuple(finding.rule_id for finding in bundle.baseline_comparison.introduced) == (
        "python.audit.new",
        "CVE-2025-99999",
    )
    assert tuple(finding.rule_id for finding in bundle.baseline_comparison.existing) == ("python.audit.old",)
    assert tuple(finding.rule_id for finding in bundle.current_inventory) == ("pkg:pypi/flask@3.0.3",)
    assert bundle.summary.total_findings == 3
    assert bundle.summary.introduced_findings == 2
    assert bundle.summary.existing_findings == 1
    assert bundle.summary.unattributed_findings == 0
    assert bundle.summary.changed_files == 3
    assert bundle.summary.dependency_changes is True
    assert bundle.summary.lockfile_changes is True
    assert bundle.summary.infrastructure_changes is False
    assert bundle.summary.inventory_packages == 1
    assert bundle.summary.by_severity == {
        "critical": 1,
        "high": 1,
        "medium": 1,
    }
    assert bundle.summary.introduced_by_severity == {
        "critical": 1,
        "high": 1,
    }
    assert bundle.summary.by_finding_type == {
        "code": 2,
        "dependency": 1,
    }
    assert bundle.summary.introduced_by_finding_type == {
        "code": 1,
        "dependency": 1,
    }


def test_analysis_bundle_to_dict_is_plain_and_stable() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(files=()),
    )

    assert bundle.to_dict() == {
        "current_findings": [],
        "baseline_findings": [],
        "current_inventory": [],
        "baseline_inventory": [],
        "change_context": {"files": []},
        "baseline_comparison": {
            "introduced": [],
            "existing": [],
            "unattributed": [],
        },
        "summary": {
            "total_findings": 0,
            "introduced_findings": 0,
            "existing_findings": 0,
            "unattributed_findings": 0,
            "changed_files": 0,
            "dependency_changes": False,
            "lockfile_changes": False,
            "infrastructure_changes": False,
            "inventory_packages": 0,
            "by_severity": {},
            "introduced_by_severity": {},
            "by_finding_type": {},
            "introduced_by_finding_type": {},
        },
    }
