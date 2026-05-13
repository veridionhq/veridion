from veridion.analysis import build_analysis_bundle
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.risk import extract_risk_features, score_analysis_bundle


def test_extract_risk_features_counts_introduced_findings_and_context() -> None:
    bundle = _bundle_with_high_code_and_dependency_risk()

    features = extract_risk_features(bundle)

    assert features.introduced_findings == 2
    assert features.introduced_critical == 0
    assert features.introduced_high == 2
    assert features.introduced_medium == 0
    assert features.introduced_low == 0
    assert features.introduced_code_findings == 1
    assert features.introduced_dependency_findings == 1
    assert features.changed_files == 4
    assert features.has_dependency_changes is True
    assert features.has_lockfile_changes is True
    assert features.has_infrastructure_changes is True


def test_score_analysis_bundle_returns_conditional_go_for_high_risk_changes() -> None:
    bundle = _bundle_with_high_code_and_dependency_risk()

    result = score_analysis_bundle(bundle)

    assert result.score == 38
    assert result.decision == "NO GO"
    assert result.confidence == "high"
    assert result.reasons == (
        "2 new high-severity issues detected",
        "the change includes infrastructure updates",
        "the change introduces vulnerable dependencies",
    )


def test_score_analysis_bundle_returns_go_for_clean_change() -> None:
    bundle = build_analysis_bundle(
        current_findings=[],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="app/routes.py",
                    change_type="modified",
                    added_lines=3,
                    removed_lines=1,
                    signals=("application_code",),
                    previous_path="app/routes.py",
                ),
            )
        ),
    )

    result = score_analysis_bundle(bundle)

    assert result.score == 100
    assert result.decision == "GO"
    assert result.confidence == "low"
    assert result.reasons == ("no introduced findings detected",)


def test_score_analysis_bundle_returns_high_confidence_for_well_covered_clean_run() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="python.audit.unattributed",
                title="Unattributed issue",
                severity="medium",
                location=NormalizedLocation(path="docs/reference.py", start_line=4, end_line=4),
            )
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="app/routes.py",
                    change_type="modified",
                    added_lines=3,
                    removed_lines=1,
                    signals=("application_code",),
                    previous_path="app/routes.py",
                ),
                ParsedFileChange(
                    path="README.md",
                    change_type="modified",
                    added_lines=2,
                    removed_lines=1,
                    signals=("application_code",),
                    previous_path="README.md",
                ),
            )
        ),
    )

    result = score_analysis_bundle(bundle)

    assert result.score == 100
    assert result.decision == "GO"
    assert result.confidence == "high"


def test_score_analysis_bundle_returns_no_go_for_critical_introduced_risk() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="trivy",
                finding_type="dependency",
                rule_id="CVE-2026-11111",
                title="Critical dependency issue",
                severity="critical",
                package_name="openssl",
                package_version="1.0.0",
                location=NormalizedLocation(path="/workspace/requirements.txt"),
            )
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="added",
                    added_lines=1,
                    removed_lines=0,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
    )

    result = score_analysis_bundle(bundle)

    assert result.score == 57
    assert result.decision == "NO GO"
    assert result.confidence == "high"
    assert result.reasons == (
        "1 new critical issue detected",
        "the change introduces vulnerable dependencies",
    )


def test_score_analysis_bundle_emits_reason_for_medium_findings() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="python.audit.medium",
                title="Medium issue",
                severity="medium",
                location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
            )
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(
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
        ),
    )

    result = score_analysis_bundle(bundle)

    assert "1 new medium-severity issue detected" in result.reasons


def _bundle_with_high_code_and_dependency_risk():
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
            title="New code issue",
            severity="high",
            location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
        ),
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2025-99999",
            title="New dependency issue",
            severity="high",
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
                path="terraform/prod/main.tf",
                change_type="added",
                added_lines=2,
                removed_lines=0,
                signals=("infrastructure",),
                previous_path="terraform/prod/main.tf",
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
    return build_analysis_bundle(current, baseline, change_context)
