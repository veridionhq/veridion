from veridion.analysis import build_analysis_bundle
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.context import RuntimeSignals, TrustBaseline
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.risk import extract_risk_features, score_analysis_bundle


def _trusted_baseline() -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            source="semgrep",
            finding_type="code",
            rule_id="python.audit.baseline",
            title="Existing baseline issue",
            severity="low",
            location=NormalizedLocation(path="app/existing.py", start_line=1, end_line=1),
        )
    ]


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
    assert features.introduced_high_epss == 0
    assert features.changed_files == 4
    assert features.has_dependency_changes is True
    assert features.has_lockfile_changes is True
    assert features.has_infrastructure_changes is True
    assert features.public_exposure is False
    assert features.high_blast_radius is False


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


def test_score_analysis_bundle_caps_confidence_to_medium_when_baseline_missing_with_findings() -> None:
    """Confidence cannot be high when baseline is absent and findings are present.

    Without a baseline we cannot verify which findings are newly introduced,
    so claiming high confidence about the decision would be dishonest.
    """
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
    assert result.confidence == "medium"


def test_score_analysis_bundle_returns_high_confidence_when_baseline_present_and_trusted() -> None:
    """Confidence reaches high when baseline is trusted and evidence is sufficient."""
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="python.audit.new",
                title="Introduced issue",
                severity="high",
                location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
            ),
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="python.audit.existing",
                title="Existing issue",
                severity="medium",
                location=NormalizedLocation(path="app/routes.py", start_line=4, end_line=4),
            ),
        ],
        baseline_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="python.audit.existing",
                title="Existing issue",
                severity="medium",
                location=NormalizedLocation(path="app/routes.py", start_line=4, end_line=4),
            )
        ],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="app/routes.py",
                    change_type="modified",
                    added_lines=10,
                    removed_lines=1,
                    signals=("application_code",),
                    previous_path="app/routes.py",
                ),
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="modified",
                    added_lines=1,
                    removed_lines=0,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
    )

    result = score_analysis_bundle(bundle)

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
        baseline_findings=_trusted_baseline(),
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
        baseline_findings=_trusted_baseline(),
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


def test_score_analysis_bundle_applies_contextual_risk_penalties() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="python.audit.high",
                title="High issue",
                severity="high",
                location=NormalizedLocation(path="app/routes.py", start_line=12, end_line=12),
            )
        ],
        baseline_findings=_trusted_baseline(),
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
                    path="deploy/prod/service.yaml",
                    change_type="modified",
                    added_lines=1,
                    removed_lines=1,
                    signals=("production_surface", "public_exposure", "resource_limit_risk"),
                    previous_path="deploy/prod/service.yaml",
                ),
                ParsedFileChange(
                    path="k8s/deployment.yaml",
                    change_type="modified",
                    added_lines=2,
                    removed_lines=0,
                    signals=("infrastructure", "privileged_container", "direct_rollout"),
                    previous_path="k8s/deployment.yaml",
                ),
            )
        ),
        runtime_signals=RuntimeSignals(
            public_exposure=True,
            blast_radius="high",
            deployment_window="after_hours",
        ),
        trust_baseline=TrustBaseline(
            rollback_readiness="weak",
            test_coverage_level="low",
        ),
    )

    result = score_analysis_bundle(bundle)

    assert result.score == 44
    assert result.decision == "NO GO"


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


def test_extract_risk_features_counts_introduced_high_epss_findings() -> None:
    """introduced_high_epss counts only findings with EPSS >= 0.5."""
    current = [
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2026-HIGH-EPSS",
            title="Actively exploited dependency",
            severity="high",
            epss_score=0.73,
            package_name="requests",
            package_version="2.28.0",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2026-LOW-EPSS",
            title="Low exploitation probability dependency",
            severity="high",
            epss_score=0.12,
            package_name="urllib3",
            package_version="2.2.2",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2026-NO-EPSS",
            title="No EPSS data dependency",
            severity="medium",
            epss_score=None,
            package_name="boto3",
            package_version="1.34.0",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
    ]
    bundle = build_analysis_bundle(
        current_findings=current,
        baseline_findings=_trusted_baseline(),
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="modified",
                    added_lines=3,
                    removed_lines=0,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
    )

    features = extract_risk_features(bundle)

    assert features.introduced_high_epss == 1
    assert features.introduced_high == 2
    assert features.introduced_medium == 1


def test_score_analysis_bundle_applies_epss_supplement_penalty() -> None:
    """EPSS supplement adds -8 per high-EPSS finding on top of severity penalty."""
    current = [
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2026-HIGH-EPSS",
            title="Actively exploited dependency",
            severity="high",
            epss_score=0.73,
            package_name="requests",
            package_version="2.28.0",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
    ]
    bundle = build_analysis_bundle(
        current_findings=current,
        baseline_findings=_trusted_baseline(),
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="modified",
                    added_lines=1,
                    removed_lines=0,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
    )

    result = score_analysis_bundle(bundle)

    # 100 - 20 (high severity) - 8 (EPSS supplement) - 8 (dependency changes + dep finding) = 64
    assert result.score == 64
    assert result.decision == "CONDITIONAL GO"
    assert any("EPSS" in reason for reason in result.reasons)


def test_score_analysis_bundle_epss_at_threshold_is_counted() -> None:
    """EPSS score exactly 0.5 meets the threshold."""
    current = [
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2026-BOUNDARY",
            title="Boundary EPSS finding",
            severity="medium",
            epss_score=0.5,
            package_name="cryptography",
            package_version="41.0.0",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
    ]
    bundle = build_analysis_bundle(
        current_findings=current,
        baseline_findings=_trusted_baseline(),
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="modified",
                    added_lines=1,
                    removed_lines=0,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
    )

    features = extract_risk_features(bundle)

    assert features.introduced_high_epss == 1


def test_score_analysis_bundle_epss_below_threshold_not_counted() -> None:
    """EPSS score below 0.5 does not trigger the supplement penalty."""
    current = [
        NormalizedFinding(
            source="trivy",
            finding_type="dependency",
            rule_id="CVE-2026-LOW",
            title="Low EPSS finding",
            severity="high",
            epss_score=0.49,
            package_name="sqlalchemy",
            package_version="2.0.0",
            location=NormalizedLocation(path="/workspace/requirements.txt"),
        ),
    ]
    bundle = build_analysis_bundle(
        current_findings=current,
        baseline_findings=_trusted_baseline(),
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="requirements.txt",
                    change_type="modified",
                    added_lines=1,
                    removed_lines=0,
                    signals=("dependency_manifest",),
                    previous_path="requirements.txt",
                ),
            )
        ),
    )

    features = extract_risk_features(bundle)
    result = score_analysis_bundle(bundle)

    assert features.introduced_high_epss == 0
    # 100 - 20 (high severity) - 8 (dependency changes + dep finding) = 72
    assert result.score == 72
    assert not any("EPSS" in reason for reason in result.reasons)
