from veridion.analysis import build_analysis_bundle
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.report.threats import ThreatExplanation, explain_introduced_threats, render_threat_line


def test_explain_introduced_threats_returns_structured_dependency_and_code_facts() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="python.lang.security.audit.dangerous-subprocess-use",
                title="Found 'subprocess' function 'run' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process.",
                severity="high",
                location=NormalizedLocation(path="app/main.py", start_line=12, end_line=12),
            ),
            NormalizedFinding(
                source="trivy",
                finding_type="dependency",
                rule_id="CVE-2026-12345",
                title="Improper Input Validation in PyYAML",
                severity="critical",
                package_name="pyyaml",
                package_version="5.3.1",
                location=NormalizedLocation(path="/workspace/requirements.txt"),
            ),
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="app/main.py",
                    change_type="modified",
                    added_lines=1,
                    removed_lines=0,
                    signals=("application_code",),
                    previous_path="app/main.py",
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

    threats = explain_introduced_threats(bundle)

    assert len(threats) == 2
    assert threats[0].severity == "critical"
    assert threats[0].threat_type == "dependency"
    assert threats[0].subject == "pyyaml 5.3.1"
    assert threats[0].location == "requirements.txt"
    assert threats[0].why_not_safe == "the change introduces vulnerable package versions"
    assert render_threat_line(threats[0]) == (
        "critical dependency risk in requirements.txt: pyyaml 5.3.1 (Improper Input Validation in PyYAML)"
    )
    assert threats[1].summary == "uses subprocess with shell=True"
    assert threats[1].why_not_safe == "shell execution can allow command injection or unsafe command expansion"


def test_explain_introduced_threats_groups_duplicate_dependency_advisories() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="trivy",
                finding_type="dependency",
                rule_id="CVE-2026-12345",
                title="Improper Input Validation in PyYAML",
                severity="critical",
                package_name="pyyaml",
                package_version="5.3.1",
                location=NormalizedLocation(path="/workspace/requirements.txt"),
            ),
            NormalizedFinding(
                source="trivy",
                finding_type="dependency",
                rule_id="CVE-2026-22222",
                title="PyYAML: incomplete fix for CVE-2020-1747",
                severity="critical",
                package_name="pyyaml",
                package_version="5.3.1",
                location=NormalizedLocation(path="/workspace/requirements.txt"),
            ),
        ],
        baseline_findings=[],
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

    threats = explain_introduced_threats(bundle)

    assert len(threats) == 1
    assert threats[0].advisory_count == 2
    assert render_threat_line(threats[0]) == (
        "critical dependency risk in requirements.txt: pyyaml 5.3.1 (Improper Input Validation in PyYAML; PyYAML: incomplete fix for CVE-2020-1747)"
    )


def test_explain_introduced_threats_summarizes_privilege_escalation_patterns() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="yaml.kubernetes.security.allow-privilege-escalation-no-securitycontext.allow-privilege-escalation-no-securitycontext",
                title="allowPrivilegeEscalation should be set to false",
                severity="medium",
                location=NormalizedLocation(path="k8s/deployment.yaml", start_line=10, end_line=10),
            ),
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="yaml.kubernetes.security.run-as-non-root.run-as-non-root",
                title="runAsNonRoot should be true",
                severity="info",
                location=NormalizedLocation(path="k8s/deployment.yaml", start_line=12, end_line=12),
            ),
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="container.security.privileged",
                title="privileged: true is configured",
                severity="high",
                location=NormalizedLocation(path="k8s/deployment.yaml", start_line=14, end_line=14),
            ),
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="k8s/deployment.yaml",
                    change_type="modified",
                    added_lines=3,
                    removed_lines=0,
                    signals=("infrastructure",),
                    previous_path="k8s/deployment.yaml",
                ),
            )
        ),
    )

    threats = explain_introduced_threats(bundle)

    summaries = {threat.summary for threat in threats}
    assert "container can allow privilege escalation" in summaries
    assert "container may run as root" in summaries
    assert "container is configured as privileged" in summaries


def test_explain_introduced_threats_normalizes_broad_iam_findings() -> None:
    bundle = build_analysis_bundle(
        current_findings=[
            NormalizedFinding(
                source="semgrep",
                finding_type="code",
                rule_id="terraform.lang.security.iam.no-iam-admin-privileges.no-iam-admin-privileges",
                title='IAM policies that allow full "*-*" admin privileges violates the principle of least privilege.',
                severity="medium",
                location=NormalizedLocation(path="infra/main.tf", start_line=10, end_line=10),
            ),
        ],
        baseline_findings=[],
        change_context=ParsedChangeContext(
            files=(
                ParsedFileChange(
                    path="infra/main.tf",
                    change_type="modified",
                    added_lines=2,
                    removed_lines=0,
                    signals=("infrastructure",),
                    previous_path="infra/main.tf",
                ),
            )
        ),
    )

    threats = explain_introduced_threats(bundle)

    assert threats[0].summary == "adds overly broad IAM permissions"


def test_render_threat_line_without_location() -> None:
    threat = ThreatExplanation(
        source="scanner",
        threat_type="code",
        severity="medium",
        subject="generic.rule",
        location=None,
        summary="Generic issue",
        why_not_safe="the change introduces new application or configuration risk",
        advisory_count=1,
    )

    assert render_threat_line(threat) == "medium code risk: Generic issue"
