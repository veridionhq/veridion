from veridion.analysis import build_analysis_bundle
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.report.threats import explain_introduced_threats, render_threat_line
from veridion.summarization import (
    SummarizationRequest,
    SummarizationResult,
    build_comment_summarizer,
)


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
    assert threats[0].why_not_safe == "the change introduces a vulnerable package version"
    assert render_threat_line(threats[0]) == (
        "critical dependency risk in requirements.txt: pyyaml 5.3.1 (Improper Input Validation in PyYAML)"
    )
    assert threats[1].summary == "uses subprocess with shell=True"
    assert threats[1].why_not_safe == "shell execution can allow command injection or unsafe command expansion"


def test_build_comment_summarizer_supports_disabled_and_errors_on_missing_requirements() -> None:
    assert build_comment_summarizer(provider=None, model=None) is None
    assert build_comment_summarizer(provider="none", model=None) is None

    try:
        build_comment_summarizer(provider="openai", model="gpt-test")
    except RuntimeError as exc:
        assert "api key is required" in str(exc)
    else:
        raise AssertionError("expected missing api key to fail")

    try:
        build_comment_summarizer(provider="bedrock", model="model")
    except RuntimeError as exc:
        assert "region is required" in str(exc)
    else:
        raise AssertionError("expected missing region to fail")


def test_summarization_request_payload_is_strict_json_shape() -> None:
    request = SummarizationRequest(
        decision="NO GO",
        score=22,
        confidence="high",
        primary_drivers=("new risk in this change crosses the current release policy",),
        threats=(),
        contextual_risk=("service is publicly exposed",),
        required_approvals=("security_owner",),
        required_next_steps=("Block release until introduced risk is remediated or policy is adjusted",),
        style="terse",
    )

    payload = request.to_payload()

    assert payload["decision"] == "NO GO"
    assert payload["primary_drivers"] == ["new risk in this change crosses the current release policy"]
    assert payload["required_approvals"] == ["security_owner"]
    assert payload["style"] == "terse"


def test_summarization_result_shape_is_simple() -> None:
    result = SummarizationResult(
        driver_summary=("this change introduces new release risk",),
        threat_summaries=("app/main.py uses subprocess with shell=True, which can allow command injection",),
    )

    assert result.driver_summary[0].startswith("this change introduces")
