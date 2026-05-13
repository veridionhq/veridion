import io
from urllib import error

from veridion.analysis import build_analysis_bundle
from veridion.change_context.diff_parser import ParsedChangeContext, ParsedFileChange
from veridion.normalize.models import NormalizedFinding, NormalizedLocation
from veridion.report.threats import explain_introduced_threats, render_threat_line
from veridion.summarization import (
    SummarizationRequest,
    SummarizationResult,
    build_comment_summarizer,
    _parse_summarization_result,
    summarize_comment_request,
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


def test_summarize_comment_request_captures_http_error_body(monkeypatch) -> None:
    summarizer = build_comment_summarizer(
        provider="openai",
        model="gpt-5-mini",
        api_key="test-key",
    )
    assert summarizer is not None

    def fake_urlopen(req, timeout=0):  # noqa: ARG001
        raise error.HTTPError(
            req.full_url,
            429,
            "Too Many Requests",
            hdrs=None,
            fp=io.BytesIO(b'{"error":{"type":"insufficient_quota","message":"Quota exceeded"}}'),
        )

    monkeypatch.setattr("veridion.summarization.request.urlopen", fake_urlopen)

    result, trace = summarize_comment_request(
        SummarizationRequest(
            decision="NO GO",
            score=0,
            confidence="high",
            primary_drivers=("policy max_severity exceeded",),
            threats=(),
            contextual_risk=(),
            required_approvals=("security_owner",),
            required_next_steps=("Block release until introduced risk is remediated or policy is adjusted",),
        ),
        summarizer,
    )

    assert result is None
    assert trace.mode == "deterministic"
    assert trace.provider == "openai"
    assert trace.model == "gpt-5-mini"
    assert trace.error == 'HTTP 429: {"error":{"type":"insufficient_quota","message":"Quota exceeded"}}'


def test_parse_summarization_result_rejects_schema_shaped_output() -> None:
    try:
        _parse_summarization_result(
            """
            {
              "driver_summary": ["required_approvals: platform_owner, security_owner"],
              "threat_summaries": ["grype: pyyaml 5.3.1 in requirements.txt -- advisory_count: 2"],
              "contextual_summary": []
            }
            """
        )
    except RuntimeError as exc:
        assert "schema-shaped fields" in str(exc)
    else:
        raise AssertionError("expected schema-shaped output to be rejected")


def test_parse_summarization_result_caps_threat_summaries() -> None:
    result = _parse_summarization_result(
        """
        {
          "driver_summary": ["this change cannot ship because it adds critical vulnerable dependencies"],
          "threat_summaries": [
            "requirements.txt introduces pyyaml 5.3.1 with critical code-execution risk",
            "requirements.txt introduces urllib3 1.25.8 with multiple high-severity advisories",
            "infra/main.tf adds overly broad IAM permissions",
            "this fourth line should be dropped"
          ],
          "contextual_summary": ["service is publicly exposed", "blast radius is high", "change touches a shared platform surface", "extra context"]
        }
        """
    )

    assert len(result.threat_summaries) == 3
    assert result.threat_summaries[-1] == "infra/main.tf adds overly broad IAM permissions"
    assert len(result.contextual_summary) == 3


def test_parse_summarization_result_rejects_redundant_decision_line() -> None:
    try:
        _parse_summarization_result(
            """
            {
              "driver_summary": [
                "Decision: NO GO.",
                "this change cannot ship because requirements.txt introduces critical vulnerable dependencies"
              ],
              "threat_summaries": [],
              "contextual_summary": []
            }
            """
        )
    except RuntimeError as exc:
        assert "restated the decision" in str(exc)
    else:
        raise AssertionError("expected redundant decision line to be rejected")


def test_parse_summarization_result_rejects_action_language_in_context() -> None:
    try:
        _parse_summarization_result(
            """
            {
              "driver_summary": [
                "this change cannot ship because requirements.txt introduces critical vulnerable dependencies"
              ],
              "threat_summaries": [],
              "contextual_summary": [
                "Block release until introduced risk is remediated or policy is adjusted."
              ]
            }
            """
        )
    except RuntimeError as exc:
        assert "action language in contextual summary" in str(exc)
    else:
        raise AssertionError("expected action language in context to be rejected")
