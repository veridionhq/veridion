import io
import sys
import types
from urllib import error

from veridion.summarization import (
    BedrockSummarizer,
    SummarizationRequest,
    SummarizationResult,
    build_comment_summarizer,
    _parse_summarization_result,
    summarize_comment_request,
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


def test_bedrock_summarizer_uses_boto3_client(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class _FakeBody:
        def read(self) -> bytes:
            return (
                b'{"content":[{"text":"{\\"driver_summary\\":[\\"this change cannot ship because it introduces critical vulnerable dependencies\\"],\\"threat_summaries\\":[\\"requirements.txt introduces pyyaml 5.3.1 with critical code-execution risk\\"],\\"contextual_summary\\":[\\"service is publicly exposed\\"]}"}]}'
            )

    class _FakeClient:
        def invoke_model(self, *, modelId: str, body: str) -> dict[str, object]:
            captured["modelId"] = modelId
            captured["body"] = body
            return {"body": _FakeBody()}

    fake_boto3 = types.SimpleNamespace(client=lambda service_name, region_name=None: _FakeClient())
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    summarizer = BedrockSummarizer(model="anthropic.test", region="us-east-1")
    result = summarizer.summarize(
        SummarizationRequest(
            decision="NO GO",
            score=0,
            confidence="high",
            primary_drivers=("policy max_severity exceeded",),
            threats=(),
            contextual_risk=("service is publicly exposed",),
            required_approvals=("security_owner",),
            required_next_steps=("Block release until introduced risk is remediated or policy is adjusted",),
        )
    )

    assert captured["modelId"] == "anthropic.test"
    assert '"anthropic_version": "bedrock-2023-05-31"' in str(captured["body"])
    assert result.driver_summary == ("this change cannot ship because it introduces critical vulnerable dependencies",)
    assert result.threat_summaries == ("requirements.txt introduces pyyaml 5.3.1 with critical code-execution risk",)


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


def test_parse_summarization_result_polishes_awkward_threat_labels() -> None:
    result = _parse_summarization_result(
        """
        {
          "driver_summary": ["this change cannot ship because it introduces critical vulnerable dependencies"],
          "threat_summaries": [
            "urllib3 1.25.8 in requirements.txt — high: cross-origin cookie header not stripped on redirects; multiple high-severity advisories"
          ],
          "contextual_summary": []
        }
        """
    )

    assert result.threat_summaries == (
        "urllib3 1.25.8 in requirements.txt — cross-origin cookie header not stripped on redirects; multiple high-severity dependency vulnerabilities",
    )


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


def test_parse_summarization_result_rejects_example_style_blocker_line() -> None:
    try:
        _parse_summarization_result(
            """
            {
              "driver_summary": [
                "this change cannot ship because it introduces critical vulnerable dependencies such as pyyaml 5.3.1"
              ],
              "threat_summaries": [],
              "contextual_summary": []
            }
            """
        )
    except RuntimeError as exc:
        assert "example phrasing" in str(exc)
    else:
        raise AssertionError("expected example-style blocker line to be rejected")


def test_parse_summarization_result_rejects_approval_language_in_driver() -> None:
    try:
        _parse_summarization_result(
            """
            {
              "driver_summary": [
                "this change needs review because app/main.py uses subprocess with shell=True",
                "platform_owner approval required"
              ],
              "threat_summaries": [],
              "contextual_summary": []
            }
            """
        )
    except RuntimeError as exc:
        assert "approval language" in str(exc)
    else:
        raise AssertionError("expected approval language in driver summary to be rejected")
