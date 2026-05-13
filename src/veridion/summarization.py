"""Optional AI summarization layer for PR comment wording."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Protocol
from urllib import error, request

from veridion.report.threats import ThreatExplanation


@dataclass(frozen=True)
class SummarizationRequest:
    """Strict structured input provided to a wording model."""

    decision: str
    score: int
    confidence: str
    primary_drivers: tuple[str, ...]
    threats: tuple[ThreatExplanation, ...]
    contextual_risk: tuple[str, ...]
    required_approvals: tuple[str, ...]
    required_next_steps: tuple[str, ...]
    style: str = "terse"

    def to_payload(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "score": self.score,
            "confidence": self.confidence,
            "primary_drivers": list(self.primary_drivers),
            "threats": [item.to_dict() for item in self.threats],
            "contextual_risk": list(self.contextual_risk),
            "required_approvals": list(self.required_approvals),
            "required_next_steps": list(self.required_next_steps),
            "style": self.style,
        }


@dataclass(frozen=True)
class SummarizationResult:
    """Validated wording overrides returned by a model."""

    driver_summary: tuple[str, ...]
    threat_summaries: tuple[str, ...]
    contextual_summary: tuple[str, ...] = ()


@dataclass(frozen=True)
class SummarizationTrace:
    """Execution metadata for optional wording summarization."""

    mode: str
    provider: str
    model: str
    error: str = ""


class CommentSummarizer(Protocol):
    """Provider-agnostic interface for wording models."""

    @property
    def provider(self) -> str: ...

    @property
    def model_name(self) -> str: ...

    def summarize(self, summary_request: SummarizationRequest) -> SummarizationResult: ...


@dataclass(frozen=True)
class OpenAICompatibleSummarizer:
    """Summarizer for OpenAI-compatible chat APIs."""

    model: str
    api_key: str
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: int = 20

    @property
    def provider(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self.model

    def summarize(self, summary_request: SummarizationRequest) -> SummarizationResult:
        payload = {
            "model": self.model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(summary_request.to_payload())},
            ],
        }
        raw = _post_json(
            url=self.base_url.rstrip("/") + "/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            payload=payload,
            timeout_seconds=self.timeout_seconds,
        )
        content = raw["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise RuntimeError("summarizer response did not contain text content")
        return _parse_summarization_result(content)


@dataclass(frozen=True)
class AnthropicSummarizer:
    """Summarizer for Anthropic messages API."""

    model: str
    api_key: str
    base_url: str = "https://api.anthropic.com/v1/messages"
    timeout_seconds: int = 20

    @property
    def provider(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self.model

    def summarize(self, summary_request: SummarizationRequest) -> SummarizationResult:
        payload = {
            "model": self.model,
            "max_tokens": 500,
            "temperature": 0.1,
            "system": _SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": json.dumps(summary_request.to_payload())},
            ],
        }
        raw = _post_json(
            url=self.base_url,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            payload=payload,
            timeout_seconds=self.timeout_seconds,
        )
        content_blocks = raw.get("content", [])
        if not isinstance(content_blocks, list) or not content_blocks:
            raise RuntimeError("summarizer response did not contain content blocks")
        first = content_blocks[0]
        if not isinstance(first, dict) or not isinstance(first.get("text"), str):
            raise RuntimeError("summarizer response did not contain text")
        return _parse_summarization_result(first["text"])


@dataclass(frozen=True)
class BedrockSummarizer:
    """Summarizer for AWS Bedrock via boto3 when available."""

    model: str
    region: str

    @property
    def provider(self) -> str:
        return "bedrock"

    @property
    def model_name(self) -> str:
        return self.model

    def summarize(self, summary_request: SummarizationRequest) -> SummarizationResult:
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise RuntimeError("boto3 is required for Bedrock summarization") from exc

        client = boto3.client("bedrock-runtime", region_name=self.region)
        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 500,
                "temperature": 0.1,
                "system": _SYSTEM_PROMPT,
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": json.dumps(summary_request.to_payload())}]}
                ],
            }
        )
        response = client.invoke_model(modelId=self.model, body=body)
        raw_body = response["body"].read()
        parsed = json.loads(raw_body)
        content_blocks = parsed.get("content", [])
        if not isinstance(content_blocks, list) or not content_blocks:
            raise RuntimeError("summarizer response did not contain content blocks")
        first = content_blocks[0]
        if not isinstance(first, dict) or not isinstance(first.get("text"), str):
            raise RuntimeError("summarizer response did not contain text")
        return _parse_summarization_result(first["text"])


def build_comment_summarizer(
    *,
    provider: str | None,
    model: str | None,
    api_key: str | None = None,
    base_url: str | None = None,
    region: str | None = None,
) -> CommentSummarizer | None:
    """Build a configured summarizer, or return None when disabled."""

    if not provider:
        return None

    normalized = provider.strip().lower()
    if normalized in {"off", "none", ""}:
        return None
    if not model:
        raise RuntimeError("comment summarization model is required when a provider is configured")

    if normalized in {"openai", "openai-compatible", "compatible"}:
        if not api_key:
            raise RuntimeError("comment summarization api key is required for OpenAI-compatible providers")
        return OpenAICompatibleSummarizer(model=model, api_key=api_key, base_url=base_url or "https://api.openai.com/v1")

    if normalized in {"anthropic", "claude"}:
        if not api_key:
            raise RuntimeError("comment summarization api key is required for Anthropic providers")
        return AnthropicSummarizer(model=model, api_key=api_key, base_url=base_url or "https://api.anthropic.com/v1/messages")

    if normalized == "bedrock":
        if not region:
            raise RuntimeError("comment summarization region is required for Bedrock")
        return BedrockSummarizer(model=model, region=region)

    raise RuntimeError(f"unsupported comment summarization provider: {provider}")


def summarize_comment_request(
    summary_request: SummarizationRequest,
    summarizer: CommentSummarizer | None,
) -> tuple[SummarizationResult | None, SummarizationTrace]:
    """Run optional summarization and return validated result plus execution trace."""

    if summarizer is None:
        return None, SummarizationTrace(mode="deterministic", provider="none", model="")
    provider = getattr(summarizer, "provider", "custom")
    model_name = getattr(summarizer, "model_name", "")
    try:
        result = summarizer.summarize(summary_request)
    except Exception as exc:
        return None, SummarizationTrace(
            mode="deterministic",
            provider=provider,
            model=model_name,
            error=str(exc),
        )
    return result, SummarizationTrace(
        mode="ai",
        provider=provider,
        model=model_name,
    )


def _post_json(
    *,
    url: str,
    headers: dict[str, str],
    payload: dict[str, object],
    timeout_seconds: int,
) -> dict[str, object]:
    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            return json.loads(response.read())
    except error.HTTPError as exc:
        raise RuntimeError(_format_http_error(exc)) from exc


def _parse_summarization_result(text: str) -> SummarizationResult:
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise RuntimeError("summarizer output must be a JSON object")
    driver_summary = _string_tuple(parsed.get("driver_summary"))
    threat_summaries = _string_tuple(parsed.get("threat_summaries"))
    contextual_summary = _string_tuple(parsed.get("contextual_summary"))
    if not threat_summaries and not driver_summary:
        raise RuntimeError("summarizer output must contain driver_summary or threat_summaries")
    return SummarizationResult(
        driver_summary=driver_summary,
        threat_summaries=threat_summaries,
        contextual_summary=contextual_summary,
    )


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        stripped = item.strip()
        if stripped:
            normalized.append(stripped)
    return tuple(normalized)


_SYSTEM_PROMPT = """
You rewrite release decision facts into short operator-facing English.

Rules:
- Never change the decision, score, severity, source, location, approvals, or required steps.
- Never invent facts.
- Keep wording direct and short.
- Prefer one sentence fragments, not paragraphs.
- Merge duplicate threats when possible.
- Return valid JSON only with:
  - driver_summary: string[]
  - threat_summaries: string[]
  - contextual_summary: string[]
""".strip()


def _format_http_error(exc: error.HTTPError) -> str:
    status = getattr(exc, "code", "unknown")
    body = ""
    try:
        raw_body = exc.read()
    except Exception:
        raw_body = b""
    if isinstance(raw_body, bytes) and raw_body:
        body = raw_body.decode("utf-8", errors="replace").strip()
    elif isinstance(raw_body, str):
        body = raw_body.strip()
    if body:
        compact_body = " ".join(body.split())
        return f"HTTP {status}: {compact_body}"
    return f"HTTP {status}: {exc.reason}"
