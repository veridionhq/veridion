"""Native Veridion release evidence normalization."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

VALID_EVIDENCE_STATUSES = {
    "passed",
    "warning",
    "failed",
    "blocked",
    "healthy",
    "degraded",
    "unhealthy",
    "missing",
    "unknown",
    "skipped",
    "stale",
    "satisfied",
    "unsatisfied",
    "expired",
    "valid",
    "invalid",
    "detected",
    "not_detected",
}

VALID_EVIDENCE_SEVERITIES = {"info", "low", "medium", "high", "critical"}

BLOCKING_STATUSES = {"failed", "blocked", "unhealthy", "invalid", "unsatisfied", "expired"}
REVIEW_STATUSES = {"warning", "degraded", "missing", "unknown", "skipped", "stale"}


@dataclass(frozen=True)
class NormalizedEvidence:
    """Source-neutral release evidence used by the decision engine."""

    evidence_id: str
    evidence_type: str
    category: str
    name: str
    status: str
    severity: str = "info"
    required: bool = False
    summary: str = ""
    details_url: str = ""
    observed_at: str = ""
    valid_for_commit: bool = True
    source: dict[str, object] = field(default_factory=dict)
    subject: dict[str, object] = field(default_factory=dict)
    attributes: dict[str, object] = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        return self.required and self.status in BLOCKING_STATUSES

    @property
    def requires_review(self) -> bool:
        return self.required and self.status in REVIEW_STATUSES

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "category": self.category,
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "required": self.required,
            "summary": self.summary,
            "details_url": self.details_url,
            "observed_at": self.observed_at,
            "valid_for_commit": self.valid_for_commit,
            "source": dict(self.source),
            "subject": dict(self.subject),
            "attributes": dict(self.attributes),
        }


def parse_evidence_text(text: str | None) -> tuple[NormalizedEvidence, ...]:
    """Parse native Veridion evidence JSON text."""

    if not text:
        return ()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("evidence JSON is not valid JSON") from exc
    return parse_evidence_payload(payload)


def parse_evidence_payload(payload: object) -> tuple[NormalizedEvidence, ...]:
    """Parse a native evidence bundle or a single evidence object."""

    if isinstance(payload, list):
        return tuple(_parse_evidence_item(item, bundle_subject={}) for item in payload)
    if not isinstance(payload, dict):
        raise RuntimeError("evidence JSON must contain an object, array, or evidence bundle")

    if "evidence" in payload:
        evidence_items = payload.get("evidence")
        if not isinstance(evidence_items, list):
            raise RuntimeError("evidence bundle field 'evidence' must be a list")
        subject = _object_dict(payload.get("subject"), field_name="subject", allow_empty=True)
        return tuple(_parse_evidence_item(item, bundle_subject=subject) for item in evidence_items)

    return (_parse_evidence_item(payload, bundle_subject={}),)


def _parse_evidence_item(item: object, *, bundle_subject: dict[str, object]) -> NormalizedEvidence:
    if not isinstance(item, dict):
        raise RuntimeError("each evidence item must be an object")

    evidence_type = _required_string(item, "evidence_type")
    category = _string(item.get("category"), default="release_readiness")
    name = _required_string(item, "name")
    status = _normalize_status(_required_string(item, "status"))
    severity = _normalize_severity(_string(item.get("severity"), default="info"))
    source = _object_dict(item.get("source"), field_name="source", allow_empty=True)
    subject = dict(bundle_subject)
    subject.update(_object_dict(item.get("subject"), field_name="subject", allow_empty=True))
    attributes = _object_dict(item.get("attributes"), field_name="attributes", allow_empty=True)

    evidence_id = _string(item.get("evidence_id") or item.get("id"), default="")
    if not evidence_id:
        provider = str(source.get("provider", "")).strip()
        evidence_id = ":".join(part for part in (provider, evidence_type, name) if part)

    return NormalizedEvidence(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        category=category,
        name=name,
        status=status,
        severity=severity,
        required=_as_bool(item.get("required"), default=False),
        summary=_string(item.get("summary"), default=""),
        details_url=_string(item.get("details_url"), default=""),
        observed_at=_string(item.get("observed_at"), default=""),
        valid_for_commit=_as_bool(item.get("valid_for_commit"), default=True),
        source=source,
        subject=subject,
        attributes=attributes,
    )


def _required_string(item: dict[str, Any], key: str) -> str:
    value = _string(item.get(key), default="")
    if not value:
        raise RuntimeError(f"evidence item requires non-empty '{key}'")
    return value


def _string(value: object, *, default: str) -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _normalize_status(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "_").replace("-", "_")
    if normalized not in VALID_EVIDENCE_STATUSES:
        raise RuntimeError(
            "unsupported evidence status "
            f"'{value}'. Supported statuses: {', '.join(sorted(VALID_EVIDENCE_STATUSES))}"
        )
    return normalized


def _normalize_severity(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in VALID_EVIDENCE_SEVERITIES:
        raise RuntimeError(
            "unsupported evidence severity "
            f"'{value}'. Supported severities: {', '.join(sorted(VALID_EVIDENCE_SEVERITIES))}"
        )
    return normalized


def _object_dict(value: object, *, field_name: str, allow_empty: bool) -> dict[str, object]:
    if value is None:
        if allow_empty:
            return {}
        raise RuntimeError(f"evidence field '{field_name}' must be an object")
    if not isinstance(value, dict):
        raise RuntimeError(f"evidence field '{field_name}' must be an object")
    return dict(value)


def _as_bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    raise RuntimeError(f"expected boolean evidence value, got: {value!r}")
