"""Versioned operational-context artifact contract."""

from __future__ import annotations

from datetime import datetime, timezone

from veridion.context.trust_profile_artifact import merge_metadata_with_trust_profile


SUPPORTED_OPERATIONAL_CONTEXT_SCHEMA_VERSION = 1


def build_operational_context_artifact(
    metadata_payload: dict[str, object],
    trust_profile_payload: dict[str, object],
    *,
    source: str = "",
    generated_at: str = "",
) -> dict[str, object]:
    """Build a versioned operational-context artifact."""

    merged_payload = merge_metadata_with_trust_profile(metadata_payload, trust_profile_payload)
    return {
        "schema_version": SUPPORTED_OPERATIONAL_CONTEXT_SCHEMA_VERSION,
        "provenance": {
            "source": source or "veridion-github-builder",
            "generated_at": generated_at or _utc_now(),
        },
        "metadata": metadata_payload,
        "historical": _as_object(merged_payload.get("historical")),
        "runtime": _as_object(merged_payload.get("runtime")),
        "ownership": _as_object(merged_payload.get("ownership")),
        "trust_baseline": _as_object(merged_payload.get("trust_baseline")),
        "trust_profile_metadata": _as_object(merged_payload.get("trust_profile_metadata")),
    }


def extract_operational_context_sections(payload: dict[str, object]) -> dict[str, object]:
    """Extract normalized context sections from a validated artifact payload."""

    return {
        "metadata": _as_object(payload.get("metadata")),
        "historical": _as_object(payload.get("historical")),
        "runtime": _as_object(payload.get("runtime")),
        "ownership": _as_object(payload.get("ownership")),
        "trust_baseline": _as_object(payload.get("trust_baseline")),
        "trust_profile_metadata": _as_object(payload.get("trust_profile_metadata")),
    }


def validate_operational_context_payload(payload: dict[str, object]) -> None:
    """Validate the versioned operational-context artifact."""

    schema_version = payload.get("schema_version")
    if schema_version != SUPPORTED_OPERATIONAL_CONTEXT_SCHEMA_VERSION:
        raise RuntimeError("operational context schema_version must be 1")

    for key in (
        "provenance",
        "metadata",
        "historical",
        "runtime",
        "ownership",
        "trust_baseline",
        "trust_profile_metadata",
    ):
        value = payload.get(key)
        if value is not None and not isinstance(value, dict):
            raise RuntimeError(f"operational context {key} must be an object when provided")


def _as_object(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
