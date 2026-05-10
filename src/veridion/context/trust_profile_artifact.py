"""Shared trust-profile artifact loading and merge helpers."""

from __future__ import annotations

import json
from pathlib import Path


CONTEXT_KEYS = ("historical", "runtime", "ownership", "trust_baseline")
SUPPORTED_TRUST_PROFILE_SCHEMA_VERSION = 1


def load_json_file(path: str, *, label: str) -> dict[str, object]:
    """Load a JSON object from disk with contextual error messages."""

    try:
        payload = json.loads(Path(path).read_text())
    except Exception as exc:
        raise RuntimeError(f"failed to load {label} JSON from {path}") from exc

    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} JSON at {path} must contain an object at the top level")

    return payload


def merge_metadata_with_trust_profile(
    metadata_payload: dict[str, object],
    trust_profile_payload: dict[str, object],
) -> dict[str, object]:
    """Merge PR metadata with trust-profile context, favoring explicit PR metadata values."""

    merged = dict(metadata_payload)

    if trust_profile_payload:
        validate_trust_profile_payload(trust_profile_payload)
        merged["trust_profile_metadata"] = build_trust_profile_metadata(trust_profile_payload)

    for key in CONTEXT_KEYS:
        merged[key] = _merge_context_section(
            trust_profile_payload.get(key),
            metadata_payload.get(key),
        )

    return merged


def build_trust_profile_metadata(payload: dict[str, object]) -> dict[str, object]:
    """Extract normalized trust-profile artifact metadata."""

    scope = payload.get("scope")
    if not isinstance(scope, dict):
        scope = {}

    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        provenance = {}

    return {
        "schema_version": payload.get("schema_version", 0),
        "repo_id": _as_string(scope.get("repo_id")),
        "service_id": _as_string(scope.get("service_id")),
        "team_id": _as_string(scope.get("team_id")),
        "source": _as_string(provenance.get("source")),
        "generated_at": _as_string(provenance.get("generated_at")),
        "precedence": "trust_profile_artifact",
    }


def validate_trust_profile_payload(payload: dict[str, object]) -> None:
    """Validate the dedicated trust-profile artifact contract."""

    schema_version = payload.get("schema_version")
    if schema_version != SUPPORTED_TRUST_PROFILE_SCHEMA_VERSION:
        raise RuntimeError("trust profile schema_version must be 1")

    scope = payload.get("scope")
    if scope is not None and not isinstance(scope, dict):
        raise RuntimeError("trust profile scope must be an object when provided")

    provenance = payload.get("provenance")
    if provenance is not None and not isinstance(provenance, dict):
        raise RuntimeError("trust profile provenance must be an object when provided")


def _merge_context_section(
    trust_value: object,
    metadata_value: object,
) -> dict[str, object]:
    base = trust_value if isinstance(trust_value, dict) else {}
    override = metadata_value if isinstance(metadata_value, dict) else {}
    return {**base, **override}


def _as_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""
