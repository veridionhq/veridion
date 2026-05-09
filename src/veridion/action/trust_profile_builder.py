"""Build trust-profile artifacts from repo-local source configuration."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from veridion.action.trust_profile import SUPPORTED_TRUST_PROFILE_SCHEMA_VERSION

DEFAULT_REPO_TRUST_SOURCE_PATH = ".veridion/trust-profile.source.json"
DEFAULT_TRUST_CATALOG_SOURCE_PATH = ".veridion/trust-catalog.source.json"
DEFAULT_SERVICE_CATALOG_EXPORT_PATH = ".veridion/service-catalog-trust.json"


def build_trust_profile(
    source_payload: dict[str, object],
    *,
    source_name: str = "",
    generated_at: str = "",
) -> dict[str, object]:
    """Build a versioned trust-profile artifact from repo-local source config."""

    scope = _as_object(source_payload.get("scope"))
    provenance = _as_object(source_payload.get("provenance"))

    resolved_source = source_name or _as_string(provenance.get("source")) or "repo-local-config"
    resolved_generated_at = generated_at or _as_string(provenance.get("generated_at")) or _utc_now()

    return {
        "schema_version": SUPPORTED_TRUST_PROFILE_SCHEMA_VERSION,
        "scope": {
            "repo_id": _as_string(scope.get("repo_id")),
            "service_id": _as_string(scope.get("service_id")),
            "team_id": _as_string(scope.get("team_id")),
        },
        "provenance": {
            "source": resolved_source,
            "generated_at": resolved_generated_at,
        },
        "historical": _as_object(source_payload.get("historical")),
        "runtime": _as_object(source_payload.get("runtime")),
        "ownership": _as_object(source_payload.get("ownership")),
        "trust_baseline": _as_object(source_payload.get("trust_baseline")),
    }


def merge_trust_profile_sources(
    catalog_payload: dict[str, object],
    repo_payload: dict[str, object],
) -> dict[str, object]:
    """Merge shared catalog posture with repo-local overrides."""

    merged: dict[str, object] = {}
    for key in ("scope", "provenance", "historical", "runtime", "ownership", "trust_baseline"):
        base = _as_object(catalog_payload.get(key))
        override = _as_object(repo_payload.get(key))
        merged[key] = {**base, **override}
    return merged


def resolve_trust_profile_paths(
    *,
    config_path: str | None = None,
    catalog_path: str | None = None,
    service_catalog_path: str | None = None,
) -> tuple[str, str | None, str | None]:
    """Resolve repo-local and catalog trust input paths using default conventions."""

    resolved_config_path = config_path or _default_existing_path((DEFAULT_REPO_TRUST_SOURCE_PATH,))
    if not resolved_config_path:
        raise RuntimeError(
            "no trust profile source found; provide --config-path or add .veridion/trust-profile.source.json"
        )

    resolved_catalog_path = catalog_path or _default_existing_path((DEFAULT_TRUST_CATALOG_SOURCE_PATH,))
    resolved_service_catalog_path = service_catalog_path or _default_existing_path((DEFAULT_SERVICE_CATALOG_EXPORT_PATH,))
    return resolved_config_path, resolved_catalog_path, resolved_service_catalog_path


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for building trust-profile artifacts."""

    parser = argparse.ArgumentParser(description="Build Veridion trust-profile artifact")
    parser.add_argument("--catalog-path", help="Path to optional shared trust catalog JSON")
    parser.add_argument("--service-catalog-path", help="Path to optional service catalog trust export JSON")
    parser.add_argument("--config-path", help="Path to repo-local trust source JSON")
    parser.add_argument("--output-path", required=True, help="Where to write the trust-profile JSON")
    parser.add_argument("--source-name", help="Optional provenance source override")
    parser.add_argument("--generated-at", help="Optional generated-at timestamp override")
    args = parser.parse_args(argv)

    resolved_config_path, resolved_catalog_path, resolved_service_catalog_path = resolve_trust_profile_paths(
        config_path=args.config_path,
        catalog_path=args.catalog_path,
        service_catalog_path=args.service_catalog_path,
    )

    repo_payload = _load_json_object(resolved_config_path, label="trust profile source")
    catalog_payload = _load_json_object(resolved_catalog_path, label="trust catalog source") if resolved_catalog_path else {}
    service_catalog_payload = (
        _load_json_object(resolved_service_catalog_path, label="service catalog trust source")
        if resolved_service_catalog_path
        else {}
    )
    catalog_merged_payload = merge_trust_profile_sources(service_catalog_payload, catalog_payload)
    payload = merge_trust_profile_sources(catalog_merged_payload, repo_payload)
    artifact = build_trust_profile(
        payload,
        source_name=args.source_name or "",
        generated_at=args.generated_at or "",
    )
    Path(args.output_path).write_text(json.dumps(artifact, indent=2) + "\n")
    return 0


def _load_json_object(path: str, *, label: str) -> dict[str, object]:
    try:
        payload = json.loads(Path(path).read_text())
    except Exception as exc:
        raise RuntimeError(f"failed to load {label} JSON from {path}") from exc

    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} JSON at {path} must contain an object at the top level")

    return payload


def _as_object(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _as_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _default_existing_path(candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
