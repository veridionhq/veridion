"""Build versioned operational-context artifacts for Veridion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from veridion.action.metadata_builder import build_pr_metadata, collect_commit_metadata
from veridion.context import build_operational_context_artifact, build_operational_context_artifact_from_sections
from veridion.context.trust_profile_artifact import load_json_file


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for building operational-context artifacts."""

    parser = argparse.ArgumentParser(description="Build Veridion operational-context artifact")
    parser.add_argument("--output-path", required=True, help="Where to write the operational-context JSON")
    parser.add_argument("--event-path", help="Path to the GitHub event payload JSON")
    parser.add_argument("--base-ref", help="PR base ref used to collect commit metadata from git")
    parser.add_argument("--head-ref", default="HEAD", help="Head revision used for commit metadata collection")
    parser.add_argument("--metadata-path", help="Path to prebuilt metadata JSON")
    parser.add_argument("--trust-profile-path", help="Path to optional trust profile JSON")
    parser.add_argument("--historical-path", help="Path to normalized historical context JSON")
    parser.add_argument("--runtime-path", help="Path to normalized runtime context JSON")
    parser.add_argument("--ownership-path", help="Path to normalized ownership context JSON")
    parser.add_argument("--trust-baseline-path", help="Path to normalized trust-baseline JSON")
    parser.add_argument("--trust-memory-path", help="Path to normalized trust-memory JSON")
    parser.add_argument("--trust-profile-metadata-path", help="Path to trust-profile metadata JSON")
    parser.add_argument("--source", help="Optional provenance source override")
    parser.add_argument("--generated-at", help="Optional generated-at timestamp override")
    args = parser.parse_args(argv)

    if _has_section_inputs(args):
        artifact = build_operational_context_artifact_from_sections(
            metadata_payload=_load_optional_json(args.metadata_path, label="metadata"),
            historical_payload=_load_optional_json(args.historical_path, label="historical"),
            runtime_payload=_load_optional_json(args.runtime_path, label="runtime"),
            ownership_payload=_load_optional_json(args.ownership_path, label="ownership"),
            trust_baseline_payload=_load_optional_json(args.trust_baseline_path, label="trust baseline"),
            trust_memory_payload=_load_optional_json(args.trust_memory_path, label="trust memory"),
            trust_profile_metadata_payload=_load_optional_json(
                args.trust_profile_metadata_path,
                label="trust profile metadata",
            ),
            source=args.source or "",
            generated_at=args.generated_at or "",
        )
    else:
        metadata_payload = _resolve_metadata_payload(
            metadata_path=args.metadata_path,
            event_path=args.event_path,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
        )
        trust_profile_payload = (
            load_json_file(args.trust_profile_path, label="trust profile") if args.trust_profile_path else {}
        )

        artifact = build_operational_context_artifact(
            metadata_payload=metadata_payload,
            trust_profile_payload=trust_profile_payload,
            source=args.source or "",
            generated_at=args.generated_at or "",
        )
    Path(args.output_path).write_text(json.dumps(artifact, indent=2) + "\n")
    return 0


def _resolve_metadata_payload(
    *,
    metadata_path: str | None,
    event_path: str | None,
    base_ref: str | None,
    head_ref: str,
) -> dict[str, object]:
    if metadata_path:
        return load_json_file(metadata_path, label="metadata")

    if event_path:
        event_payload = load_json_file(event_path, label="event payload")
        commits = collect_commit_metadata(base_ref, head_ref=head_ref) if base_ref else []
        return build_pr_metadata(event_payload=event_payload, commits=commits)

    return {}


def _load_optional_json(path: str | None, *, label: str) -> dict[str, object]:
    if not path:
        return {}
    return load_json_file(path, label=label)


def _has_section_inputs(args: argparse.Namespace) -> bool:
    return any(
        (
            args.historical_path,
            args.runtime_path,
            args.ownership_path,
            args.trust_baseline_path,
            args.trust_memory_path,
            args.trust_profile_metadata_path,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
