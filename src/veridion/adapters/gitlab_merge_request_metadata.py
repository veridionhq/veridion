"""Build merge request metadata artifacts from GitLab event payloads and git history."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from veridion.action.metadata_builder import parse_git_log_output


def build_merge_request_metadata(
    *,
    event_payload: dict[str, object],
    commits: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build the metadata JSON consumed by Veridion analysis."""

    attributes = event_payload.get("object_attributes", {})
    if not isinstance(attributes, dict):
        attributes = {}

    labels = _extract_labels(attributes.get("labels"))
    return {
        "title": _as_string(attributes.get("title")),
        "body": _as_string(attributes.get("description")),
        "labels": labels,
        "commits": commits or [],
    }


def collect_commit_metadata(
    base_ref: str,
    *,
    head_ref: str = "HEAD",
    remote_name: str = "origin",
) -> list[dict[str, object]]:
    """Collect commit metadata for the merge request commit range using git log."""

    revision_range = f"{remote_name}/{base_ref}..{head_ref}"
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                "--format=%an%x1f%ae%x1f%B%x1e",
                revision_range,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"git log failed for range {revision_range!r}") from exc
    return parse_git_log_output(result.stdout)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for building GitLab merge request metadata artifacts."""

    parser = argparse.ArgumentParser(description="Build Veridion merge request metadata artifact from GitLab event JSON")
    parser.add_argument("--event-path", required=True, help="Path to the GitLab event payload JSON")
    parser.add_argument("--output-path", required=True, help="Where to write the metadata JSON")
    parser.add_argument("--base-ref", help="Target branch used to collect commit metadata from git")
    parser.add_argument("--head-ref", default="HEAD", help="Head revision used for commit metadata collection")
    parser.add_argument("--remote-name", default="origin", help="Remote name used for commit metadata collection")
    args = parser.parse_args(argv)

    event_payload = json.loads(Path(args.event_path).read_text())
    commits = collect_commit_metadata(args.base_ref, head_ref=args.head_ref, remote_name=args.remote_name) if args.base_ref else []
    metadata = build_merge_request_metadata(event_payload=event_payload, commits=commits)
    Path(args.output_path).write_text(json.dumps(metadata, indent=2) + "\n")
    return 0


def _extract_labels(value: object) -> list[str]:
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _as_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


if __name__ == "__main__":
    raise SystemExit(main())
