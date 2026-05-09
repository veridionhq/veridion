"""Build PR metadata artifacts from GitHub event payloads and git history."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


CO_AUTHOR_PATTERN = re.compile(r"^co-authored-by:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
FIELD_SEPARATOR = "\x1f"
RECORD_SEPARATOR = "\x1e"


def build_pr_metadata(
    *,
    event_payload: dict[str, object],
    commits: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build the metadata JSON consumed by Veridion analysis."""

    pull_request = event_payload.get("pull_request", {})
    if not isinstance(pull_request, dict):
        pull_request = {}

    return {
        "title": _as_string(pull_request.get("title")),
        "body": _as_string(pull_request.get("body")),
        "labels": _extract_labels(pull_request.get("labels")),
        "commits": commits or [],
    }


def collect_commit_metadata(base_ref: str, *, head_ref: str = "HEAD") -> list[dict[str, object]]:
    """Collect commit metadata for the PR commit range using git log."""

    revision_range = f"origin/{base_ref}..{head_ref}"
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


def parse_git_log_output(text: str) -> list[dict[str, object]]:
    """Parse the compact git log output into commit metadata records."""

    commits: list[dict[str, object]] = []
    for raw_record in text.split(RECORD_SEPARATOR):
        record = raw_record.strip()
        if not record:
            continue
        fields = record.split(FIELD_SEPARATOR, maxsplit=2)
        if len(fields) != 3:
            continue
        author_name, author_email, message = fields
        normalized_message = message.strip()
        commits.append(
            {
                "message": normalized_message,
                "author_name": author_name.strip(),
                "author_email": author_email.strip(),
                "co_authors": _extract_co_authors(normalized_message),
            }
        )
    return commits


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for building PR metadata artifacts."""

    parser = argparse.ArgumentParser(description="Build Veridion PR metadata artifact")
    parser.add_argument("--event-path", required=True, help="Path to the GitHub event payload JSON")
    parser.add_argument("--output-path", required=True, help="Where to write the PR metadata JSON")
    parser.add_argument("--base-ref", help="PR base ref used to collect commit metadata from git")
    parser.add_argument("--head-ref", default="HEAD", help="Head revision used for commit metadata collection")
    args = parser.parse_args(argv)

    event_payload = json.loads(Path(args.event_path).read_text())
    commits = collect_commit_metadata(args.base_ref, head_ref=args.head_ref) if args.base_ref else []
    metadata = build_pr_metadata(event_payload=event_payload, commits=commits)
    Path(args.output_path).write_text(json.dumps(metadata, indent=2) + "\n")
    return 0


def _extract_labels(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    labels: list[str] = []
    for item in value:
        if isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                labels.append(name.strip())
    return labels


def _extract_co_authors(message: str) -> list[str]:
    return [match.group(1).strip() for match in CO_AUTHOR_PATTERN.finditer(message) if match.group(1).strip()]


def _as_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


if __name__ == "__main__":
    raise SystemExit(main())
