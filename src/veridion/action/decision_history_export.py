"""Export org- and repo-scope decision-history analytics snapshots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from veridion.action.decision_history import analyze_history


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export Veridion decision-history analytics snapshots")
    parser.add_argument(
        "--history-path",
        action="append",
        required=True,
        help="Path to decision-history NDJSON, decision-event JSON, or exported event directory",
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write analytics snapshots")
    parser.add_argument("--since", help="Optional inclusive ISO-8601 lower bound for generated_at")
    parser.add_argument("--until", help="Optional inclusive ISO-8601 upper bound for generated_at")
    args = parser.parse_args(argv)

    export_decision_history(
        history_paths=tuple(args.history_path),
        output_dir=args.output_dir,
        since=args.since,
        until=args.until,
    )
    return 0


def export_decision_history(
    *,
    history_paths: tuple[str, ...],
    output_dir: str | Path,
    since: str | None = None,
    until: str | None = None,
) -> None:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)

    overall = analyze_history(history_paths=history_paths, since=since, until=until)
    (root / "overall.json").write_text(json.dumps(overall, indent=2) + "\n")

    repositories = sorted(str(item["repository"]) for item in overall["policy_rollout"]["latest_by_repository"])
    repos_dir = root / "repositories"
    repos_dir.mkdir(exist_ok=True)
    for repository in repositories:
        payload = analyze_history(history_paths=history_paths, repository=repository, since=since, until=until)
        (repos_dir / f"{repository.replace('/', '_')}.json").write_text(json.dumps(payload, indent=2) + "\n")

    packs_dir = root / "policy-packs"
    packs_dir.mkdir(exist_ok=True)
    seen_pack_ids = sorted({str(item["pack_id"]) for item in overall["by_policy_pack"] if item.get("pack_id")})
    for pack_id in seen_pack_ids:
        payload = analyze_history(history_paths=history_paths, policy_pack_id=pack_id, since=since, until=until)
        (packs_dir / f"{pack_id}.json").write_text(json.dumps(payload, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
