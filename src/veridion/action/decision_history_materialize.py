"""Materialize timestamped decision-history analytics snapshots."""

from __future__ import annotations

import argparse
import shutil
from datetime import datetime, timezone
from pathlib import Path

from veridion.action.decision_history_export import export_configured_decision_history, export_decision_history


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize Veridion decision-history analytics snapshots")
    parser.add_argument(
        "--history-path",
        action="append",
        default=[],
        help="Path to decision-history NDJSON, decision-event JSON, or exported event directory",
    )
    parser.add_argument("--config-path", help="Optional multi-tenant history service config JSON")
    parser.add_argument("--output-root", required=True, help="Root directory for materialized runs")
    parser.add_argument("--run-id", help="Optional run identifier; defaults to current UTC timestamp")
    parser.add_argument("--since", help="Optional inclusive ISO-8601 lower bound for generated_at")
    parser.add_argument("--until", help="Optional inclusive ISO-8601 upper bound for generated_at")
    args = parser.parse_args(argv)

    if not args.history_path and not args.config_path:
        raise SystemExit("either --history-path or --config-path is required")

    materialize_decision_history(
        history_paths=tuple(args.history_path),
        config_path=args.config_path,
        output_root=args.output_root,
        run_id=args.run_id or _default_run_id(),
        since=args.since,
        until=args.until,
    )
    return 0


def materialize_decision_history(
    *,
    history_paths: tuple[str, ...],
    config_path: str | None,
    output_root: str | Path,
    run_id: str,
    since: str | None = None,
    until: str | None = None,
) -> Path:
    root = Path(output_root)
    runs_dir = root / "runs"
    latest_dir = root / "latest"
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    if config_path:
        export_configured_decision_history(
            config_path=config_path,
            output_dir=run_dir,
            since=since,
            until=until,
        )
    else:
        export_decision_history(
            history_paths=history_paths,
            output_dir=run_dir,
            since=since,
            until=until,
        )

    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    shutil.copytree(run_dir, latest_dir)
    return run_dir


def _default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    raise SystemExit(main())
