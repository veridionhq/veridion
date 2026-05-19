"""Materialize timestamped decision-history analytics snapshots."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from veridion.action.decision_history_config import load_history_service_config
from veridion.action.decision_history_export import export_configured_decision_history, export_decision_history
from veridion.action.decision_history_store import materialize_warehouse_queries, record_materialization_run


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
    parser.add_argument("--athena-database", help="Optional Athena database for generated query packs")
    parser.add_argument("--athena-table", default="veridion_decision_events", help="Athena table name")
    parser.add_argument("--athena-s3-location-template", help="Optional format string for tenant-specific S3 locations; supports {tenant_id}")
    parser.add_argument("--schedule-id", help="Optional materialization schedule identifier")
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
        athena_database=args.athena_database,
        athena_table=args.athena_table,
        athena_s3_location_template=args.athena_s3_location_template,
        schedule_id=args.schedule_id or "",
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
    athena_database: str | None = None,
    athena_table: str = "veridion_decision_events",
    athena_s3_location_template: str | None = None,
    tenant_ids: tuple[str, ...] = (),
    schedule_id: str = "",
) -> Path:
    root = Path(output_root)
    runs_dir = root / "runs"
    latest_dir = root / "latest"
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    config = load_history_service_config(config_path) if config_path else None
    if config_path:
        export_configured_decision_history(
            config_path=config_path,
            output_dir=run_dir,
            since=since,
            until=until,
            tenant_ids=tenant_ids,
        )
    else:
        export_decision_history(
            history_paths=history_paths,
            output_dir=run_dir,
            since=since,
            until=until,
        )

    _write_run_manifest(
        run_dir / "run-manifest.json",
        run_id=run_id,
        history_paths=history_paths,
        config_path=config_path,
        since=since,
        until=until,
        athena_database=athena_database,
        athena_table=athena_table,
        athena_s3_location_template=athena_s3_location_template,
        schedule_id=schedule_id,
    )

    if config and (config.sqlite_path or config.store_dsn) and athena_database and athena_s3_location_template:
        warehouse_dir = run_dir / "warehouse"
        warehouse_dir.mkdir(exist_ok=True)
        selected_tenants = tuple(tenant for tenant in config.tenants if not tenant_ids or tenant.tenant_id in tenant_ids)
        generated_at = _now_iso()
        for tenant in selected_tenants:
            materialize_warehouse_queries(
                sqlite_path=config.sqlite_path,
                store_dsn=config.store_dsn,
                tenant_id=tenant.tenant_id,
                output_path=warehouse_dir / f"{tenant.tenant_id}.athena.json",
                database=athena_database,
                table=athena_table,
                s3_location=athena_s3_location_template.format(tenant_id=tenant.tenant_id),
                since=since,
            )
            record_materialization_run(
                sqlite_path=config.sqlite_path,
                store_dsn=config.store_dsn,
                run_id=run_id,
                tenant_id=tenant.tenant_id,
                generated_at=generated_at,
                output_root=root,
                run_path=run_dir,
                since=since,
                until=until,
                athena_database=athena_database,
                athena_table=athena_table,
                athena_s3_location=athena_s3_location_template.format(tenant_id=tenant.tenant_id),
            )
    elif config and (config.sqlite_path or config.store_dsn):
        generated_at = _now_iso()
        selected_tenants = tuple(tenant for tenant in config.tenants if not tenant_ids or tenant.tenant_id in tenant_ids)
        for tenant in selected_tenants:
            record_materialization_run(
                sqlite_path=config.sqlite_path,
                store_dsn=config.store_dsn,
                run_id=run_id,
                tenant_id=tenant.tenant_id,
                generated_at=generated_at,
                output_root=root,
                run_path=run_dir,
                since=since,
                until=until,
                athena_database=athena_database,
                athena_table=athena_table,
                athena_s3_location="",
            )

    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    shutil.copytree(run_dir, latest_dir)
    return run_dir


def _default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_run_manifest(
    path: Path,
    *,
    run_id: str,
    history_paths: tuple[str, ...],
    config_path: str | None,
    since: str | None,
    until: str | None,
    athena_database: str | None,
    athena_table: str,
    athena_s3_location_template: str | None,
    schedule_id: str,
) -> None:
    payload = {
        "schema_version": 1,
        "source": "veridion.action.decision_history_materialize@1",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "inputs": {
            "history_paths": list(history_paths),
            "config_path": config_path or "",
            "since": since or "",
            "until": until or "",
            "schedule_id": schedule_id,
        },
        "warehouse": {
            "athena_database": athena_database or "",
            "athena_table": athena_table,
            "athena_s3_location_template": athena_s3_location_template or "",
            "target_kind": "athena" if athena_database else "",
        },
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
