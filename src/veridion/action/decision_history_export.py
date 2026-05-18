"""Export org- and repo-scope decision-history analytics snapshots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from veridion.action.decision_history_config import load_history_service_config
from veridion.action.decision_history import analyze_history
from veridion.action.decision_history_store import analyze_history_store


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export Veridion decision-history analytics snapshots")
    parser.add_argument(
        "--history-path",
        action="append",
        default=[],
        help="Path to decision-history NDJSON, decision-event JSON, or exported event directory",
    )
    parser.add_argument("--config-path", help="Optional multi-tenant history service config JSON")
    parser.add_argument("--output-dir", required=True, help="Directory to write analytics snapshots")
    parser.add_argument("--since", help="Optional inclusive ISO-8601 lower bound for generated_at")
    parser.add_argument("--until", help="Optional inclusive ISO-8601 upper bound for generated_at")
    args = parser.parse_args(argv)

    if not args.history_path and not args.config_path:
        raise SystemExit("either --history-path or --config-path is required")

    if args.config_path:
        export_configured_decision_history(
            config_path=args.config_path,
            output_dir=args.output_dir,
            since=args.since,
            until=args.until,
        )
        return 0

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


def export_configured_decision_history(
    *,
    config_path: str | Path,
    output_dir: str | Path,
    since: str | None = None,
    until: str | None = None,
) -> None:
    config = load_history_service_config(config_path)
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)

    if config.sqlite_path or config.store_dsn:
        export_stored_decision_history(
            sqlite_path=config.sqlite_path,
            store_dsn=config.store_dsn,
            tenant_ids=tuple(tenant.tenant_id for tenant in config.tenants),
            output_dir=root,
            since=since,
            until=until,
        )
        return

    tenants_dir = root / "tenants"
    tenants_dir.mkdir(exist_ok=True)
    for tenant in config.tenants:
        tenant_root = tenants_dir / tenant.tenant_id
        export_decision_history(
            history_paths=tenant.history_paths,
            output_dir=tenant_root,
            since=since,
            until=until,
        )


def export_stored_decision_history(
    *,
    sqlite_path: str,
    store_dsn: str = "",
    tenant_ids: tuple[str, ...],
    output_dir: str | Path,
    since: str | None = None,
    until: str | None = None,
) -> None:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    tenants_dir = root / "tenants"
    tenants_dir.mkdir(exist_ok=True)
    for tenant_id in tenant_ids:
        tenant_root = tenants_dir / tenant_id
        tenant_root.mkdir(parents=True, exist_ok=True)
        payload = analyze_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id, since=since, until=until)
        (tenant_root / "overall.json").write_text(json.dumps(payload, indent=2) + "\n")
        repos_dir = tenant_root / "repositories"
        repos_dir.mkdir(exist_ok=True)
        for item in payload["policy_rollout"]["latest_by_repository"]:
            repository = str(item["repository"])
            repo_payload = analyze_history_store(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                repository=repository,
                since=since,
                until=until,
            )
            (repos_dir / f"{repository.replace('/', '_')}.json").write_text(json.dumps(repo_payload, indent=2) + "\n")
        packs_dir = tenant_root / "policy-packs"
        packs_dir.mkdir(exist_ok=True)
        for item in payload["by_policy_pack"]:
            pack_id = str(item["pack_id"])
            pack_payload = analyze_history_store(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                policy_pack_id=pack_id,
                since=since,
                until=until,
            )
            (packs_dir / f"{pack_id}.json").write_text(json.dumps(pack_payload, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
