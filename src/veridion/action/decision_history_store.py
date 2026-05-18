"""Persistent SQLite storage for Veridion decision-history events."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from veridion.action.athena_queries import build_athena_query_pack
from veridion.action.decision_history import _load_history, analyze_history_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage persistent Veridion decision-history storage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="Ingest history files into a SQLite store")
    ingest.add_argument("--sqlite-path", required=True)
    ingest.add_argument("--tenant-id", required=True)
    ingest.add_argument("--history-path", action="append", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze events from a SQLite store")
    analyze.add_argument("--sqlite-path", required=True)
    analyze.add_argument("--tenant-id")
    analyze.add_argument("--repository")
    analyze.add_argument("--policy-pack-id")
    analyze.add_argument("--since")
    analyze.add_argument("--until")
    analyze.add_argument("--output-path")

    args = parser.parse_args(argv)
    if args.command == "ingest":
        upsert_history_store(
            sqlite_path=args.sqlite_path,
            tenant_id=args.tenant_id,
            history_paths=tuple(args.history_path),
        )
        return 0

    payload = analyze_history_store(
        sqlite_path=args.sqlite_path,
        tenant_id=args.tenant_id or "",
        repository=args.repository,
        policy_pack_id=args.policy_pack_id,
        since=args.since,
        until=args.until,
    )
    rendered = json.dumps(payload, indent=2) + "\n"
    if args.output_path:
        Path(args.output_path).write_text(rendered)
    print(rendered, end="")
    return 0


def ensure_history_store(sqlite_path: str | Path) -> None:
    with sqlite3.connect(sqlite_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS decision_events (
                tenant_id TEXT NOT NULL,
                event_key TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                repository TEXT NOT NULL,
                policy_pack_id TEXT NOT NULL,
                event_payload TEXT NOT NULL,
                PRIMARY KEY (tenant_id, event_key)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_decision_events_lookup
            ON decision_events (tenant_id, generated_at, repository, policy_pack_id)
            """
        )


def upsert_history_store(
    *,
    sqlite_path: str | Path,
    tenant_id: str,
    history_paths: tuple[str, ...],
) -> int:
    ensure_history_store(sqlite_path)
    events = _load_history(history_paths)
    with sqlite3.connect(sqlite_path) as connection:
        for event in events:
            event_key = build_event_key(event)
            connection.execute(
                """
                INSERT OR REPLACE INTO decision_events
                (tenant_id, event_key, generated_at, repository, policy_pack_id, event_payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    event_key,
                    str(event.get("generated_at", "")),
                    str(event.get("repository", "")),
                    _policy_value(event, "pack_id"),
                    json.dumps(event, sort_keys=True),
                ),
            )
        connection.commit()
    return len(events)


def analyze_history_store(
    *,
    sqlite_path: str | Path,
    tenant_id: str = "",
    repository: str | None = None,
    policy_pack_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, object]:
    ensure_history_store(sqlite_path)
    events = _load_store_events(
        sqlite_path=sqlite_path,
        tenant_id=tenant_id,
        repository=repository,
        policy_pack_id=policy_pack_id,
        since=since,
        until=until,
    )
    return analyze_history_events(events)


def build_event_key(event: dict[str, object]) -> str:
    return "|".join(
        [
            str(event.get("generated_at", "")),
            str(event.get("repository", "")),
            str(event.get("pull_request_number", "")),
            _decision_value(event, "verdict"),
            _policy_value(event, "pack_id"),
            _policy_value(event, "pack_version"),
        ]
    )


def materialize_warehouse_queries(
    *,
    sqlite_path: str | Path,
    tenant_id: str,
    output_path: str | Path,
    database: str,
    table: str,
    s3_location: str,
    since: str | None = None,
) -> None:
    payload = build_athena_query_pack(
        database=database,
        table=table,
        s3_location=s3_location,
        repository="",
        since=since or "",
    )
    rendered = {
        "schema_version": 1,
        "source": "veridion.action.decision_history_store@1",
        "tenant_id": tenant_id,
        "sqlite_path": str(sqlite_path),
        "athena": payload,
    }
    Path(output_path).write_text(json.dumps(rendered, indent=2) + "\n")


def _load_store_events(
    *,
    sqlite_path: str | Path,
    tenant_id: str,
    repository: str | None,
    policy_pack_id: str | None,
    since: str | None,
    until: str | None,
) -> tuple[dict[str, object], ...]:
    query = "SELECT event_payload FROM decision_events WHERE 1=1"
    params: list[str] = []
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    if repository:
        query += " AND repository = ?"
        params.append(repository)
    if policy_pack_id:
        query += " AND policy_pack_id = ?"
        params.append(policy_pack_id)
    if since:
        query += " AND generated_at >= ?"
        params.append(since)
    if until:
        query += " AND generated_at <= ?"
        params.append(until)
    query += " ORDER BY generated_at ASC"

    with sqlite3.connect(sqlite_path) as connection:
        rows = connection.execute(query, params).fetchall()
    return tuple(json.loads(row[0]) for row in rows)


def _decision_value(event: dict[str, object], key: str) -> str:
    decision = event.get("decision")
    return decision.get(key, "") if isinstance(decision, dict) and isinstance(decision.get(key, ""), str) else ""


def _policy_value(event: dict[str, object], key: str) -> str:
    policy = event.get("policy")
    return policy.get(key, "") if isinstance(policy, dict) and isinstance(policy.get(key, ""), str) else ""


if __name__ == "__main__":
    raise SystemExit(main())
