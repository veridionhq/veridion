"""Persistent storage backends for Veridion decision-history events."""

from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from veridion.action.athena_queries import build_athena_query_pack
from veridion.action.decision_history import _load_history, analyze_history_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage persistent Veridion decision-history storage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="Ingest history files into a persistent store")
    _add_store_args(ingest)
    ingest.add_argument("--tenant-id", required=True)
    ingest.add_argument("--history-path", action="append", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze events from a persistent store")
    _add_store_args(analyze)
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
            store_dsn=args.store_dsn,
            tenant_id=args.tenant_id,
            history_paths=tuple(args.history_path),
        )
        return 0

    payload = analyze_history_store(
        sqlite_path=args.sqlite_path,
        store_dsn=args.store_dsn,
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


def ensure_history_store(*, sqlite_path: str | Path = "", store_dsn: str = "") -> None:
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        store.ensure_schema()


def upsert_history_store(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    history_paths: tuple[str, ...],
) -> int:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    events = _load_history(history_paths)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        for event in events:
            store.upsert_event(
                tenant_id=tenant_id,
                event_key=build_event_key(event),
                generated_at=str(event.get("generated_at", "")),
                repository=str(event.get("repository", "")),
                policy_pack_id=_policy_value(event, "pack_id"),
                event_payload=json.dumps(event, sort_keys=True),
            )
        store.commit()
    return len(events)


def analyze_history_store(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str = "",
    repository: str | None = None,
    policy_pack_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, object]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        events = store.load_events(
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
    sqlite_path: str | Path = "",
    store_dsn: str = "",
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
        "sqlite_path": str(sqlite_path) if sqlite_path else "",
        "store_dsn": store_dsn,
        "athena": payload,
    }
    Path(output_path).write_text(json.dumps(rendered, indent=2) + "\n")


@contextmanager
def open_history_store(*, sqlite_path: str | Path = "", store_dsn: str = "") -> Iterator[HistoryStore]:
    target_sqlite = str(sqlite_path) if sqlite_path else ""
    if store_dsn:
        store = _open_store_dsn(store_dsn)
        try:
            yield store
        finally:
            store.close()
        return
    if not target_sqlite:
        raise RuntimeError("either sqlite_path or store_dsn is required")
    store = SQLiteHistoryStore(target_sqlite)
    try:
        yield store
    finally:
        store.close()


class HistoryStore:
    def ensure_schema(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def upsert_event(
        self,
        *,
        tenant_id: str,
        event_key: str,
        generated_at: str,
        repository: str,
        policy_pack_id: str,
        event_payload: str,
    ) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def load_events(
        self,
        *,
        tenant_id: str,
        repository: str | None,
        policy_pack_id: str | None,
        since: str | None,
        until: str | None,
    ) -> tuple[dict[str, object], ...]:  # pragma: no cover - interface
        raise NotImplementedError

    def record_materialization_run(
        self,
        *,
        run_id: str,
        tenant_id: str,
        generated_at: str,
        output_root: str,
        run_path: str,
        since: str,
        until: str,
        status: str,
        athena_database: str,
        athena_table: str,
        athena_s3_location: str,
    ) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def list_materialization_runs(
        self,
        *,
        tenant_id: str,
        limit: int = 20,
    ) -> tuple[dict[str, str], ...]:  # pragma: no cover - interface
        raise NotImplementedError

    def commit(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class SQLiteHistoryStore(HistoryStore):
    def __init__(self, sqlite_path: str) -> None:
        self.connection = sqlite3.connect(sqlite_path)

    def ensure_schema(self) -> None:
        self.connection.execute(
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
        self.connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_decision_events_lookup
            ON decision_events (tenant_id, generated_at, repository, policy_pack_id)
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS materialization_runs (
                tenant_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                output_root TEXT NOT NULL,
                run_path TEXT NOT NULL,
                since_value TEXT NOT NULL,
                until_value TEXT NOT NULL,
                status TEXT NOT NULL,
                athena_database TEXT NOT NULL,
                athena_table TEXT NOT NULL,
                athena_s3_location TEXT NOT NULL,
                PRIMARY KEY (tenant_id, run_id)
            )
            """
        )
        self.connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_materialization_runs_lookup
            ON materialization_runs (tenant_id, generated_at)
            """
        )

    def upsert_event(
        self,
        *,
        tenant_id: str,
        event_key: str,
        generated_at: str,
        repository: str,
        policy_pack_id: str,
        event_payload: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO decision_events
            (tenant_id, event_key, generated_at, repository, policy_pack_id, event_payload)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (tenant_id, event_key, generated_at, repository, policy_pack_id, event_payload),
        )

    def load_events(
        self,
        *,
        tenant_id: str,
        repository: str | None,
        policy_pack_id: str | None,
        since: str | None,
        until: str | None,
    ) -> tuple[dict[str, object], ...]:
        query, params = _build_select_query(
            placeholder="?",
            tenant_id=tenant_id,
            repository=repository,
            policy_pack_id=policy_pack_id,
            since=since,
            until=until,
        )
        rows = self.connection.execute(query, params).fetchall()
        return tuple(json.loads(row[0]) for row in rows)

    def record_materialization_run(
        self,
        *,
        run_id: str,
        tenant_id: str,
        generated_at: str,
        output_root: str,
        run_path: str,
        since: str,
        until: str,
        status: str,
        athena_database: str,
        athena_table: str,
        athena_s3_location: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO materialization_runs
            (tenant_id, run_id, generated_at, output_root, run_path, since_value, until_value, status, athena_database, athena_table, athena_s3_location)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                run_id,
                generated_at,
                output_root,
                run_path,
                since,
                until,
                status,
                athena_database,
                athena_table,
                athena_s3_location,
            ),
        )

    def list_materialization_runs(
        self,
        *,
        tenant_id: str,
        limit: int = 20,
    ) -> tuple[dict[str, str], ...]:
        query = """
            SELECT tenant_id, run_id, generated_at, output_root, run_path, since_value, until_value, status, athena_database, athena_table, athena_s3_location
            FROM materialization_runs
        """
        params: list[object] = []
        if tenant_id:
            query += " WHERE tenant_id = ?"
            params.append(tenant_id)
        query += " ORDER BY generated_at DESC, run_id DESC LIMIT ?"
        params.append(limit)
        rows = self.connection.execute(query, params).fetchall()
        return tuple(_materialization_row_to_dict(row) for row in rows)

    def commit(self) -> None:
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


class PostgresHistoryStore(HistoryStore):
    def __init__(self, connection, module_name: str) -> None:
        self.connection = connection
        self.module_name = module_name

    def ensure_schema(self) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
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
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_decision_events_lookup
                ON decision_events (tenant_id, generated_at, repository, policy_pack_id)
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS materialization_runs (
                    tenant_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    output_root TEXT NOT NULL,
                    run_path TEXT NOT NULL,
                    since_value TEXT NOT NULL,
                    until_value TEXT NOT NULL,
                    status TEXT NOT NULL,
                    athena_database TEXT NOT NULL,
                    athena_table TEXT NOT NULL,
                    athena_s3_location TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, run_id)
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_materialization_runs_lookup
                ON materialization_runs (tenant_id, generated_at)
                """
            )

    def upsert_event(
        self,
        *,
        tenant_id: str,
        event_key: str,
        generated_at: str,
        repository: str,
        policy_pack_id: str,
        event_payload: str,
    ) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO decision_events
                (tenant_id, event_key, generated_at, repository, policy_pack_id, event_payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_key)
                DO UPDATE SET
                  generated_at = EXCLUDED.generated_at,
                  repository = EXCLUDED.repository,
                  policy_pack_id = EXCLUDED.policy_pack_id,
                  event_payload = EXCLUDED.event_payload
                """,
                (tenant_id, event_key, generated_at, repository, policy_pack_id, event_payload),
            )

    def load_events(
        self,
        *,
        tenant_id: str,
        repository: str | None,
        policy_pack_id: str | None,
        since: str | None,
        until: str | None,
    ) -> tuple[dict[str, object], ...]:
        query, params = _build_select_query(
            placeholder="%s",
            tenant_id=tenant_id,
            repository=repository,
            policy_pack_id=policy_pack_id,
            since=since,
            until=until,
        )
        with self.connection.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()
        return tuple(json.loads(row[0]) for row in rows)

    def record_materialization_run(
        self,
        *,
        run_id: str,
        tenant_id: str,
        generated_at: str,
        output_root: str,
        run_path: str,
        since: str,
        until: str,
        status: str,
        athena_database: str,
        athena_table: str,
        athena_s3_location: str,
    ) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO materialization_runs
                (tenant_id, run_id, generated_at, output_root, run_path, since_value, until_value, status, athena_database, athena_table, athena_s3_location)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, run_id)
                DO UPDATE SET
                  generated_at = EXCLUDED.generated_at,
                  output_root = EXCLUDED.output_root,
                  run_path = EXCLUDED.run_path,
                  since_value = EXCLUDED.since_value,
                  until_value = EXCLUDED.until_value,
                  status = EXCLUDED.status,
                  athena_database = EXCLUDED.athena_database,
                  athena_table = EXCLUDED.athena_table,
                  athena_s3_location = EXCLUDED.athena_s3_location
                """,
                (
                    tenant_id,
                    run_id,
                    generated_at,
                    output_root,
                    run_path,
                    since,
                    until,
                    status,
                    athena_database,
                    athena_table,
                    athena_s3_location,
                ),
            )

    def list_materialization_runs(
        self,
        *,
        tenant_id: str,
        limit: int = 20,
    ) -> tuple[dict[str, str], ...]:
        query = """
            SELECT tenant_id, run_id, generated_at, output_root, run_path, since_value, until_value, status, athena_database, athena_table, athena_s3_location
            FROM materialization_runs
        """
        params: list[object] = []
        if tenant_id:
            query += " WHERE tenant_id = %s"
            params.append(tenant_id)
        query += " ORDER BY generated_at DESC, run_id DESC LIMIT %s"
        params.append(limit)
        with self.connection.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()
        return tuple(_materialization_row_to_dict(row) for row in rows)

    def commit(self) -> None:
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


def _open_store_dsn(store_dsn: str) -> HistoryStore:
    if store_dsn.startswith("sqlite:///"):
        return SQLiteHistoryStore(store_dsn[len("sqlite:///") :])
    try:
        import psycopg  # type: ignore

        return PostgresHistoryStore(psycopg.connect(store_dsn), "psycopg")
    except Exception:
        try:
            import psycopg2  # type: ignore

            return PostgresHistoryStore(psycopg2.connect(store_dsn), "psycopg2")
        except Exception as exc:  # pragma: no cover - import guard
            raise RuntimeError("postgres history store requires psycopg or psycopg2") from exc


def _add_store_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sqlite-path", help="SQLite history store path")
    parser.add_argument("--store-dsn", help="Persistent history store DSN; postgres://... or sqlite:///...")


def _build_select_query(
    *,
    placeholder: str,
    tenant_id: str,
    repository: str | None,
    policy_pack_id: str | None,
    since: str | None,
    until: str | None,
) -> tuple[str, list[str]]:
    query = "SELECT event_payload FROM decision_events WHERE 1=1"
    params: list[str] = []
    if tenant_id:
        query += f" AND tenant_id = {placeholder}"
        params.append(tenant_id)
    if repository:
        query += f" AND repository = {placeholder}"
        params.append(repository)
    if policy_pack_id:
        query += f" AND policy_pack_id = {placeholder}"
        params.append(policy_pack_id)
    if since:
        query += f" AND generated_at >= {placeholder}"
        params.append(since)
    if until:
        query += f" AND generated_at <= {placeholder}"
        params.append(until)
    query += " ORDER BY generated_at ASC"
    return query, params


def _decision_value(event: dict[str, object], key: str) -> str:
    decision = event.get("decision")
    return decision.get(key, "") if isinstance(decision, dict) and isinstance(decision.get(key, ""), str) else ""


def _policy_value(event: dict[str, object], key: str) -> str:
    policy = event.get("policy")
    return policy.get(key, "") if isinstance(policy, dict) and isinstance(policy.get(key, ""), str) else ""


def record_materialization_run(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    run_id: str,
    tenant_id: str,
    generated_at: str,
    output_root: str | Path,
    run_path: str | Path,
    since: str | None = None,
    until: str | None = None,
    status: str = "completed",
    athena_database: str | None = None,
    athena_table: str = "",
    athena_s3_location: str | None = None,
) -> None:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        store.record_materialization_run(
            run_id=run_id,
            tenant_id=tenant_id,
            generated_at=generated_at,
            output_root=str(output_root),
            run_path=str(run_path),
            since=since or "",
            until=until or "",
            status=status,
            athena_database=athena_database or "",
            athena_table=athena_table,
            athena_s3_location=athena_s3_location or "",
        )
        store.commit()


def list_materialization_runs(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str = "",
    limit: int = 20,
) -> tuple[dict[str, str], ...]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.list_materialization_runs(tenant_id=tenant_id, limit=limit)


def _materialization_row_to_dict(row: tuple[object, ...]) -> dict[str, str]:
    return {
        "tenant_id": str(row[0]),
        "run_id": str(row[1]),
        "generated_at": str(row[2]),
        "output_root": str(row[3]),
        "run_path": str(row[4]),
        "since": str(row[5]),
        "until": str(row[6]),
        "status": str(row[7]),
        "athena_database": str(row[8]),
        "athena_table": str(row[9]),
        "athena_s3_location": str(row[10]),
    }


if __name__ == "__main__":
    raise SystemExit(main())
