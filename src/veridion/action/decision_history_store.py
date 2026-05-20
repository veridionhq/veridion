"""Persistent storage backends for Veridion decision-history events."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from veridion.action.athena_queries import build_athena_query_pack
from veridion.action.decision_history_config import HistoryToken
from veridion.action.decision_history import _load_history, analyze_history_events

STORE_SCHEMA_VERSION = 5
STORE_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("001_decision_events", "core decision event history"),
    ("002_materialization_runs", "managed materialization tracking"),
    ("003_catalog_models", "tenant org/project/service catalog"),
    ("004_control_plane_state", "tenant admin, secret, session, and producer state"),
    ("005_producer_client_audit", "producer token lifecycle metadata and audit trail"),
)


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

    status = subparsers.add_parser("status", help="Inspect persistent store schema and counts")
    _add_store_args(status)
    status.add_argument("--tenant-id")

    migrate = subparsers.add_parser("migrate", help="Apply store schema migrations")
    _add_store_args(migrate)

    args = parser.parse_args(argv)
    if args.command == "ingest":
        upsert_history_store(
            sqlite_path=args.sqlite_path,
            store_dsn=args.store_dsn,
            tenant_id=args.tenant_id,
            history_paths=tuple(args.history_path),
        )
        return 0
    if args.command == "status":
        payload = get_history_store_status(
            sqlite_path=args.sqlite_path,
            store_dsn=args.store_dsn,
            tenant_id=args.tenant_id or "",
        )
        rendered = json.dumps(payload, indent=2) + "\n"
        print(rendered, end="")
        return 0
    if args.command == "migrate":
        ensure_history_store(sqlite_path=args.sqlite_path, store_dsn=args.store_dsn)
        payload = get_history_store_status(sqlite_path=args.sqlite_path, store_dsn=args.store_dsn)
        rendered = json.dumps(payload, indent=2) + "\n"
        print(rendered, end="")
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


def upsert_decision_event_store(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    event: dict[str, object],
) -> None:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        store.upsert_event(
            tenant_id=tenant_id,
            event_key=build_event_key(event),
            generated_at=str(event.get("generated_at", "")),
            repository=str(event.get("repository", "")),
            policy_pack_id=_policy_value(event, "pack_id"),
            event_payload=json.dumps(event, sort_keys=True),
        )
        store.commit()


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


def get_history_store_status(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str = "",
) -> dict[str, object]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.get_service_status(tenant_id=tenant_id)


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

    def list_catalog(self, *, tenant_id: str) -> dict[str, tuple[dict[str, str], ...]]:  # pragma: no cover - interface
        raise NotImplementedError

    def upsert_managed_tenant(
        self,
        *,
        tenant_id: str,
        display_name: str,
        organization_name: str,
        status: str,
    ) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def list_managed_tenants(self) -> tuple[dict[str, str], ...]:  # pragma: no cover - interface
        raise NotImplementedError

    def upsert_provider_secret_ref(
        self,
        *,
        tenant_id: str,
        secret_name: str,
        provider: str,
        secret_ref: str,
        description: str,
    ) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def list_provider_secret_refs(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:  # pragma: no cover - interface
        raise NotImplementedError

    def upsert_service_user(
        self,
        *,
        tenant_id: str,
        user_id: str,
        principal_name: str,
        email: str,
        roles_csv: str,
        status: str,
    ) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def list_service_users(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:  # pragma: no cover - interface
        raise NotImplementedError

    def create_session(
        self,
        *,
        session_id: str,
        tenant_id: str,
        user_id: str,
        principal_name: str,
        auth_type: str,
        roles_csv: str,
        status: str,
        expires_at: str,
    ) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def list_sessions(self, *, tenant_id: str, limit: int = 20) -> tuple[dict[str, str], ...]:  # pragma: no cover - interface
        raise NotImplementedError

    def create_producer_client(
        self,
        *,
        tenant_id: str,
        client_id: str,
        display_name: str,
        roles_csv: str,
        status: str,
    ) -> dict[str, str]:  # pragma: no cover - interface
        raise NotImplementedError

    def update_producer_client_status(self, *, tenant_id: str, client_id: str, status: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def list_producer_clients(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:  # pragma: no cover - interface
        raise NotImplementedError

    def list_producer_client_audit(self, *, tenant_id: str, client_id: str, limit: int = 20) -> tuple[dict[str, str], ...]:  # pragma: no cover - interface
        raise NotImplementedError

    def resolve_producer_token(self, *, token: str) -> HistoryToken | None:  # pragma: no cover - interface
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

    def get_service_status(
        self,
        *,
        tenant_id: str,
    ) -> dict[str, object]:  # pragma: no cover - interface
        raise NotImplementedError

    def commit(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class SQLiteHistoryStore(HistoryStore):
    def __init__(self, sqlite_path: str) -> None:
        self.connection = sqlite3.connect(sqlite_path)

    def ensure_schema(self) -> None:
        _ensure_migration_table(self.connection)
        _apply_sqlite_migrations(self.connection)
        _record_migrations_sqlite(self.connection)
        self.connection.commit()

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
        self._upsert_catalog(
            tenant_id=tenant_id,
            event_payload=event_payload,
            repository=repository,
        )

    def _upsert_catalog(self, *, tenant_id: str, event_payload: str, repository: str) -> None:
        event = json.loads(event_payload)
        organization_id = _catalog_value(event, "organization") or _repo_owner(repository)
        project_id = _catalog_value(event, "project") or repository
        service_id = _catalog_value(event, "service") or _repo_name(repository)
        trust = event.get("trust_context") if isinstance(event.get("trust_context"), dict) else {}
        service_owner = str(trust.get("service_owner", "")) if isinstance(trust, dict) else ""
        owning_team = str(trust.get("owning_team", "")) if isinstance(trust, dict) else ""
        criticality = str(trust.get("service_criticality", "")) if isinstance(trust, dict) else ""
        self.connection.execute(
            "INSERT OR REPLACE INTO organizations (tenant_id, organization_id, display_name) VALUES (?, ?, ?)",
            (tenant_id, organization_id, organization_id),
        )
        self.connection.execute(
            "INSERT OR REPLACE INTO projects (tenant_id, organization_id, project_id, display_name, repository) VALUES (?, ?, ?, ?, ?)",
            (tenant_id, organization_id, project_id, project_id, repository),
        )
        self.connection.execute(
            """
            INSERT OR REPLACE INTO services
            (tenant_id, organization_id, project_id, service_id, display_name, repository, service_owner, owning_team, service_criticality)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (tenant_id, organization_id, project_id, service_id, service_id, repository, service_owner, owning_team, criticality),
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

    def get_service_status(
        self,
        *,
        tenant_id: str,
    ) -> dict[str, object]:
        return _build_service_status(
            backend="sqlite",
            schema_rows=self.connection.execute(
                "SELECT migration_id, description, applied_at FROM schema_migrations ORDER BY migration_id ASC"
            ).fetchall(),
            event_count=_count_sqlite_rows(self.connection, "decision_events", tenant_id=tenant_id),
            materialization_count=_count_sqlite_rows(self.connection, "materialization_runs", tenant_id=tenant_id),
            tenant_count=_count_distinct_tenants_sqlite(self.connection),
            tenant_id=tenant_id,
        )

    def list_catalog(self, *, tenant_id: str) -> dict[str, tuple[dict[str, str], ...]]:
        tenant_filter = " WHERE tenant_id = ?" if tenant_id else ""
        params: list[object] = [tenant_id] if tenant_id else []
        orgs = tuple(
            {"tenant_id": str(row[0]), "organization_id": str(row[1]), "display_name": str(row[2])}
            for row in self.connection.execute(
                f"SELECT tenant_id, organization_id, display_name FROM organizations{tenant_filter} ORDER BY organization_id ASC",
                params,
            ).fetchall()
        )
        projects = tuple(
            {
                "tenant_id": str(row[0]),
                "organization_id": str(row[1]),
                "project_id": str(row[2]),
                "display_name": str(row[3]),
                "repository": str(row[4]),
            }
            for row in self.connection.execute(
                f"SELECT tenant_id, organization_id, project_id, display_name, repository FROM projects{tenant_filter} ORDER BY project_id ASC",
                params,
            ).fetchall()
        )
        services = tuple(
            {
                "tenant_id": str(row[0]),
                "organization_id": str(row[1]),
                "project_id": str(row[2]),
                "service_id": str(row[3]),
                "display_name": str(row[4]),
                "repository": str(row[5]),
                "service_owner": str(row[6]),
                "owning_team": str(row[7]),
                "service_criticality": str(row[8]),
            }
            for row in self.connection.execute(
                f"SELECT tenant_id, organization_id, project_id, service_id, display_name, repository, service_owner, owning_team, service_criticality FROM services{tenant_filter} ORDER BY service_id ASC",
                params,
            ).fetchall()
        )
        return {"organizations": orgs, "projects": projects, "services": services}

    def upsert_managed_tenant(self, *, tenant_id: str, display_name: str, organization_name: str, status: str) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO managed_tenants
            (tenant_id, display_name, organization_name, status, created_at)
            VALUES (?, ?, ?, ?, COALESCE((SELECT created_at FROM managed_tenants WHERE tenant_id = ?), CURRENT_TIMESTAMP))
            """,
            (tenant_id, display_name, organization_name, status, tenant_id),
        )

    def list_managed_tenants(self) -> tuple[dict[str, str], ...]:
        rows = self.connection.execute(
            "SELECT tenant_id, display_name, organization_name, status, created_at FROM managed_tenants ORDER BY tenant_id ASC"
        ).fetchall()
        return tuple(_managed_tenant_row(row) for row in rows)

    def upsert_provider_secret_ref(self, *, tenant_id: str, secret_name: str, provider: str, secret_ref: str, description: str) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO provider_secret_refs
            (tenant_id, secret_name, provider, secret_ref, description, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (tenant_id, secret_name, provider, secret_ref, description),
        )

    def list_provider_secret_refs(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:
        rows = self.connection.execute(
            "SELECT tenant_id, secret_name, provider, secret_ref, description, updated_at FROM provider_secret_refs WHERE tenant_id = ? ORDER BY provider, secret_name",
            (tenant_id,),
        ).fetchall()
        return tuple(_provider_secret_row(row) for row in rows)

    def upsert_service_user(self, *, tenant_id: str, user_id: str, principal_name: str, email: str, roles_csv: str, status: str) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO service_users
            (tenant_id, user_id, principal_name, email, roles_csv, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM service_users WHERE tenant_id = ? AND user_id = ?), CURRENT_TIMESTAMP))
            """,
            (tenant_id, user_id, principal_name, email, roles_csv, status, tenant_id, user_id),
        )

    def list_service_users(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:
        rows = self.connection.execute(
            "SELECT tenant_id, user_id, principal_name, email, roles_csv, status, created_at FROM service_users WHERE tenant_id = ? ORDER BY user_id ASC",
            (tenant_id,),
        ).fetchall()
        return tuple(_service_user_row(row) for row in rows)

    def create_session(self, *, session_id: str, tenant_id: str, user_id: str, principal_name: str, auth_type: str, roles_csv: str, status: str, expires_at: str) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO service_sessions
            (session_id, tenant_id, user_id, principal_name, auth_type, roles_csv, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """,
            (session_id, tenant_id, user_id, principal_name, auth_type, roles_csv, status, expires_at),
        )

    def list_sessions(self, *, tenant_id: str, limit: int = 20) -> tuple[dict[str, str], ...]:
        rows = self.connection.execute(
            "SELECT session_id, tenant_id, user_id, principal_name, auth_type, roles_csv, status, created_at, expires_at FROM service_sessions WHERE tenant_id = ? ORDER BY created_at DESC, session_id DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
        return tuple(_service_session_row(row) for row in rows)

    def create_producer_client(self, *, tenant_id: str, client_id: str, display_name: str, roles_csv: str, status: str) -> dict[str, str]:
        token = secrets.token_urlsafe(24)
        token_hash = _token_hash(token)
        token_prefix = token[:8]
        self.connection.execute(
            """
            INSERT OR REPLACE INTO producer_clients
            (tenant_id, client_id, display_name, token_hash, token_prefix, roles_csv, status, created_at, last_issued_at, last_rotated_at, revoked_at, last_used_at)
            VALUES (
              ?, ?, ?, ?, ?, ?, ?,
              COALESCE((SELECT created_at FROM producer_clients WHERE tenant_id = ? AND client_id = ?), CURRENT_TIMESTAMP),
              CURRENT_TIMESTAMP,
              CASE WHEN EXISTS(SELECT 1 FROM producer_clients WHERE tenant_id = ? AND client_id = ?) THEN CURRENT_TIMESTAMP ELSE '' END,
              '',
              COALESCE((SELECT last_used_at FROM producer_clients WHERE tenant_id = ? AND client_id = ?), '')
            )
            """,
            (tenant_id, client_id, display_name, token_hash, token_prefix, roles_csv, status, tenant_id, client_id, tenant_id, client_id, tenant_id, client_id),
        )
        action = "rotated" if self.connection.execute(
            "SELECT 1 FROM producer_client_audit WHERE tenant_id = ? AND client_id = ? LIMIT 1",
            (tenant_id, client_id),
        ).fetchone() else "created"
        self.connection.execute(
            """
            INSERT INTO producer_client_audit
            (tenant_id, client_id, action, actor, detail, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (tenant_id, client_id, action, "system", f"status={status};roles={roles_csv};prefix={token_prefix}"),
        )
        return {
            "tenant_id": tenant_id,
            "client_id": client_id,
            "display_name": display_name,
            "token": token,
            "token_prefix": token_prefix,
            "roles_csv": roles_csv,
            "status": status,
        }

    def update_producer_client_status(self, *, tenant_id: str, client_id: str, status: str) -> None:
        self.connection.execute(
            "UPDATE producer_clients SET status = ?, revoked_at = CASE WHEN ? = 'revoked' THEN CURRENT_TIMESTAMP ELSE revoked_at END WHERE tenant_id = ? AND client_id = ?",
            (status, status, tenant_id, client_id),
        )
        self.connection.execute(
            """
            INSERT INTO producer_client_audit
            (tenant_id, client_id, action, actor, detail, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (tenant_id, client_id, "status_changed", "system", f"status={status}"),
        )

    def list_producer_clients(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:
        rows = self.connection.execute(
            "SELECT tenant_id, client_id, display_name, token_prefix, roles_csv, status, created_at, last_issued_at, last_rotated_at, last_used_at, revoked_at FROM producer_clients WHERE tenant_id = ? ORDER BY client_id ASC",
            (tenant_id,),
        ).fetchall()
        return tuple(_producer_client_row(row) for row in rows)

    def list_producer_client_audit(self, *, tenant_id: str, client_id: str, limit: int = 20) -> tuple[dict[str, str], ...]:
        rows = self.connection.execute(
            "SELECT tenant_id, client_id, action, actor, detail, created_at FROM producer_client_audit WHERE tenant_id = ? AND client_id = ? ORDER BY created_at DESC LIMIT ?",
            (tenant_id, client_id, limit),
        ).fetchall()
        return tuple(_producer_client_audit_row(row) for row in rows)

    def resolve_producer_token(self, *, token: str) -> HistoryToken | None:
        row = self.connection.execute(
            "SELECT tenant_id, client_id, display_name, token_hash, roles_csv, status FROM producer_clients WHERE token_prefix = ?",
            (token[:8],),
        ).fetchone()
        if row is None or not secrets.compare_digest(str(row[3]), _token_hash(token)):
            return None
        self.connection.execute(
            "UPDATE producer_clients SET last_used_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND client_id = ?",
            (str(row[0]), str(row[1])),
        )
        self.connection.execute(
            """
            INSERT INTO producer_client_audit
            (tenant_id, client_id, action, actor, detail, created_at)
            VALUES (?, ?, 'used', ?, ?, CURRENT_TIMESTAMP)
            """,
            (str(row[0]), str(row[1]), str(row[1]), "producer token resolved"),
        )
        self.connection.commit()
        roles = tuple(item for item in str(row[4]).split(",") if item)
        return HistoryToken(
            token=token,
            token_id=str(row[1]),
            principal_name=str(row[2]),
            auth_type="producer_token",
            status=str(row[5]),
            tenants=(str(row[0]),),
            roles=roles,
        )

    def commit(self) -> None:
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


class PostgresHistoryStore(HistoryStore):
    def __init__(self, connection, module_name: str) -> None:
        self.connection = connection
        self.module_name = module_name

    def ensure_schema(self) -> None:
        _ensure_migration_table(self.connection)
        _apply_postgres_migrations(self.connection)
        _record_migrations_postgres(self.connection)
        self.connection.commit()

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
        self._upsert_catalog(tenant_id=tenant_id, event_payload=event_payload, repository=repository)

    def _upsert_catalog(self, *, tenant_id: str, event_payload: str, repository: str) -> None:
        event = json.loads(event_payload)
        organization_id = _catalog_value(event, "organization") or _repo_owner(repository)
        project_id = _catalog_value(event, "project") or repository
        service_id = _catalog_value(event, "service") or _repo_name(repository)
        trust = event.get("trust_context") if isinstance(event.get("trust_context"), dict) else {}
        service_owner = str(trust.get("service_owner", "")) if isinstance(trust, dict) else ""
        owning_team = str(trust.get("owning_team", "")) if isinstance(trust, dict) else ""
        criticality = str(trust.get("service_criticality", "")) if isinstance(trust, dict) else ""
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO organizations (tenant_id, organization_id, display_name)
                VALUES (%s, %s, %s)
                ON CONFLICT (tenant_id, organization_id)
                DO UPDATE SET display_name = EXCLUDED.display_name
                """,
                (tenant_id, organization_id, organization_id),
            )
            cursor.execute(
                """
                INSERT INTO projects (tenant_id, organization_id, project_id, display_name, repository)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, project_id)
                DO UPDATE SET
                  organization_id = EXCLUDED.organization_id,
                  display_name = EXCLUDED.display_name,
                  repository = EXCLUDED.repository
                """,
                (tenant_id, organization_id, project_id, project_id, repository),
            )
            cursor.execute(
                """
                INSERT INTO services (tenant_id, organization_id, project_id, service_id, display_name, repository, service_owner, owning_team, service_criticality)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, service_id)
                DO UPDATE SET
                  organization_id = EXCLUDED.organization_id,
                  project_id = EXCLUDED.project_id,
                  display_name = EXCLUDED.display_name,
                  repository = EXCLUDED.repository,
                  service_owner = EXCLUDED.service_owner,
                  owning_team = EXCLUDED.owning_team,
                  service_criticality = EXCLUDED.service_criticality
                """,
                (tenant_id, organization_id, project_id, service_id, service_id, repository, service_owner, owning_team, criticality),
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

    def get_service_status(
        self,
        *,
        tenant_id: str,
    ) -> dict[str, object]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT migration_id, description, applied_at FROM schema_migrations ORDER BY migration_id ASC")
            schema_rows = cursor.fetchall()
        return _build_service_status(
            backend="postgres",
            schema_rows=schema_rows,
            event_count=_count_postgres_rows(self.connection, "decision_events", tenant_id=tenant_id),
            materialization_count=_count_postgres_rows(self.connection, "materialization_runs", tenant_id=tenant_id),
            tenant_count=_count_distinct_tenants_postgres(self.connection),
            tenant_id=tenant_id,
        )

    def list_catalog(self, *, tenant_id: str) -> dict[str, tuple[dict[str, str], ...]]:
        where = " WHERE tenant_id = %s" if tenant_id else ""
        params: list[object] = [tenant_id] if tenant_id else []
        with self.connection.cursor() as cursor:
            cursor.execute(
                f"SELECT tenant_id, organization_id, display_name FROM organizations{where} ORDER BY organization_id ASC",
                params,
            )
            orgs = tuple(
                {"tenant_id": str(row[0]), "organization_id": str(row[1]), "display_name": str(row[2])}
                for row in cursor.fetchall()
            )
            cursor.execute(
                f"SELECT tenant_id, organization_id, project_id, display_name, repository FROM projects{where} ORDER BY project_id ASC",
                params,
            )
            projects = tuple(
                {
                    "tenant_id": str(row[0]),
                    "organization_id": str(row[1]),
                    "project_id": str(row[2]),
                    "display_name": str(row[3]),
                    "repository": str(row[4]),
                }
                for row in cursor.fetchall()
            )
            cursor.execute(
                f"SELECT tenant_id, organization_id, project_id, service_id, display_name, repository, service_owner, owning_team, service_criticality FROM services{where} ORDER BY service_id ASC",
                params,
            )
            services = tuple(
                {
                    "tenant_id": str(row[0]),
                    "organization_id": str(row[1]),
                    "project_id": str(row[2]),
                    "service_id": str(row[3]),
                    "display_name": str(row[4]),
                    "repository": str(row[5]),
                    "service_owner": str(row[6]),
                    "owning_team": str(row[7]),
                    "service_criticality": str(row[8]),
                }
                for row in cursor.fetchall()
            )
        return {"organizations": orgs, "projects": projects, "services": services}

    def upsert_managed_tenant(self, *, tenant_id: str, display_name: str, organization_name: str, status: str) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO managed_tenants (tenant_id, display_name, organization_name, status, created_at)
                VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (tenant_id)
                DO UPDATE SET display_name = EXCLUDED.display_name, organization_name = EXCLUDED.organization_name, status = EXCLUDED.status
                """,
                (tenant_id, display_name, organization_name, status),
            )

    def list_managed_tenants(self) -> tuple[dict[str, str], ...]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT tenant_id, display_name, organization_name, status, created_at FROM managed_tenants ORDER BY tenant_id ASC")
            rows = cursor.fetchall()
        return tuple(_managed_tenant_row(row) for row in rows)

    def upsert_provider_secret_ref(self, *, tenant_id: str, secret_name: str, provider: str, secret_ref: str, description: str) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO provider_secret_refs (tenant_id, secret_name, provider, secret_ref, description, updated_at)
                VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (tenant_id, secret_name)
                DO UPDATE SET provider = EXCLUDED.provider, secret_ref = EXCLUDED.secret_ref, description = EXCLUDED.description, updated_at = CURRENT_TIMESTAMP
                """,
                (tenant_id, secret_name, provider, secret_ref, description),
            )

    def list_provider_secret_refs(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT tenant_id, secret_name, provider, secret_ref, description, updated_at FROM provider_secret_refs WHERE tenant_id = %s ORDER BY provider, secret_name",
                (tenant_id,),
            )
            rows = cursor.fetchall()
        return tuple(_provider_secret_row(row) for row in rows)

    def upsert_service_user(self, *, tenant_id: str, user_id: str, principal_name: str, email: str, roles_csv: str, status: str) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO service_users (tenant_id, user_id, principal_name, email, roles_csv, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (tenant_id, user_id)
                DO UPDATE SET principal_name = EXCLUDED.principal_name, email = EXCLUDED.email, roles_csv = EXCLUDED.roles_csv, status = EXCLUDED.status
                """,
                (tenant_id, user_id, principal_name, email, roles_csv, status),
            )

    def list_service_users(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT tenant_id, user_id, principal_name, email, roles_csv, status, created_at FROM service_users WHERE tenant_id = %s ORDER BY user_id ASC",
                (tenant_id,),
            )
            rows = cursor.fetchall()
        return tuple(_service_user_row(row) for row in rows)

    def create_session(self, *, session_id: str, tenant_id: str, user_id: str, principal_name: str, auth_type: str, roles_csv: str, status: str, expires_at: str) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO service_sessions (session_id, tenant_id, user_id, principal_name, auth_type, roles_csv, status, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, %s)
                ON CONFLICT (session_id)
                DO UPDATE SET status = EXCLUDED.status, expires_at = EXCLUDED.expires_at
                """,
                (session_id, tenant_id, user_id, principal_name, auth_type, roles_csv, status, expires_at),
            )

    def list_sessions(self, *, tenant_id: str, limit: int = 20) -> tuple[dict[str, str], ...]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT session_id, tenant_id, user_id, principal_name, auth_type, roles_csv, status, created_at, expires_at FROM service_sessions WHERE tenant_id = %s ORDER BY created_at DESC, session_id DESC LIMIT %s",
                (tenant_id, limit),
            )
            rows = cursor.fetchall()
        return tuple(_service_session_row(row) for row in rows)

    def create_producer_client(self, *, tenant_id: str, client_id: str, display_name: str, roles_csv: str, status: str) -> dict[str, str]:
        token = secrets.token_urlsafe(24)
        token_hash = _token_hash(token)
        token_prefix = token[:8]
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM producer_clients WHERE tenant_id = %s AND client_id = %s)",
                (tenant_id, client_id),
            )
            row = cursor.fetchone()
        existed = bool(row and row[0])
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO producer_clients
                (tenant_id, client_id, display_name, token_hash, token_prefix, roles_csv, status, created_at, last_issued_at, last_rotated_at, revoked_at, last_used_at)
                VALUES (
                  %s, %s, %s, %s, %s, %s, %s,
                  CURRENT_TIMESTAMP,
                  CURRENT_TIMESTAMP,
                  CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE '' END,
                  '',
                  ''
                )
                ON CONFLICT (tenant_id, client_id)
                DO UPDATE SET
                  display_name = EXCLUDED.display_name,
                  token_hash = EXCLUDED.token_hash,
                  token_prefix = EXCLUDED.token_prefix,
                  roles_csv = EXCLUDED.roles_csv,
                  status = EXCLUDED.status,
                  last_issued_at = CURRENT_TIMESTAMP,
                  last_rotated_at = CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE producer_clients.last_rotated_at END,
                  revoked_at = '',
                  last_used_at = producer_clients.last_used_at
                """,
                (tenant_id, client_id, display_name, token_hash, token_prefix, roles_csv, status, existed, existed),
            )
            cursor.execute(
                """
                INSERT INTO producer_client_audit
                (tenant_id, client_id, action, actor, detail, created_at)
                VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                """,
                (tenant_id, client_id, "rotated" if existed else "created", "system", f"status={status};roles={roles_csv};prefix={token_prefix}"),
            )
        return {
            "tenant_id": tenant_id,
            "client_id": client_id,
            "display_name": display_name,
            "token": token,
            "token_prefix": token_prefix,
            "roles_csv": roles_csv,
            "status": status,
        }

    def update_producer_client_status(self, *, tenant_id: str, client_id: str, status: str) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE producer_clients SET status = %s, revoked_at = CASE WHEN %s = 'revoked' THEN CURRENT_TIMESTAMP ELSE revoked_at END WHERE tenant_id = %s AND client_id = %s",
                (status, status, tenant_id, client_id),
            )
            cursor.execute(
                """
                INSERT INTO producer_client_audit
                (tenant_id, client_id, action, actor, detail, created_at)
                VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                """,
                (tenant_id, client_id, "status_changed", "system", f"status={status}"),
            )

    def list_producer_clients(self, *, tenant_id: str) -> tuple[dict[str, str], ...]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT tenant_id, client_id, display_name, token_prefix, roles_csv, status, created_at, last_issued_at, last_rotated_at, last_used_at, revoked_at FROM producer_clients WHERE tenant_id = %s ORDER BY client_id ASC",
                (tenant_id,),
            )
            rows = cursor.fetchall()
        return tuple(_producer_client_row(row) for row in rows)

    def list_producer_client_audit(self, *, tenant_id: str, client_id: str, limit: int = 20) -> tuple[dict[str, str], ...]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT tenant_id, client_id, action, actor, detail, created_at FROM producer_client_audit WHERE tenant_id = %s AND client_id = %s ORDER BY created_at DESC LIMIT %s",
                (tenant_id, client_id, limit),
            )
            rows = cursor.fetchall()
        return tuple(_producer_client_audit_row(row) for row in rows)

    def resolve_producer_token(self, *, token: str) -> HistoryToken | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT tenant_id, client_id, display_name, token_hash, roles_csv, status FROM producer_clients WHERE token_prefix = %s",
                (token[:8],),
            )
            row = cursor.fetchone()
        if row is None or not secrets.compare_digest(str(row[3]), _token_hash(token)):
            return None
        with self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE producer_clients SET last_used_at = CURRENT_TIMESTAMP WHERE tenant_id = %s AND client_id = %s",
                (str(row[0]), str(row[1])),
            )
            cursor.execute(
                """
                INSERT INTO producer_client_audit
                (tenant_id, client_id, action, actor, detail, created_at)
                VALUES (%s, %s, 'used', %s, %s, CURRENT_TIMESTAMP)
                """,
                (str(row[0]), str(row[1]), str(row[1]), "producer token resolved"),
            )
        self.connection.commit()
        roles = tuple(item for item in str(row[4]).split(",") if item)
        return HistoryToken(
            token=token,
            token_id=str(row[1]),
            principal_name=str(row[2]),
            auth_type="producer_token",
            status=str(row[5]),
            tenants=(str(row[0]),),
            roles=roles,
        )

    def commit(self) -> None:
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


def _apply_sqlite_migrations(connection: sqlite3.Connection) -> None:
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
    connection.execute(
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
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_materialization_runs_lookup
        ON materialization_runs (tenant_id, generated_at)
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            tenant_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            PRIMARY KEY (tenant_id, organization_id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
            tenant_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            repository TEXT NOT NULL,
            PRIMARY KEY (tenant_id, project_id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS services (
            tenant_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            service_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            repository TEXT NOT NULL,
            service_owner TEXT NOT NULL,
            owning_team TEXT NOT NULL,
            service_criticality TEXT NOT NULL,
            PRIMARY KEY (tenant_id, service_id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS managed_tenants (
            tenant_id TEXT NOT NULL PRIMARY KEY,
            display_name TEXT NOT NULL,
            organization_name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS provider_secret_refs (
            tenant_id TEXT NOT NULL,
            secret_name TEXT NOT NULL,
            provider TEXT NOT NULL,
            secret_ref TEXT NOT NULL,
            description TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, secret_name)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS service_users (
            tenant_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            principal_name TEXT NOT NULL,
            email TEXT NOT NULL,
            roles_csv TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, user_id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS service_sessions (
            session_id TEXT NOT NULL PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            principal_name TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            roles_csv TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS producer_clients (
            tenant_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            token_prefix TEXT NOT NULL,
            roles_csv TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_issued_at TEXT NOT NULL DEFAULT '',
            last_rotated_at TEXT NOT NULL DEFAULT '',
            last_used_at TEXT NOT NULL DEFAULT '',
            revoked_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (tenant_id, client_id)
        )
        """
    )
    _sqlite_add_column_if_missing(connection, "producer_clients", "last_issued_at", "TEXT NOT NULL DEFAULT ''")
    _sqlite_add_column_if_missing(connection, "producer_clients", "last_rotated_at", "TEXT NOT NULL DEFAULT ''")
    _sqlite_add_column_if_missing(connection, "producer_clients", "last_used_at", "TEXT NOT NULL DEFAULT ''")
    _sqlite_add_column_if_missing(connection, "producer_clients", "revoked_at", "TEXT NOT NULL DEFAULT ''")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS producer_client_audit (
            tenant_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

def _apply_postgres_migrations(connection) -> None:
    with connection.cursor() as cursor:
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
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                tenant_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                PRIMARY KEY (tenant_id, organization_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                tenant_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                repository TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                tenant_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                service_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                repository TEXT NOT NULL,
                service_owner TEXT NOT NULL,
                owning_team TEXT NOT NULL,
                service_criticality TEXT NOT NULL,
                PRIMARY KEY (tenant_id, service_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS managed_tenants (
                tenant_id TEXT NOT NULL PRIMARY KEY,
                display_name TEXT NOT NULL,
                organization_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_secret_refs (
                tenant_id TEXT NOT NULL,
                secret_name TEXT NOT NULL,
                provider TEXT NOT NULL,
                secret_ref TEXT NOT NULL,
                description TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, secret_name)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS service_users (
                tenant_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                principal_name TEXT NOT NULL,
                email TEXT NOT NULL,
                roles_csv TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, user_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS service_sessions (
                session_id TEXT NOT NULL PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                principal_name TEXT NOT NULL,
                auth_type TEXT NOT NULL,
                roles_csv TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS producer_clients (
                tenant_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                token_prefix TEXT NOT NULL,
                roles_csv TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_issued_at TEXT NOT NULL DEFAULT '',
                last_rotated_at TEXT NOT NULL DEFAULT '',
                last_used_at TEXT NOT NULL DEFAULT '',
                revoked_at TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, client_id)
            )
            """
        )
        _postgres_add_column_if_missing(cursor, "producer_clients", "last_issued_at", "TEXT NOT NULL DEFAULT ''")
        _postgres_add_column_if_missing(cursor, "producer_clients", "last_rotated_at", "TEXT NOT NULL DEFAULT ''")
        _postgres_add_column_if_missing(cursor, "producer_clients", "last_used_at", "TEXT NOT NULL DEFAULT ''")
        _postgres_add_column_if_missing(cursor, "producer_clients", "revoked_at", "TEXT NOT NULL DEFAULT ''")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS producer_client_audit (
                tenant_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def _ensure_migration_table(connection) -> None:
    statement = """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_id TEXT NOT NULL PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
    """
    if isinstance(connection, sqlite3.Connection):
        connection.execute(statement)
        return
    with connection.cursor() as cursor:
        cursor.execute(statement)


def _record_migrations_sqlite(connection: sqlite3.Connection) -> None:
    for migration_id, description in STORE_MIGRATIONS:
        connection.execute(
            """
            INSERT OR IGNORE INTO schema_migrations (migration_id, description, applied_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            """,
            (migration_id, description),
        )


def _record_migrations_postgres(connection) -> None:
    with connection.cursor() as cursor:
        for migration_id, description in STORE_MIGRATIONS:
            cursor.execute(
                """
                INSERT INTO schema_migrations (migration_id, description, applied_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (migration_id) DO NOTHING
                """,
                (migration_id, description),
            )


def _sqlite_add_column_if_missing(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column in columns:
        return
    connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _postgres_add_column_if_missing(cursor, table: str, column: str, definition: str) -> None:
    cursor.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}")


def _count_sqlite_rows(connection: sqlite3.Connection, table: str, *, tenant_id: str) -> int:
    query = f"SELECT COUNT(*) FROM {table}"
    params: list[object] = []
    if tenant_id:
        query += " WHERE tenant_id = ?"
        params.append(tenant_id)
    return int(connection.execute(query, params).fetchone()[0])


def _count_postgres_rows(connection, table: str, *, tenant_id: str) -> int:
    query = f"SELECT COUNT(*) FROM {table}"
    params: list[object] = []
    if tenant_id:
        query += " WHERE tenant_id = %s"
        params.append(tenant_id)
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        row = cursor.fetchone()
    return int(row[0]) if row else 0


def _count_distinct_tenants_sqlite(connection: sqlite3.Connection) -> int:
    return int(connection.execute("SELECT COUNT(DISTINCT tenant_id) FROM decision_events").fetchone()[0])


def _count_distinct_tenants_postgres(connection) -> int:
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(DISTINCT tenant_id) FROM decision_events")
        row = cursor.fetchone()
    return int(row[0]) if row else 0


def _build_service_status(
    *,
    backend: str,
    schema_rows: list[tuple[object, ...]] | tuple[tuple[object, ...], ...],
    event_count: int,
    materialization_count: int,
    tenant_count: int,
    tenant_id: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "source": "veridion.action.decision_history_store.status@1",
        "store": {
            "backend": backend,
            "schema_version": STORE_SCHEMA_VERSION,
            "tenant_scope": tenant_id,
            "current_migration_count": len(schema_rows),
            "pending_migration_count": max(0, len(STORE_MIGRATIONS) - len(schema_rows)),
            "migrations": [
                {
                    "migration_id": str(row[0]),
                    "description": str(row[1]),
                    "applied_at": str(row[2]),
                }
                for row in schema_rows
            ],
        },
        "counts": {
            "events": event_count,
            "materializations": materialization_count,
            "tenants": tenant_count,
        },
    }


def list_catalog_models(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str = "",
) -> dict[str, tuple[dict[str, str], ...]]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.list_catalog(tenant_id=tenant_id)


def provision_managed_tenant(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    display_name: str,
    organization_name: str,
    status: str = "active",
) -> None:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        store.upsert_managed_tenant(
            tenant_id=tenant_id,
            display_name=display_name,
            organization_name=organization_name,
            status=status,
        )
        store.commit()


def list_managed_tenants(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
) -> tuple[dict[str, str], ...]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.list_managed_tenants()


def upsert_provider_secret_ref(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    secret_name: str,
    provider: str,
    secret_ref: str,
    description: str = "",
) -> None:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        store.upsert_provider_secret_ref(
            tenant_id=tenant_id,
            secret_name=secret_name,
            provider=provider,
            secret_ref=secret_ref,
            description=description,
        )
        store.commit()


def list_provider_secret_refs(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
) -> tuple[dict[str, str], ...]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.list_provider_secret_refs(tenant_id=tenant_id)


def upsert_service_user(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    user_id: str,
    principal_name: str,
    email: str,
    roles_csv: str,
    status: str = "active",
) -> None:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        store.upsert_service_user(
            tenant_id=tenant_id,
            user_id=user_id,
            principal_name=principal_name,
            email=email,
            roles_csv=roles_csv,
            status=status,
        )
        store.commit()


def list_service_users(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
) -> tuple[dict[str, str], ...]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.list_service_users(tenant_id=tenant_id)


def create_service_session(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    session_id: str,
    tenant_id: str,
    user_id: str,
    principal_name: str,
    auth_type: str,
    roles_csv: str,
    status: str,
    expires_at: str,
) -> None:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        store.create_session(
            session_id=session_id,
            tenant_id=tenant_id,
            user_id=user_id,
            principal_name=principal_name,
            auth_type=auth_type,
            roles_csv=roles_csv,
            status=status,
            expires_at=expires_at,
        )
        store.commit()


def list_service_sessions(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    limit: int = 20,
) -> tuple[dict[str, str], ...]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.list_sessions(tenant_id=tenant_id, limit=limit)


def create_producer_client(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    client_id: str,
    display_name: str,
    roles_csv: str = "ingestor",
    status: str = "active",
) -> dict[str, str]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        result = store.create_producer_client(
            tenant_id=tenant_id,
            client_id=client_id,
            display_name=display_name,
            roles_csv=roles_csv,
            status=status,
        )
        store.commit()
        return result


def update_producer_client_status(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    client_id: str,
    status: str,
) -> None:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        store.update_producer_client_status(
            tenant_id=tenant_id,
            client_id=client_id,
            status=status,
        )
        store.commit()


def list_producer_client_audit(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
    client_id: str,
    limit: int = 20,
) -> tuple[dict[str, str], ...]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.list_producer_client_audit(tenant_id=tenant_id, client_id=client_id, limit=limit)


def list_producer_clients(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    tenant_id: str,
) -> tuple[dict[str, str], ...]:
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.list_producer_clients(tenant_id=tenant_id)


def resolve_persistent_bearer_identity(
    *,
    sqlite_path: str | Path = "",
    store_dsn: str = "",
    token: str,
) -> HistoryToken | None:
    if not (sqlite_path or store_dsn):
        return None
    ensure_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn)
    with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
        return store.resolve_producer_token(token=token)


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


def _catalog_value(event: dict[str, object], key: str) -> str:
    value = event.get(key, "")
    return value if isinstance(value, str) else ""


def _repo_owner(repository: str) -> str:
    return repository.split("/", 1)[0] if "/" in repository else repository


def _repo_name(repository: str) -> str:
    return repository.split("/", 1)[1] if "/" in repository else repository


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


def _managed_tenant_row(row: tuple[object, ...]) -> dict[str, str]:
    return {
        "tenant_id": str(row[0]),
        "display_name": str(row[1]),
        "organization_name": str(row[2]),
        "status": str(row[3]),
        "created_at": str(row[4]),
    }


def _provider_secret_row(row: tuple[object, ...]) -> dict[str, str]:
    return {
        "tenant_id": str(row[0]),
        "secret_name": str(row[1]),
        "provider": str(row[2]),
        "secret_ref": str(row[3]),
        "description": str(row[4]),
        "updated_at": str(row[5]),
    }


def _service_user_row(row: tuple[object, ...]) -> dict[str, str]:
    return {
        "tenant_id": str(row[0]),
        "user_id": str(row[1]),
        "principal_name": str(row[2]),
        "email": str(row[3]),
        "roles_csv": str(row[4]),
        "status": str(row[5]),
        "created_at": str(row[6]),
    }


def _service_session_row(row: tuple[object, ...]) -> dict[str, str]:
    return {
        "session_id": str(row[0]),
        "tenant_id": str(row[1]),
        "user_id": str(row[2]),
        "principal_name": str(row[3]),
        "auth_type": str(row[4]),
        "roles_csv": str(row[5]),
        "status": str(row[6]),
        "created_at": str(row[7]),
        "expires_at": str(row[8]),
    }


def _producer_client_row(row: tuple[object, ...]) -> dict[str, str]:
    return {
        "tenant_id": str(row[0]),
        "client_id": str(row[1]),
        "display_name": str(row[2]),
        "token_prefix": str(row[3]),
        "roles_csv": str(row[4]),
        "status": str(row[5]),
        "created_at": str(row[6]),
        "last_issued_at": str(row[7]),
        "last_rotated_at": str(row[8]),
        "last_used_at": str(row[9]),
        "revoked_at": str(row[10]),
    }


def _producer_client_audit_row(row: tuple[object, ...]) -> dict[str, str]:
    return {
        "tenant_id": str(row[0]),
        "client_id": str(row[1]),
        "action": str(row[2]),
        "actor": str(row[3]),
        "detail": str(row[4]),
        "created_at": str(row[5]),
    }


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
