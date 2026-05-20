"""Serve file-backed Veridion decision-history analytics over HTTP."""

from __future__ import annotations

import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from veridion.action.decision_history_config import (
    HistoryTenant,
    HistoryToken,
    JWTAuthConfig,
    MaterializationSchedule,
    TrustedHeaderAuthConfig,
    load_history_service_config,
    schedule_map,
    tenant_map,
    token_map,
)
from veridion.action.decision_history import analyze_history
from veridion.action.decision_history_materialize import materialize_decision_history
from veridion.action.decision_history_store import (
    analyze_history_store,
    create_producer_client,
    create_service_session,
    get_history_store_status,
    list_catalog_models,
    list_managed_tenants,
    list_materialization_runs,
    list_producer_clients,
    list_provider_secret_refs,
    list_service_sessions,
    list_service_users,
    provision_managed_tenant,
    resolve_persistent_bearer_identity,
    upsert_provider_secret_ref,
    upsert_service_user,
    upsert_decision_event_store,
)
from veridion.action.history_identity import jwt_auth_enabled, resolve_bearer_identity, resolve_trusted_header_identity

API_VERSION = "v1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve Veridion decision-history analytics over HTTP")
    parser.add_argument(
        "--history-path",
        action="append",
        default=[],
        help="Path to decision-history NDJSON, decision-event JSON, or exported event directory",
    )
    parser.add_argument("--config-path", help="Optional multi-tenant history service config JSON")
    parser.add_argument("--auth-token", help="Optional bearer token required for analytics endpoints")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8787, help="Bind port")
    args = parser.parse_args(argv)

    if not args.history_path and not args.config_path:
        raise SystemExit("either --history-path or --config-path is required")

    serve_decision_history(
        history_paths=tuple(args.history_path),
        config_path=args.config_path,
        auth_token=args.auth_token or "",
        host=args.host,
        port=args.port,
    )
    return 0


def serve_decision_history(
    *,
    history_paths: tuple[str, ...],
    config_path: str | None,
    auth_token: str,
    host: str,
    port: int,
) -> None:
    config = load_history_service_config(config_path) if config_path else None
    handler = _build_handler(
        history_paths,
        service_name=config.service_name if config else "Veridion History Service",
        tenants=tenant_map(config) if config else {},
        schedules=schedule_map(config) if config else {},
        jwt_config=config.jwt if config else JWTAuthConfig(),
        trusted_header_auth=config.trusted_headers if config else TrustedHeaderAuthConfig(),
        sqlite_path=config.sqlite_path if config else "",
        store_dsn=config.store_dsn if config else "",
        materialization_root=config.materialization_root if config else "",
        config_path=config_path or "",
        auth_tokens=_merge_auth_tokens(config.auth_tokens if config else (), auth_token),
        scoped_tokens=token_map(config) if config else {},
    )
    with ThreadingHTTPServer((host, port), handler) as server:
        server.serve_forever()


def _build_handler(
    history_paths: tuple[str, ...],
    *,
    service_name: str,
    tenants: dict[str, HistoryTenant],
    schedules: dict[str, MaterializationSchedule],
    jwt_config: JWTAuthConfig,
    trusted_header_auth: TrustedHeaderAuthConfig,
    sqlite_path: str,
    store_dsn: str,
    materialization_root: str,
    config_path: str,
    auth_tokens: tuple[str, ...],
    scoped_tokens: dict[str, HistoryToken],
):
    class DecisionHistoryHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler interface
            status, payload = resolve_history_request(
                self.path,
                history_paths=history_paths,
                service_name=service_name,
                tenants=tenants,
                schedules=schedules,
                jwt_config=jwt_config,
                trusted_header_auth=trusted_header_auth,
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                materialization_root=materialization_root,
                config_path=config_path,
                headers=dict(self.headers.items()),
                auth_tokens=auth_tokens,
                scoped_tokens=scoped_tokens,
            )
            if "html" in payload:
                self._write_html(status, str(payload["html"]))
            else:
                self._write_json(status, payload)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler interface
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(content_length) if content_length > 0 else b""
            status, payload = resolve_history_request(
                self.path,
                method="POST",
                body=raw.decode("utf-8") if raw else "",
                history_paths=history_paths,
                service_name=service_name,
                tenants=tenants,
                schedules=schedules,
                jwt_config=jwt_config,
                trusted_header_auth=trusted_header_auth,
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                materialization_root=materialization_root,
                config_path=config_path,
                headers=dict(self.headers.items()),
                auth_tokens=auth_tokens,
                scoped_tokens=scoped_tokens,
            )
            if "html" in payload:
                self._write_html(status, str(payload["html"]))
            else:
                self._write_json(status, payload)

        def log_message(self, format: str, *args) -> None:  # noqa: A003 - stdlib signature
            return

        def _write_json(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _write_html(self, status: int, payload: str) -> None:
            body = payload.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DecisionHistoryHandler


def resolve_history_request(
    path: str,
    *,
    method: str = "GET",
    body: str = "",
    history_paths: tuple[str, ...],
    service_name: str = "Veridion History Service",
    tenants: dict[str, HistoryTenant] | None = None,
    schedules: dict[str, MaterializationSchedule] | None = None,
    jwt_config: JWTAuthConfig | None = None,
    trusted_header_auth: TrustedHeaderAuthConfig | None = None,
    sqlite_path: str = "",
    store_dsn: str = "",
    materialization_root: str = "",
    config_path: str = "",
    headers: dict[str, str] | None = None,
    auth_tokens: tuple[str, ...] = (),
    scoped_tokens: dict[str, HistoryToken] | None = None,
) -> tuple[int, dict[str, object]]:
    parsed = urlparse(path)
    route, api_version = _normalize_route(parsed.path)
    if route == "/healthz":
        return _respond(200, {"status": "ok"}, route=route, api_version=api_version)
    scoped_lookup = scoped_tokens or {}
    tenant_lookup = tenants or {}
    schedule_lookup = schedules or {}
    params = _query_params(parsed.query)
    authz, identity = _authorize_request(
        headers=headers or {},
        auth_tokens=auth_tokens,
        scoped_tokens=scoped_lookup,
        jwt_config=jwt_config or JWTAuthConfig(),
        trusted_header_auth=trusted_header_auth or TrustedHeaderAuthConfig(),
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id=params.get("tenant", ""),
        path=route,
        method=method,
    )
    if authz is not None:
        return _respond(authz[0], authz[1], route=route, api_version=api_version, identity=identity)
    if method == "POST":
        status, payload = _handle_post_request(
            route,
            body=body,
            history_paths=history_paths,
            tenants=tenant_lookup,
            schedules=schedule_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            materialization_root=materialization_root,
            config_path=config_path,
            scoped_token=identity,
            headers=headers or {},
            api_version=api_version or API_VERSION,
            service_name=service_name,
        )
        return _respond(status, payload, route=route, api_version=api_version, identity=identity)
    if route == "/tenants":
        if identity is not None and identity.tenants:
            payload = {"tenants": sorted(identity.tenants)} if not api_version else {
                "tenants": [{"tenant_id": tenant_id, "display_name": tenant_id} for tenant_id in sorted(identity.tenants)]
            }
            return _respond(200, payload, route=route, api_version=api_version, identity=identity)
        tenant_items = [
            {
                "tenant_id": tenant.tenant_id,
                "display_name": tenant.display_name or tenant.tenant_id,
            }
            for tenant in sorted(tenant_lookup.values(), key=lambda item: item.tenant_id)
        ]
        payload = {"tenants": tenant_items if api_version else [item["tenant_id"] for item in tenant_items]}
        return _respond(200, payload, route=route, api_version=api_version, identity=identity)
    if route == "/analytics":
        payload = _analyze_request(
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
            repository=params.get("repository"),
            policy_pack_id=params.get("policy_pack_id"),
            since=params.get("since"),
            until=params.get("until"),
        )
        if payload is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        return _respond(200, payload, route=route, api_version=api_version, identity=identity)
    if route == "/app":
        overview = _build_overview_payload(
            history_paths=history_paths,
            tenants=tenant_lookup,
            schedules=schedule_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            materialization_root=materialization_root,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
            identity=identity,
        )
        if overview is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        if isinstance(overview.get("tenant"), dict):
            overview["tenant"]["selected_repository"] = params.get("repository", "")
            overview["tenant"]["selected_service"] = params.get("service", "")
        return _respond(
            200,
            {"html": render_app_html(overview, api_version=api_version or API_VERSION, identity=identity, service_name=service_name)},
            route=route,
            api_version=api_version,
            identity=identity,
        )
    if route == "/repositories":
        payload = _analyze_request(
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
        )
        if payload is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        repositories = [item["repository"] for item in payload["policy_rollout"]["latest_by_repository"]]
        return _respond(200, {"repositories": repositories}, route=route, api_version=api_version, identity=identity)
    if route == "/organizations":
        catalog = _catalog_payload(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=params.get("tenant", ""))
        return _respond(200, {"organizations": list(catalog["organizations"])}, route=route, api_version=api_version, identity=identity)
    if route == "/projects":
        catalog = _catalog_payload(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=params.get("tenant", ""))
        return _respond(200, {"projects": list(catalog["projects"])}, route=route, api_version=api_version, identity=identity)
    if route == "/services":
        catalog = _catalog_payload(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=params.get("tenant", ""))
        return _respond(200, {"services": list(catalog["services"])}, route=route, api_version=api_version, identity=identity)
    if route == "/admin/tenants":
        return _respond(200, {"tenants": list(list_managed_tenants(sqlite_path=sqlite_path, store_dsn=store_dsn))}, route=route, api_version=api_version, identity=identity)
    if route == "/admin/users":
        return _respond(200, {"users": list(list_service_users(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=params.get("tenant", "")))}, route=route, api_version=api_version, identity=identity)
    if route == "/admin/provider-secrets":
        return _respond(200, {"provider_secrets": list(list_provider_secret_refs(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=params.get("tenant", "")))}, route=route, api_version=api_version, identity=identity)
    if route == "/admin/producer-clients":
        return _respond(200, {"producer_clients": list(list_producer_clients(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=params.get("tenant", "")))}, route=route, api_version=api_version, identity=identity)
    if route == "/auth/sessions":
        return _respond(200, {"sessions": list(list_service_sessions(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=params.get("tenant", "")))}, route=route, api_version=api_version, identity=identity)
    if route == "/policy-rollouts":
        payload = _analyze_request(
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
        )
        if payload is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        return _respond(200, payload["policy_rollout"], route=route, api_version=api_version, identity=identity)
    if route == "/dashboard":
        analytics = _analyze_request(
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
        )
        if analytics is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        overview = _build_overview_payload(
            history_paths=history_paths,
            tenants=tenant_lookup,
            schedules=schedule_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            materialization_root=materialization_root,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
            identity=identity,
            analytics=analytics,
        )
        return _respond(
            200,
            {
                "html": render_dashboard_html(
                    overview,
                    tenant_id=params.get("tenant", ""),
                    service_name=service_name,
                    api_version=api_version or API_VERSION,
                    identity=identity,
                )
            },
            route=route,
            api_version=api_version,
            identity=identity,
        )
    if route == "/identity":
        return _respond(200, {"identity": _identity_payload(identity)}, route=route, api_version=api_version, identity=identity)
    if route == "/overview":
        payload = _build_overview_payload(
            history_paths=history_paths,
            tenants=tenant_lookup,
            schedules=schedule_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            materialization_root=materialization_root,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
            identity=identity,
        )
        if payload is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        if isinstance(payload.get("tenant"), dict):
            payload["tenant"]["selected_repository"] = params.get("repository", "")
            payload["tenant"]["selected_service"] = params.get("service", "")
        return _respond(200, payload, route=route, api_version=api_version, identity=identity)
    if route == "/materializations":
        if not materialization_root and not (sqlite_path or store_dsn):
            return _respond(404, {"error": "materialization_not_configured"}, route=route, api_version=api_version, identity=identity)
        tenant_id = params.get("tenant", "")
        limit = _parse_limit(params.get("limit", "20"))
        if sqlite_path or store_dsn:
            runs = list_materialization_runs(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                limit=limit,
            )
        else:
            runs = ()
        return _respond(200, {"materializations": list(runs)}, route=route, api_version=api_version, identity=identity)
    if route == "/materialization-schedules":
        visible = _visible_schedules(schedule_lookup, identity)
        return _respond(
            200,
            {
                "schedules": [
                    {
                        "schedule_id": schedule.schedule_id,
                        "cron": schedule.cron,
                        "enabled": schedule.enabled,
                        "tenants": list(schedule.tenants),
                        "athena_database": schedule.athena_database,
                        "athena_table": schedule.athena_table,
                        "athena_s3_location_template": schedule.athena_s3_location_template,
                    }
                    for schedule in visible
                ]
            },
            route=route,
            api_version=api_version,
            identity=identity,
        )
    if route == "/service/status":
        if sqlite_path or store_dsn:
            payload = get_history_store_status(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=params.get("tenant", ""),
            )
        else:
            payload = {
                "schema_version": 1,
                "source": "veridion.action.decision_history_service.status@1",
                "store": {
                    "backend": "file",
                    "schema_version": 0,
                    "tenant_scope": params.get("tenant", ""),
                    "migrations": [],
                },
                "counts": {
                    "events": 0,
                    "materializations": 0,
                    "tenants": len(tenant_lookup),
                },
            }
        return _respond(200, payload, route=route, api_version=api_version, identity=identity)
    return _respond(404, {"error": "not_found"}, route=route, api_version=api_version, identity=identity)


def _normalize_route(path: str) -> tuple[str, str]:
    if path in {f"/api/{API_VERSION}/health", f"/api/{API_VERSION}/healthz"}:
        return ("/healthz", API_VERSION)
    if path.startswith(f"/api/{API_VERSION}/"):
        suffix = path[len(f"/api/{API_VERSION}") :]
        return (suffix or "/", API_VERSION)
    if path in {f"/api/{API_VERSION}", f"/api/{API_VERSION}/"}:
        return ("/", API_VERSION)
    return (path, "")


def _respond(
    status: int,
    payload: dict[str, object],
    *,
    route: str,
    api_version: str,
    identity: HistoryToken | None = None,
) -> tuple[int, dict[str, object]]:
    if not api_version:
        return (status, payload)
    if route in {"/dashboard", "/app"} and "html" in payload:
        return (status, payload)
    return (
        status,
        {
            "api_version": api_version,
            "route": route,
            "identity": _identity_payload(identity) if status < 400 else {},
            "data": payload,
        },
    )


def _query_params(raw: str) -> dict[str, str]:
    parsed = parse_qs(raw)
    return {key: values[0] for key, values in parsed.items() if values}


def _analyze_request(
    *,
    history_paths: tuple[str, ...],
    tenants: dict[str, HistoryTenant],
    sqlite_path: str,
    store_dsn: str,
    tenant_id: str,
    repository: str | None = None,
    policy_pack_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, object] | None:
    if sqlite_path or store_dsn:
        return analyze_history_store(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            repository=repository,
            policy_pack_id=policy_pack_id,
            since=since,
            until=until,
        )
    selected_paths = _select_history_paths(history_paths=history_paths, tenants=tenants, tenant_id=tenant_id)
    if selected_paths is None:
        return None
    return analyze_history(
        history_paths=selected_paths,
        repository=repository,
        policy_pack_id=policy_pack_id,
        since=since,
        until=until,
    )


def _select_history_paths(
    *,
    history_paths: tuple[str, ...],
    tenants: dict[str, HistoryTenant],
    tenant_id: str,
) -> tuple[str, ...] | None:
    if tenant_id:
        tenant = tenants.get(tenant_id)
        return tenant.history_paths if tenant is not None else None
    if tenants:
        merged: list[str] = []
        for tenant in tenants.values():
            merged.extend(tenant.history_paths)
        return tuple(merged)
    return history_paths


def _authorize_request(
    *,
    headers: dict[str, str],
    auth_tokens: tuple[str, ...],
    scoped_tokens: dict[str, HistoryToken],
    jwt_config: JWTAuthConfig,
    trusted_header_auth: TrustedHeaderAuthConfig,
    sqlite_path: str,
    store_dsn: str,
    tenant_id: str,
    path: str,
    method: str,
) -> tuple[tuple[int, dict[str, object]] | None, HistoryToken | None]:
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
    header_identity = resolve_trusted_header_identity(headers=headers, config=trusted_header_auth)
    if not auth_tokens and not scoped_tokens and not jwt_auth_enabled(jwt_config) and header_identity is None:
        return (None, None)
    if header_identity is not None:
        scoped = header_identity
    else:
        if not auth_header.startswith("Bearer "):
            return ((401, {"error": "unauthorized"}), None)
        token = auth_header[len("Bearer ") :].strip()
        if token in auth_tokens:
            return (None, None)
        scoped = resolve_bearer_identity(token=token, scoped_tokens=scoped_tokens, jwt_config=jwt_config)
        if scoped is None:
            scoped = resolve_persistent_bearer_identity(sqlite_path=sqlite_path, store_dsn=store_dsn, token=token)
        if scoped is None:
            return ((401, {"error": "unauthorized"}), None)
    if scoped.status and scoped.status != "active":
        return ((403, {"error": "identity_inactive"}), scoped)
    # Tenant boundary checks run before role checks so that accessing the wrong
    # tenant always returns "forbidden" rather than "insufficient_role".
    if not tenant_id and scoped.tenants and path not in {"/tenants", "/materialization-schedules", "/identity", "/admin/tenants"} and method == "GET":
        return ((403, {"error": "tenant_scope_required"}), scoped)
    if tenant_id and scoped.tenants and tenant_id not in scoped.tenants:
        return ((403, {"error": "forbidden"}), scoped)
    if path == "/events" and not _has_explicit_role(scoped, "ingestor", "materializer", "admin"):
        return ((403, {"error": "insufficient_role"}), scoped)
    if method != "GET" and path != "/events" and not _has_explicit_role(scoped, "materializer", "admin"):
        return ((403, {"error": "insufficient_role"}), scoped)
    if path in {"/analytics", "/repositories", "/policy-rollouts", "/dashboard", "/overview", "/materializations", "/materialization-schedules", "/service/status"} and not _has_role(
        scoped, "reader", "materializer", "admin"
    ):
        return ((403, {"error": "insufficient_role"}), scoped)
    if path in {"/organizations", "/projects", "/services"} and not _has_role(scoped, "reader", "materializer", "admin"):
        return ((403, {"error": "insufficient_role"}), scoped)
    if path in {"/admin/tenants", "/admin/users", "/admin/provider-secrets", "/admin/producer-clients"} and not _has_explicit_role(scoped, "admin"):
        return ((403, {"error": "insufficient_role"}), scoped)
    if path == "/auth/sessions" and not _has_role(scoped, "reader", "materializer", "admin"):
        return ((403, {"error": "insufficient_role"}), scoped)
    return (None, scoped)


def _build_overview_payload(
    *,
    history_paths: tuple[str, ...],
    tenants: dict[str, HistoryTenant],
    schedules: dict[str, MaterializationSchedule],
    sqlite_path: str,
    store_dsn: str,
    materialization_root: str,
    tenant_id: str,
    since: str | None,
    until: str | None,
    identity: HistoryToken | None,
    analytics: dict[str, object] | None = None,
) -> dict[str, object] | None:
    analytics_payload = analytics or _analyze_request(
        history_paths=history_paths,
        tenants=tenants,
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id=tenant_id,
        since=since,
        until=until,
    )
    if analytics_payload is None:
        return None
    visible_schedules = _visible_schedules(schedules, identity)
    if sqlite_path or store_dsn:
        status = get_history_store_status(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)
        materializations = list(list_materialization_runs(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id, limit=10))
    else:
        status = {
            "schema_version": 1,
            "source": "veridion.action.decision_history_service.status@1",
            "store": {
                "backend": "file",
                "schema_version": 0,
                "tenant_scope": tenant_id,
                "migrations": [],
            },
            "counts": {
                "events": int(((analytics_payload.get("summary") or {}).get("events")) or 0),
                "materializations": 0,
                "tenants": len(tenants),
            },
        }
        materializations = []
    return {
        "tenant": {
            "tenant_id": tenant_id,
            "display_name": tenants.get(tenant_id).display_name if tenant_id and tenant_id in tenants else "",
        },
        "analytics": analytics_payload,
        "status": status,
        "materializations": materializations,
        "schedules": [
            {
                "schedule_id": schedule.schedule_id,
                "cron": schedule.cron,
                "enabled": schedule.enabled,
                "tenants": list(schedule.tenants),
                "athena_database": schedule.athena_database,
                "athena_table": schedule.athena_table,
                "athena_s3_location_template": schedule.athena_s3_location_template,
            }
            for schedule in visible_schedules
        ],
        "service": {
            "materialization_root": materialization_root,
            "history_paths": list(history_paths),
            "has_persistent_store": bool(sqlite_path or store_dsn),
        },
        "catalog": _catalog_payload(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id),
        "admin": {
            "managed_tenants": list(list_managed_tenants(sqlite_path=sqlite_path, store_dsn=store_dsn)) if (sqlite_path or store_dsn) else [],
            "service_users": list(list_service_users(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if (sqlite_path or store_dsn) and tenant_id else [],
            "provider_secrets": list(list_provider_secret_refs(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if (sqlite_path or store_dsn) and tenant_id else [],
            "producer_clients": list(list_producer_clients(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if (sqlite_path or store_dsn) and tenant_id else [],
            "sessions": list(list_service_sessions(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if (sqlite_path or store_dsn) and tenant_id else [],
        },
    }


def _handle_post_request(
    path: str,
    *,
    body: str,
    history_paths: tuple[str, ...],
    tenants: dict[str, HistoryTenant],
    schedules: dict[str, MaterializationSchedule],
    sqlite_path: str,
    store_dsn: str,
    materialization_root: str,
    config_path: str,
    scoped_token: HistoryToken | None,
    headers: dict[str, str],
    api_version: str,
    service_name: str,
) -> tuple[int, dict[str, object]]:
    if path == "/app":
        return _handle_app_post_request(
            body=body,
            headers=headers,
            history_paths=history_paths,
            tenants=tenants,
            schedules=schedules,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            materialization_root=materialization_root,
            config_path=config_path,
            scoped_token=scoped_token,
            api_version=api_version,
            service_name=service_name,
        )
    if path == "/admin/tenants":
        try:
            payload = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            return (400, {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return (400, {"error": "invalid_json"})
        tenant_id = _body_string(payload, "tenant_id")
        if not tenant_id:
            return (400, {"error": "tenant_id_required"})
        provision_managed_tenant(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            display_name=_body_string(payload, "display_name") or tenant_id,
            organization_name=_body_string(payload, "organization_name") or tenant_id,
            status=_body_string(payload, "status") or "active",
        )
        return (201, {"status": "created", "tenant_id": tenant_id})
    if path == "/admin/users":
        try:
            payload = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            return (400, {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return (400, {"error": "invalid_json"})
        tenant_id = _body_string(payload, "tenant")
        user_id = _body_string(payload, "user_id")
        if not tenant_id or not user_id:
            return (400, {"error": "tenant_and_user_id_required"})
        upsert_service_user(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            user_id=user_id,
            principal_name=_body_string(payload, "principal_name") or user_id,
            email=_body_string(payload, "email"),
            roles_csv=_body_string(payload, "roles_csv") or "reader",
            status=_body_string(payload, "status") or "active",
        )
        return (201, {"status": "created", "tenant": tenant_id, "user_id": user_id})
    if path == "/admin/provider-secrets":
        try:
            payload = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            return (400, {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return (400, {"error": "invalid_json"})
        tenant_id = _body_string(payload, "tenant")
        secret_name = _body_string(payload, "secret_name")
        if not tenant_id or not secret_name:
            return (400, {"error": "tenant_and_secret_name_required"})
        upsert_provider_secret_ref(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            secret_name=secret_name,
            provider=_body_string(payload, "provider"),
            secret_ref=_body_string(payload, "secret_ref"),
            description=_body_string(payload, "description"),
        )
        return (201, {"status": "created", "tenant": tenant_id, "secret_name": secret_name})
    if path == "/admin/producer-clients":
        try:
            payload = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            return (400, {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return (400, {"error": "invalid_json"})
        tenant_id = _body_string(payload, "tenant")
        client_id = _body_string(payload, "client_id")
        if not tenant_id or not client_id:
            return (400, {"error": "tenant_and_client_id_required"})
        result = create_producer_client(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            client_id=client_id,
            display_name=_body_string(payload, "display_name") or client_id,
            roles_csv=_body_string(payload, "roles_csv") or "ingestor",
            status=_body_string(payload, "status") or "active",
        )
        return (201, {"status": "created", "producer_client": result})
    if path == "/auth/sessions":
        try:
            payload = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        if scoped_token is None:
            return (401, {"error": "unauthorized"})
        tenant_id = _body_string(payload, "tenant") or (scoped_token.tenants[0] if scoped_token.tenants else "")
        if not tenant_id:
            return (400, {"error": "tenant_required"})
        session_id = _body_string(payload, "session_id") or _materialization_run_id()
        create_service_session(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            session_id=session_id,
            tenant_id=tenant_id,
            user_id=scoped_token.token_id or scoped_token.principal_name or "session-user",
            principal_name=scoped_token.principal_name or scoped_token.token_id or "session-user",
            auth_type=scoped_token.auth_type or "bearer",
            roles_csv=",".join(scoped_token.roles),
            status="active",
            expires_at=_body_string(payload, "expires_at"),
        )
        return (201, {"status": "created", "session_id": session_id, "tenant": tenant_id})
    if path == "/events":
        if not (sqlite_path or store_dsn):
            return (400, {"error": "persistent_store_required"})
        try:
            payload = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            return (400, {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return (400, {"error": "invalid_json"})
        tenant_id = _body_string(payload, "tenant")
        if not tenant_id:
            return (400, {"error": "tenant_required"})
        if tenants and tenant_id not in tenants:
            return (404, {"error": "tenant_not_found"})
        if scoped_token is not None and scoped_token.tenants and tenant_id not in scoped_token.tenants:
            return (403, {"error": "forbidden"})
        event = payload.get("event")
        if not isinstance(event, dict):
            return (400, {"error": "event_required"})
        repository = event.get("repository", "")
        if not isinstance(repository, str) or not repository.strip():
            return (400, {"error": "repository_required"})
        upsert_decision_event_store(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            event=event,
        )
        return (202, {"status": "accepted", "tenant": tenant_id, "repository": repository})
    if path != "/materializations":
        return (404, {"error": "not_found"})
    if not materialization_root or not config_path:
        return (400, {"error": "materialization_root_required"})
    try:
        payload = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError:
        return (400, {"error": "invalid_json"})
    if not isinstance(payload, dict):
        return (400, {"error": "invalid_json"})
    tenant_id = _body_string(payload, "tenant")
    if not tenant_id:
        return (400, {"error": "tenant_required"})
    if tenant_id not in tenants:
        return (404, {"error": "tenant_not_found"})
    if scoped_token is not None and scoped_token.tenants and tenant_id not in scoped_token.tenants:
        return (403, {"error": "forbidden"})
    run_id = _body_string(payload, "run_id") or ""
    since = _body_string(payload, "since") or None
    until = _body_string(payload, "until") or None
    athena_database = _body_string(payload, "athena_database") or None
    athena_table = _body_string(payload, "athena_table") or "veridion_decision_events"
    athena_template = _body_string(payload, "athena_s3_location_template") or None
    schedule_id = _body_string(payload, "schedule_id")
    if schedule_id:
        schedule = schedules.get(schedule_id)
        if schedule is None:
            return (404, {"error": "schedule_not_found"})
        if schedule.tenants and tenant_id not in schedule.tenants:
            return (403, {"error": "schedule_forbidden"})
        athena_database = athena_database or schedule.athena_database or None
        athena_table = athena_table or schedule.athena_table or "veridion_decision_events"
        athena_template = athena_template or schedule.athena_s3_location_template or None
    run_dir = materialize_decision_history(
        history_paths=history_paths,
        config_path=config_path,
        output_root=materialization_root,
        run_id=run_id or _materialization_run_id(),
        since=since,
        until=until,
        athena_database=athena_database,
        athena_table=athena_table,
        athena_s3_location_template=athena_template,
        tenant_ids=(tenant_id,),
    )
    runs = ()
    if sqlite_path or store_dsn:
        runs = list_materialization_runs(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id, limit=1)
    return (
        201,
        {
            "status": "created",
            "tenant": tenant_id,
            "schedule_id": schedule_id,
            "run_path": str(run_dir),
            "materialization": runs[0] if runs else {"tenant_id": tenant_id, "run_path": str(run_dir)},
        },
    )


def _handle_app_post_request(
    *,
    body: str,
    headers: dict[str, str],
    history_paths: tuple[str, ...],
    tenants: dict[str, HistoryTenant],
    schedules: dict[str, MaterializationSchedule],
    sqlite_path: str,
    store_dsn: str,
    materialization_root: str,
    config_path: str,
    scoped_token: HistoryToken | None,
    api_version: str,
    service_name: str,
) -> tuple[int, dict[str, object]]:
    payload = _parse_form_payload(body, headers)
    action = _body_string(payload, "action")
    tenant_id = _body_string(payload, "tenant_id") or _body_string(payload, "tenant") or (
        scoped_token.tenants[0] if scoped_token and scoped_token.tenants else ""
    )
    message = ""
    level = "info"
    if not action:
        message = "Select an onboarding action to submit."
        level = "warning"
    elif action == "create_tenant":
        target_tenant = _body_string(payload, "tenant_id")
        if not target_tenant:
            message = "Tenant ID is required."
            level = "error"
        else:
            provision_managed_tenant(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=target_tenant,
                display_name=_body_string(payload, "display_name") or target_tenant,
                organization_name=_body_string(payload, "organization_name") or target_tenant,
                status=_body_string(payload, "status") or "active",
            )
            tenant_id = target_tenant
            message = f"Tenant {target_tenant} provisioned."
            level = "success"
    elif action == "create_producer_client":
        client_id = _body_string(payload, "client_id")
        if not tenant_id or not client_id:
            message = "Tenant and client ID are required."
            level = "error"
        else:
            created = create_producer_client(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                client_id=client_id,
                display_name=_body_string(payload, "display_name") or client_id,
                roles_csv=_body_string(payload, "roles_csv") or "ingestor",
                status=_body_string(payload, "status") or "active",
            )
            message = f"Producer client {client_id} created."
            level = "success"
            payload["revealed_token"] = created.get("token", "")
            payload["revealed_token_prefix"] = created.get("token_prefix", "")
    elif action == "create_service_user":
        user_id = _body_string(payload, "user_id")
        if not tenant_id or not user_id:
            message = "Tenant and user ID are required."
            level = "error"
        else:
            upsert_service_user(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                user_id=user_id,
                principal_name=_body_string(payload, "principal_name") or user_id,
                email=_body_string(payload, "email"),
                roles_csv=_body_string(payload, "roles_csv") or "reader",
                status=_body_string(payload, "status") or "active",
            )
            message = f"Service user {user_id} created."
            level = "success"
    elif action == "create_provider_secret":
        secret_name = _body_string(payload, "secret_name")
        if not tenant_id or not secret_name:
            message = "Tenant and secret name are required."
            level = "error"
        else:
            upsert_provider_secret_ref(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                secret_name=secret_name,
                provider=_body_string(payload, "provider"),
                secret_ref=_body_string(payload, "secret_ref"),
                description=_body_string(payload, "description"),
            )
            message = f"Provider secret reference {secret_name} stored."
            level = "success"
    else:
        message = f"Unsupported app action: {action}"
        level = "error"

    overview = _build_overview_payload(
        history_paths=history_paths,
        tenants=tenants,
        schedules=schedules,
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        materialization_root=materialization_root,
        tenant_id=tenant_id,
        since=None,
        until=None,
        identity=scoped_token,
    )
    if overview is None:
        return (404, {"error": "tenant_not_found"})
    overview["ui"] = {
        "message": message,
        "level": level,
        "revealed_token": _body_string(payload, "revealed_token"),
        "revealed_token_prefix": _body_string(payload, "revealed_token_prefix"),
    }
    return (
        200,
        {
            "html": render_app_html(
                overview,
                api_version=api_version,
                identity=scoped_token,
                service_name=service_name,
            )
        },
    )


def _parse_form_payload(body: str, headers: dict[str, str]) -> dict[str, object]:
    content_type = headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type == "application/x-www-form-urlencoded":
        parsed = parse_qs(body, keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed.items()}
    try:
        payload = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _body_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    return value.strip() if isinstance(value, str) else ""


def _parse_limit(raw: str) -> int:
    try:
        return max(1, min(100, int(raw)))
    except Exception:
        return 20


def _materialization_run_id() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _has_role(token: HistoryToken, *roles: str) -> bool:
    """Permissive check: a token with no roles assigned passes (reader-level default)."""
    if not token.roles:
        return True
    return any(role in token.roles for role in roles)


def _has_explicit_role(token: HistoryToken, *roles: str) -> bool:
    """Strict check: roles must be explicitly assigned; no roles → no access."""
    return any(role in token.roles for role in roles)


def _identity_payload(identity: HistoryToken | None) -> dict[str, object]:
    if identity is None:
        return {}
    return {
        "token_id": identity.token_id or identity.token,
        "principal_name": identity.principal_name or "",
        "auth_type": identity.auth_type or "bearer",
        "status": identity.status or "active",
        "roles": list(identity.roles),
        "tenants": list(identity.tenants),
    }


def _catalog_payload(*, sqlite_path: str, store_dsn: str, tenant_id: str) -> dict[str, tuple[dict[str, str], ...]]:
    if not (sqlite_path or store_dsn):
        return {"organizations": (), "projects": (), "services": ()}
    return list_catalog_models(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)


def _visible_schedules(
    schedules: dict[str, MaterializationSchedule],
    identity: HistoryToken | None,
) -> tuple[MaterializationSchedule, ...]:
    values = tuple(schedules.values())
    if identity is None or not identity.tenants:
        return tuple(schedule for schedule in values if schedule.enabled)
    return tuple(
        schedule
        for schedule in values
        if schedule.enabled and (not schedule.tenants or any(tenant in identity.tenants for tenant in schedule.tenants))
    )


def render_dashboard_html(
    payload: dict[str, object],
    *,
    tenant_id: str,
    service_name: str,
    api_version: str,
    identity: HistoryToken | None,
) -> str:
    analytics = payload.get("analytics", {})
    status = payload.get("status", {})
    summary = analytics.get("summary", {}) if isinstance(analytics, dict) else {}
    by_verdict = analytics.get("by_verdict", {}) if isinstance(analytics, dict) else {}
    policy_rollout = analytics.get("policy_rollout", {}) if isinstance(analytics, dict) else {}
    blocking_categories = analytics.get("top_blocking_categories", []) if isinstance(analytics, dict) else []
    latest_repositories = policy_rollout.get("latest_by_repository", []) if isinstance(policy_rollout, dict) else []
    materializations = payload.get("materializations", [])
    schedules = payload.get("schedules", [])
    catalog = payload.get("catalog", {})
    organizations = catalog.get("organizations", []) if isinstance(catalog, dict) else []
    projects = catalog.get("projects", []) if isinstance(catalog, dict) else []
    services = catalog.get("services", []) if isinstance(catalog, dict) else []
    status_store = status.get("store", {}) if isinstance(status, dict) else {}
    principal = identity.principal_name or identity.token_id if identity is not None else "anonymous"
    service_items = "".join(
        f"<li>{_html_escape(str(item.get('service_id', '')))}{_service_criticality_suffix(item)}</li>"
        for item in services[:5]
    ) or "<li>No services recorded</li>"
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{_html_escape(service_name)}</title>
    <style>
      :root {{ --bg:#f4f7fb; --panel:#ffffff; --line:#d7e0ea; --ink:#10243e; --muted:#5c6b7a; --accent:#0b6bcb; }}
      body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; background: var(--bg); color: var(--ink); }}
      .shell {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
      .hero {{ display:flex; justify-content:space-between; align-items:flex-start; gap:2rem; margin-bottom:1.5rem; }}
      .hero h1 {{ margin:0 0 0.35rem 0; font-size:2rem; }}
      .meta {{ color: var(--muted); }}
      .pill {{ display:inline-block; padding:0.3rem 0.6rem; border-radius:999px; border:1px solid var(--line); background:#eef5ff; margin-right:0.4rem; font-size:0.9rem; }}
      .grid {{ display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:1rem; margin-bottom:1.5rem; }}
      .card {{ border:1px solid var(--line); border-radius:16px; padding:1rem; background:var(--panel); box-shadow:0 10px 25px rgba(16,36,62,0.04); }}
      .card .label {{ color:var(--muted); font-size:0.9rem; margin-bottom:0.35rem; }}
      .card .value {{ font-size:1.8rem; font-weight:700; }}
      .panels {{ display:grid; grid-template-columns: 1.15fr 0.85fr; gap:1rem; }}
      .panels-3 {{ display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap:1rem; margin-top:1rem; }}
      .section-title {{ margin:0 0 0.85rem 0; font-size:1rem; }}
      table {{ width:100%; border-collapse:collapse; }}
      th, td {{ text-align:left; padding:0.65rem 0.5rem; border-top:1px solid var(--line); font-size:0.95rem; }}
      th {{ color:var(--muted); font-weight:600; border-top:none; }}
      ul {{ margin:0; padding-left:1rem; }}
      pre {{ white-space:pre-wrap; word-break:break-word; background:#0f1720; color:#dce7f3; padding:1rem; border-radius:12px; overflow:auto; }}
      .footer {{ margin-top:1rem; color:var(--muted); font-size:0.9rem; }}
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="hero">
        <div>
          <h1>{_html_escape(service_name)}</h1>
          <div class="meta">Tenant: {_html_escape(tenant_id) or "all"} | API: {_html_escape(api_version)} | Identity: {_html_escape(principal)}</div>
        </div>
        <div>
          <span class="pill">Analytics</span>
          <span class="pill">Rollouts</span>
          <span class="pill">Materializations</span>
        </div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Events</div><div class="value">{summary.get("events", 0)}</div></div>
        <div class="card"><div class="label">Repositories</div><div class="value">{summary.get("repositories", 0)}</div></div>
        <div class="card"><div class="label">Policy Variants</div><div class="value">{summary.get("policy_pack_variants", 0)}</div></div>
        <div class="card"><div class="label">Blocked Reviews</div><div class="value">{summary.get("blocked_events", 0)}</div></div>
      </div>
      <div class="panels">
        <div class="card">
          <h2 class="section-title">Latest Repositories</h2>
          <table>
            <thead><tr><th>Repository</th><th>Pack</th><th>Version</th><th>Stage</th></tr></thead>
            <tbody>
              {"".join(f"<tr><td>{_html_escape(str(item.get('repository', '')))}</td><td>{_html_escape(str(item.get('pack_id', '')))}</td><td>{_html_escape(str(item.get('pack_version', '')))}</td><td>{_html_escape(str(item.get('rollout_stage', '')))}</td></tr>" for item in latest_repositories[:8]) or "<tr><td colspan='4'>No repository rollout data</td></tr>"}
            </tbody>
          </table>
        </div>
        <div class="card">
          <h2 class="section-title">Top Blocking Categories</h2>
          <ul>
            {"".join(f"<li>{_html_escape(str(item.get('name', '')))} ({_html_escape(str(item.get('count', '0')) )})</li>" for item in blocking_categories[:8]) or "<li>No blocking categories recorded</li>"}
          </ul>
          <h2 class="section-title" style="margin-top:1rem;">Verdicts</h2>
          <pre>{_html_escape(json.dumps(by_verdict, indent=2))}</pre>
        </div>
      </div>
      <div class="panels-3">
        <div class="card">
          <h2 class="section-title">Store Status</h2>
          <ul>
            <li>Backend: {_html_escape(str(status_store.get("backend", "file")))}</li>
            <li>Schema version: {_html_escape(str(status_store.get("schema_version", "0")))}</li>
            <li>Tenant scope: {_html_escape(str(status_store.get("tenant_scope", tenant_id or "all")))}</li>
            <li>Migrations: {_html_escape(str(len(status_store.get("migrations", [])) if isinstance(status_store.get("migrations"), list) else 0))}</li>
          </ul>
        </div>
        <div class="card">
          <h2 class="section-title">Recent Materializations</h2>
          <ul>
            {"".join(f"<li>{_html_escape(str(item.get('run_id', '')))} ({_html_escape(str(item.get('status', '')) or 'unknown')})</li>" for item in materializations[:5]) or "<li>No materializations recorded</li>"}
          </ul>
        </div>
        <div class="card">
          <h2 class="section-title">Schedules</h2>
          <ul>
            {"".join(f"<li>{_html_escape(str(item.get('schedule_id', '')))}: {_html_escape(str(item.get('cron', '')))}</li>" for item in schedules[:5]) or "<li>No schedules configured</li>"}
          </ul>
        </div>
      </div>
      <div class="panels-3">
        <div class="card">
          <h2 class="section-title">Organizations</h2>
          <ul>
            {"".join(f"<li>{_html_escape(str(item.get('organization_id', '')))}</li>" for item in organizations[:5]) or "<li>No organizations recorded</li>"}
          </ul>
        </div>
        <div class="card">
          <h2 class="section-title">Projects</h2>
          <ul>
            {"".join(f"<li>{_html_escape(str(item.get('project_id', '')))}</li>" for item in projects[:5]) or "<li>No projects recorded</li>"}
          </ul>
        </div>
        <div class="card">
          <h2 class="section-title">Services</h2>
          <ul>
            {service_items}
          </ul>
        </div>
      </div>
      <div class="card" style="margin-top:1rem;">
        <h2 class="section-title">Policy Rollout JSON</h2>
        <pre>{_html_escape(json.dumps(policy_rollout, indent=2))}</pre>
      </div>
      <div class="footer">Versioned endpoints are available under /api/{_html_escape(api_version)}/overview, /identity, /analytics, /repositories, /organizations, /projects, /services, /policy-rollouts, /materializations, /materialization-schedules, /service/status, /events, and /tenants.</div>
    </div>
  </body>
</html>"""


def render_app_html(
    payload: dict[str, object],
    *,
    api_version: str,
    identity: HistoryToken | None,
    service_name: str,
) -> str:
    tenant = payload.get("tenant", {}) if isinstance(payload, dict) else {}
    analytics = payload.get("analytics", {}) if isinstance(payload, dict) else {}
    summary = analytics.get("summary", {}) if isinstance(analytics, dict) else {}
    status = payload.get("status", {}) if isinstance(payload, dict) else {}
    status_store = status.get("store", {}) if isinstance(status, dict) else {}
    catalog = payload.get("catalog", {}) if isinstance(payload, dict) else {}
    admin = payload.get("admin", {}) if isinstance(payload, dict) else {}
    materializations = payload.get("materializations", []) if isinstance(payload, dict) else []
    schedules = payload.get("schedules", []) if isinstance(payload, dict) else []
    service = payload.get("service", {}) if isinstance(payload, dict) else {}
    principal = identity.principal_name or identity.token_id if identity is not None else "anonymous"
    managed_tenants = admin.get("managed_tenants", []) if isinstance(admin, dict) else []
    service_users = admin.get("service_users", []) if isinstance(admin, dict) else []
    provider_secrets = admin.get("provider_secrets", []) if isinstance(admin, dict) else []
    producer_clients = admin.get("producer_clients", []) if isinstance(admin, dict) else []
    sessions = admin.get("sessions", []) if isinstance(admin, dict) else []
    organizations = catalog.get("organizations", []) if isinstance(catalog, dict) else []
    projects = catalog.get("projects", []) if isinstance(catalog, dict) else []
    services = catalog.get("services", []) if isinstance(catalog, dict) else []
    latest_by_repository = ((analytics.get("policy_rollout") or {}).get("latest_by_repository", [])) if isinstance(analytics, dict) else []
    blocking_categories = analytics.get("top_blocking_categories", []) if isinstance(analytics, dict) else []
    schedule_runs = [
        item for item in materializations if isinstance(item, dict) and str(item.get("run_id", "")).startswith("nightly-")
    ]
    checklist = (
        ("Tenant provisioned", bool(managed_tenants), "Create a tenant record so the control plane has an org boundary."),
        ("Producer connected", bool(producer_clients), "Create a producer client so CI can POST decision events."),
        ("Events arriving", int(summary.get("events", 0) or 0) > 0, "Verify at least one decision event has landed."),
        ("Scheduler active", bool(schedule_runs), "Confirm the worker is creating scheduled materialization runs."),
        ("Provider refs stored", bool(provider_secrets), "Store at least one provider secret reference for live integrations."),
        ("Human access modeled", bool(service_users) or bool(sessions), "Add service users or confirm authenticated sessions are flowing."),
    )
    completed_steps = sum(1 for _, ready, _ in checklist if ready)
    next_step = next((detail for _, ready, detail in checklist if not ready), "Core onboarding is complete. Next focus: expand repos, providers, and user roles.")
    tenant_label = _html_escape(str(tenant.get("tenant_id", "")) or "all")
    display_name = _html_escape(str(tenant.get("display_name", "")) or str(tenant.get("tenant_id", "")) or "Hosted Tenant")
    events = int(summary.get("events", 0) or 0)
    repositories = int(summary.get("repositories", 0) or 0)
    blocked_events = int(summary.get("blocked_events", 0) or 0)
    producer_count = len(producer_clients)
    session_count = len(sessions)
    schedule_count = len(schedules)
    materialization_count = len(materializations)
    store_backend = _html_escape(str(status_store.get("backend", "file")))
    schema_version = _html_escape(str(status_store.get("schema_version", "0")))
    has_persistent_store = "Yes" if bool(service.get("has_persistent_store")) else "No"
    history_paths = service.get("history_paths", []) if isinstance(service, dict) else []
    onboarding_items = "".join(
        f"<li><strong>{_html_escape(label)}</strong> <span class='status {'ready' if ready else 'todo'}'>{'ready' if ready else 'next'}</span><div class='hint'>{_html_escape(detail)}</div></li>"
        for label, ready, detail in checklist
    )
    producer_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('client_id', '')))}</strong> <span class='mono'>{_html_escape(str(item.get('token_prefix', '')))}...</span><div class='hint'>{_html_escape(str(item.get('status', 'active')))} / {_html_escape(str(item.get('roles_csv', '')) or 'ingestor')}</div></li>"
        for item in producer_clients[:6]
    ) or "<li>No producer clients yet</li>"
    schedule_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('schedule_id', '')))}</strong> <span class='mono'>{_html_escape(str(item.get('cron', '')))}</span><div class='hint'>{_html_escape(str(', '.join(item.get('tenants', [])) if isinstance(item.get('tenants'), list) else 'all tenants'))}</div></li>"
        for item in schedules[:6]
    ) or "<li>No schedules configured</li>"
    materialization_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('run_id', '')))}</strong><div class='hint'>{_html_escape(str(item.get('generated_at', '')))} / {_html_escape(str(item.get('status', 'unknown')))}</div></li>"
        for item in materializations[:6]
    ) or "<li>No materializations recorded</li>"
    repository_rows = "".join(
        f"<tr><td>{_html_escape(str(item.get('repository', '')))}</td><td>{_html_escape(str(item.get('verdict', '')))}</td><td>{_html_escape(str(item.get('gate_status', '')))}</td><td>{_html_escape(str(item.get('generated_at', '')))}</td></tr>"
        for item in latest_by_repository[:8]
    ) or "<tr><td colspan='4'>No repository activity yet</td></tr>"
    blocking_items = "".join(
        f"<li>{_html_escape(str(item.get('name', '')))} <span class='count'>{_html_escape(str(item.get('count', '0')))}</span></li>"
        for item in blocking_categories[:6]
    ) or "<li>No blocking categories recorded</li>"
    managed_tenant_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('tenant_id', '')))}</strong><div class='hint'>{_html_escape(str(item.get('status', 'active')))}</div></li>"
        for item in managed_tenants[:6]
    ) or "<li>No tenants provisioned</li>"
    secret_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('provider', '')))}</strong> / {_html_escape(str(item.get('secret_name', '')))}<div class='hint mono'>{_html_escape(str(item.get('secret_ref', '')))}</div></li>"
        for item in provider_secrets[:6]
    ) or "<li>No provider secret refs</li>"
    user_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('user_id', '')))}</strong><div class='hint'>{_html_escape(str(item.get('roles_csv', '')) or 'reader')} / {_html_escape(str(item.get('status', 'active')))}</div></li>"
        for item in service_users[:6]
    ) or "<li>No service users recorded</li>"
    session_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('session_id', '')))}</strong><div class='hint'>{_html_escape(str(item.get('principal_name', '')))}</div></li>"
        for item in sessions[:6]
    ) or "<li>No sessions recorded</li>"
    tenant_value = str(tenant.get("tenant_id", "")).strip()
    tenant_query = quote(tenant_value) if tenant_value else ""
    repository_link_items = "".join(
        f"<li><a href='/api/{_html_escape(api_version)}/app?tenant={tenant_query}&repository={quote(str(item.get('repository', '')))}'>{_html_escape(str(item.get('repository', '')))}</a><div class='hint'>{_html_escape(str(item.get('verdict', '')))} / {_html_escape(str(item.get('gate_status', '')))}</div></li>"
        for item in latest_by_repository[:8]
    ) or "<li>No repository activity yet</li>"
    service_link_items = "".join(
        f"<li><a href='/api/{_html_escape(api_version)}/app?tenant={tenant_query}&service={quote(str(item.get('service_id', '')))}'>{_html_escape(str(item.get('service_id', '')))}</a><div class='hint'>{_html_escape(str(item.get('repository', '')))} / {_html_escape(str(item.get('service_criticality', '')) or 'unknown')}</div></li>"
        for item in services[:8]
    ) or "<li>No services recorded</li>"
    selected_repository = str(tenant.get("selected_repository", "")).strip()
    selected_service = str(tenant.get("selected_service", "")).strip()
    repository_detail = next((item for item in latest_by_repository if str(item.get("repository", "")) == selected_repository), None)
    if repository_detail is None and latest_by_repository:
        repository_detail = latest_by_repository[0]
    service_detail = next((item for item in services if str(item.get("service_id", "")) == selected_service), None)
    if service_detail is None and services:
        service_detail = services[0]
    repository_detail_html = "<p class='hint'>Select a repository to inspect its latest decision state.</p>"
    if isinstance(repository_detail, dict):
        repository_detail_html = (
            f"<ul>"
            f"<li><strong>Repository</strong><div class='hint mono'>{_html_escape(str(repository_detail.get('repository', '')))}</div></li>"
            f"<li><strong>Verdict</strong><div class='hint'>{_html_escape(str(repository_detail.get('verdict', '')))}</div></li>"
            f"<li><strong>Gate status</strong><div class='hint'>{_html_escape(str(repository_detail.get('gate_status', '')))}</div></li>"
            f"<li><strong>Pack</strong><div class='hint'>{_html_escape(str(repository_detail.get('pack_id', '')))} / {_html_escape(str(repository_detail.get('pack_version', '')))}</div></li>"
            f"<li><strong>Generated at</strong><div class='hint mono'>{_html_escape(str(repository_detail.get('generated_at', '')))}</div></li>"
            f"</ul>"
        )
    service_detail_html = "<p class='hint'>Select a service to inspect ownership and criticality details.</p>"
    if isinstance(service_detail, dict):
        service_detail_html = (
            f"<ul>"
            f"<li><strong>Service</strong><div class='hint mono'>{_html_escape(str(service_detail.get('service_id', '')))}</div></li>"
            f"<li><strong>Repository</strong><div class='hint mono'>{_html_escape(str(service_detail.get('repository', '')))}</div></li>"
            f"<li><strong>Owner</strong><div class='hint'>{_html_escape(str(service_detail.get('service_owner', '')) or 'unassigned')}</div></li>"
            f"<li><strong>Owning team</strong><div class='hint'>{_html_escape(str(service_detail.get('owning_team', '')) or 'unassigned')}</div></li>"
            f"<li><strong>Criticality</strong><div class='hint'>{_html_escape(str(service_detail.get('service_criticality', '')) or 'unknown')}</div></li>"
            f"<li><strong>Project</strong><div class='hint'>{_html_escape(str(service_detail.get('project_id', '')))}</div></li>"
            f"</ul>"
        )
    ui = payload.get("ui", {}) if isinstance(payload, dict) else {}
    flash = ""
    if isinstance(ui, dict) and ui.get("message"):
        flash = f"<div class='flash {_html_escape(str(ui.get('level', 'info')))}'>{_html_escape(str(ui.get('message', '')))}</div>"
    revealed_token = str(ui.get("revealed_token", "")).strip() if isinstance(ui, dict) else ""
    token_reveal = ""
    if revealed_token:
        token_reveal = (
            f"<div class='flash warning'><strong>Producer token issued once.</strong>"
            f"<div class='hint'>Store this now. Only the prefix is persisted by the control plane after this response.</div>"
            f"<div class='token-box mono'>{_html_escape(revealed_token)}</div>"
            f"</div>"
        )
    repository_event_count = sum(1 for item in latest_by_repository if str(item.get("repository", "")) == str(repository_detail.get("repository", ""))) if isinstance(repository_detail, dict) else 0
    if isinstance(repository_detail, dict):
        related_service = next((item for item in services if str(item.get("repository", "")) == str(repository_detail.get("repository", ""))), None)
        if isinstance(related_service, dict):
            repository_detail_html += (
                f"<div class='hint' style='margin-top:.75rem;'><strong>Related service:</strong> {_html_escape(str(related_service.get('service_id', '')))} / "
                f"{_html_escape(str(related_service.get('service_criticality', '')) or 'unknown')}</div>"
            )
        repository_detail_html += f"<div class='hint' style='margin-top:.5rem;'><strong>Observed latest-repository entries:</strong> {repository_event_count}</div>"
    if isinstance(service_detail, dict):
        matching_repo_detail = next((item for item in latest_by_repository if str(item.get("repository", "")) == str(service_detail.get("repository", ""))), None)
        if isinstance(matching_repo_detail, dict):
            service_detail_html += (
                f"<div class='hint' style='margin-top:.75rem;'><strong>Latest decision:</strong> "
                f"{_html_escape(str(matching_repo_detail.get('verdict', '')))} / {_html_escape(str(matching_repo_detail.get('gate_status', '')))}</div>"
            )
    if not latest_by_repository:
        repository_detail_html = "<p class='hint'>No decision history yet. Connect a producer client and send the first event to unlock repository drilldowns.</p>"
    if not services:
        service_detail_html = "<p class='hint'>No services cataloged yet. Service drilldowns appear after decisions arrive with service metadata.</p>"
    onboarding_empty = ""
    if not events:
        onboarding_empty = "<div class='flash warning'>No decision events have landed for this tenant yet. Create or copy a producer token below, wire it into CI, and then return here to verify the first event.</div>"
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{_html_escape(service_name)} App</title>
    <style>
      :root {{ --bg:#f3f6f4; --panel:#fffdf8; --line:#d7ddd4; --ink:#12231d; --muted:#5d6e65; --accent:#176b52; --accent-soft:#e8f5ef; --warn:#9b5a00; --warn-soft:#fff3df; --danger:#9a2f1f; --danger-soft:#fff0eb; }}
      * {{ box-sizing:border-box; }}
      body {{ margin:0; font-family:Georgia, "Iowan Old Style", "Palatino Linotype", serif; background:radial-gradient(circle at top, #fcfffb 0%, var(--bg) 48%, #edf2ee 100%); color:var(--ink); }}
      .shell {{ max-width:1320px; margin:0 auto; padding:2rem 1.25rem 3rem; }}
      .hero {{ display:grid; grid-template-columns:1.1fr 0.9fr; gap:1rem; margin-bottom:1rem; }}
      .hero-card {{ background:linear-gradient(135deg, #153b2d 0%, #245843 55%, #dff0e7 180%); color:#f6fbf8; border-radius:28px; padding:1.5rem; min-height:220px; box-shadow:0 22px 48px rgba(18,35,29,.15); }}
      .hero h1 {{ margin:0 0 .4rem 0; font-size:2.3rem; letter-spacing:-0.04em; }}
      .hero p {{ margin:.45rem 0 0 0; max-width:42rem; color:rgba(246,251,248,.84); line-height:1.45; }}
      .meta {{ color:rgba(246,251,248,.74); font-size:.95rem; }}
      .hero-side {{ display:grid; gap:1rem; }}
      .card {{ background:var(--panel); border:1px solid var(--line); border-radius:22px; padding:1rem; box-shadow:0 12px 32px rgba(18,35,29,.06); }}
      .summary-grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:1rem; margin:1rem 0; }}
      .mini-card {{ background:var(--panel); border:1px solid var(--line); border-radius:20px; padding:1rem; }}
      .label {{ color:var(--muted); font-size:.84rem; text-transform:uppercase; letter-spacing:.08em; }}
      .value {{ font-size:2rem; margin-top:.35rem; font-weight:700; }}
      .value.small {{ font-size:1.2rem; }}
      .section-grid {{ display:grid; grid-template-columns:1.15fr .85fr; gap:1rem; margin-top:1rem; }}
      .stack {{ display:grid; gap:1rem; }}
      .triple {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:1rem; margin-top:1rem; }}
      .section-title {{ margin:0 0 .85rem 0; font-size:1rem; letter-spacing:-0.01em; }}
      .section-kicker {{ color:var(--muted); font-size:.9rem; margin:-.35rem 0 .9rem 0; }}
      .pill {{ display:inline-block; padding:.35rem .7rem; border-radius:999px; background:rgba(255,255,255,.1); border:1px solid rgba(255,255,255,.18); margin-right:.45rem; margin-bottom:.45rem; font-size:.88rem; }}
      .status {{ display:inline-block; margin-left:.4rem; padding:.18rem .45rem; border-radius:999px; font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; }}
      .status.ready {{ background:var(--accent-soft); color:var(--accent); }}
      .status.todo {{ background:var(--warn-soft); color:var(--warn); }}
      .mono {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.85rem; }}
      ul {{ margin:0; padding-left:1rem; }}
      li {{ margin:.45rem 0; }}
      .hint {{ color:var(--muted); font-size:.9rem; margin-top:.2rem; }}
      .callout {{ background:linear-gradient(180deg, #fff9ef 0%, #fffdf9 100%); border:1px solid #f0d7aa; }}
      .callout strong {{ color:#7a4d00; }}
      .flash {{ border-radius:18px; padding:1rem 1.1rem; margin:1rem 0; border:1px solid var(--line); }}
      .flash.success {{ background:#edf8f2; border-color:#b9dccb; color:#15553f; }}
      .flash.warning {{ background:#fff6e7; border-color:#efd49f; color:#7a4d00; }}
      .flash.error {{ background:#fff0eb; border-color:#f1beb5; color:#8b2d1f; }}
      .token-box {{ margin-top:.75rem; padding:.9rem 1rem; background:#fffdf8; border:1px dashed #d2b276; border-radius:14px; word-break:break-all; color:#6b4300; }}
      table {{ width:100%; border-collapse:collapse; }}
      th, td {{ text-align:left; padding:.7rem .55rem; border-top:1px solid var(--line); font-size:.94rem; vertical-align:top; }}
      th {{ color:var(--muted); font-weight:600; border-top:none; }}
      .count {{ float:right; color:var(--muted); font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }}
      .footer {{ margin-top:1rem; color:var(--muted); font-size:.92rem; }}
      .two-col {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:1rem; }}
      form {{ display:grid; gap:.75rem; }}
      label {{ display:grid; gap:.25rem; font-size:.92rem; color:var(--muted); }}
      input {{ width:100%; border:1px solid var(--line); border-radius:12px; padding:.75rem .8rem; background:#fff; color:var(--ink); font:inherit; }}
      button {{ border:none; border-radius:999px; padding:.75rem 1rem; background:var(--accent); color:#fff; font:inherit; cursor:pointer; }}
      a {{ color:var(--accent); text-decoration:none; }}
      a:hover {{ text-decoration:underline; }}
      @media (max-width: 1080px) {{
        .hero, .section-grid, .triple, .summary-grid, .two-col {{ grid-template-columns:1fr; }}
      }}
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="hero">
        <div class="hero-card">
          <div class="meta">Tenant {tenant_label} / Identity {_html_escape(principal)} / API {_html_escape(api_version)}</div>
          <h1>{display_name}</h1>
          <p>Hosted control plane for release decisions, CI event intake, scheduled materializations, and operator state. This screen should answer whether the tenant is onboarded, whether decisions are arriving, and whether the worker is alive.</p>
          <div style="margin-top:1rem;">
            <span class="pill">{events} decision events</span>
            <span class="pill">{repositories} repositories</span>
            <span class="pill">{schedule_count} schedules</span>
            <span class="pill">{materialization_count} materializations</span>
          </div>
        </div>
        <div class="hero-side">
          <div class="card callout">
            <div class="label">Onboarding Progress</div>
            <div class="value small">{completed_steps} / {len(checklist)} complete</div>
            <p class="hint"><strong>Next step:</strong> {_html_escape(next_step)}</p>
          </div>
          <div class="card">
            <div class="label">Service Shape</div>
            <div class="hint">Backend {store_backend} / schema {schema_version} / persistent store {has_persistent_store}</div>
            <div class="hint">History paths: {_html_escape(str(len(history_paths)))}</div>
          </div>
        </div>
      </div>
      {flash}
      {token_reveal}
      {onboarding_empty}

      <div class="summary-grid">
        <div class="mini-card"><div class="label">Events</div><div class="value">{events}</div></div>
        <div class="mini-card"><div class="label">Repositories</div><div class="value">{repositories}</div></div>
        <div class="mini-card"><div class="label">Blocked Decisions</div><div class="value">{blocked_events}</div></div>
        <div class="mini-card"><div class="label">Producer Clients</div><div class="value">{producer_count}</div></div>
      </div>

      <div class="section-grid">
        <div class="card">
          <h2 class="section-title">Onboarding Checklist</h2>
          <div class="section-kicker">Track the minimum viable tenant setup for a live hosted rollout.</div>
          <ul>
            {onboarding_items}
          </ul>
        </div>
        <div class="card">
          <h2 class="section-title">Live Signals</h2>
          <div class="section-kicker">What is flowing through the control plane right now.</div>
          <ul>
            <li><strong>Recent sessions</strong><span class="count">{session_count}</span><div class="hint">Authenticated app or API sessions recorded for this tenant.</div></li>
            <li><strong>Scheduled runs</strong><span class="count">{len(schedule_runs)}</span><div class="hint">Materializations created by the worker daemon.</div></li>
            <li><strong>Catalog objects</strong><span class="count">{len(organizations) + len(projects) + len(services)}</span><div class="hint">Organizations, projects, and services linked to this tenant.</div></li>
            <li><strong>Provider secret refs</strong><span class="count">{len(provider_secrets)}</span><div class="hint">References ready for incident, alert, or rollout integrations.</div></li>
          </ul>
        </div>
      </div>

      <div class="triple">
        <div class="card">
          <h2 class="section-title">Add Tenant</h2>
          <div class="section-kicker">Provision a new tenant boundary directly from the app.</div>
          <form method="post" action="/api/{_html_escape(api_version)}/app">
            <input type="hidden" name="action" value="create_tenant">
            <label>Tenant ID<input name="tenant_id" value="{_html_escape(tenant_value)}" placeholder="acme"></label>
            <label>Display Name<input name="display_name" value="{_html_escape(str(tenant.get('display_name', '')))}" placeholder="Acme Production"></label>
            <label>Organization Name<input name="organization_name" value="{_html_escape(str(tenant.get('display_name', '')))}" placeholder="Acme"></label>
            <label>Status<input name="status" value="active"></label>
            <button type="submit">Provision Tenant</button>
          </form>
        </div>
        <div class="card">
          <h2 class="section-title">Add Producer Client</h2>
          <div class="section-kicker">Create a CI ingestor token without leaving the control plane.</div>
          <form method="post" action="/api/{_html_escape(api_version)}/app">
            <input type="hidden" name="action" value="create_producer_client">
            <input type="hidden" name="tenant_id" value="{_html_escape(tenant_value)}">
            <label>Client ID<input name="client_id" placeholder="github-actions"></label>
            <label>Display Name<input name="display_name" placeholder="GitHub Actions"></label>
            <label>Roles<input name="roles_csv" value="ingestor"></label>
            <label>Status<input name="status" value="active"></label>
            <button type="submit">Create Producer</button>
          </form>
        </div>
        <div class="card">
          <h2 class="section-title">Add Service User</h2>
          <div class="section-kicker">Create an operator identity record for this tenant.</div>
          <form method="post" action="/api/{_html_escape(api_version)}/app">
            <input type="hidden" name="action" value="create_service_user">
            <input type="hidden" name="tenant_id" value="{_html_escape(tenant_value)}">
            <label>User ID<input name="user_id" placeholder="alice"></label>
            <label>Principal Name<input name="principal_name" placeholder="Alice Doe"></label>
            <label>Email<input name="email" placeholder="alice@example.com"></label>
            <label>Roles<input name="roles_csv" value="reader"></label>
            <label>Status<input name="status" value="active"></label>
            <button type="submit">Create User</button>
          </form>
        </div>
      </div>

      <div class="triple">
        <div class="card">
          <h2 class="section-title">Add Provider Secret Ref</h2>
          <div class="section-kicker">Store an integration reference for incidents, alerts, or rollout systems.</div>
          <form method="post" action="/api/{_html_escape(api_version)}/app">
            <input type="hidden" name="action" value="create_provider_secret">
            <input type="hidden" name="tenant_id" value="{_html_escape(tenant_value)}">
            <label>Provider<input name="provider" placeholder="pagerduty"></label>
            <label>Secret Name<input name="secret_name" placeholder="pagerduty-token"></label>
            <label>Secret Ref<input name="secret_ref" placeholder="aws-secretsmanager://veridion/acme/pagerduty"></label>
            <label>Description<input name="description" placeholder="PagerDuty API token"></label>
            <button type="submit">Store Secret Ref</button>
          </form>
        </div>
        <div class="card">
          <h2 class="section-title">First Run Notes</h2>
          <div class="section-kicker">How to make this tenant stop looking empty.</div>
          <ul>
            <li><strong>Step 1</strong><div class="hint">Provision the tenant boundary and at least one producer client.</div></li>
            <li><strong>Step 2</strong><div class="hint">Send the first decision event from CI so repository and service drilldowns become meaningful.</div></li>
            <li><strong>Step 3</strong><div class="hint">Add provider refs and service users so the control plane reflects real operator ownership.</div></li>
          </ul>
        </div>
        <div class="card">
          <h2 class="section-title">Current Control Signals</h2>
          <div class="section-kicker">Fast read of what is live for this tenant.</div>
          <ul>
            <li><strong>Latest repo decision</strong><div class="hint">{_html_escape(str((latest_by_repository[0] if latest_by_repository else {}).get('repository', 'none')))} / {_html_escape(str((latest_by_repository[0] if latest_by_repository else {}).get('verdict', 'none')))}</div></li>
            <li><strong>Latest materialization</strong><div class="hint">{_html_escape(str((materializations[0] if materializations else {}).get('run_id', 'none')))}</div></li>
            <li><strong>Latest session</strong><div class="hint">{_html_escape(str((sessions[0] if sessions else {}).get('session_id', 'none')))}</div></li>
          </ul>
        </div>
      </div>

      <div class="section-grid">
        <div class="card">
          <h2 class="section-title">Recent Repository Decisions</h2>
          <div class="section-kicker">Latest release-control state seen per repository.</div>
          <table>
            <thead><tr><th>Repository</th><th>Verdict</th><th>Gate</th><th>Generated At</th></tr></thead>
            <tbody>{repository_rows}</tbody>
          </table>
        </div>
        <div class="stack">
          <div class="card">
            <h2 class="section-title">Top Blocking Categories</h2>
            <ul>{blocking_items}</ul>
          </div>
          <div class="card">
            <h2 class="section-title">Producer Clients</h2>
            <ul>{producer_items}</ul>
          </div>
        </div>
      </div>

      <div class="triple">
        <div class="card">
          <h2 class="section-title">Schedules</h2>
          <ul>{schedule_items}</ul>
        </div>
        <div class="card">
          <h2 class="section-title">Recent Materializations</h2>
          <ul>{materialization_items}</ul>
        </div>
        <div class="card">
          <h2 class="section-title">Managed Tenants</h2>
          <div class="section-kicker">Tenant boundaries provisioned inside the hosted control plane.</div>
          <ul>{managed_tenant_items}</ul>
          <div class="section-kicker" style="margin-top:1rem;">Catalog inventory: {len(organizations)} orgs / {len(projects)} projects / {len(services)} services.</div>
        </div>
      </div>

      <div class="section-grid">
        <div class="card">
          <h2 class="section-title">Repository Drilldown</h2>
          <div class="section-kicker">Select a repository to inspect its latest decision state.</div>
          <div class="two-col">
            <div>
              <h3 class="section-title" style="margin-top:0;">Repositories</h3>
              <ul>{repository_link_items}</ul>
            </div>
            <div>
              <h3 class="section-title" style="margin-top:0;">Selected Repository</h3>
              {repository_detail_html}
            </div>
          </div>
        </div>
        <div class="card">
          <h2 class="section-title">Service Drilldown</h2>
          <div class="section-kicker">Inspect cataloged service ownership and criticality.</div>
          <div class="two-col">
            <div>
              <h3 class="section-title" style="margin-top:0;">Services</h3>
              <ul>{service_link_items}</ul>
            </div>
            <div>
              <h3 class="section-title" style="margin-top:0;">Selected Service</h3>
              {service_detail_html}
            </div>
          </div>
        </div>
      </div>

      <div class="two-col">
        <div class="card">
          <h2 class="section-title">People And Access</h2>
          <div class="section-kicker">Persistent identities and observed operator sessions.</div>
          <div class="two-col">
            <div>
              <h3 class="section-title" style="margin-top:0;">Service Users</h3>
              <ul>{user_items}</ul>
            </div>
            <div>
              <h3 class="section-title" style="margin-top:0;">Sessions</h3>
              <ul>{session_items}</ul>
            </div>
          </div>
        </div>
        <div class="card">
          <h2 class="section-title">Provider Secret References</h2>
          <div class="section-kicker">Control-plane references only. Secret values stay outside the service.</div>
          <ul>{secret_items}</ul>
        </div>
      </div>

      <div class="card" style="margin-top:1rem;">
        <h2 class="section-title">Operator Actions</h2>
        <div class="section-kicker">Use the versioned API surface to provision, ingest, and monitor.</div>
        <ul>
          <li><span class="mono">/api/{_html_escape(api_version)}/admin/tenants</span> to provision new tenant boundaries.</li>
          <li><span class="mono">/api/{_html_escape(api_version)}/admin/producer-clients</span> to onboard another CI producer.</li>
          <li><span class="mono">/api/{_html_escape(api_version)}/events</span> to ingest canonical decision events.</li>
          <li><span class="mono">/api/{_html_escape(api_version)}/materializations</span> and <span class="mono">/api/{_html_escape(api_version)}/materialization-schedules</span> to inspect scheduled analytics.</li>
          <li><span class="mono">/api/{_html_escape(api_version)}/overview</span> and <span class="mono">/api/{_html_escape(api_version)}/analytics</span> for automation-friendly reads.</li>
        </ul>
      </div>

      <div class="footer">Hosted alpha UX is now centered on onboarding, live intake, and worker health. The next layer should turn these static operator cues into writable forms and deeper repo/service drilldowns.</div>
    </div>
  </body>
</html>"""


def _html_escape(value: str) -> str:
    return html.escape(value, quote=True)


def _service_criticality_suffix(item: dict[str, object]) -> str:
    criticality = str(item.get("service_criticality", "")).strip()
    return f" {_html_escape(f'({criticality})')}" if criticality else ""


def _merge_auth_tokens(config_tokens: tuple[str, ...], cli_token: str) -> tuple[str, ...]:
    merged = list(config_tokens)
    if cli_token:
        merged.append(cli_token)
    return tuple(dict.fromkeys(merged))


if __name__ == "__main__":
    raise SystemExit(main())
