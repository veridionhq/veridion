"""Serve file-backed Veridion decision-history analytics over HTTP."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import html
import json
import threading
import time
from http.cookies import SimpleCookie
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
from veridion.action.decision_history import analyze_history, load_history_events
from veridion.action.decision_history_materialize import materialize_decision_history
from veridion.action.decision_history_store import (
    analyze_history_store,
    create_producer_client,
    create_service_session,
    get_service_session,
    get_history_store_status,
    list_catalog_models,
    list_control_plane_audit,
    list_managed_tenants,
    list_materialization_runs,
    list_producer_client_audit,
    list_producer_clients,
    list_provider_secret_refs,
    record_control_plane_audit,
    list_service_sessions,
    list_service_users,
    open_history_store,
    provision_managed_tenant,
    resolve_persistent_bearer_identity,
    update_producer_client_status,
    upsert_provider_secret_ref,
    upsert_service_user,
    upsert_decision_event_store,
)
from veridion.action.history_identity import jwt_auth_enabled, resolve_bearer_identity, resolve_trusted_header_identity

API_VERSION = "v1"
APP_SESSION_COOKIE = "veridion_app_bearer"
APP_SESSION_ID_COOKIE = "veridion_app_session_id"

# Login rate limiting (F-05): max attempts per IP within the sliding window.
_LOGIN_RATE_LIMIT = 10
_LOGIN_RATE_WINDOW = 60.0  # seconds
_LOGIN_ATTEMPTS: dict[str, tuple[int, float]] = {}
_LOGIN_LOCK = threading.Lock()


def _check_login_rate(key: str) -> bool:
    """Return True if the request is allowed, False if it exceeds the rate limit."""
    now = time.monotonic()
    with _LOGIN_LOCK:
        count, window_start = _LOGIN_ATTEMPTS.get(key, (0, now))
        if now - window_start >= _LOGIN_RATE_WINDOW:
            count, window_start = 0, now
        count += 1
        _LOGIN_ATTEMPTS[key] = (count, window_start)
        return count <= _LOGIN_RATE_LIMIT


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
        service_version=config.service_version if config else "",
        deployment_id=config.deployment_id if config else "",
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
    service_version: str,
    deployment_id: str,
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
                service_version=service_version,
                deployment_id=deployment_id,
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
                self._write_html(status, str(payload["html"]), headers=payload.get("__headers", {}))
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
                service_version=service_version,
                deployment_id=deployment_id,
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
                self._write_html(status, str(payload["html"]), headers=payload.get("__headers", {}))
            else:
                self._write_json(status, payload)

        def log_message(self, format: str, *args) -> None:  # noqa: A003 - stdlib signature
            return

        def _write_json(self, status: int, payload: dict[str, object]) -> None:
            response_headers = payload.get("__headers", {}) if isinstance(payload.get("__headers"), dict) else {}
            response_payload = {key: value for key, value in payload.items() if key != "__headers"}
            body = json.dumps(response_payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for key, value in response_headers.items():
                self.send_header(str(key), str(value))
            self.end_headers()
            self.wfile.write(body)

        def _write_html(self, status: int, payload: str, *, headers: dict[str, object] | None = None) -> None:
            body = payload.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for key, value in (headers or {}).items():
                self.send_header(str(key), str(value))
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
    service_version: str = "",
    deployment_id: str = "",
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
        if (
            authz[0] == 403
            and isinstance(authz[1], dict)
            and authz[1].get("error") == "tenant_scope_required"
            and method == "GET"
            and route in {"/app", "/app/repository", "/app/service"}
            and identity is not None
            and identity.tenants
        ):
            params["tenant"] = identity.tenants[0]
            authz = None
        if authz is not None and authz[0] == 401 and method == "GET" and route in {"/app", "/app/repository", "/app/service"}:
            return (
                200,
                {
                    "html": render_app_login_html(
                        api_version=api_version or API_VERSION,
                        tenant_id=params.get("tenant", ""),
                        next_path=path,
                        service_name=service_name,
                        managed_identity_ready=bool((trusted_header_auth or TrustedHeaderAuthConfig()).enabled) or bool(jwt_auth_enabled(jwt_config or JWTAuthConfig())),
                        auth_mode_hint=_browser_auth_mode_label(jwt_config or JWTAuthConfig(), trusted_header_auth or TrustedHeaderAuthConfig()),
                    )
                },
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
            auth_tokens=auth_tokens,
            scoped_tokens=scoped_lookup,
            headers=headers or {},
            api_version=api_version or API_VERSION,
            service_name=service_name,
            jwt_config=jwt_config or JWTAuthConfig(),
            trusted_header_auth=trusted_header_auth or TrustedHeaderAuthConfig(),
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
    if route == "/app/login":
        return (
            200,
            {
                "html": render_app_login_html(
                    api_version=api_version or API_VERSION,
                    tenant_id=params.get("tenant", ""),
                    next_path=params.get("next") or f"/api/{api_version or API_VERSION}/app?tenant={params.get('tenant', '')}",
                    service_name=service_name,
                    managed_identity_ready=bool((trusted_header_auth or TrustedHeaderAuthConfig()).enabled) or bool(jwt_auth_enabled(jwt_config or JWTAuthConfig())),
                    auth_mode_hint=_browser_auth_mode_label(jwt_config or JWTAuthConfig(), trusted_header_auth or TrustedHeaderAuthConfig()),
                )
            },
        )
    if route == "/app":
        overview = _build_overview_payload(
            history_paths=history_paths,
            tenants=tenant_lookup,
            schedules=schedule_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            materialization_root=materialization_root,
            service_version=service_version,
            deployment_id=deployment_id,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
            identity=identity,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
        )
        if overview is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        _attach_selected_detail_analytics(
            overview,
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
            selected_repository=params.get("repository", ""),
            selected_service=params.get("service", ""),
            selected_producer_client=params.get("producer_client", ""),
        )
        browser_headers = _browser_session_response_headers(
            headers=headers or {},
            identity=identity,
            tenant_id=params.get("tenant", ""),
            auth_tokens=auth_tokens,
            scoped_tokens=scoped_lookup,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
        )
        return _respond(
            200,
            {"html": render_app_html(overview, api_version=api_version or API_VERSION, identity=identity, service_name=service_name), "__headers": browser_headers} if browser_headers else {"html": render_app_html(overview, api_version=api_version or API_VERSION, identity=identity, service_name=service_name)},
            route=route,
            api_version=api_version,
            identity=identity,
        )
    if route == "/app/repository" or route == "/app/service":
        overview = _build_overview_payload(
            history_paths=history_paths,
            tenants=tenant_lookup,
            schedules=schedule_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            materialization_root=materialization_root,
            service_version=service_version,
            deployment_id=deployment_id,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
            identity=identity,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
        )
        if overview is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        _attach_selected_detail_analytics(
            overview,
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
            selected_repository=params.get("repository", ""),
            selected_service=params.get("service", ""),
            selected_producer_client=params.get("producer_client", ""),
        )
        browser_headers = _browser_session_response_headers(
            headers=headers or {},
            identity=identity,
            tenant_id=params.get("tenant", ""),
            auth_tokens=auth_tokens,
            scoped_tokens=scoped_lookup,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
        )
        return _respond(
            200,
            {"html": render_focus_page_html(overview, api_version=api_version or API_VERSION, identity=identity, service_name=service_name, kind="repository" if route.endswith("/repository") else "service"), "__headers": browser_headers}
            if browser_headers
            else {
                "html": render_focus_page_html(
                    overview,
                    api_version=api_version or API_VERSION,
                    identity=identity,
                    service_name=service_name,
                    kind="repository" if route.endswith("/repository") else "service",
                )
            },
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
            service_version=service_version,
            deployment_id=deployment_id,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
            identity=identity,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
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
            service_version=service_version,
            deployment_id=deployment_id,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
            identity=identity,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
        )
        if payload is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        _attach_selected_detail_analytics(
            payload,
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
            selected_repository=params.get("repository", ""),
            selected_service=params.get("service", ""),
            selected_producer_client=params.get("producer_client", ""),
        )
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
    if route in {"/dashboard", "/app", "/app/login", "/app/logout"} and "html" in payload:
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


def _app_path_with_tenant(*, route: str, api_version: str, tenant_id: str, repository: str = "", service: str = "") -> str:
    base_route = route if route in {"/app", "/app/repository", "/app/service"} else "/app"
    version = api_version or API_VERSION
    query = [f"tenant={quote(tenant_id)}"] if tenant_id else []
    if repository:
        query.append(f"repository={quote(repository)}")
    if service:
        query.append(f"service={quote(service)}")
    suffix = "&".join(query)
    return f"/api/{version}{base_route}" + (f"?{suffix}" if suffix else "")


def _cookie_value(headers: dict[str, str], name: str) -> str:
    raw_cookie = headers.get("Cookie", "") or headers.get("cookie", "")
    if not raw_cookie:
        return ""
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except Exception:
        return ""
    morsel = cookie.get(name)
    return morsel.value.strip() if morsel is not None and morsel.value else ""


def _named_cookie_header(*, name: str, value: str, secure: bool) -> str:
    cookie = SimpleCookie()
    cookie[name] = value
    cookie[name]["path"] = "/"
    cookie[name]["httponly"] = True
    cookie[name]["samesite"] = "Lax"
    if secure:
        cookie[name]["secure"] = True
    return cookie.output(header="").strip()


def _session_cookie_header(*, token: str, secure: bool) -> str:
    return _named_cookie_header(name=APP_SESSION_COOKIE, value=token, secure=secure)


def _session_id_cookie_header(*, session_id: str, secure: bool) -> str:
    return _named_cookie_header(name=APP_SESSION_ID_COOKIE, value=session_id, secure=secure)


def _clear_named_cookie_header(*, name: str, secure: bool) -> str:
    cookie = SimpleCookie()
    cookie[name] = ""
    cookie[name]["path"] = "/"
    cookie[name]["httponly"] = True
    cookie[name]["samesite"] = "Lax"
    cookie[name]["max-age"] = 0
    if secure:
        cookie[name]["secure"] = True
    return cookie.output(header="").strip()


def _clear_session_cookie_header(*, secure: bool) -> str:
    return _clear_named_cookie_header(name=APP_SESSION_COOKIE, secure=secure)


def _clear_session_id_cookie_header(*, secure: bool) -> str:
    return _clear_named_cookie_header(name=APP_SESSION_ID_COOKIE, secure=secure)


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


def _session_not_expired(session: dict[str, str]) -> bool:
    """Return True if the session has no expiry or its expiry is in the future (F-03)."""
    expires_at = str(session.get("expires_at", "")).strip()
    if not expires_at:
        return True
    try:
        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < exp
    except ValueError:
        return True


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
    scoped: HistoryToken | None = None
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
    if not auth_header:
        cookie_token = _cookie_value(headers, APP_SESSION_COOKIE)
        if cookie_token:
            auth_header = f"Bearer {cookie_token}"
        else:
            session_id = _cookie_value(headers, APP_SESSION_ID_COOKIE)
            if session_id:
                session = get_service_session(sqlite_path=sqlite_path, store_dsn=store_dsn, session_id=session_id)
                if session is not None and str(session.get("status", "active")) == "active" and _session_not_expired(session):
                    scoped = HistoryToken(
                        token=session_id,
                        token_id=str(session.get("user_id", "") or session.get("session_id", "")),
                        principal_name=str(session.get("principal_name", "")),
                        auth_type=str(session.get("auth_type", "") or "session"),
                        tenants=(str(session.get("tenant_id", "")),) if str(session.get("tenant_id", "")).strip() else (),
                        roles=tuple(role.strip() for role in str(session.get("roles_csv", "")).split(",") if role.strip()),
                        status="active",
                    )
                    auth_header = ""
                else:
                    scoped = None
    header_identity = resolve_trusted_header_identity(headers=headers, config=trusted_header_auth)
    if not auth_tokens and not scoped_tokens and not jwt_auth_enabled(jwt_config) and header_identity is None:
        return (None, None)
    if header_identity is not None:
        scoped = header_identity
    else:
        if path in {"/app/login", "/app/logout"}:
            return (None, None)
        if scoped is not None:
            pass
        elif not auth_header.startswith("Bearer "):
            return ((401, {"error": "unauthorized"}), None)
        else:
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
    if path in {"/analytics", "/repositories", "/policy-rollouts", "/dashboard", "/overview", "/materializations", "/materialization-schedules", "/service/status", "/app", "/app/repository", "/app/service"} and not _has_role(
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


def _resolve_browser_session_identity(
    *,
    headers: dict[str, str],
    auth_tokens: tuple[str, ...],
    scoped_tokens: dict[str, HistoryToken],
    jwt_config: JWTAuthConfig,
    trusted_header_auth: TrustedHeaderAuthConfig,
    sqlite_path: str,
    store_dsn: str,
) -> HistoryToken | None:
    authz, identity = _authorize_request(
        headers=headers,
        auth_tokens=auth_tokens,
        scoped_tokens=scoped_tokens,
        jwt_config=jwt_config,
        trusted_header_auth=trusted_header_auth,
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id="",
        path="/app",
        method="GET",
    )
    if identity is not None:
        return identity
    if authz is None:
        return None
    if authz[0] == 403 and isinstance(authz[1], dict) and authz[1].get("error") == "tenant_scope_required":
        return identity
    return None


def _build_overview_payload(
    *,
    history_paths: tuple[str, ...],
    tenants: dict[str, HistoryTenant],
    schedules: dict[str, MaterializationSchedule],
    sqlite_path: str,
    store_dsn: str,
    materialization_root: str,
    service_version: str,
    deployment_id: str,
    tenant_id: str,
    since: str | None,
    until: str | None,
    identity: HistoryToken | None,
    jwt_config: JWTAuthConfig,
    trusted_header_auth: TrustedHeaderAuthConfig | None = None,
    analytics: dict[str, object] | None = None,
) -> dict[str, object] | None:
    jwt_config = jwt_config or JWTAuthConfig()
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
    overview = {
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
            "service_version": service_version,
            "deployment_id": deployment_id,
            "jwt_issuer": jwt_config.issuer,
            "jwt_audience": jwt_config.audience,
            "jwks_url": jwt_config.jwks_url,
            "oidc_discovery_url": jwt_config.oidc_discovery_url,
            "jwt_enabled": bool(jwt_auth_enabled(jwt_config)),
            "trusted_header_enabled": bool(trusted_header_auth.enabled) if trusted_header_auth is not None else False,
        },
        "catalog": _catalog_payload(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id),
        "admin": {
            "managed_tenants": list(list_managed_tenants(sqlite_path=sqlite_path, store_dsn=store_dsn)) if (sqlite_path or store_dsn) else [],
            "service_users": list(list_service_users(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if (sqlite_path or store_dsn) and tenant_id else [],
            "provider_secrets": list(list_provider_secret_refs(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if (sqlite_path or store_dsn) and tenant_id else [],
            "producer_clients": list(list_producer_clients(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if (sqlite_path or store_dsn) and tenant_id else [],
            "sessions": list(list_service_sessions(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if (sqlite_path or store_dsn) and tenant_id else [],
            "control_audit": list(list_control_plane_audit(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id, limit=20)) if (sqlite_path or store_dsn) and tenant_id else [],
        },
    }
    admin_payload = overview.get("admin", {}) if isinstance(overview.get("admin"), dict) else {}
    overview["observability"] = _observability_payload(
        analytics=analytics_payload,
        materializations=materializations,
        sessions=admin_payload.get("sessions", []) if isinstance(admin_payload.get("sessions"), list) else [],
        producer_clients=admin_payload.get("producer_clients", []) if isinstance(admin_payload.get("producer_clients"), list) else [],
        service=overview.get("service", {}) if isinstance(overview.get("service"), dict) else {},
        control_audit=admin_payload.get("control_audit", []) if isinstance(admin_payload.get("control_audit"), list) else [],
    )
    return overview


def _browser_auth_mode_label(jwt_config: JWTAuthConfig, trusted_header_auth: TrustedHeaderAuthConfig) -> str:
    if trusted_header_auth.enabled:
        return "Managed browser sign-in through trusted gateway headers is active."
    if jwt_auth_enabled(jwt_config):
        return "Managed browser sign-in through JWT or OIDC is ready."
    return "Paste an operator token once to bridge into a browser session."


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
    auth_tokens: tuple[str, ...],
    scoped_tokens: dict[str, HistoryToken],
    headers: dict[str, str],
    api_version: str,
    service_name: str,
    jwt_config: JWTAuthConfig,
    trusted_header_auth: TrustedHeaderAuthConfig,
) -> tuple[int, dict[str, object]]:
    if path == "/app/login":
        return _handle_app_login_post_request(
            body=body,
            headers=headers,
            scoped_tokens=scoped_tokens,
            auth_tokens=auth_tokens,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            api_version=api_version,
            service_name=service_name,
        )
    if path == "/app/logout":
        secure_cookie = (headers.get("X-Forwarded-Proto", "") or headers.get("x-forwarded-proto", "")).strip().lower() == "https"
        browser_identity = _resolve_browser_session_identity(
            headers=headers,
            auth_tokens=auth_tokens,
            scoped_tokens=scoped_tokens,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
        )
        logout_tenant = browser_identity.tenants[0] if browser_identity and browser_identity.tenants else ""
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=logout_tenant,
            actor=_audit_actor(browser_identity),
            action="browser_logout",
            target_kind="browser_session",
            target_id=_cookie_value(headers, APP_SESSION_ID_COOKIE) or "session",
            detail="browser session cleared",
        )
        return (
            200,
            {
                "html": render_app_login_html(
                    api_version=api_version,
                    tenant_id="",
                    next_path=f"/api/{api_version}/app",
                    service_name=service_name,
                    message="Signed out.",
                    level="success",
                ),
                "__headers": {"Set-Cookie": f"{_clear_session_cookie_header(secure=secure_cookie)}, {_clear_session_id_cookie_header(secure=secure_cookie)}"},
            },
        )
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
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header_auth,
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
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            actor=_audit_actor(scoped_token),
            action="tenant_provisioned",
            target_kind="tenant",
            target_id=tenant_id,
            detail=f"status={_body_string(payload, 'status') or 'active'}",
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
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            actor=_audit_actor(scoped_token),
            action="service_user_upserted",
            target_kind="service_user",
            target_id=user_id,
            detail=f"roles={_body_string(payload, 'roles_csv') or 'reader'};status={_body_string(payload, 'status') or 'active'}",
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
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            actor=_audit_actor(scoped_token),
            action="provider_secret_upserted",
            target_kind="provider_secret",
            target_id=secret_name,
            detail=f"provider={_body_string(payload, 'provider')}",
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
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            actor=_audit_actor(scoped_token),
            action="producer_created",
            target_kind="producer_client",
            target_id=client_id,
            detail=f"roles={_body_string(payload, 'roles_csv') or 'ingestor'};status={_body_string(payload, 'status') or 'active'}",
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
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            actor=_audit_actor(scoped_token),
            action="session_created",
            target_kind="service_session",
            target_id=session_id,
            detail=f"auth_type={scoped_token.auth_type or 'bearer'};roles={','.join(scoped_token.roles)}",
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
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=_audit_actor(scoped_token),
                action="event_ingest_failed",
                target_kind="repository",
                target_id="unknown",
                detail="event payload missing",
            )
            return (400, {"error": "event_required"})
        repository = event.get("repository", "")
        if not isinstance(repository, str) or not repository.strip():
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=_audit_actor(scoped_token),
                action="event_ingest_failed",
                target_kind="repository",
                target_id="unknown",
                detail="repository field missing",
            )
            return (400, {"error": "repository_required"})
        upsert_decision_event_store(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            event=event,
        )
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            actor=_audit_actor(scoped_token),
            action="event_ingested",
            target_kind="repository",
            target_id=repository.strip(),
            detail=f"auth_type={scoped_token.auth_type if scoped_token is not None else 'anonymous'}",
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
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=_audit_actor(scoped_token),
                action="materialization_create_failed",
                target_kind="materialization_run",
                target_id=schedule_id,
                detail="schedule not found",
            )
            return (404, {"error": "schedule_not_found"})
        if schedule.tenants and tenant_id not in schedule.tenants:
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=_audit_actor(scoped_token),
                action="materialization_create_failed",
                target_kind="materialization_run",
                target_id=schedule_id,
                detail="schedule forbidden for tenant",
            )
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
    _record_control_audit(
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id=tenant_id,
        actor=_audit_actor(scoped_token),
        action="materialization_created",
        target_kind="materialization_run",
        target_id=str(runs[0].get("run_id", "")) if runs else str(run_dir),
        detail=f"schedule_id={schedule_id or 'manual'}",
    )
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
    jwt_config: JWTAuthConfig,
    trusted_header_auth: TrustedHeaderAuthConfig | None = None,
) -> tuple[int, dict[str, object]]:
    payload = _parse_form_payload(body, headers)
    action = _body_string(payload, "action")
    actor = _audit_actor(scoped_token)
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
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=target_tenant,
                actor=actor,
                action="tenant_provisioned",
                target_kind="tenant",
                target_id=target_tenant,
                detail=f"status={_body_string(payload, 'status') or 'active'}",
            )
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
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=actor,
                action="producer_created",
                target_kind="producer_client",
                target_id=client_id,
                detail=f"roles={_body_string(payload, 'roles_csv') or 'ingestor'};status={_body_string(payload, 'status') or 'active'}",
            )
    elif action == "rotate_producer_client":
        client_id = _body_string(payload, "client_id")
        existing = _producer_client_record(
            list(list_producer_clients(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if tenant_id else [],
            client_id,
        )
        if not tenant_id or not client_id:
            message = "Tenant and client ID are required."
            level = "error"
        elif not isinstance(existing, dict):
            message = f"Producer client {client_id} not found."
            level = "error"
        else:
            created = create_producer_client(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                client_id=client_id,
                display_name=str(existing.get("display_name", "")) or client_id,
                roles_csv=str(existing.get("roles_csv", "")) or "ingestor",
                status="active",
            )
            message = f"Producer client {client_id} rotated."
            level = "success"
            payload["revealed_token"] = created.get("token", "")
            payload["revealed_token_prefix"] = created.get("token_prefix", "")
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=actor,
                action="producer_rotated",
                target_kind="producer_client",
                target_id=client_id,
                detail="fresh token issued",
            )
    elif action == "revoke_producer_client":
        client_id = _body_string(payload, "client_id")
        if not tenant_id or not client_id:
            message = "Tenant and client ID are required."
            level = "error"
        else:
            update_producer_client_status(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                client_id=client_id,
                status="revoked",
            )
            message = f"Producer client {client_id} revoked."
            level = "success"
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=actor,
                action="producer_revoked",
                target_kind="producer_client",
                target_id=client_id,
                detail="status=revoked",
            )
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
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=actor,
                action="service_user_upserted",
                target_kind="service_user",
                target_id=user_id,
                detail=f"roles={_body_string(payload, 'roles_csv') or 'reader'};status={_body_string(payload, 'status') or 'active'}",
            )
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
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=actor,
                action="provider_secret_upserted",
                target_kind="provider_secret",
                target_id=secret_name,
                detail=f"provider={_body_string(payload, 'provider')}",
            )
    elif action == "connect_repository":
        repository = _body_string(payload, "repository")
        service_id = _body_string(payload, "service")
        selected_client = _body_string(payload, "producer_client")
        if not tenant_id or not repository or not service_id:
            message = "Tenant, repository, and service are required."
            level = "error"
        else:
            if not selected_client:
                clients = list(list_producer_clients(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id))
                active = next((item for item in clients if str(item.get("status", "")) == "active"), None)
                selected_client = str((active or (clients[0] if clients else {})).get("client_id", "")) if clients else ""
            payload["producer_client"] = selected_client
            message = f"Repository onboarding plan prepared for {repository}."
            level = "success"
            _record_control_audit(
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                tenant_id=tenant_id,
                actor=actor,
                action="repository_onboarding_prepared",
                target_kind="repository",
                target_id=repository,
                detail=f"service={service_id};producer={selected_client}",
            )
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
        service_version="",
        deployment_id="",
        tenant_id=tenant_id,
        since=None,
        until=None,
        identity=scoped_token,
        jwt_config=jwt_config,
        trusted_header_auth=None,
    )
    if overview is None:
        return (404, {"error": "tenant_not_found"})
    _attach_selected_detail_analytics(
        overview,
        history_paths=history_paths,
        tenants=tenants,
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id=tenant_id,
        selected_repository=_body_string(payload, "repository"),
        selected_service=_body_string(payload, "service"),
        selected_producer_client=_body_string(payload, "producer_client"),
    )
    overview["ui"] = {
        "message": message,
        "level": level,
        "revealed_token": _body_string(payload, "revealed_token"),
        "revealed_token_prefix": _body_string(payload, "revealed_token_prefix"),
        "repo_connect": _build_repo_connect_payload(
            tenant_id=tenant_id,
            repository=_body_string(payload, "repository"),
            service_id=_body_string(payload, "service"),
            organization=_body_string(payload, "organization"),
            project_id=_body_string(payload, "project_id"),
            owner=_body_string(payload, "service_owner"),
            team=_body_string(payload, "owning_team"),
            criticality=_body_string(payload, "service_criticality"),
            client_id=_body_string(payload, "producer_client"),
            service_url=(
                # Only derive the URL from forwarded headers when the trusted-header auth
                # mechanism is active (already validates via shared secret), so an arbitrary
                # client cannot spoof the service URL shown in setup snippets (F-04).
                f"{headers.get('X-Forwarded-Proto', '').strip()}://{headers.get('Host', '').strip()}"
                if trusted_header_auth is not None and trusted_header_auth.enabled
                and headers.get("X-Forwarded-Proto", "").strip() and headers.get("Host", "").strip()
                else ""
            ),
            api_version=api_version,
            revealed_token=_body_string(payload, "revealed_token"),
            producer_record=_producer_client_record(
                list(list_producer_clients(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id)) if tenant_id else [],
                _body_string(payload, "producer_client"),
            ),
            repository_analytics=(overview.get("detail") or {}).get("repository_analytics") if isinstance(overview.get("detail"), dict) else None,
            tenant_analytics=overview.get("analytics") if isinstance(overview.get("analytics"), dict) else None,
        ),
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


def _handle_app_login_post_request(
    *,
    body: str,
    headers: dict[str, str],
    scoped_tokens: dict[str, HistoryToken],
    auth_tokens: tuple[str, ...],
    jwt_config: JWTAuthConfig,
    trusted_header_auth: TrustedHeaderAuthConfig,
    sqlite_path: str,
    store_dsn: str,
    api_version: str,
    service_name: str,
) -> tuple[int, dict[str, object]]:
    # Rate-limit login attempts by client IP (F-05: brute-force protection).
    client_ip = (
        headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or headers.get("X-Real-IP", "").strip()
        or "global"
    )
    if not _check_login_rate(client_ip):
        return (429, {"error": "too_many_requests"})
    payload = _parse_form_payload(body, headers)
    token = _body_string(payload, "token")
    tenant_id = _body_string(payload, "tenant_id")
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    next_path = _body_string(payload, "next") or _app_path_with_tenant(route="/app", api_version=api_version, tenant_id=tenant_id)
    parsed_next = urlparse(next_path)
    next_params = _query_params(parsed_next.query)
    if tenant_id and parsed_next.path in {f"/api/{api_version}/app", f"/api/{api_version}/app/repository", f"/api/{api_version}/app/service"} and not next_params.get("tenant"):
        next_path = _app_path_with_tenant(
            route=parsed_next.path[len(f"/api/{api_version}") :] or "/app",
            api_version=api_version,
            tenant_id=tenant_id,
            repository=next_params.get("repository", ""),
            service=next_params.get("service", ""),
        )
    if not token:
        return (
            200,
            {
                "html": render_app_login_html(
                    api_version=api_version,
                    tenant_id=tenant_id,
                    next_path=next_path,
                    service_name=service_name,
                    message="Bearer token is required.",
                    level="error",
                )
            },
        )
    authz, identity = _authorize_request(
        headers={"Authorization": f"Bearer {token}"},
        auth_tokens=auth_tokens,
        scoped_tokens=scoped_tokens,
        jwt_config=jwt_config,
        trusted_header_auth=trusted_header_auth,
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id=tenant_id,
        path="/app",
        method="GET",
    )
    if (
        authz is not None
        and authz[0] == 403
        and isinstance(authz[1], dict)
        and authz[1].get("error") == "tenant_scope_required"
        and identity is not None
        and identity.tenants
    ):
        tenant_id = identity.tenants[0]
        next_path = _app_path_with_tenant(route="/app", api_version=api_version, tenant_id=tenant_id)
        authz = None
    if authz is not None or identity is None:
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            actor="anonymous",
            action="browser_login_failed",
            target_kind="browser_session",
            target_id=tenant_id or "session",
            detail="token or tenant scope rejected",
        )
        return (
            200,
            {
                "html": render_app_login_html(
                    api_version=api_version,
                    tenant_id=tenant_id,
                    next_path=next_path,
                    service_name=service_name,
                    message="Sign-in failed. Use the raw operator token or JWT. If the token is tenant-scoped, make sure the tenant is selected.",
                    level="error",
                )
            },
        )
    secure_cookie = (headers.get("X-Forwarded-Proto", "") or headers.get("x-forwarded-proto", "")).strip().lower() == "https"
    session_id = f"app-{_materialization_run_id()}"
    session_tenant = tenant_id or (identity.tenants[0] if identity.tenants else "")
    if session_tenant:
        create_service_session(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            session_id=session_id,
            tenant_id=session_tenant,
            user_id=identity.token_id or identity.principal_name or "browser-user",
            principal_name=identity.principal_name or identity.token_id or "browser-user",
            auth_type=identity.auth_type or "bearer",
            roles_csv=",".join(identity.roles),
            status="active",
            expires_at="",
        )
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=session_tenant,
            actor=_audit_actor(identity),
            action="browser_login_succeeded",
            target_kind="browser_session",
            target_id=session_id,
            detail=f"auth_type={identity.auth_type or 'bearer'};roles={','.join(identity.roles)}",
        )
    redirect_html = render_app_login_html(
        api_version=api_version,
        tenant_id=tenant_id,
        next_path=next_path,
        service_name=service_name,
        message="Signed in. Redirecting to the hosted app.",
        level="success",
        auto_redirect=True,
    )
    return (
        200,
        {
            "html": redirect_html,
            "__headers": {"Set-Cookie": _session_cookie_header(token=token, secure=secure_cookie)},
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


def _producer_client_record(producer_clients: list[dict[str, object]], client_id: str) -> dict[str, object] | None:
    return next((item for item in producer_clients if str(item.get("client_id", "")) == client_id), None)


def _audit_actor(identity: HistoryToken | None) -> str:
    if identity is None:
        return "anonymous"
    return identity.principal_name or identity.token_id or identity.token or "anonymous"


def _record_control_audit(
    *,
    sqlite_path: str,
    store_dsn: str,
    tenant_id: str,
    actor: str,
    action: str,
    target_kind: str,
    target_id: str,
    detail: str,
) -> None:
    if not (sqlite_path or store_dsn) or not tenant_id:
        return
    record_control_plane_audit(
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        target_kind=target_kind,
        target_id=target_id,
        detail=detail,
    )


def _browser_session_response_headers(
    *,
    headers: dict[str, str],
    identity: HistoryToken | None,
    tenant_id: str,
    auth_tokens: tuple[str, ...],
    scoped_tokens: dict[str, HistoryToken],
    jwt_config: JWTAuthConfig,
    trusted_header_auth: TrustedHeaderAuthConfig | None,
    sqlite_path: str,
    store_dsn: str,
) -> dict[str, str]:
    if identity is None or _cookie_value(headers, APP_SESSION_COOKIE):
        return {}
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
    trusted_header = trusted_header_auth or TrustedHeaderAuthConfig()
    header_identity = resolve_trusted_header_identity(headers=headers, config=trusted_header)
    token = ""
    auth_type = identity.auth_type or "bearer"
    if header_identity is not None:
        token = identity.token or ""
        auth_type = header_identity.auth_type or auth_type
    elif auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer ") :].strip()
    else:
        resolved = _resolve_browser_session_identity(
            headers=headers,
            auth_tokens=auth_tokens,
            scoped_tokens=scoped_tokens,
            jwt_config=jwt_config,
            trusted_header_auth=trusted_header,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
        )
        if resolved is None:
            return {}
        token = resolved.token
        auth_type = resolved.auth_type or auth_type
    secure_cookie = (headers.get("X-Forwarded-Proto", "") or headers.get("x-forwarded-proto", "")).strip().lower() == "https"
    session_id = f"app-{_materialization_run_id()}"
    session_tenant = tenant_id or (identity.tenants[0] if identity.tenants else "")
    if session_tenant:
        create_service_session(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            session_id=session_id,
            tenant_id=session_tenant,
            user_id=identity.token_id or identity.principal_name or "browser-user",
            principal_name=identity.principal_name or identity.token_id or "browser-user",
            auth_type=auth_type,
            roles_csv=",".join(identity.roles),
            status="active",
            expires_at="",
        )
        _record_control_audit(
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=session_tenant,
            actor=_audit_actor(identity),
            action="browser_session_bootstrapped",
            target_kind="browser_session",
            target_id=session_id,
            detail=f"auth_type={auth_type};roles={','.join(identity.roles)}",
        )
    if token:
        return {"Set-Cookie": _session_cookie_header(token=token, secure=secure_cookie)}
    return {"Set-Cookie": _session_id_cookie_header(session_id=session_id, secure=secure_cookie)}


def _repository_event_state(
    analytics_payload: object,
    *,
    repository: str,
    producer_record: dict[str, object] | None = None,
    tenant_analytics: dict[str, object] | None = None,
) -> dict[str, object]:
    repository_value = repository.strip()
    if not repository_value or not isinstance(analytics_payload, dict):
        return {
            "repository": repository_value,
            "events": 0,
            "state": "idle",
            "message": "Select a repository to generate onboarding instructions and wait for the first hosted decision.",
            "next_step": "Pick the repository and service you want to wire first.",
            "troubleshooting": (
                "Choose a repository, service, and producer client before generating onboarding instructions.",
            ),
        }
    producer_status = str((producer_record or {}).get("status", "")).strip().lower()
    producer_client = str((producer_record or {}).get("client_id", "")).strip()
    token_prefix = str((producer_record or {}).get("token_prefix", "")).strip()
    summary = analytics_payload.get("summary", {}) if isinstance(analytics_payload.get("summary"), dict) else {}
    latest_rollout = (analytics_payload.get("policy_rollout") or {}) if isinstance(analytics_payload.get("policy_rollout"), dict) else {}
    latest_items = latest_rollout.get("latest_by_repository", []) if isinstance(latest_rollout.get("latest_by_repository"), list) else []
    latest_item = next((item for item in latest_items if str(item.get("repository", "")) == repository_value), None)
    tenant_latest_rollout = (tenant_analytics.get("policy_rollout") or {}) if isinstance(tenant_analytics, dict) else {}
    tenant_latest_items = tenant_latest_rollout.get("latest_by_repository", []) if isinstance(tenant_latest_rollout.get("latest_by_repository"), list) else []
    tenant_latest_item = tenant_latest_items[0] if tenant_latest_items and isinstance(tenant_latest_items[0], dict) else {}
    events = int(summary.get("events", 0) or 0)
    if not producer_client:
        return {
            "repository": repository_value,
            "events": events,
            "state": "blocked",
            "message": "No producer client is selected for this repository yet.",
            "next_step": "Create or choose an active producer before copying the repo secrets and variables.",
            "troubleshooting": (
                "Create a producer client in the dashboard first.",
                "Use a dedicated producer per repo or team so rotation stays isolated.",
            ),
        }
    if producer_status == "revoked":
        return {
            "repository": repository_value,
            "events": events,
            "state": "blocked",
            "message": f"Producer {producer_client} is revoked, so CI cannot authenticate to ingest events.",
            "next_step": "Rotate the producer to reveal a fresh token and replace the repository secret.",
            "troubleshooting": (
                "Use Recover With Fresh Token to issue a new ingestor token.",
                "Update VERIDION_HOSTED_INGESTOR_TOKEN in the repository secrets before rerunning CI.",
            ),
        }
    if not token_prefix:
        return {
            "repository": repository_value,
            "events": events,
            "state": "blocked",
            "message": f"Producer {producer_client} exists, but no token prefix is stored for it yet.",
            "next_step": "Rotate the producer or create a new one so you can reveal a token once and store it in CI.",
            "troubleshooting": (
                "Reveal a fresh token from the control plane.",
                "Set VERIDION_HOSTED_INGESTOR_TOKEN before running the workflow again.",
            ),
        }
    if events > 0 and isinstance(latest_item, dict):
        verdict = str(latest_item.get("verdict", "")).strip() or "decision received"
        gate_status = str(latest_item.get("gate_status", "")).strip() or "unknown"
        return {
            "repository": repository_value,
            "events": events,
            "state": "success",
            "message": f"First hosted decision received. Latest verdict: {verdict} / gate: {gate_status}.",
            "latest": latest_item,
            "next_step": "Open the repository page to review the latest decision and operator guidance.",
            "troubleshooting": (
                "Confirm the service metadata and ownership fields are accurate.",
                "Use the focused repository page to decide whether rollout can continue.",
            ),
        }
    tenant_latest_repository = str(tenant_latest_item.get("repository", "")).strip()
    if tenant_latest_repository and tenant_latest_repository != repository_value:
        return {
            "repository": repository_value,
            "events": events,
            "state": "warning",
            "message": f"This tenant is ingesting events, but the latest one landed for {tenant_latest_repository}, not {repository_value}.",
            "next_step": "Check the workflow variables and the repository field inside the event payload before rerunning CI.",
            "troubleshooting": (
                "Verify VERIDION_HOSTED_TENANT_ID points at this tenant.",
                "Verify the emitted event uses the expected repository slug.",
                "Compare the generated workflow snippet against the repo currently sending events.",
            ),
        }
    return {
        "repository": repository_value,
        "events": events,
        "state": "waiting",
        "message": "Listening for the first hosted decision event from CI. Run the workflow once after setting the variables and secret.",
        "next_step": "Run the onboarding workflow once after setting the repository variables and secret.",
        "troubleshooting": (
            "Confirm VERIDION_HOSTED_SERVICE_URL and VERIDION_HOSTED_TENANT_ID are set as repo variables.",
            "Confirm VERIDION_HOSTED_INGESTOR_TOKEN is set as a repo secret.",
            "If CI runs but no event lands, rotate the producer and replace the secret.",
        ),
    }


def _build_repo_connect_payload(
    *,
    tenant_id: str,
    repository: str,
    service_id: str,
    organization: str,
    project_id: str,
    owner: str,
    team: str,
    criticality: str,
    client_id: str,
    service_url: str,
    api_version: str,
    revealed_token: str,
    producer_record: dict[str, object] | None,
    repository_analytics: dict[str, object] | None,
    tenant_analytics: dict[str, object] | None,
) -> dict[str, object]:
    repo_value = repository.strip()
    service_value = service_id.strip()
    client_value = client_id.strip()
    if not tenant_id or not repo_value:
        return {}
    org_value = organization.strip() or tenant_id.strip()
    project_value = project_id.strip() or repo_value
    owner_value = owner.strip() or "service-owner"
    team_value = team.strip() or "owning-team"
    criticality_value = criticality.strip() or "high"
    token_prefix = str((producer_record or {}).get("token_prefix", "")).strip()
    producer_status = str((producer_record or {}).get("status", "")).strip() or "unknown"
    service_url_value = service_url.strip() or "https://hosted-control-plane.example.com"
    workflow_yaml = "\n".join(
        (
            "name: veridion-hosted-producer",
            "on:",
            "  workflow_dispatch:",
            "jobs:",
            "  deliver-decision:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - name: Emit hosted decision event",
            "        env:",
            f"          VERIDION_HOSTED_SERVICE_URL: {service_url_value}",
            f"          VERIDION_HOSTED_TENANT_ID: {tenant_id}",
            "          VERIDION_HOSTED_INGESTOR_TOKEN: ${{ secrets.VERIDION_HOSTED_INGESTOR_TOKEN }}",
            "        run: |",
            "          cat > veridion-decision-event.json <<'json'",
            json.dumps(
                {
                    "tenant": tenant_id,
                    "event": {
                        "generated_at": "2026-05-20T00:00:00Z",
                        "repository": repo_value,
                        "organization": org_value,
                        "project": project_value,
                        "service": service_value,
                        "decision": {"verdict": "GO", "gate_status": "pass", "blocking_categories": []},
                        "automation": {"approval_gate_status": "satisfied", "stale_approvals": []},
                        "policy": {"pack_id": "application-team", "pack_version": "1", "rollout_stage": "general"},
                        "trust_context": {
                            "service_owner": owner_value,
                            "owning_team": team_value,
                            "service_criticality": criticality_value,
                        },
                    },
                },
                indent=2,
            ).replace("\n", "\n          "),
            "          json",
            f"          curl -sS -X POST \"$VERIDION_HOSTED_SERVICE_URL/api/{api_version}/events\" \\",
            "            -H \"Authorization: Bearer $VERIDION_HOSTED_INGESTOR_TOKEN\" \\",
            "            -H \"Content-Type: application/json\" \\",
            "            -d @veridion-decision-event.json",
        )
    )
    return {
        "tenant_id": tenant_id,
        "repository": repo_value,
        "service_id": service_value,
        "organization": org_value,
        "project_id": project_value,
        "service_owner": owner_value,
        "owning_team": team_value,
        "service_criticality": criticality_value,
        "client_id": client_value,
        "producer_status": producer_status,
        "token_prefix": token_prefix,
        "needs_rotation": producer_status == "revoked" or (not revealed_token and not token_prefix),
        "event_state": _repository_event_state(
            repository_analytics,
            repository=repo_value,
            producer_record=producer_record,
            tenant_analytics=tenant_analytics,
        ),
        "vars": {
            "VERIDION_HOSTED_SERVICE_URL": service_url_value,
            "VERIDION_HOSTED_TENANT_ID": tenant_id,
        },
        "secret_name": "VERIDION_HOSTED_INGESTOR_TOKEN",
        "secret_value": revealed_token,
        "workflow_yaml": workflow_yaml,
    }


def _recent_event_slice(
    *,
    history_paths: tuple[str, ...],
    sqlite_path: str,
    store_dsn: str,
    tenant_id: str,
    repository: str = "",
    limit: int = 5,
) -> tuple[dict[str, object], ...]:
    if sqlite_path or store_dsn:
        with open_history_store(sqlite_path=sqlite_path, store_dsn=store_dsn) as store:
            events = store.load_events(
                tenant_id=tenant_id,
                repository=repository or None,
                policy_pack_id=None,
                since=None,
                until=None,
            )
    else:
        events = load_history_events(history_paths=history_paths)
        if repository:
            events = tuple(item for item in events if str(item.get("repository", "")) == repository)
    return tuple(events[-limit:][::-1])


def _event_gate_status(event: dict[str, object]) -> str:
    decision = event.get("decision")
    if isinstance(decision, dict):
        return str(decision.get("gate_status", "")).strip()
    return ""


def _event_verdict(event: dict[str, object]) -> str:
    decision = event.get("decision")
    if isinstance(decision, dict):
        return str(decision.get("verdict", "")).strip()
    return ""


def _event_next_action(event: dict[str, object]) -> str:
    verdict = _event_verdict(event).upper()
    gate = _event_gate_status(event).lower()
    automation = event.get("automation") if isinstance(event.get("automation"), dict) else {}
    unsatisfied = automation.get("unsatisfied_approvals") if isinstance(automation.get("unsatisfied_approvals"), list) else []
    blocking = event.get("reasons", {}).get("blocking") if isinstance(event.get("reasons"), dict) and isinstance(event.get("reasons", {}).get("blocking"), list) else []
    if gate == "block" or verdict == "NO GO":
        if blocking:
            return f"Resolve blockers: {', '.join(str(item) for item in blocking[:2])}."
        return "Resolve blockers before another rollout attempt."
    if gate == "review" or unsatisfied:
        if unsatisfied:
            return f"Collect approvals from: {', '.join(str(item) for item in unsatisfied[:3])}."
        return "Collect approvals and complete the required review steps."
    return "Ready to continue rollout and monitor follow-on automation."


def _event_blocking_categories(event: dict[str, object]) -> tuple[str, ...]:
    decision = event.get("decision")
    if isinstance(decision, dict) and isinstance(decision.get("blocking_categories"), list):
        return tuple(str(item).strip() for item in decision.get("blocking_categories", []) if str(item).strip())
    return ()


def _event_approval_summary(event: dict[str, object]) -> str:
    automation = event.get("automation")
    if not isinstance(automation, dict):
        return "Approval state unknown."
    approval_status = str(automation.get("approval_gate_status", "")).strip() or "unknown"
    unsatisfied = automation.get("unsatisfied_approvals")
    if isinstance(unsatisfied, list) and unsatisfied:
        return f"{approval_status} / pending: {', '.join(str(item) for item in unsatisfied[:3])}"
    return approval_status


def _event_pack_summary(event: dict[str, object]) -> str:
    policy = event.get("policy")
    if not isinstance(policy, dict):
        return "unknown"
    pack_id = str(policy.get("pack_id", "")).strip() or "unknown"
    pack_version = str(policy.get("pack_version", "")).strip() or "unversioned"
    rollout_stage = str(policy.get("rollout_stage", "")).strip() or "unspecified"
    return f"{pack_id} / {pack_version} / {rollout_stage}"


def _event_reason_lines(event: dict[str, object]) -> tuple[str, ...]:
    reasons = event.get("reasons")
    if not isinstance(reasons, dict):
        return ()
    blocking = reasons.get("blocking")
    if not isinstance(blocking, list):
        return ()
    return tuple(str(item).strip() for item in blocking if str(item).strip())


def _event_evidence_status(event: dict[str, object]) -> str:
    if any("baseline attribution is incomplete" in line for line in _event_reason_lines(event)):
        return "degraded attribution confidence"
    gate = _event_gate_status(event).lower()
    verdict = _event_verdict(event).upper()
    if gate == "block" or verdict == "NO GO":
        return "strong blocking signal"
    if gate == "review":
        return "reviewable but incomplete"
    if verdict in {"GO", "CONDITIONAL GO"}:
        return "actionable release signal"
    return "limited evidence"


def _event_verify_next(event: dict[str, object]) -> str:
    if any("baseline attribution is incomplete" in line for line in _event_reason_lines(event)):
        return "Repair baseline scanner outputs and verify the same finding against the correct base before relying on introduction claims."
    gate = _event_gate_status(event).lower()
    blocking_categories = _event_blocking_categories(event)
    if gate == "block" or _event_verdict(event).upper() == "NO GO":
        if blocking_categories:
            return f"Verify remediation for: {', '.join(blocking_categories[:3])}."
        return "Verify blocker remediation before the next rollout attempt."
    if gate == "review":
        return "Verify approvals, reviewer ownership, and rollback readiness before rollout."
    return "Verify production monitoring and rollback ownership while rollout continues."


def _event_required_approvals(event: dict[str, object]) -> list[str]:
    actions = event.get("actions")
    if isinstance(actions, dict) and isinstance(actions.get("required_approvals"), list):
        result = [str(item).strip() for item in actions["required_approvals"] if str(item).strip()]
        if result:
            return result
    automation = event.get("automation")
    if isinstance(automation, dict) and isinstance(automation.get("unsatisfied_approvals"), list):
        return [str(item).strip() for item in automation["unsatisfied_approvals"] if str(item).strip()]
    return []


def _event_required_next_steps(event: dict[str, object]) -> list[str]:
    actions = event.get("actions")
    if isinstance(actions, dict) and isinstance(actions.get("required_next_steps"), list):
        return [str(item).strip() for item in actions["required_next_steps"] if str(item).strip()]
    return []


def _verdict_css_class(verdict: str) -> str:
    v = verdict.upper()
    if v == "GO":
        return "verdict-go"
    if v == "NO GO":
        return "verdict-nogo"
    if "CONDITIONAL" in v:
        return "verdict-conditional"
    return "verdict-unknown"


def _verdict_badge_html(verdict: str) -> str:
    """Return an inline colored verdict badge span."""
    if not verdict:
        return ""
    css = _verdict_css_class(verdict)
    badge_css = css.replace("verdict-", "vbadge-")
    return f"<span class='vbadge {_html_escape(badge_css)}'>{_html_escape(verdict)}</span>"


def _event_trust_context_summary(event: dict[str, object]) -> str:
    tc = event.get("trust_context")
    if not isinstance(tc, dict):
        return ""
    parts: list[str] = []
    if tc.get("environment"):
        parts.append(str(tc["environment"]))
    if tc.get("blast_radius"):
        parts.append(f"blast radius: {tc['blast_radius']}")
    criticality = str(tc.get("service_criticality") or tc.get("repo_criticality") or "").strip()
    if criticality:
        parts.append(f"criticality: {criticality}")
    if tc.get("public_exposure"):
        parts.append("publicly exposed")
    return " · ".join(parts)


def _event_detail_html(event: dict[str, object] | None, *, empty_message: str) -> str:
    if not isinstance(event, dict) or not event:
        return f"<p class='hint'>{_html_escape(empty_message)}</p>"

    verdict = _event_verdict(event) or "unknown"
    css_class = _verdict_css_class(verdict)
    gate = _event_gate_status(event) or "unknown"
    decision = event.get("decision") if isinstance(event.get("decision"), dict) else {}
    score = decision.get("score")
    confidence = str(decision.get("confidence", "")).strip()
    score_text = f"Score {score}" if score is not None else ""
    meta_parts = [p for p in [score_text, confidence] if p]
    meta_text = " · ".join(meta_parts)

    reasons = [line for line in _event_reason_lines(event) if line]
    approvals = _event_required_approvals(event)
    next_steps = _event_required_next_steps(event)
    trust_ctx = _event_trust_context_summary(event)

    reason_rows = "".join(
        f"<li>{_html_escape(r)}</li>" for r in reasons[:5]
    ) if reasons else "<li class='hint'>No explicit blockers recorded.</li>"

    approval_rows = "".join(
        f"<li><span class='approval-tag'>{_html_escape(a.replace('_', ' ').title())}</span></li>"
        for a in approvals[:6]
    ) if approvals else ""

    step_rows = "".join(
        f"<li>{_html_escape(s)}</li>" for s in next_steps[:6]
    ) if next_steps else f"<li>{_html_escape(_event_next_action(event))}</li>"

    verify_text = _event_verify_next(event)
    evidence_status = _event_evidence_status(event)
    pack_summary = _event_pack_summary(event)

    sections = (
        f"<div class='decision-verdict-row'>"
        f"<span class='verdict-badge {_html_escape(css_class)}'>{_html_escape(verdict)}</span>"
        f"<span class='verdict-meta'>{_html_escape(meta_text)}</span>"
        f"<span class='verdict-gate'>{_html_escape(gate)}</span>"
        f"</div>"
    )
    sections += (
        f"<div class='decision-section'>"
        f"<div class='decision-section-label'>Why</div>"
        f"<ul class='decision-list'>{reason_rows}</ul>"
        f"</div>"
    )
    if approvals:
        sections += (
            f"<div class='decision-section'>"
            f"<div class='decision-section-label'>Required Approvals</div>"
            f"<ul class='decision-list approval-list'>{approval_rows}</ul>"
            f"</div>"
        )
    sections += (
        f"<div class='decision-section'>"
        f"<div class='decision-section-label'>What To Do Next</div>"
        f"<ul class='decision-list'>{step_rows}</ul>"
        f"</div>"
    )
    sections += (
        f"<div class='decision-section'>"
        f"<div class='decision-section-label'>What To Verify</div>"
        f"<div class='hint'>{_html_escape(verify_text)}</div>"
        f"</div>"
    )
    if evidence_status and evidence_status not in {"actionable release signal"}:
        sections += (
            f"<div class='decision-section'>"
            f"<div class='decision-section-label'>Evidence Status</div>"
            f"<div class='hint'>{_html_escape(evidence_status)}</div>"
            f"</div>"
        )
    if trust_ctx:
        sections += (
            f"<div class='decision-section'>"
            f"<div class='decision-section-label'>Trust Context</div>"
            f"<div class='hint mono'>{_html_escape(trust_ctx)}</div>"
            f"</div>"
        )
    if pack_summary and pack_summary != "unknown / unversioned / unspecified":
        sections += (
            f"<div class='decision-section'>"
            f"<div class='decision-section-label'>Policy Pack</div>"
            f"<div class='hint mono'>{_html_escape(pack_summary)}</div>"
            f"</div>"
        )

    return f"<div class='decision-card'>{sections}</div>"


def _observability_payload(
    *,
    analytics: dict[str, object],
    materializations: list[dict[str, object]],
    sessions: list[dict[str, object]],
    producer_clients: list[dict[str, object]],
    service: dict[str, object],
    control_audit: list[dict[str, object]],
) -> dict[str, str]:
    latest_by_repository = ((analytics.get("policy_rollout") or {}).get("latest_by_repository", [])) if isinstance(analytics, dict) else []
    latest_event = latest_by_repository[0] if latest_by_repository and isinstance(latest_by_repository[0], dict) else {}
    latest_materialization = materializations[0] if materializations else {}
    latest_session = sessions[0] if sessions else {}
    latest_producer_use = (
        next(
            (
                entry
                for entry in sorted(producer_clients, key=lambda entry: str(entry.get("last_used_at", "")), reverse=True)
                if str(entry.get("last_used_at", "")).strip()
            ),
            {},
        )
        if producer_clients
        else {}
    )
    latest_auth_failure = next((item for item in control_audit if str(item.get("action", "")) in {"browser_login_failed", "auth_failed"}), {})
    latest_ingest_issue = next((item for item in control_audit if str(item.get("action", "")).endswith("_rejected") or str(item.get("action", "")) == "event_ingest_failed"), {})
    latest_scheduler_issue = next((item for item in control_audit if str(item.get("action", "")).startswith("scheduler_") or str(item.get("action", "")) == "materialization_create_failed"), {})
    if bool(service.get("trusted_header_enabled")):
        auth_mode = "trusted-header-browser-session"
    elif bool(service.get("jwt_enabled")):
        auth_mode = "jwt-browser-session"
    else:
        auth_mode = "bearer-browser-session"
    oidc_ready = bool(str(service.get("oidc_discovery_url", "")).strip())
    ingest_status = "healthy" if str(latest_event.get("generated_at", "")).strip() else "missing"
    scheduler_status = "healthy" if str(latest_materialization.get("generated_at", "")).strip() else "missing"
    producer_status = "healthy" if str(latest_producer_use.get("last_used_at", "")).strip() else "idle"
    return {
        "last_event_at": str(latest_event.get("generated_at", "")),
        "last_event_repo": str(latest_event.get("repository", "")),
        "last_materialization_at": str(latest_materialization.get("generated_at", "")),
        "last_materialization_run": str(latest_materialization.get("run_id", "")),
        "last_session_at": str(latest_session.get("created_at", "")),
        "last_session_principal": str(latest_session.get("principal_name", "")),
        "last_producer_use_at": str(latest_producer_use.get("last_used_at", "")),
        "last_producer_client": str(latest_producer_use.get("client_id", "")),
        "auth_mode": auth_mode,
        "ingest_status": ingest_status,
        "scheduler_status": scheduler_status,
        "producer_status": producer_status,
        "last_auth_failure_at": str(latest_auth_failure.get("created_at", "")),
        "last_auth_failure_detail": str(latest_auth_failure.get("detail", "")),
        "last_ingest_issue_at": str(latest_ingest_issue.get("created_at", "")),
        "last_ingest_issue_detail": str(latest_ingest_issue.get("detail", "")),
        "last_scheduler_issue_at": str(latest_scheduler_issue.get("created_at", "")),
        "last_scheduler_issue_detail": str(latest_scheduler_issue.get("detail", "")),
        "service_version": str(service.get("service_version", "")),
        "deployment_id": str(service.get("deployment_id", "")),
        "auth_recommendation": "OIDC or JWT-backed operator sign-in is ready." if oidc_ready or bool(service.get("jwt_enabled")) else "Use the bearer session bridge for now, then move operators onto JWT or OIDC.",
    }


def _attach_selected_detail_analytics(
    overview: dict[str, object],
    *,
    history_paths: tuple[str, ...],
    tenants: dict[str, HistoryTenant],
    sqlite_path: str,
    store_dsn: str,
    tenant_id: str,
    selected_repository: str,
    selected_service: str,
    selected_producer_client: str,
) -> None:
    tenant = overview.get("tenant", {})
    if isinstance(tenant, dict):
        tenant["selected_repository"] = selected_repository
        tenant["selected_service"] = selected_service
        tenant["selected_producer_client"] = selected_producer_client

    catalog = overview.get("catalog", {})
    services = catalog.get("services", []) if isinstance(catalog, dict) else []
    latest_by_repository = ((overview.get("analytics") or {}).get("policy_rollout") or {}).get("latest_by_repository", []) if isinstance(overview.get("analytics"), dict) else []
    admin = overview.get("admin", {})
    producer_clients = admin.get("producer_clients", []) if isinstance(admin, dict) else []

    selected_repository_value = selected_repository
    if not selected_repository_value and latest_by_repository:
        selected_repository_value = str(latest_by_repository[0].get("repository", ""))

    selected_service_value = selected_service
    if not selected_service_value and services:
        selected_service_value = str(services[0].get("service_id", ""))

    selected_service_record = next((item for item in services if str(item.get("service_id", "")) == selected_service_value), None)
    service_repository = str(selected_service_record.get("repository", "")) if isinstance(selected_service_record, dict) else ""

    repository_analytics = (
        _analyze_request(
            history_paths=history_paths,
            tenants=tenants,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            repository=selected_repository_value,
        )
        if selected_repository_value
        else None
    )
    service_analytics = (
        _analyze_request(
            history_paths=history_paths,
            tenants=tenants,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=tenant_id,
            repository=service_repository,
        )
        if service_repository
        else None
    )
    repository_recent_events = _recent_event_slice(
        history_paths=history_paths,
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id=tenant_id,
        repository=selected_repository_value,
        limit=5,
    ) if selected_repository_value else ()
    service_recent_events = _recent_event_slice(
        history_paths=history_paths,
        sqlite_path=sqlite_path,
        store_dsn=store_dsn,
        tenant_id=tenant_id,
        repository=service_repository,
        limit=5,
    ) if service_repository else ()
    selected_producer_value = selected_producer_client
    if not selected_producer_value and producer_clients:
        selected_producer_value = str(producer_clients[0].get("client_id", ""))
    producer_audit = (
        list(list_producer_client_audit(sqlite_path=sqlite_path, store_dsn=store_dsn, tenant_id=tenant_id, client_id=selected_producer_value, limit=10))
        if selected_producer_value and (sqlite_path or store_dsn)
        else []
    )

    overview["detail"] = {
        "selected_repository": selected_repository_value,
        "selected_service": selected_service_value,
        "selected_producer_client": selected_producer_value,
        "service_repository": service_repository,
        "repository_analytics": repository_analytics,
        "service_analytics": service_analytics,
        "repository_recent_events": repository_recent_events,
        "service_recent_events": service_recent_events,
        "producer_audit": producer_audit,
    }


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


def render_app_login_html(
    *,
    api_version: str,
    tenant_id: str,
    next_path: str,
    service_name: str,
    message: str = "",
    level: str = "info",
    auto_redirect: bool = False,
    managed_identity_ready: bool = False,
    auth_mode_hint: str = "",
) -> str:
    flash = (
        f"<div class='flash { _html_escape(level) }'>{_html_escape(message)}</div>"
        if message
        else ""
    )
    redirect_meta = f"<meta http-equiv='refresh' content='0;url={_html_escape(next_path)}'>" if auto_redirect else ""
    redirect_copy = (
        f"<p class='hint'>If redirect does not start, continue to <a href='{_html_escape(next_path)}'>{_html_escape(next_path)}</a>.</p>"
        if auto_redirect
        else ""
    )
    tenant_hint = (
        "Use the tenant slug tied to your operator access. Tenant-scoped identities are redirected into that tenant automatically after sign-in."
        if tenant_id
        else "If your operator token only belongs to one tenant, the app will route you there after sign-in."
    )
    auth_hint = auth_mode_hint or (
        "Managed browser sign-in through JWT, OIDC, or trusted headers is ready."
        if managed_identity_ready
        else "Paste an operator token once to bridge into a browser session."
    )
    managed_continue = (
        f"<a class='btn-managed' href='{_html_escape(next_path)}'>Continue With Managed Sign-In</a>"
        if managed_identity_ready and not auto_redirect
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_html_escape(service_name)} &middot; Sign In</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
  {redirect_meta}
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; }}
    body {{
      font-family: 'Space Grotesk', system-ui, sans-serif;
      background: #0b0d0a;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem 1rem;
      position: relative;
      overflow: hidden;
      -webkit-font-smoothing: antialiased;
    }}
    .bg-glow {{
      position: fixed; top: -200px; left: 50%;
      transform: translateX(-50%);
      width: 700px; height: 600px;
      background: radial-gradient(circle at center, rgba(179,75,24,.22) 0%, transparent 65%);
      pointer-events: none;
    }}
    .bg-grid {{
      position: fixed; inset: 0;
      background-image: linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px);
      background-size: 60px 60px;
      mask-image: radial-gradient(ellipse 80% 55% at 50% 0%, black 30%, transparent 100%);
      -webkit-mask-image: radial-gradient(ellipse 80% 55% at 50% 0%, black 30%, transparent 100%);
      pointer-events: none;
    }}
    .wrap {{
      position: relative; z-index: 1;
      width: 100%; max-width: 400px;
      display: flex; flex-direction: column; align-items: center; gap: 1.5rem;
    }}
    .brand {{ display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: .92rem; letter-spacing: -.02em; color: rgba(255,255,255,.92); }}
    .brand-logo {{
      width: 24px; height: 24px; background: #b34b18; color: #fff;
      font-size: .7rem; font-weight: 700; border-radius: 5px;
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }}
    .card {{
      width: 100%; background: #faf7f2;
      border: 1px solid rgba(24,22,16,.16); border-radius: 16px;
      padding: 2.25rem;
      box-shadow: 0 8px 32px rgba(0,0,0,.28), 0 32px 80px rgba(0,0,0,.20);
      color: #161710;
    }}
    .eyebrow {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: .65rem; letter-spacing: .13em; text-transform: uppercase;
      color: #b34b18; margin-bottom: .7rem;
    }}
    h1 {{ font-size: 1.55rem; font-weight: 700; letter-spacing: -.028em; line-height: 1.15; color: #161710; margin-bottom: .4rem; }}
    .sub {{ font-size: .88rem; color: #4b4d45; line-height: 1.6; margin-bottom: 1.5rem; }}
    .flash {{ border-radius: 8px; padding: .75rem .9rem; margin-bottom: 1rem; font-size: .87rem; line-height: 1.5; border: 1px solid; }}
    .flash.success {{ background: rgba(22,163,74,.09); border-color: rgba(22,163,74,.25); color: #166534; }}
    .flash.error {{ background: rgba(220,38,38,.09); border-color: rgba(220,38,38,.25); color: #991b1b; }}
    .flash.info {{ background: rgba(59,130,246,.09); border-color: rgba(59,130,246,.25); color: #1e3a8a; }}
    form {{ display: grid; gap: .85rem; }}
    label {{
      display: grid; gap: .35rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: .7rem; font-weight: 500; letter-spacing: .08em; text-transform: uppercase; color: #8b8c84;
    }}
    input {{
      width: 100%; border: 1px solid rgba(24,22,16,.16); border-radius: 8px;
      padding: .72rem .85rem; background: #fff; color: #161710;
      font-family: 'Space Grotesk', system-ui, sans-serif; font-size: .93rem;
      transition: border-color .15s, box-shadow .15s;
    }}
    input:focus {{ outline: none; border-color: #b34b18; box-shadow: 0 0 0 3px rgba(179,75,24,.12); }}
    .btn-primary {{
      width: 100%; border: none; border-radius: 8px; padding: .78rem 1rem;
      background: #b34b18; color: #fff;
      font-family: 'Space Grotesk', system-ui, sans-serif; font-size: .93rem; font-weight: 600;
      cursor: pointer; margin-top: .4rem; letter-spacing: -.01em;
      box-shadow: 0 4px 14px rgba(179,75,24,.38);
      transition: background .15s, transform .12s, box-shadow .12s;
    }}
    .btn-primary:hover {{ background: #c05520; transform: translateY(-1px); box-shadow: 0 6px 20px rgba(179,75,24,.50); }}
    .btn-primary:active {{ transform: translateY(0); }}
    .btn-managed {{
      display: inline-flex; align-items: center; justify-content: center;
      width: 100%; border: 1px solid rgba(24,22,16,.16); border-radius: 8px;
      padding: .78rem 1rem; background: transparent; color: #161710; text-decoration: none;
      font-weight: 600; margin-top: .7rem;
    }}
    .btn-managed:hover {{ border-color: #161710; text-decoration: none; }}
    .divider {{ border: none; border-top: 1px solid rgba(24,22,16,.09); margin: 1.25rem 0; }}
    .actions {{ display: flex; gap: .75rem; align-items: center; flex-wrap: wrap; font-size: .87rem; }}
    a {{ color: #b34b18; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .btn-ghost {{
      border: 1px solid rgba(24,22,16,.16); border-radius: 6px; padding: .38rem .8rem;
      background: transparent; color: #4b4d45;
      font-family: 'Space Grotesk', system-ui, sans-serif; font-size: .87rem;
      cursor: pointer; transition: border-color .15s, color .15s;
    }}
    .btn-ghost:hover {{ border-color: #161710; color: #161710; }}
    .hint {{ font-size: .84rem; color: #8b8c84; margin-top: .75rem; line-height: 1.55; }}
    .mono {{ font-family: 'IBM Plex Mono', monospace; }}
  </style>
</head>
<body>
  <div class="bg-glow" aria-hidden="true"></div>
  <div class="bg-grid" aria-hidden="true"></div>
  <div class="wrap">
    <div class="brand">
      <span class="brand-logo" aria-hidden="true">V</span>
      {_html_escape(service_name)}
    </div>
    <div class="card">
      <div class="eyebrow">Control Plane</div>
      <h1>Sign In To The Control Plane</h1>
      <div class="sub">Use your operator token or JWT to open a browser session for the hosted control plane.</div>
      {flash}
      <form method="post" action="/api/{_html_escape(api_version)}/app/login">
        <label>Tenant
          <input name="tenant_id" value="{_html_escape(tenant_id)}" placeholder="acme" autocomplete="username">
        </label>
        <label>Operator Token Or JWT
          <input name="token" type="password" placeholder="veridion-&hellip;" autocomplete="current-password">
        </label>
        <input type="hidden" name="next" value="{_html_escape(next_path)}">
        <button class="btn-primary" type="submit">Sign In</button>
      </form>
      {managed_continue}
      <p class="hint">{_html_escape(tenant_hint)}</p>
      <p class="hint">{_html_escape(auth_hint)}</p>
      <p class="hint">This form accepts the raw token value. If you paste a value that starts with <span class="mono">Bearer </span>, the app strips the prefix for you.</p>
      <hr class="divider">
      <div class="actions">
        <a href="/api/{_html_escape(api_version)}/app?tenant={_html_escape(tenant_id)}">Back to app</a>
        <form method="post" action="/api/{_html_escape(api_version)}/app/logout">
          <button class="btn-ghost" type="submit">Sign Out</button>
        </form>
      </div>
      {redirect_copy}
    </div>
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
    control_audit = admin.get("control_audit", []) if isinstance(admin, dict) else []
    organizations = catalog.get("organizations", []) if isinstance(catalog, dict) else []
    projects = catalog.get("projects", []) if isinstance(catalog, dict) else []
    services = catalog.get("services", []) if isinstance(catalog, dict) else []
    latest_by_repository = ((analytics.get("policy_rollout") or {}).get("latest_by_repository", [])) if isinstance(analytics, dict) else []
    detail = payload.get("detail", {}) if isinstance(payload, dict) else {}
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
    jwt_enabled = bool(service.get("jwt_enabled"))
    service_version = _html_escape(str(service.get("service_version", "")) or "n/a")
    deployment_id = _html_escape(str(service.get("deployment_id", "")) or "n/a")
    jwt_issuer = _html_escape(str(service.get("jwt_issuer", "")) or "not configured")
    jwt_audience = _html_escape(str(service.get("jwt_audience", "")) or "not configured")
    jwks_url = _html_escape(str(service.get("jwks_url", "")) or "not configured")
    oidc_discovery_url = _html_escape(str(service.get("oidc_discovery_url", "")) or "not configured")
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
        f"<tr><td><span class='mono' style='font-size:.88rem;'>{_html_escape(str(item.get('repository', '')))}</span></td><td>{_verdict_badge_html(str(item.get('verdict', '')))}</td><td><span class='mono' style='font-size:.82rem;'>{_html_escape(str(item.get('gate_status', '')))}</span></td><td><span class='hint mono'>{_html_escape(str(item.get('generated_at', '')))}</span></td></tr>"
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
    service_link_items = "".join(
        f"<li><a href='/api/{_html_escape(api_version)}/app?tenant={tenant_query}&service={quote(str(item.get('service_id', '')))}'>{_html_escape(str(item.get('service_id', '')))}</a> · <a href='/api/{_html_escape(api_version)}/app/service?tenant={tenant_query}&service={quote(str(item.get('service_id', '')))}'>open page</a><div class='hint'>{_html_escape(str(item.get('repository', '')))} / {_html_escape(str(item.get('service_criticality', '')) or 'unknown')}</div></li>"
        for item in services[:8]
    ) or "<li>No services recorded</li>"
    repository_link_items = "".join(
        f"<li><a href='/api/{_html_escape(api_version)}/app/repository?tenant={tenant_query}&repository={quote(str(item.get('repository', '')))}'>{_html_escape(str(item.get('repository', '')))}</a>"
        f" {_verdict_badge_html(str(item.get('verdict', '')))}"
        f"<div class='hint mono' style='font-size:.8rem;'>{_html_escape(str(item.get('gate_status', '')))} · {_html_escape(str(item.get('generated_at', '')))}</div></li>"
        for item in latest_by_repository[:8]
    ) or "<li>No repository activity yet</li>"
    selected_repository = str((detail.get("selected_repository") if isinstance(detail, dict) else "") or tenant.get("selected_repository", "")).strip()
    selected_service = str((detail.get("selected_service") if isinstance(detail, dict) else "") or tenant.get("selected_service", "")).strip()
    selected_producer_client = str((detail.get("selected_producer_client") if isinstance(detail, dict) else "") or tenant.get("selected_producer_client", "")).strip()
    repository_detail = next((item for item in latest_by_repository if str(item.get("repository", "")) == selected_repository), None)
    if repository_detail is None and latest_by_repository:
        repository_detail = latest_by_repository[0]
    service_detail = next((item for item in services if str(item.get("service_id", "")) == selected_service), None)
    if service_detail is None and services:
        service_detail = services[0]
    repository_analytics = detail.get("repository_analytics") if isinstance(detail, dict) else None
    service_analytics = detail.get("service_analytics") if isinstance(detail, dict) else None
    repository_recent_events = detail.get("repository_recent_events", []) if isinstance(detail, dict) else []
    service_recent_events = detail.get("service_recent_events", []) if isinstance(detail, dict) else []
    producer_audit = detail.get("producer_audit", []) if isinstance(detail, dict) else []
    observability = payload.get("observability", {}) if isinstance(payload, dict) else {}
    latest_repository_event = repository_recent_events[0] if repository_recent_events and isinstance(repository_recent_events[0], dict) else None
    latest_service_event = service_recent_events[0] if service_recent_events and isinstance(service_recent_events[0], dict) else None
    selected_producer = next((item for item in producer_clients if str(item.get("client_id", "")) == selected_producer_client), None)
    if selected_producer is None and producer_clients:
        selected_producer = producer_clients[0]
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
    def _detail_analytics_html(detail_payload: object, *, empty_message: str) -> str:
        if not isinstance(detail_payload, dict):
            return f"<p class='hint'>{_html_escape(empty_message)}</p>"
        detail_summary = detail_payload.get("summary", {}) if isinstance(detail_payload.get("summary"), dict) else {}
        detail_blocks = detail_payload.get("top_blocking_categories", []) if isinstance(detail_payload.get("top_blocking_categories"), list) else []
        detail_series = ((detail_payload.get("time_series") or {}).get("by_day", [])) if isinstance(detail_payload.get("time_series"), dict) else []
        detail_verdicts = detail_payload.get("by_verdict", {}) if isinstance(detail_payload.get("by_verdict"), dict) else {}
        block_items = "".join(
            f"<li>{_html_escape(str(item.get('name', '')))} <span class='count'>{_html_escape(str(item.get('count', '0')))}</span></li>"
            for item in detail_blocks[:4]
        ) or "<li>No blocking categories recorded</li>"
        series_items = "".join(
            f"<li>{_html_escape(str(item.get('day', '')))} <span class='count'>{_html_escape(str(item.get('events', '0')))}</span></li>"
            for item in detail_series[-4:]
        ) or "<li>No time-series points recorded</li>"
        verdict_items = ", ".join(f"{key}={value}" for key, value in detail_verdicts.items()) or "none"
        return (
            f"<div class='card' style='margin-top:1rem; background:var(--panel-alt,#f7faf8);'>"
            f"<h3 class='section-title'>History Slice</h3>"
            f"<div class='two-col'>"
            f"<div><div class='hint'><strong>Events:</strong> {_html_escape(str(detail_summary.get('events', 0)))}</div>"
            f"<div class='hint'><strong>Repositories:</strong> {_html_escape(str(detail_summary.get('repositories', 0)))}</div>"
            f"<div class='hint'><strong>Verdicts:</strong> {_html_escape(verdict_items)}</div></div>"
            f"<div><div class='hint'><strong>Window start:</strong> {_html_escape(str(((detail_summary.get('window') or {}).get('first_generated_at', 'n/a')) if isinstance(detail_summary.get('window'), dict) else 'n/a'))}</div>"
            f"<div class='hint'><strong>Window end:</strong> {_html_escape(str(((detail_summary.get('window') or {}).get('last_generated_at', 'n/a')) if isinstance(detail_summary.get('window'), dict) else 'n/a'))}</div></div>"
            f"</div>"
            f"<div class='two-col' style='margin-top:1rem;'><div><h3 class='section-title'>Blocking Trend</h3><ul>{block_items}</ul></div>"
            f"<div><h3 class='section-title'>Recent Event Days</h3><ul>{series_items}</ul></div></div>"
            f"</div>"
        )
    producer_ops_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('client_id', '')))}</strong> <span class='mono'>{_html_escape(str(item.get('token_prefix', '')))}...</span> · <a href='/api/{_html_escape(api_version)}/app?tenant={tenant_query}&producer_client={quote(str(item.get('client_id', '')))}'>inspect</a>"
        f"<div class='hint'>{_html_escape(str(item.get('status', 'active')))} / {_html_escape(str(item.get('roles_csv', '')) or 'ingestor')}</div>"
        f"<div class='hint'>issued {_html_escape(str(item.get('last_issued_at', '') or 'n/a'))} / used {_html_escape(str(item.get('last_used_at', '') or 'never'))}</div>"
        f"<div style='display:flex; gap:.5rem; margin-top:.55rem; flex-wrap:wrap;'>"
        f"<form method='post' action='/api/{_html_escape(api_version)}/app'><input type='hidden' name='action' value='rotate_producer_client'><input type='hidden' name='tenant_id' value='{_html_escape(tenant_value)}'><input type='hidden' name='client_id' value='{_html_escape(str(item.get('client_id', '')))}'><button type='submit'>Rotate Token</button></form>"
        f"<form method='post' action='/api/{_html_escape(api_version)}/app'><input type='hidden' name='action' value='revoke_producer_client'><input type='hidden' name='tenant_id' value='{_html_escape(tenant_value)}'><input type='hidden' name='client_id' value='{_html_escape(str(item.get('client_id', '')))}'><button type='submit' style='background:var(--danger,#8b2d1f);'>Revoke</button></form>"
        f"</div></li>"
        for item in producer_clients[:6]
    ) or "<li>No producer clients yet</li>"
    producer_audit_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('action', '')))}</strong><div class='hint'>{_html_escape(str(item.get('created_at', '')))} / {_html_escape(str(item.get('detail', '')))}</div></li>"
        for item in producer_audit[:6]
    ) or "<li>No producer audit events recorded</li>"
    control_audit_items = "".join(
        f"<li><strong>{_html_escape(str(item.get('action', '')))}</strong><div class='hint'>{_html_escape(str(item.get('created_at', '')))} / {_html_escape(str(item.get('actor', '')))} / {_html_escape(str(item.get('target_kind', '')))}:{_html_escape(str(item.get('target_id', '')))}</div><div class='hint'>{_html_escape(str(item.get('detail', '')))}</div></li>"
        for item in control_audit[:8]
    ) or "<li>No control-plane audit events recorded yet.</li>"
    service_user_roles = sorted({role.strip() for item in service_users for role in str(item.get("roles_csv", "")).split(",") if role.strip()})
    producer_roles = sorted({role.strip() for item in producer_clients for role in str(item.get("roles_csv", "")).split(",") if role.strip()})
    role_coverage_items = (
        "<ul>"
        f"<li><strong>Service user roles</strong><div class='hint'>{_html_escape(', '.join(service_user_roles) or 'none')}</div></li>"
        f"<li><strong>Producer roles</strong><div class='hint'>{_html_escape(', '.join(producer_roles) or 'none')}</div></li>"
        "<li><strong>Reader</strong><div class='hint'>Can inspect analytics, repo pages, materializations, and sessions.</div></li>"
        "<li><strong>Materializer</strong><div class='hint'>Can create materializations and operate scheduled warehouse exports.</div></li>"
        "<li><strong>Admin</strong><div class='hint'>Can provision tenants, users, providers, and producers.</div></li>"
        "<li><strong>Ingestor</strong><div class='hint'>Can POST decision events from CI producers.</div></li>"
        "</ul>"
    )
    selected_producer_html = "<p class='hint'>Select a producer client to inspect last-used and rotation history.</p>"
    if isinstance(selected_producer, dict):
        selected_producer_html = (
            f"<ul>"
            f"<li><strong>Client</strong><div class='hint mono'>{_html_escape(str(selected_producer.get('client_id', '')))}</div></li>"
            f"<li><strong>Status</strong><div class='hint'>{_html_escape(str(selected_producer.get('status', 'active')))}</div></li>"
            f"<li><strong>Roles</strong><div class='hint'>{_html_escape(str(selected_producer.get('roles_csv', '')))}</div></li>"
            f"<li><strong>Last issued</strong><div class='hint'>{_html_escape(str(selected_producer.get('last_issued_at', '') or 'n/a'))}</div></li>"
            f"<li><strong>Last rotated</strong><div class='hint'>{_html_escape(str(selected_producer.get('last_rotated_at', '') or 'never'))}</div></li>"
            f"<li><strong>Last used</strong><div class='hint'>{_html_escape(str(selected_producer.get('last_used_at', '') or 'never'))}</div></li>"
            f"<li><strong>Revoked at</strong><div class='hint'>{_html_escape(str(selected_producer.get('revoked_at', '') or 'active'))}</div></li>"
            f"</ul>"
        )
    auth_hardening_items = (
        "<ul>"
        f"<li><strong>Browser sign-in</strong><div class='hint'>{'JWT / managed identity ready' if jwt_enabled else 'Bearer session bridge active'}</div></li>"
        f"<li><strong>JWT enabled</strong><div class='hint'>{'yes' if jwt_enabled else 'no'}</div></li>"
        f"<li><strong>Issuer</strong><div class='hint mono'>{jwt_issuer}</div></li>"
        f"<li><strong>Audience</strong><div class='hint mono'>{jwt_audience}</div></li>"
        f"<li><strong>JWKS URL</strong><div class='hint mono'>{jwks_url}</div></li>"
        f"<li><strong>OIDC discovery</strong><div class='hint mono'>{oidc_discovery_url}</div></li>"
        f"<li><strong>Next auth move</strong><div class='hint'>{_html_escape(str(observability.get('auth_recommendation', 'Use the browser sign-in flow and move operators onto JWT when ready.')) if isinstance(observability, dict) else 'Use the browser sign-in flow and move operators onto JWT when ready.')}</div></li>"
        "</ul>"
    )
    ingest_recovery = (
        "<ul>"
        f"<li><strong>Current ingest health</strong><div class='hint'>{_html_escape(str(observability.get('ingest_status', 'unknown')) if isinstance(observability, dict) else 'unknown')}</div></li>"
        "<li><strong>Recovery</strong><div class='hint'>If no event lands, verify repo vars/secrets, rerun CI once, then rotate the producer if the repo still shows no decision.</div></li>"
        "</ul>"
    )
    auth_recovery = (
        "<ul>"
        f"<li><strong>Current auth mode</strong><div class='hint'>{_html_escape(str(observability.get('auth_mode', 'unknown')) if isinstance(observability, dict) else 'unknown')}</div></li>"
        "<li><strong>Recovery</strong><div class='hint'>If browser sign-in fails, retry with the raw token value, confirm tenant scope, then switch operators to JWT or OIDC-backed sign-in when available.</div></li>"
        "</ul>"
    )
    scheduler_recovery = (
        "<ul>"
        f"<li><strong>Current scheduler health</strong><div class='hint'>{_html_escape(str(observability.get('scheduler_status', 'unknown')) if isinstance(observability, dict) else 'unknown')}</div></li>"
        "<li><strong>Recovery</strong><div class='hint'>If materializations stop appearing, check the latest run in this app first, then inspect worker logs and schedule config.</div></li>"
        "</ul>"
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
    repo_connect = ui.get("repo_connect", {}) if isinstance(ui, dict) and isinstance(ui.get("repo_connect"), dict) else {}
    repo_connect_repository = str(repo_connect.get("repository", "")).strip() if isinstance(repo_connect, dict) else ""
    repo_event_state = repo_connect.get("event_state", {}) if isinstance(repo_connect, dict) and isinstance(repo_connect.get("event_state"), dict) else {}
    repo_event_status = str(repo_event_state.get("state", "idle")) if isinstance(repo_event_state, dict) else "idle"
    repo_event_message = _html_escape(str(repo_event_state.get("message", ""))) if isinstance(repo_event_state, dict) else ""
    repo_event_next_step = _html_escape(str(repo_event_state.get("next_step", ""))) if isinstance(repo_event_state, dict) else ""
    repo_event_troubleshooting = repo_event_state.get("troubleshooting", ()) if isinstance(repo_event_state, dict) else ()
    repo_workflow_yaml = _html_escape(str(repo_connect.get("workflow_yaml", ""))) if isinstance(repo_connect, dict) else ""
    repo_secret_value = str(repo_connect.get("secret_value", "")).strip() if isinstance(repo_connect, dict) else ""
    repo_secret_state = (
        "<div class='flash success'><strong>Fresh ingestor token available now.</strong>"
        f"<div class='hint'>Set <span class='mono'>{_html_escape(str(repo_connect.get('secret_name', 'VERIDION_HOSTED_INGESTOR_TOKEN')))}</span> in the repository secrets using the token shown above.</div>"
        "</div>"
        if repo_secret_value
        else "<div class='hint'>No fresh token is visible in this response. Rotate or create the selected producer if you need a one-time token reveal.</div>"
    )
    repo_recovery_html = ""
    if isinstance(repo_connect, dict) and repo_connect_repository:
        producer_status_value = _html_escape(str(repo_connect.get("producer_status", "unknown")))
        token_prefix_value = _html_escape(str(repo_connect.get("token_prefix", "")) or "not issued")
        selected_client_value = _html_escape(str(repo_connect.get("client_id", "")) or "unassigned")
        recovery_button = (
            f"<form method='post' action='/api/{_html_escape(api_version)}/app'><input type='hidden' name='action' value='rotate_producer_client'><input type='hidden' name='tenant_id' value='{_html_escape(tenant_value)}'><input type='hidden' name='client_id' value='{selected_client_value}'><input type='hidden' name='repository' value='{_html_escape(repo_connect_repository)}'><input type='hidden' name='service' value='{_html_escape(str(repo_connect.get('service_id', '')))}'><input type='hidden' name='producer_client' value='{selected_client_value}'><button type='submit'>Recover With Fresh Token</button></form>"
            if str(repo_connect.get("client_id", "")).strip()
            else ""
        )
        repo_recovery_html = (
            "<ul>"
            f"<li><strong>Producer</strong><div class='hint mono'>{selected_client_value}</div></li>"
            f"<li><strong>Status</strong><div class='hint'>{producer_status_value}</div></li>"
            f"<li><strong>Persisted prefix</strong><div class='hint mono'>{token_prefix_value}...</div></li>"
            "<li><strong>Recovery path</strong><div class='hint'>If CI never lands an event, rotate the producer to reveal a new token and replace the repo secret.</div></li>"
            "</ul>"
            f"{recovery_button}"
        )
    repo_connect_steps = (
        "<ul>"
        "<li><strong>Repo variables</strong><div class='hint mono'>VERIDION_HOSTED_SERVICE_URL</div><div class='hint mono'>VERIDION_HOSTED_TENANT_ID</div></li>"
        "<li><strong>Repo secret</strong><div class='hint mono'>VERIDION_HOSTED_INGESTOR_TOKEN</div></li>"
        "<li><strong>Expected path</strong><div class='hint'>Enable the hosted producer workflow or the internal decision sink so CI POSTs to <span class='mono'>/api/v1/events</span>.</div></li>"
        "</ul>"
    )
    if isinstance(repo_connect, dict) and repo_connect_repository:
        success_actions = ""
        if repo_event_status == "success":
            success_actions = (
                f"<div class='flash success'><strong>Repository onboarding complete.</strong>"
                f"<div class='hint'>Open the focused pages to inspect the latest decision and service posture.</div>"
                f"<div class='hint'><a href='/api/{_html_escape(api_version)}/app/repository?tenant={tenant_query}&repository={quote(repo_connect_repository)}'>Open repository page</a> · "
                f"<a href='/api/{_html_escape(api_version)}/app/service?tenant={tenant_query}&service={quote(str(repo_connect.get('service_id', '')))}'>Open service page</a></div>"
                f"</div>"
            )
        troubleshooting_items = "".join(
            f"<li>{_html_escape(str(item))}</li>"
            for item in repo_event_troubleshooting
        ) or "<li>Run the workflow once and return here to check for the first hosted decision.</li>"
        state_label = "success" if repo_event_status == "success" else "warning" if repo_event_status in {"waiting", "warning"} else "error" if repo_event_status == "blocked" else "info"
        repo_connect_steps = (
            f"<div class='flash {state_label}'>"
            f"<strong>{_html_escape(repo_connect_repository)}</strong><div class='hint'>{repo_event_message}</div></div>"
            "<ul>"
            f"<li><strong>Repository</strong><div class='hint mono'>{_html_escape(repo_connect_repository)}</div></li>"
            f"<li><strong>Service</strong><div class='hint mono'>{_html_escape(str(repo_connect.get('service_id', '')))}</div></li>"
            f"<li><strong>Owner / team</strong><div class='hint'>{_html_escape(str(repo_connect.get('service_owner', '')))} / {_html_escape(str(repo_connect.get('owning_team', '')))}</div></li>"
            f"<li><strong>Criticality</strong><div class='hint'>{_html_escape(str(repo_connect.get('service_criticality', '')))}</div></li>"
            f"<li><strong>Next step</strong><div class='hint'>{repo_event_next_step}</div></li>"
            f"<li><strong>Vars</strong><div class='hint mono'>VERIDION_HOSTED_SERVICE_URL={_html_escape(str(((repo_connect.get('vars') or {}).get('VERIDION_HOSTED_SERVICE_URL', '')) if isinstance(repo_connect.get('vars'), dict) else ''))}</div><div class='hint mono'>VERIDION_HOSTED_TENANT_ID={_html_escape(str(((repo_connect.get('vars') or {}).get('VERIDION_HOSTED_TENANT_ID', '')) if isinstance(repo_connect.get('vars'), dict) else ''))}</div></li>"
            f"<li><strong>Secret</strong><div class='hint mono'>{_html_escape(str(repo_connect.get('secret_name', 'VERIDION_HOSTED_INGESTOR_TOKEN')))}</div></li>"
            "</ul>"
            f"{success_actions}"
            f"{repo_secret_state}"
            f"<div class='card' style='margin-top:1rem; background:var(--panel-alt,#f7faf8);'><h3 class='section-title'>Troubleshoot Missing Events</h3><ul>{troubleshooting_items}</ul></div>"
            f"<pre>{repo_workflow_yaml}</pre>"
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
    observability_items = "".join(
        (
            f"<li><strong>Ingest health</strong><div class='hint'>{_html_escape(str(observability.get('ingest_status', 'unknown')))} / {_html_escape(str(observability.get('last_event_at', '') or 'n/a'))} / {_html_escape(str(observability.get('last_event_repo', '') or 'none'))}</div></li>"
            f"<li><strong>Scheduler health</strong><div class='hint'>{_html_escape(str(observability.get('scheduler_status', 'unknown')))} / {_html_escape(str(observability.get('last_materialization_at', '') or 'n/a'))} / {_html_escape(str(observability.get('last_materialization_run', '') or 'none'))}</div></li>"
            f"<li><strong>Producer health</strong><div class='hint'>{_html_escape(str(observability.get('producer_status', 'unknown')))} / {_html_escape(str(observability.get('last_producer_use_at', '') or 'never'))} / {_html_escape(str(observability.get('last_producer_client', '') or 'none'))}</div></li>"
            f"<li><strong>Last operator session</strong><div class='hint'>{_html_escape(str(observability.get('last_session_at', '') or 'n/a'))} / {_html_escape(str(observability.get('last_session_principal', '') or 'none'))}</div></li>"
            f"<li><strong>Latest auth failure</strong><div class='hint'>{_html_escape(str(observability.get('last_auth_failure_at', '') or 'n/a'))} / {_html_escape(str(observability.get('last_auth_failure_detail', '') or 'none'))}</div></li>"
            f"<li><strong>Latest ingest issue</strong><div class='hint'>{_html_escape(str(observability.get('last_ingest_issue_at', '') or 'n/a'))} / {_html_escape(str(observability.get('last_ingest_issue_detail', '') or 'none'))}</div></li>"
            f"<li><strong>Latest scheduler issue</strong><div class='hint'>{_html_escape(str(observability.get('last_scheduler_issue_at', '') or 'n/a'))} / {_html_escape(str(observability.get('last_scheduler_issue_detail', '') or 'none'))}</div></li>"
            f"<li><strong>Build / deploy</strong><div class='hint mono'>{_html_escape(str(observability.get('service_version', '') or 'n/a'))} / {_html_escape(str(observability.get('deployment_id', '') or 'n/a'))}</div></li>"
        )
        if isinstance(observability, dict)
        else "<li>No observability data available yet</li>"
    )
    repo_recent_event_items = "".join(
        f"<li>{_verdict_badge_html(_event_verdict(item))} <span class='hint mono' style='font-size:.8rem;'>{_html_escape(str(item.get('generated_at', '')))}</span><div class='hint' style='margin-top:.2rem;'>{_html_escape(_event_next_action(item))}</div></li>"
        for item in repository_recent_events[:4]
        if isinstance(item, dict)
    ) or "<li>No recent decisions for this repository yet.</li>"
    service_recent_event_items = "".join(
        f"<li>{_verdict_badge_html(_event_verdict(item))} <span class='hint mono' style='font-size:.8rem;'>{_html_escape(str(item.get('generated_at', '')))}</span><div class='hint' style='margin-top:.2rem;'>{_html_escape(_event_next_action(item))}</div></li>"
        for item in service_recent_events[:4]
        if isinstance(item, dict)
    ) or "<li>No recent decisions for this service yet.</li>"
    repository_decision_guidance = _event_detail_html(
        latest_repository_event,
        empty_message="No decision has landed for this repository yet. Run the onboarding workflow to generate the first event.",
    )
    service_decision_guidance = _event_detail_html(
        latest_service_event,
        empty_message="No repository-linked decision has landed for this service yet. Send the next CI event to unlock service guidance.",
    )
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{_html_escape(service_name)} App</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
      :root {{
        --bg: #f0ebe1;
        --surface: #faf7f2;
        --surface-alt: #f5f0e8;
        --line: #ddd6cc;
        --ink: #161710;
        --muted: #6b6c64;
        --accent: #b34b18;
        --accent-dark: #923c12;
        --accent-soft: #fdf0ea;
        --warn: #8a5000;
        --warn-soft: #fff8ec;
        --danger: #8b2d1f;
        --danger-soft: #fff1ed;
        /* legacy aliases for inline styles */
        --panel: var(--surface);
        --panel-alt: var(--surface-alt);
      }}
      *, *::before, *::after {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: 'Space Grotesk', system-ui, sans-serif;
        background: var(--bg);
        color: var(--ink);
        font-size: 15px;
        line-height: 1.5;
        -webkit-font-smoothing: antialiased;
      }}
      .shell {{ max-width: 1360px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }}

      /* Top nav */
      .topnav {{
        background: #0b0d0a;
        border-bottom: 1px solid rgba(255,255,255,.06);
        position: sticky; top: 0; z-index: 100;
      }}
      .topnav-inner {{
        max-width: 1360px; margin: 0 auto;
        padding: .65rem 1.5rem;
        display: flex; align-items: center; gap: .75rem;
      }}
      .brand-logo {{
        width: 22px; height: 22px; background: #b34b18; color: #fff;
        font-size: .65rem; font-weight: 700; border-radius: 4px;
        display: flex; align-items: center; justify-content: center; flex-shrink: 0;
      }}
      .brand-name {{ color: rgba(255,255,255,.9); font-weight: 700; font-size: .88rem; letter-spacing: -.02em; }}
      .topnav-right {{ margin-left: auto; font-size: .72rem; color: rgba(255,255,255,.4); font-family: 'IBM Plex Mono', monospace; }}

      /* Hero */
      .hero {{ display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 1.25rem; margin-bottom: 1.25rem; }}
      .hero-card {{
        background: #0b0d0a;
        color: #f4f9f6;
        border-radius: 28px;
        padding: 2rem 2rem 1.75rem;
        min-height: 210px;
        box-shadow: 0 28px 60px rgba(0,0,0,.22);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        position: relative; overflow: hidden;
      }}
      .hero-card::before {{
        content: ''; position: absolute; top: -80px; left: 50%;
        transform: translateX(-50%);
        width: 500px; height: 320px;
        background: radial-gradient(circle at center, rgba(179,75,24,.38) 0%, transparent 65%);
        pointer-events: none;
      }}
      .hero h1 {{ margin: 0 0 .4rem; font-size: 2.1rem; letter-spacing: -0.04em; line-height: 1.15; position: relative; }}
      .hero p {{ margin: .4rem 0 0; color: rgba(244,249,246,.72); line-height: 1.55; font-size: .94rem; max-width: 40rem; position: relative; }}
      .meta {{ color: rgba(244,249,246,.5); font-size: .75rem; letter-spacing: .02em; margin-bottom: .5rem; font-family: 'IBM Plex Mono', monospace; position: relative; }}
      .hero-side {{ display: grid; gap: 1.25rem; }}

      /* Cards */
      .card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 22px; padding: 1.25rem; box-shadow: 0 6px 20px rgba(22,23,16,.04); }}
      .callout {{ background: #fffcf0; border-color: #e4d090; }}
      .callout strong {{ color: var(--warn); }}

      /* Metric grid */
      .summary-grid {{ display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 1rem; margin: 1.25rem 0; }}
      .mini-card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 20px; padding: 1.25rem 1.1rem; box-shadow: 0 4px 12px rgba(22,23,16,.04); }}
      .label {{ color: var(--muted); font-size: .68rem; text-transform: uppercase; letter-spacing: .1em; font-family: 'IBM Plex Mono', monospace; font-weight: 500; }}
      .value {{ font-size: 2.25rem; font-weight: 700; margin-top: .3rem; line-height: 1; letter-spacing: -0.02em; }}
      .value.small {{ font-size: 1.3rem; line-height: 1.2; }}

      /* Layout grids */
      .section-grid {{ display: grid; grid-template-columns: 1.2fr .8fr; gap: 1.25rem; margin-top: 1.25rem; }}
      .stack {{ display: grid; gap: 1.25rem; }}
      .triple {{ display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 1.25rem; margin-top: 1.25rem; }}
      .two-col {{ display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 1.25rem; }}

      /* Typography */
      .section-title {{ margin: 0 0 .55rem; font-size: 1rem; font-weight: 700; letter-spacing: -0.015em; }}
      .section-kicker {{ color: var(--muted); font-size: .87rem; margin: -.2rem 0 .9rem; line-height: 1.5; }}
      h3.section-title {{ font-size: .92rem; margin-bottom: .5rem; }}

      /* Chips & badges */
      .pill {{ display: inline-block; padding: .28rem .75rem; border-radius: 999px; background: rgba(255,255,255,.1); border: 1px solid rgba(255,255,255,.18); margin-right: .4rem; margin-bottom: .4rem; font-size: .83rem; position: relative; }}
      .status {{ display: inline-flex; align-items: center; margin-left: .45rem; padding: .17rem .5rem; border-radius: 999px; font-size: .68rem; text-transform: uppercase; letter-spacing: .08em; font-family: 'IBM Plex Mono', monospace; font-weight: 600; }}
      .status.ready {{ background: var(--accent-soft); color: var(--accent); }}
      .status.todo {{ background: var(--warn-soft); color: var(--warn); }}

      /* Utility */
      .mono {{ font-family: 'IBM Plex Mono', monospace; font-size: .85rem; }}
      ul {{ margin: 0; padding-left: 1.1rem; }}
      li {{ margin: .5rem 0; line-height: 1.45; }}
      .hint {{ color: var(--muted); font-size: .9rem; margin-top: .2rem; line-height: 1.45; }}
      .count {{ float: right; color: var(--muted); font-family: 'IBM Plex Mono', monospace; font-size: .88rem; }}

      /* Flash */
      .flash {{ border-radius: 16px; padding: 1rem 1.1rem; margin: 1rem 0; border: 1px solid var(--line); font-size: .92rem; line-height: 1.5; }}
      .flash.success {{ background: rgba(22,163,74,.07); border-color: rgba(22,163,74,.22); color: #166534; }}
      .flash.warning {{ background: var(--warn-soft); border-color: #e8c97a; color: var(--warn); }}
      .flash.error {{ background: var(--danger-soft); border-color: #f1beb5; color: var(--danger); }}
      .token-box {{ margin-top: .75rem; padding: .9rem 1rem; background: #fffdf8; border: 1px dashed #d2b276; border-radius: 12px; word-break: break-all; color: #6b4300; font-family: 'IBM Plex Mono', monospace; font-size: .87rem; }}

      /* Table */
      table {{ width: 100%; border-collapse: collapse; }}
      th, td {{ text-align: left; padding: .7rem .6rem; border-top: 1px solid var(--line); font-size: .92rem; vertical-align: top; }}
      th {{ color: var(--muted); font-weight: 500; border-top: none; font-size: .68rem; text-transform: uppercase; letter-spacing: .07em; font-family: 'IBM Plex Mono', monospace; }}

      /* Verdict badges — used in tables, lists, and detail cards */
      .vbadge {{ display: inline-block; font-family: 'IBM Plex Mono', monospace; font-weight: 600; font-size: .78rem; padding: .15rem .5rem; border-radius: 5px; white-space: nowrap; }}
      .vbadge-go {{ background:#d4f0de; color:#0f5c28; }}
      .vbadge-nogo {{ background:#fde4e1; color:#8b1a12; }}
      .vbadge-conditional {{ background:#fef3cd; color:#7a5200; }}
      .vbadge-unknown {{ background:var(--line); color:var(--muted); }}

      /* Decision card (used in repo/service detail panels) */
      .decision-card {{ padding: 0; }}
      .decision-verdict-row {{
        display: flex; align-items: center; gap: .75rem; flex-wrap: wrap;
        padding-bottom: .85rem; margin-bottom: .85rem;
        border-bottom: 1px solid var(--line);
      }}
      .verdict-badge {{
        display: inline-flex; align-items: center; justify-content: center;
        font-family: 'IBM Plex Mono', monospace; font-weight: 700;
        font-size: .95rem; letter-spacing: .04em; padding: .3rem .8rem;
        border-radius: 8px; white-space: nowrap;
      }}
      .verdict-go    {{ background:#d4f0de; color:#0f5c28; border:1.5px solid #a3d9b5; }}
      .verdict-nogo  {{ background:#fde4e1; color:#8b1a12; border:1.5px solid #f5b3ac; }}
      .verdict-conditional {{ background:#fef3cd; color:#7a5200; border:1.5px solid #f0d080; }}
      .verdict-unknown {{ background:var(--line); color:var(--muted); border:1.5px solid var(--line); }}
      .verdict-meta {{ font-family:'IBM Plex Mono',monospace; font-size:.82rem; color:var(--muted); }}
      .verdict-gate {{ margin-left:auto; font-family:'IBM Plex Mono',monospace; font-size:.75rem; color:var(--muted); background:var(--bg); padding:.18rem .5rem; border-radius:99px; border:1px solid var(--line); }}
      .decision-section {{ margin-bottom:.7rem; }}
      .decision-section:last-child {{ margin-bottom:0; }}
      .decision-section-label {{ font-size:.65rem; text-transform:uppercase; letter-spacing:.1em; font-family:'IBM Plex Mono',monospace; color:var(--muted); font-weight:600; margin-bottom:.25rem; }}
      .decision-list {{ margin:0; padding-left:1.1rem; }}
      .decision-list li {{ font-size:.88rem; margin:.2rem 0; color:var(--ink); }}
      .approval-list {{ list-style:none; padding-left:0; display:flex; flex-wrap:wrap; gap:.35rem; }}
      .approval-tag {{ display:inline-block; font-size:.78rem; font-family:'IBM Plex Mono',monospace; background:#fff3e0; color:#7a4000; border:1px solid #f0c070; padding:.12rem .5rem; border-radius:5px; }}

      /* Forms */
      form {{ display: grid; gap: .75rem; }}
      label {{ display: grid; gap: .3rem; font-size: .68rem; color: var(--muted); font-family: 'IBM Plex Mono', monospace; letter-spacing: .07em; text-transform: uppercase; font-weight: 500; }}
      input {{ width: 100%; border: 1px solid var(--line); border-radius: 10px; padding: .7rem .85rem; background: #fff; color: var(--ink); font-family: 'Space Grotesk', system-ui, sans-serif; font-size: .94rem; transition: border-color .15s; }}
      input:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(179,75,24,.1); }}

      /* Buttons */
      button {{ border: none; border-radius: 10px; padding: .65rem 1.1rem; background: var(--accent); color: #fff; font-family: 'Space Grotesk', system-ui, sans-serif; font-size: .9rem; font-weight: 600; cursor: pointer; transition: background .15s; }}
      button:hover {{ background: var(--accent-dark); }}
      button[style*="8b2d1f"], button[style*="danger"] {{ background: var(--danger); }}

      /* Links */
      a {{ color: var(--accent); text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}

      /* Footer */
      .footer {{ margin-top: 2rem; color: var(--muted); font-size: .82rem; text-align: center; line-height: 1.6; font-family: 'IBM Plex Mono', monospace; }}

      @media (max-width: 1080px) {{
        .hero, .section-grid, .triple, .summary-grid, .two-col {{ grid-template-columns: 1fr; }}
      }}
    </style>
  </head>
  <body>
    <nav class="topnav" aria-label="Site navigation">
      <div class="topnav-inner">
        <span class="brand-logo" aria-hidden="true">V</span>
        <span class="brand-name">{_html_escape(service_name)}</span>
        <span class="topnav-right">Tenant&nbsp;{tenant_label}&nbsp;&middot;&nbsp;{_html_escape(principal)}</span>
      </div>
    </nav>
    <div class="shell">
      <div class="hero">
        <div class="hero-card">
          <div>
            <div class="meta">Tenant {tenant_label}</div>
            <h1>{display_name}</h1>
            <p>Release-control overview for this tenant. Track whether events are arriving, producers are live, and the scheduler is running.</p>
          </div>
          <div>
            <span class="pill">{events} events</span>
            <span class="pill">{repositories} repositories</span>
            <span class="pill">{schedule_count} schedules</span>
            <span class="pill">{materialization_count} materializations</span>
          </div>
        </div>
        <div class="hero-side">
          <div class="card callout">
            <div class="label">Onboarding Progress</div>
            <div class="value small">{completed_steps} / {len(checklist)} complete</div>
            <p class="hint" style="margin-top:.6rem;"><strong>Next:</strong> {_html_escape(next_step)}</p>
          </div>
          <div class="card">
            <div class="label">Service Shape</div>
            <div class="hint" style="margin-top:.5rem;">Backend: <strong>{store_backend}</strong> &nbsp;·&nbsp; Schema: <strong>{schema_version}</strong> &nbsp;·&nbsp; Persistent store: <strong>{has_persistent_store}</strong></div>
            <div class="hint">History paths: {_html_escape(str(len(history_paths)))}</div>
            <form method="post" action="/api/{_html_escape(api_version)}/app/logout" style="margin-top:1rem; display:block;">
              <button type="submit" style="width:100%;">Sign Out</button>
            </form>
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
          <h2 class="section-title">Second Tenant Playbook</h2>
          <div class="section-kicker">Use this when onboarding the next org, not just the first one.</div>
          <ul>
            <li><strong>Tenant skeleton</strong><div class="hint">Create a second tenant ID such as <span class="mono">beta</span> before sharing producer credentials.</div></li>
            <li><strong>Dedicated producer</strong><div class="hint">Issue a separate CI ingestor per repo or team so rotation and revocation stay isolated.</div></li>
            <li><strong>Service mapping</strong><div class="hint">Verify the first decision event contains organization, project, service owner, and criticality metadata.</div></li>
            <li><strong>Operator access</strong><div class="hint">Create at least one named service user before sharing the app URL with a new team.</div></li>
          </ul>
          <form method="post" action="/api/{_html_escape(api_version)}/app" style="margin-top:1rem;">
            <input type="hidden" name="action" value="create_tenant">
            <label>Next Tenant ID<input name="tenant_id" value="beta"></label>
            <label>Display Name<input name="display_name" value="Beta Production"></label>
            <label>Organization Name<input name="organization_name" value="Beta"></label>
            <label>Status<input name="status" value="active"></label>
            <button type="submit">Provision Second Tenant</button>
          </form>
        </div>
      </div>

      <div class="triple">
        <div class="card">
          <h2 class="section-title">Connect First Repo</h2>
          <div class="section-kicker">Generate the repo-specific CI wiring, then wait here for the first hosted decision to arrive.</div>
          <form method="post" action="/api/{_html_escape(api_version)}/app">
            <input type="hidden" name="action" value="connect_repository">
            <input type="hidden" name="tenant_id" value="{_html_escape(tenant_value)}">
            <label>Repository<input name="repository" value="{_html_escape(repo_connect_repository or selected_repository)}" placeholder="veridionhq/veridion"></label>
            <label>Service<input name="service" value="{_html_escape(str((repo_connect.get('service_id', '') if isinstance(repo_connect, dict) else '') or selected_service))}" placeholder="history-service"></label>
            <label>Organization<input name="organization" value="{_html_escape(str((repo_connect.get('organization', '') if isinstance(repo_connect, dict) else '') or tenant_value))}" placeholder="veridionhq"></label>
            <label>Project<input name="project_id" value="{_html_escape(str((repo_connect.get('project_id', '') if isinstance(repo_connect, dict) else '') or repo_connect_repository or selected_repository))}" placeholder="veridionhq/veridion"></label>
            <label>Service Owner<input name="service_owner" value="{_html_escape(str((repo_connect.get('service_owner', '') if isinstance(repo_connect, dict) else '') or 'platform-owner'))}" placeholder="platform-owner"></label>
            <label>Owning Team<input name="owning_team" value="{_html_escape(str((repo_connect.get('owning_team', '') if isinstance(repo_connect, dict) else '') or 'platform-team'))}" placeholder="platform-team"></label>
            <label>Criticality<input name="service_criticality" value="{_html_escape(str((repo_connect.get('service_criticality', '') if isinstance(repo_connect, dict) else '') or 'high'))}" placeholder="high"></label>
            <label>Producer Client<input name="producer_client" value="{_html_escape(str((repo_connect.get('client_id', '') if isinstance(repo_connect, dict) else '') or selected_producer_client))}" placeholder="github-actions"></label>
            <button type="submit">Generate Repo Plan</button>
          </form>
          <div style="margin-top:1rem;">{repo_connect_steps}</div>
        </div>
        <div class="card">
          <h2 class="section-title">Auth Hardening</h2>
          <div class="section-kicker">Move operators off bootstrap tokens and onto JWT/JWKS-backed identities.</div>
          {auth_hardening_items}
          <div class="hint" style="margin-top:.75rem;">Browser sign-in accepts the raw token or JWT value. The form also strips a pasted <span class="mono">Bearer </span> prefix automatically.</div>
        </div>
        <div class="card">
          <h2 class="section-title">Current Control Signals</h2>
          <div class="section-kicker">Fast read of what is live for this tenant.</div>
          <ul>
            <li><strong>Latest repo decision</strong><div class="hint">{_html_escape(str((latest_by_repository[0] if latest_by_repository else {}).get('repository', 'none')))} / {_html_escape(str((latest_by_repository[0] if latest_by_repository else {}).get('verdict', 'none')))}</div></li>
            <li><strong>Latest materialization</strong><div class="hint">{_html_escape(str((materializations[0] if materializations else {}).get('run_id', 'none')))}</div></li>
            <li><strong>Latest session</strong><div class="hint">{_html_escape(str((sessions[0] if sessions else {}).get('session_id', 'none')))}</div></li>
            <li><strong>Auth mode</strong><div class="hint">{_html_escape(str(observability.get('auth_mode', 'unknown')) if isinstance(observability, dict) else 'unknown')}</div></li>
            <li><strong>Build version</strong><div class="hint mono">{service_version}</div></li>
            <li><strong>Deployment id</strong><div class="hint mono">{deployment_id}</div></li>
          </ul>
        </div>
      </div>

      <div class="triple">
        <div class="card">
          <h2 class="section-title">Role Model</h2>
          <div class="section-kicker">Make it obvious which identities should hold which permissions.</div>
          {role_coverage_items}
        </div>
        <div class="card">
          <h2 class="section-title">Auth Recovery</h2>
          <div class="section-kicker">Use this when operators cannot get into the hosted app cleanly.</div>
          {auth_recovery}
        </div>
        <div class="card">
          <h2 class="section-title">Recovery Playbooks</h2>
          <div class="section-kicker">Fast remediation paths for the most common hosted failures.</div>
          <div class="two-col">
            <div>{ingest_recovery}</div>
            <div>{scheduler_recovery}</div>
          </div>
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
            <h2 class="section-title">Operator Observability</h2>
            <div class="section-kicker">Answers the most common operator questions without the AWS console.</div>
            <ul>{observability_items}</ul>
          </div>
          <div class="card">
            <h2 class="section-title">Producer Recovery</h2>
            <div class="section-kicker">Rotate or recover credentials when onboarding gets stuck or a token leaks.</div>
            {repo_recovery_html or "<p class='hint'>Generate a repo plan above to anchor recovery instructions to a specific producer client.</p>"}
          </div>
          <div class="card">
            <h2 class="section-title">Producer Token Controls</h2>
            <div class="section-kicker">Rotate active credentials and revoke stale ones without leaving the app.</div>
            <div class="two-col">
              <div>
                <ul>{producer_ops_items}</ul>
              </div>
              <div>
                <h3 class="section-title" style="margin-top:0;">Selected Producer</h3>
                {selected_producer_html}
                <h3 class="section-title" style="margin-top:1rem;">Audit Trail</h3>
                <ul>{producer_audit_items}</ul>
              </div>
            </div>
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
              <div class='card' style='margin-top:1rem; background:var(--panel-alt,#f7faf8);'><h3 class='section-title'>Decision Guidance</h3>{repository_decision_guidance}</div>
              {_detail_analytics_html(repository_analytics, empty_message="No repository history slice yet. Send more decisions for this repository to unlock trends.")}
              <div class='card' style='margin-top:1rem; background:var(--panel-alt,#f7faf8);'><h3 class='section-title'>Recent Decisions</h3><ul>{repo_recent_event_items}</ul></div>
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
              <div class='card' style='margin-top:1rem; background:var(--panel-alt,#f7faf8);'><h3 class='section-title'>Decision Guidance</h3>{service_decision_guidance}</div>
              {_detail_analytics_html(service_analytics, empty_message="No service-linked history slice yet. The selected service needs repository-backed decision events.")}
              <div class='card' style='margin-top:1rem; background:var(--panel-alt,#f7faf8);'><h3 class='section-title'>Recent Service Decisions</h3><ul>{service_recent_event_items}</ul></div>
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

      <div class="two-col" style="margin-top:1rem;">
        <div class="card">
          <h2 class="section-title">Control Plane Audit</h2>
          <div class="section-kicker">Operator, auth, and admin actions that changed hosted state.</div>
          <ul>{control_audit_items}</ul>
        </div>
        <div class="card">
          <h2 class="section-title">Operator Trust Notes</h2>
          <div class="section-kicker">What to trust, and what to verify next, before broadening usage.</div>
          <ul>
            <li><strong>Auth</strong><div class="hint">Prefer JWT or OIDC-backed sign-in for named operators. Keep bootstrap bearer for break-glass only.</div></li>
            <li><strong>Ingestion</strong><div class="hint">Trust the app once a decision lands for the expected repository and the producer audit shows recent use.</div></li>
            <li><strong>Scheduler</strong><div class="hint">Trust scheduled exports once recent materializations keep advancing without manual POSTs.</div></li>
            <li><strong>Recovery</strong><div class="hint">Use rotate, revoke, and the audit surfaces here before leaving for AWS tooling.</div></li>
          </ul>
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

      <div class="footer">{_html_escape(service_name)} &middot; Tenant {tenant_label} &middot; API {_html_escape(api_version)}</div>
    </div>
  </body>
</html>"""


def render_focus_page_html(
    payload: dict[str, object],
    *,
    api_version: str,
    identity: HistoryToken | None,
    service_name: str,
    kind: str,
) -> str:
    tenant = payload.get("tenant", {}) if isinstance(payload, dict) else {}
    detail = payload.get("detail", {}) if isinstance(payload, dict) else {}
    principal = identity.principal_name or identity.token_id if identity is not None else "anonymous"
    repository_analytics = detail.get("repository_analytics") if isinstance(detail, dict) else None
    service_analytics = detail.get("service_analytics") if isinstance(detail, dict) else None
    repository_recent_events = detail.get("repository_recent_events", []) if isinstance(detail, dict) else []
    service_recent_events = detail.get("service_recent_events", []) if isinstance(detail, dict) else []
    selected_repository = str((detail.get("selected_repository") if isinstance(detail, dict) else "") or tenant.get("selected_repository", "")).strip()
    selected_service = str((detail.get("selected_service") if isinstance(detail, dict) else "") or tenant.get("selected_service", "")).strip()
    catalog = payload.get("catalog", {}) if isinstance(payload, dict) else {}
    services = catalog.get("services", []) if isinstance(catalog, dict) else []
    latest_by_repository = ((payload.get("analytics") or {}).get("policy_rollout") or {}).get("latest_by_repository", []) if isinstance(payload.get("analytics"), dict) else []
    repository_detail = next((item for item in latest_by_repository if str(item.get("repository", "")) == selected_repository), None)
    service_detail = next((item for item in services if str(item.get("service_id", "")) == selected_service), None)
    focus_title = selected_repository if kind == "repository" else selected_service
    focus_title = focus_title or ("Repository" if kind == "repository" else "Service")
    tenant_value = quote(str(tenant.get("tenant_id", "")).strip())

    def _focus_analytics(detail_payload: object) -> str:
        if not isinstance(detail_payload, dict):
            return "<p class='hint'>No history available yet for this selection.</p>"
        summary = detail_payload.get("summary", {}) if isinstance(detail_payload.get("summary"), dict) else {}
        series = ((detail_payload.get("time_series") or {}).get("by_day", [])) if isinstance(detail_payload.get("time_series"), dict) else []
        blocks = detail_payload.get("top_blocking_categories", []) if isinstance(detail_payload.get("top_blocking_categories"), list) else []
        series_items = "".join(
            f"<li>{_html_escape(str(item.get('day', '')))}<span class='count'>{_html_escape(str(item.get('events', '0')))}</span></li>"
            for item in series[-6:]
        ) or "<li>No time-series points recorded</li>"
        block_items = "".join(
            f"<li>{_html_escape(str(item.get('name', '')))}<span class='count'>{_html_escape(str(item.get('count', '0')))}</span></li>"
            for item in blocks[:6]
        ) or "<li>No blocking categories recorded</li>"
        return (
            f"<div class='card'><h2 class='section-title'>History Summary</h2>"
            f"<ul><li><strong>Events</strong><span class='count'>{_html_escape(str(summary.get('events', 0)))}</span></li>"
            f"<li><strong>Repositories</strong><span class='count'>{_html_escape(str(summary.get('repositories', 0)))}</span></li>"
            f"<li><strong>Blocked decisions</strong><span class='count'>{_html_escape(str(summary.get('blocked_events', 0)))}</span></li></ul></div>"
            f"<div class='card'><h2 class='section-title'>Recent Event Days</h2><ul>{series_items}</ul></div>"
            f"<div class='card'><h2 class='section-title'>Blocking Categories</h2><ul>{block_items}</ul></div>"
        )

    focus_meta = ""
    if kind == "repository" and isinstance(repository_detail, dict):
        latest_event = repository_recent_events[0] if repository_recent_events and isinstance(repository_recent_events[0], dict) else {}
        focus_meta = (
            f"<ul><li><strong>Repository</strong><div class='hint mono'>{_html_escape(str(repository_detail.get('repository', '')))}</div></li>"
            f"<li><strong>Verdict</strong><div class='hint'>{_html_escape(str(repository_detail.get('verdict', '')))}</div></li>"
            f"<li><strong>Gate</strong><div class='hint'>{_html_escape(str(repository_detail.get('gate_status', '')))}</div></li>"
            f"<li><strong>Pack</strong><div class='hint'>{_html_escape(str(repository_detail.get('pack_id', '')))} / {_html_escape(str(repository_detail.get('pack_version', '')))}</div></li>"
            f"<li><strong>Next action</strong><div class='hint'>{_html_escape(_event_next_action(latest_event) if isinstance(latest_event, dict) and latest_event else 'Collect the next decision event for this repository.')}</div></li></ul>"
        )
    elif kind == "repository" and selected_repository:
        focus_meta = (
            f"<ul><li><strong>Repository</strong><div class='hint mono'>{_html_escape(selected_repository)}</div></li>"
            f"<li><strong>Next action</strong><div class='hint'>Collect the next decision event for this repository.</div></li></ul>"
        )
    elif kind == "service" and isinstance(service_detail, dict):
        latest_event = service_recent_events[0] if service_recent_events and isinstance(service_recent_events[0], dict) else {}
        focus_meta = (
            f"<ul><li><strong>Service</strong><div class='hint mono'>{_html_escape(str(service_detail.get('service_id', '')))}</div></li>"
            f"<li><strong>Repository</strong><div class='hint mono'>{_html_escape(str(service_detail.get('repository', '')))}</div></li>"
            f"<li><strong>Owner</strong><div class='hint'>{_html_escape(str(service_detail.get('service_owner', '')) or 'unassigned')}</div></li>"
            f"<li><strong>Owning team</strong><div class='hint'>{_html_escape(str(service_detail.get('owning_team', '')) or 'unassigned')}</div></li>"
            f"<li><strong>Criticality</strong><div class='hint'>{_html_escape(str(service_detail.get('service_criticality', '')) or 'unknown')}</div></li>"
            f"<li><strong>Next action</strong><div class='hint'>{_html_escape(_event_next_action(latest_event) if isinstance(latest_event, dict) and latest_event else 'Send repository-linked decisions to unlock service posture guidance.')}</div></li></ul>"
        )
    elif kind == "service" and selected_service:
        focus_meta = (
            f"<ul><li><strong>Service</strong><div class='hint mono'>{_html_escape(selected_service)}</div></li>"
            f"<li><strong>Next action</strong><div class='hint'>Send repository-linked decisions to unlock service posture guidance.</div></li></ul>"
        )
    else:
        focus_meta = "<p class='hint'>No focused selection found.</p>"

    focus_recent_events = repository_recent_events if kind == "repository" else service_recent_events
    focus_latest_event = focus_recent_events[0] if focus_recent_events and isinstance(focus_recent_events[0], dict) else None
    recent_event_items = "".join(
        f"<li>{_verdict_badge_html(_event_verdict(item))} <span class='hint mono' style='font-size:.8rem;'>{_html_escape(str(item.get('generated_at', '')))}</span><div class='hint' style='margin-top:.2rem;'>{_html_escape(_event_next_action(item))}</div></li>"
        for item in focus_recent_events[:5]
        if isinstance(item, dict)
    ) or "<li>No recent decisions recorded.</li>"
    focus_decision_guidance = _event_detail_html(
        focus_latest_event,
        empty_message=(
            "No repository decision has landed yet. Finish onboarding and run the workflow once."
            if kind == "repository"
            else "No service-linked decision has landed yet. Send the next repository event to unlock guidance."
        ),
    )

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{_html_escape(service_name)} &middot; {_html_escape(focus_title)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
      :root {{
        --bg: #f0ebe1;
        --surface: #faf7f2;
        --line: #ddd6cc;
        --ink: #161710;
        --muted: #6b6c64;
        --accent: #b34b18;
        --accent-dark: #923c12;
        --accent-soft: #fdf0ea;
        /* legacy alias */
        --panel: var(--surface);
      }}
      *, *::before, *::after {{ box-sizing: border-box; margin: 0; }}
      body {{
        font-family: 'Space Grotesk', system-ui, sans-serif;
        background: var(--bg);
        color: var(--ink);
        font-size: 15px;
        line-height: 1.5;
        -webkit-font-smoothing: antialiased;
      }}

      /* Top nav */
      .topnav {{
        background: #0b0d0a;
        border-bottom: 1px solid rgba(255,255,255,.06);
        position: sticky; top: 0; z-index: 100;
      }}
      .topnav-inner {{
        max-width: 1200px; margin: 0 auto;
        padding: .65rem 1.5rem;
        display: flex; align-items: center; gap: .75rem;
      }}
      .brand-logo {{
        width: 22px; height: 22px; background: #b34b18; color: #fff;
        font-size: .65rem; font-weight: 700; border-radius: 4px;
        display: flex; align-items: center; justify-content: center; flex-shrink: 0;
      }}
      .brand-name {{ color: rgba(255,255,255,.9); font-weight: 700; font-size: .88rem; letter-spacing: -.02em; }}
      .topnav-right {{ margin-left: auto; font-size: .72rem; color: rgba(255,255,255,.4); font-family: 'IBM Plex Mono', monospace; }}

      .shell {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }}

      /* Breadcrumb */
      .breadcrumb {{ display: flex; align-items: center; gap: .5rem; margin-bottom: 1.5rem; font-size: .86rem; color: var(--muted); }}
      .breadcrumb a {{ color: var(--accent); text-decoration: none; }}
      .breadcrumb a:hover {{ text-decoration: underline; }}
      .breadcrumb .sep {{ opacity: .45; }}

      /* Header */
      .page-header {{ margin-bottom: 1.5rem; }}
      .page-kicker {{ font-size: .68rem; text-transform: uppercase; letter-spacing: .12em; color: #b34b18; font-family: 'IBM Plex Mono', monospace; font-weight: 500; margin-bottom: .45rem; }}
      .page-title {{ font-size: 2rem; letter-spacing: -0.035em; line-height: 1.15; font-weight: 700; }}
      .page-sub {{ color: var(--muted); font-size: .9rem; margin-top: .35rem; font-family: 'IBM Plex Mono', monospace; }}

      /* Cards */
      .card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 22px; padding: 1.25rem; box-shadow: 0 6px 20px rgba(22,23,16,.04); }}
      .section-title {{ margin: 0 0 .65rem; font-size: 1rem; font-weight: 700; letter-spacing: -0.015em; }}
      .hint {{ color: var(--muted); font-size: .9rem; margin-top: .2rem; line-height: 1.45; }}
      .count {{ float: right; color: var(--muted); font-family: 'IBM Plex Mono', monospace; font-size: .88rem; }}
      .mono {{ font-family: 'IBM Plex Mono', monospace; font-size: .85rem; }}

      /* Lists */
      ul {{ margin: 0; padding-left: 1.1rem; }}
      li {{ margin: .5rem 0; line-height: 1.4; }}

      /* State panel */
      .state-grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 1.25rem; margin-bottom: 1.25rem; }}
      .analytics-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 1.25rem; }}

      /* Decision card — the release decision hero */
      .decision-panel {{ margin-bottom: 1.5rem; }}
      .decision-card {{ padding: 0; }}
      .decision-verdict-row {{
        display: flex; align-items: center; gap: .75rem; flex-wrap: wrap;
        padding-bottom: .85rem; margin-bottom: .85rem;
        border-bottom: 1px solid var(--line);
      }}
      .verdict-badge {{
        display: inline-flex; align-items: center; justify-content: center;
        font-family: 'IBM Plex Mono', monospace; font-weight: 700;
        font-size: 1rem; letter-spacing: .04em; padding: .35rem .9rem;
        border-radius: 8px; white-space: nowrap;
      }}
      .verdict-go    {{ background: #d4f0de; color: #0f5c28; border: 1.5px solid #a3d9b5; }}
      .verdict-nogo  {{ background: #fde4e1; color: #8b1a12; border: 1.5px solid #f5b3ac; }}
      .verdict-conditional {{ background: #fef3cd; color: #7a5200; border: 1.5px solid #f0d080; }}
      .verdict-unknown {{ background: var(--line); color: var(--muted); border: 1.5px solid var(--line); }}
      .verdict-meta {{ font-family: 'IBM Plex Mono', monospace; font-size: .82rem; color: var(--muted); }}
      .verdict-gate {{ margin-left: auto; font-family: 'IBM Plex Mono', monospace; font-size: .78rem; color: var(--muted); background: var(--bg); padding: .2rem .55rem; border-radius: 99px; border: 1px solid var(--line); }}
      .decision-section {{ margin-bottom: .75rem; }}
      .decision-section:last-child {{ margin-bottom: 0; }}
      .decision-section-label {{
        font-size: .68rem; text-transform: uppercase; letter-spacing: .1em;
        font-family: 'IBM Plex Mono', monospace; color: var(--muted); font-weight: 600;
        margin-bottom: .3rem;
      }}
      .decision-list {{ margin: 0; padding-left: 1.1rem; }}
      .decision-list li {{ font-size: .9rem; margin: .25rem 0; color: var(--ink); }}
      .approval-list {{ list-style: none; padding-left: 0; display: flex; flex-wrap: wrap; gap: .4rem; }}
      .approval-tag {{
        display: inline-block; font-size: .8rem; font-family: 'IBM Plex Mono', monospace;
        background: #fff3e0; color: #7a4000; border: 1px solid #f0c070;
        padding: .15rem .55rem; border-radius: 6px;
      }}

      /* Verdict badges in tables and lists */
      .vbadge {{ display: inline-block; font-family: 'IBM Plex Mono', monospace; font-weight: 600; font-size: .78rem; padding: .15rem .5rem; border-radius: 5px; white-space: nowrap; }}
      .vbadge-go {{ background:#d4f0de; color:#0f5c28; }}
      .vbadge-nogo {{ background:#fde4e1; color:#8b1a12; }}
      .vbadge-conditional {{ background:#fef3cd; color:#7a5200; }}
      .vbadge-unknown {{ background:var(--line); color:var(--muted); }}

      a {{ color: var(--accent); text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}

      @media (max-width: 900px) {{
        .state-grid, .analytics-grid {{ grid-template-columns: 1fr; }}
        .verdict-gate {{ margin-left: 0; }}
      }}
    </style>
  </head>
  <body>
    <nav class="topnav" aria-label="Site navigation">
      <div class="topnav-inner">
        <span class="brand-logo" aria-hidden="true">V</span>
        <span class="brand-name">{_html_escape(service_name)}</span>
        <span class="topnav-right">Tenant&nbsp;{_html_escape(str(tenant.get('tenant_id', '')) or 'all')}&nbsp;&middot;&nbsp;{_html_escape(principal)}</span>
      </div>
    </nav>
    <div class="shell">
      <nav class="breadcrumb">
        <a href="/api/{_html_escape(api_version)}/app?tenant={tenant_value}">{_html_escape(service_name)}</a>
        <span class="sep">&rsaquo;</span>
        <span>{kind.title()}s</span>
        <span class="sep">&rsaquo;</span>
        <span>{_html_escape(focus_title)}</span>
      </nav>

      <header class="page-header">
        <div class="page-kicker">Dedicated {kind} page for operator review and historical analysis.</div>
        <div class="page-title">{_html_escape(focus_title)}</div>
        <div class="page-sub">Tenant {_html_escape(str(tenant.get('tenant_id', '')) or 'all')} &middot; {_html_escape(principal)}</div>
      </header>

      <div class="decision-panel card">
        <div style="display:flex; align-items:baseline; gap:.75rem; margin-bottom:.85rem; flex-wrap:wrap;">
          <h2 class="section-title" style="margin:0;">Release Decision</h2>
          <span style="font-size:.8rem; color:var(--muted); font-family:'IBM Plex Mono',monospace;">{_html_escape(str(focus_latest_event.get('generated_at', '')) if isinstance(focus_latest_event, dict) else '')}</span>
        </div>
        {focus_decision_guidance}
      </div>

      <div class="state-grid">
        <div class="card">
          <h2 class="section-title">Current State</h2>
          {focus_meta}
        </div>
        <div class="card">
          <h2 class="section-title">Recent Decisions &amp; Navigation</h2>
          <ul style="margin-bottom:.75rem;">{recent_event_items}</ul>
          <div style="border-top:1px solid var(--line); padding-top:.65rem; margin-top:.5rem;">
            <ul>
              <li><a href="/api/{_html_escape(api_version)}/app?tenant={tenant_value}">&larr; Back to dashboard</a></li>
              <li><a href="/api/{_html_escape(api_version)}/app/repository?tenant={tenant_value}&repository={quote(selected_repository)}">Repository focus page</a></li>
              <li><a href="/api/{_html_escape(api_version)}/app/service?tenant={tenant_value}&service={quote(selected_service)}">Service focus page</a></li>
            </ul>
          </div>
        </div>
      </div>

      <div class="analytics-grid">
        {_focus_analytics(repository_analytics if kind == 'repository' else service_analytics)}
      </div>
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
