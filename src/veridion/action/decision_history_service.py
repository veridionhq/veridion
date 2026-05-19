"""Serve file-backed Veridion decision-history analytics over HTTP."""

from __future__ import annotations

import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

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
from veridion.action.decision_history_store import analyze_history_store, get_history_store_status, list_materialization_runs
from veridion.action.history_identity import resolve_bearer_identity, resolve_trusted_header_identity

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
    jwt_config: JWTAuthConfig = JWTAuthConfig(),
    trusted_header_auth: TrustedHeaderAuthConfig = TrustedHeaderAuthConfig(),
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
        jwt_config=jwt_config,
        trusted_header_auth=trusted_header_auth,
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
        payload = _analyze_request(
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
            since=params.get("since"),
            until=params.get("until"),
        )
        if payload is None:
            return _respond(404, {"error": "tenant_not_found"}, route=route, api_version=api_version, identity=identity)
        return _respond(
            200,
            {
                "html": render_dashboard_html(
                    payload,
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
    if route == "/dashboard" and "html" in payload:
        return (status, payload)
    return (
        status,
        {
            "api_version": api_version,
            "route": route,
            "identity": _identity_payload(identity),
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
        if tenant_id and tenant_id not in tenants:
            return None
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
    tenant_id: str,
    path: str,
    method: str,
) -> tuple[tuple[int, dict[str, object]] | None, HistoryToken | None]:
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
    header_identity = resolve_trusted_header_identity(headers=headers, config=trusted_header_auth)
    if not auth_tokens and not scoped_tokens and not jwt_config.shared_secret and header_identity is None:
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
            return ((401, {"error": "unauthorized"}), None)
    if scoped.status and scoped.status != "active":
        return ((403, {"error": "identity_inactive"}), scoped)
    if method != "GET" and not _has_role(scoped, "materializer", "admin"):
        return ((403, {"error": "insufficient_role"}), scoped)
    if path in {"/analytics", "/repositories", "/policy-rollouts", "/dashboard", "/materializations", "/materialization-schedules", "/service/status"} and not _has_role(
        scoped, "reader", "materializer", "admin"
    ):
        return ((403, {"error": "insufficient_role"}), scoped)
    if not tenant_id and scoped.tenants and path not in {"/tenants", "/materialization-schedules"} and method == "GET":
        return ((403, {"error": "tenant_scope_required"}), scoped)
    if tenant_id and scoped.tenants and tenant_id not in scoped.tenants:
        return ((403, {"error": "forbidden"}), scoped)
    return (None, scoped)


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
) -> tuple[int, dict[str, object]]:
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
    if not token.roles:
        return True
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
    summary = payload.get("summary", {})
    by_verdict = payload.get("by_verdict", {})
    policy_rollout = payload.get("policy_rollout", {})
    blocking_categories = payload.get("top_blocking_categories", [])
    latest_repositories = policy_rollout.get("latest_by_repository", []) if isinstance(policy_rollout, dict) else []
    principal = identity.principal_name or identity.token_id if identity is not None else "anonymous"
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
      <div class="card" style="margin-top:1rem;">
        <h2 class="section-title">Policy Rollout JSON</h2>
        <pre>{_html_escape(json.dumps(policy_rollout, indent=2))}</pre>
      </div>
      <div class="footer">Versioned endpoints are available under /api/{_html_escape(api_version)}/analytics, /repositories, /policy-rollouts, /materializations, /service/status, and /tenants.</div>
    </div>
  </body>
</html>"""


def _html_escape(value: str) -> str:
    return html.escape(value, quote=True)


def _merge_auth_tokens(config_tokens: tuple[str, ...], cli_token: str) -> tuple[str, ...]:
    merged = list(config_tokens)
    if cli_token:
        merged.append(cli_token)
    return tuple(dict.fromkeys(merged))


if __name__ == "__main__":
    raise SystemExit(main())
