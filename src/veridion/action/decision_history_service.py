"""Serve file-backed Veridion decision-history analytics over HTTP."""

from __future__ import annotations

import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from veridion.action.decision_history_config import HistoryTenant, HistoryToken, load_history_service_config, tenant_map, token_map
from veridion.action.decision_history import analyze_history
from veridion.action.decision_history_materialize import materialize_decision_history
from veridion.action.decision_history_store import analyze_history_store, list_materialization_runs


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
        tenants=tenant_map(config) if config else {},
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
    tenants: dict[str, HistoryTenant],
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
                tenants=tenants,
                sqlite_path=sqlite_path,
                store_dsn=store_dsn,
                materialization_root=materialization_root,
                config_path=config_path,
                headers=dict(self.headers.items()),
                auth_tokens=auth_tokens,
                scoped_tokens=scoped_tokens,
            )
            parsed = urlparse(self.path)
            if parsed.path == "/dashboard" and "html" in payload:
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
                tenants=tenants,
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
    tenants: dict[str, HistoryTenant] | None = None,
    sqlite_path: str = "",
    store_dsn: str = "",
    materialization_root: str = "",
    config_path: str = "",
    headers: dict[str, str] | None = None,
    auth_tokens: tuple[str, ...] = (),
    scoped_tokens: dict[str, HistoryToken] | None = None,
) -> tuple[int, dict[str, object]]:
    parsed = urlparse(path)
    if parsed.path == "/healthz":
        return (200, {"status": "ok"})
    scoped_lookup = scoped_tokens or {}
    tenant_lookup = tenants or {}
    params = _query_params(parsed.query)
    authz, scoped_token = _authorize_request(
        headers=headers or {},
        auth_tokens=auth_tokens,
        scoped_tokens=scoped_lookup,
        tenant_id=params.get("tenant", ""),
        path=parsed.path,
        method=method,
    )
    if authz is not None:
        return authz
    if method == "POST":
        return _handle_post_request(
            parsed.path,
            body=body,
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            materialization_root=materialization_root,
            config_path=config_path,
            scoped_token=scoped_token,
        )
    if parsed.path == "/tenants":
        if scoped_token is not None and scoped_token.tenants:
            return (200, {"tenants": sorted(scoped_token.tenants)})
        return (200, {"tenants": sorted(tenant_lookup)})
    if parsed.path == "/analytics":
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
            return (404, {"error": "tenant_not_found"})
        return (200, payload)
    if parsed.path == "/repositories":
        payload = _analyze_request(
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
        )
        if payload is None:
            return (404, {"error": "tenant_not_found"})
        repositories = [item["repository"] for item in payload["policy_rollout"]["latest_by_repository"]]
        return (200, {"repositories": repositories})
    if parsed.path == "/policy-rollouts":
        payload = _analyze_request(
            history_paths=history_paths,
            tenants=tenant_lookup,
            sqlite_path=sqlite_path,
            store_dsn=store_dsn,
            tenant_id=params.get("tenant", ""),
        )
        if payload is None:
            return (404, {"error": "tenant_not_found"})
        return (200, payload["policy_rollout"])
    if parsed.path == "/dashboard":
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
            return (404, {"error": "tenant_not_found"})
        return (200, {"html": render_dashboard_html(payload, tenant_id=params.get("tenant", ""))})
    if parsed.path == "/materializations":
        if not materialization_root and not (sqlite_path or store_dsn):
            return (404, {"error": "materialization_not_configured"})
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
        return (200, {"materializations": list(runs)})
    return (404, {"error": "not_found"})


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
    tenant_id: str,
    path: str,
    method: str,
) -> tuple[tuple[int, dict[str, object]] | None, HistoryToken | None]:
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
    if not auth_tokens and not scoped_tokens:
        return (None, None)
    if not auth_header.startswith("Bearer "):
        return ((401, {"error": "unauthorized"}), None)
    token = auth_header[len("Bearer ") :].strip()
    if token in auth_tokens:
        return (None, None)
    scoped = scoped_tokens.get(token)
    if scoped is None:
        return ((401, {"error": "unauthorized"}), None)
    if method != "GET" and not _has_role(scoped, "materializer", "admin"):
        return ((403, {"error": "insufficient_role"}), scoped)
    if path in {"/analytics", "/repositories", "/policy-rollouts", "/dashboard", "/materializations"} and not _has_role(
        scoped, "reader", "materializer", "admin"
    ):
        return ((403, {"error": "insufficient_role"}), scoped)
    if not tenant_id and scoped.tenants and path != "/tenants" and method == "GET":
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


def render_dashboard_html(payload: dict[str, object], *, tenant_id: str) -> str:
    summary = payload.get("summary", {})
    by_verdict = payload.get("by_verdict", {})
    policy_rollout = payload.get("policy_rollout", {})
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Veridion History Dashboard</title>
    <style>
      body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 2rem; color: #10243e; }}
      .grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; }}
      .card {{ border: 1px solid #d7e0ea; border-radius: 12px; padding: 1rem; background: #f7fbff; }}
      h1 {{ margin-bottom: 0.25rem; }}
      pre {{ white-space: pre-wrap; word-break: break-word; }}
    </style>
  </head>
  <body>
    <h1>Veridion Decision History</h1>
    <p>Tenant: {_html_escape(tenant_id) or "all"}</p>
    <div class="grid">
      <div class="card"><strong>Events</strong><div>{summary.get("events", 0)}</div></div>
      <div class="card"><strong>Repositories</strong><div>{summary.get("repositories", 0)}</div></div>
      <div class="card"><strong>Policy Variants</strong><div>{summary.get("policy_pack_variants", 0)}</div></div>
    </div>
    <h2>Verdicts</h2>
    <pre>{_html_escape(json.dumps(by_verdict, indent=2))}</pre>
    <h2>Policy Rollout</h2>
    <pre>{_html_escape(json.dumps(policy_rollout, indent=2))}</pre>
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
