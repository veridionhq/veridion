"""Serve file-backed Veridion decision-history analytics over HTTP."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from veridion.action.decision_history_config import HistoryTenant, load_history_service_config, tenant_map
from veridion.action.decision_history import analyze_history


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
        auth_tokens=_merge_auth_tokens(config.auth_tokens if config else (), auth_token),
    )
    with ThreadingHTTPServer((host, port), handler) as server:
        server.serve_forever()


def _build_handler(
    history_paths: tuple[str, ...],
    *,
    tenants: dict[str, HistoryTenant],
    auth_tokens: tuple[str, ...],
):
    class DecisionHistoryHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler interface
            status, payload = resolve_history_request(
                self.path,
                history_paths=history_paths,
                tenants=tenants,
                headers=dict(self.headers.items()),
                auth_tokens=auth_tokens,
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

    return DecisionHistoryHandler


def resolve_history_request(
    path: str,
    *,
    history_paths: tuple[str, ...],
    tenants: dict[str, HistoryTenant] | None = None,
    headers: dict[str, str] | None = None,
    auth_tokens: tuple[str, ...] = (),
) -> tuple[int, dict[str, object]]:
    parsed = urlparse(path)
    if parsed.path == "/healthz":
        return (200, {"status": "ok"})
    if auth_tokens and not _authorized(headers or {}, auth_tokens):
        return (401, {"error": "unauthorized"})
    tenant_lookup = tenants or {}
    if parsed.path == "/tenants":
        return (200, {"tenants": sorted(tenant_lookup)})
    if parsed.path == "/analytics":
        params = _query_params(parsed.query)
        selected_paths = _select_history_paths(
            history_paths=history_paths,
            tenants=tenant_lookup,
            tenant_id=params.get("tenant", ""),
        )
        if selected_paths is None:
            return (404, {"error": "tenant_not_found"})
        payload = analyze_history(
            history_paths=selected_paths,
            repository=params.get("repository"),
            policy_pack_id=params.get("policy_pack_id"),
            since=params.get("since"),
            until=params.get("until"),
        )
        return (200, payload)
    if parsed.path == "/repositories":
        params = _query_params(parsed.query)
        selected_paths = _select_history_paths(
            history_paths=history_paths,
            tenants=tenant_lookup,
            tenant_id=params.get("tenant", ""),
        )
        if selected_paths is None:
            return (404, {"error": "tenant_not_found"})
        payload = analyze_history(history_paths=selected_paths)
        repositories = [item["repository"] for item in payload["policy_rollout"]["latest_by_repository"]]
        return (200, {"repositories": repositories})
    if parsed.path == "/policy-rollouts":
        params = _query_params(parsed.query)
        selected_paths = _select_history_paths(
            history_paths=history_paths,
            tenants=tenant_lookup,
            tenant_id=params.get("tenant", ""),
        )
        if selected_paths is None:
            return (404, {"error": "tenant_not_found"})
        payload = analyze_history(history_paths=selected_paths)
        return (200, payload["policy_rollout"])
    return (404, {"error": "not_found"})


def _query_params(raw: str) -> dict[str, str]:
    parsed = parse_qs(raw)
    return {key: values[0] for key, values in parsed.items() if values}


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


def _authorized(headers: dict[str, str], auth_tokens: tuple[str, ...]) -> bool:
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    token = auth_header[len("Bearer ") :].strip()
    return token in auth_tokens


def _merge_auth_tokens(config_tokens: tuple[str, ...], cli_token: str) -> tuple[str, ...]:
    merged = list(config_tokens)
    if cli_token:
        merged.append(cli_token)
    return tuple(dict.fromkeys(merged))


if __name__ == "__main__":
    raise SystemExit(main())
