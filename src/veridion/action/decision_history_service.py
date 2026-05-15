"""Serve file-backed Veridion decision-history analytics over HTTP."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from veridion.action.decision_history import analyze_history


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve Veridion decision-history analytics over HTTP")
    parser.add_argument(
        "--history-path",
        action="append",
        required=True,
        help="Path to decision-history NDJSON, decision-event JSON, or exported event directory",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8787, help="Bind port")
    args = parser.parse_args(argv)

    serve_decision_history(history_paths=tuple(args.history_path), host=args.host, port=args.port)
    return 0


def serve_decision_history(*, history_paths: tuple[str, ...], host: str, port: int) -> None:
    handler = _build_handler(history_paths)
    with ThreadingHTTPServer((host, port), handler) as server:
        server.serve_forever()


def _build_handler(history_paths: tuple[str, ...]):
    class DecisionHistoryHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler interface
            status, payload = resolve_history_request(self.path, history_paths=history_paths)
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


def resolve_history_request(path: str, *, history_paths: tuple[str, ...]) -> tuple[int, dict[str, object]]:
    parsed = urlparse(path)
    if parsed.path == "/healthz":
        return (200, {"status": "ok"})
    if parsed.path == "/analytics":
        params = _query_params(parsed.query)
        payload = analyze_history(
            history_paths=history_paths,
            repository=params.get("repository"),
            policy_pack_id=params.get("policy_pack_id"),
            since=params.get("since"),
            until=params.get("until"),
        )
        return (200, payload)
    if parsed.path == "/repositories":
        payload = analyze_history(history_paths=history_paths)
        repositories = [item["repository"] for item in payload["policy_rollout"]["latest_by_repository"]]
        return (200, {"repositories": repositories})
    if parsed.path == "/policy-rollouts":
        payload = analyze_history(history_paths=history_paths)
        return (200, payload["policy_rollout"])
    return (404, {"error": "not_found"})


def _query_params(raw: str) -> dict[str, str]:
    parsed = parse_qs(raw)
    return {key: values[0] for key, values in parsed.items() if values}


if __name__ == "__main__":
    raise SystemExit(main())
