"""Generic webhook emitter for Veridion decision contracts."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class EventDeliveryResult:
    status: str
    event_type: str
    destination: str


class EventEmitterError(RuntimeError):
    """Raised when webhook emission fails."""

    pass


def emit_decision_event(
    *,
    webhook_url: str,
    event_type: str,
    decision_contract: dict[str, object],
    repository: str = "",
    pull_request_number: int | None = None,
    token: str = "",
) -> EventDeliveryResult:
    """POST the decision contract to an external webhook endpoint."""

    validated_webhook_url = _validate_webhook_url(webhook_url)
    envelope = {
        "event_type": event_type,
        "repository": repository,
        "pull_request_number": pull_request_number,
        "decision_contract": decision_contract,
    }
    _post_json(url=validated_webhook_url, payload=envelope, token=token)
    return EventDeliveryResult(status="delivered", event_type=event_type, destination=validated_webhook_url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit Veridion decision contract to an external webhook")
    parser.add_argument("--webhook-url", required=True, help="Destination webhook URL")
    parser.add_argument("--decision-contract-path", required=True, help="Path to veridion-decision.json")
    parser.add_argument("--event-type", default="veridion.rdi.decision.v1", help="Logical event type")
    parser.add_argument("--repository", default="", help="Optional owner/repo for event context")
    parser.add_argument("--pull-request-number", type=int, help="Optional pull request number")
    parser.add_argument("--token", default="", help="Optional bearer token")
    args = parser.parse_args(argv)

    contract = json.loads(Path(args.decision_contract_path).read_text())
    result = emit_decision_event(
        webhook_url=args.webhook_url,
        event_type=args.event_type,
        decision_contract=contract,
        repository=args.repository,
        pull_request_number=args.pull_request_number,
        token=args.token,
    )
    _write_github_outputs(result)
    print(json.dumps({"status": result.status, "event_type": result.event_type, "destination": result.destination}))
    return 0


def _post_json(*, url: str, payload: dict[str, object], token: str) -> Any:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "veridion-rdi",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    # URL is validated by _validate_webhook_url() before reaching this sink.
    req = request.Request(  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(req) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            body = response.read().decode("utf-8")
        return json.loads(body) if body else {}
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8") if exc.fp else ""
        raise EventEmitterError(f"webhook POST {url} failed with HTTP {exc.code}: {payload or exc.reason}") from exc
    except error.URLError as exc:
        raise EventEmitterError(f"webhook POST {url} failed: {exc.reason}") from exc


def _validate_webhook_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme != "https":
        raise ValueError("webhook-url must use https")
    if not parsed.netloc:
        raise ValueError("webhook-url must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("webhook-url must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("webhook-url must not include a fragment")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _write_github_outputs(result: EventDeliveryResult) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        return

    with Path(github_output).open("a", encoding="utf-8") as handle:
        handle.write(f"webhook_delivery_status={result.status}\n")
        handle.write(f"webhook_event_type={result.event_type}\n")


if __name__ == "__main__":
    raise SystemExit(main())
