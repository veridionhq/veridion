"""Fetch live runtime payloads from provider APIs and normalize them for Veridion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from veridion.action.runtime_context_builder import build_runtime_context


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch live provider payloads and build normalized runtime context")
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--incident-provider", default="generic")
    parser.add_argument("--incident-base-url", default="")
    parser.add_argument("--incident-token", default="")
    parser.add_argument("--alerts-provider", default="generic")
    parser.add_argument("--alerts-base-url", default="")
    parser.add_argument("--alerts-token", default="")
    parser.add_argument("--cloudwatch-region", default="")
    parser.add_argument("--canary-provider", default="generic")
    parser.add_argument("--canary-base-url", default="")
    parser.add_argument("--canary-token", default="")
    parser.add_argument("--environment", default="")
    parser.add_argument("--deployment-window", default="")
    parser.add_argument("--public-exposure", default="")
    parser.add_argument("--blast-radius", default="")
    parser.add_argument("--rollout-strategy", default="")
    args = parser.parse_args(argv)

    payload = fetch_and_build_runtime_context(
        incident_provider=args.incident_provider,
        incident_base_url=args.incident_base_url,
        incident_token=args.incident_token,
        alerts_provider=args.alerts_provider,
        alerts_base_url=args.alerts_base_url,
        alerts_token=args.alerts_token,
        cloudwatch_region=args.cloudwatch_region,
        canary_provider=args.canary_provider,
        canary_base_url=args.canary_base_url,
        canary_token=args.canary_token,
        environment=args.environment,
        deployment_window=args.deployment_window,
        public_exposure=args.public_exposure,
        blast_radius=args.blast_radius,
        rollout_strategy=args.rollout_strategy,
    )
    Path(args.output_path).write_text(json.dumps(payload, indent=2) + "\n")
    return 0


def fetch_and_build_runtime_context(
    *,
    incident_provider: str,
    incident_base_url: str,
    incident_token: str,
    alerts_provider: str,
    alerts_base_url: str,
    alerts_token: str,
    cloudwatch_region: str,
    canary_provider: str,
    canary_base_url: str,
    canary_token: str,
    environment: str,
    deployment_window: str,
    public_exposure: str,
    blast_radius: str,
    rollout_strategy: str,
) -> dict[str, object]:
    incident_payload = fetch_incident_payload(provider=incident_provider, base_url=incident_base_url, token=incident_token)
    alerts_payload = fetch_alerts_payload(
        provider=alerts_provider,
        base_url=alerts_base_url,
        token=alerts_token,
        cloudwatch_region=cloudwatch_region,
    )
    canary_payload = fetch_canary_payload(provider=canary_provider, base_url=canary_base_url, token=canary_token)
    rollback_payload = fetch_rollback_payload(provider=canary_provider, base_url=canary_base_url, token=canary_token)
    runtime = build_runtime_context(
        incident_payload=incident_payload,
        incident_provider=incident_provider,
        freeze_payload={},
        freeze_provider="generic",
        alerts_payload=alerts_payload,
        alerts_provider=alerts_provider,
        canary_payload=canary_payload,
        canary_provider=canary_provider,
        rollback_payload=rollback_payload,
        rollback_provider=canary_provider,
        environment=environment,
        deployment_window=deployment_window,
        public_exposure=_parse_bool_flag(public_exposure),
        blast_radius=blast_radius,
        rollout_strategy=rollout_strategy,
    )
    return {
        "schema_version": 1,
        "source": "veridion.action.runtime_live_fetch@1",
        "runtime": runtime,
        "raw": {
            "incident": incident_payload,
            "alerts": alerts_payload,
            "canary": canary_payload,
            "rollback": rollback_payload,
        },
    }


def fetch_incident_payload(*, provider: str, base_url: str, token: str) -> dict[str, object]:
    if provider == "pagerduty":
        return _fetch_json(
            f"{_strip_slash(base_url)}/incidents?statuses[]=triggered&statuses[]=acknowledged",
            token=token,
        )
    if provider == "incident-io":
        return _fetch_json(f"{_strip_slash(base_url)}/v2/incidents", token=token)
    return {}


def fetch_alerts_payload(
    *,
    provider: str,
    base_url: str,
    token: str,
    cloudwatch_region: str,
) -> dict[str, object]:
    if provider == "statuspage":
        return _fetch_json(f"{_strip_slash(base_url)}/api/v2/incidents/unresolved.json", token=token)
    if provider == "cloudwatch":
        try:
            import boto3  # type: ignore
        except Exception as exc:  # pragma: no cover - import guard
            raise RuntimeError("cloudwatch live fetch requires boto3") from exc
        client = boto3.client("cloudwatch", region_name=cloudwatch_region or None)
        return client.describe_alarms()
    return {}


def fetch_canary_payload(*, provider: str, base_url: str, token: str) -> dict[str, object]:
    if provider == "spinnaker":
        return _fetch_json(f"{_strip_slash(base_url)}/pipelines", token=token)
    if provider == "harness":
        return _fetch_json(f"{_strip_slash(base_url)}/pipeline/api/executions", token=token)
    return {}


def fetch_rollback_payload(*, provider: str, base_url: str, token: str) -> dict[str, object]:
    if provider == "spinnaker":
        return _fetch_json(f"{_strip_slash(base_url)}/pipelines", token=token)
    if provider == "harness":
        return _fetch_json(f"{_strip_slash(base_url)}/pipeline/api/rollback", token=token)
    return {}


def _fetch_json(url: str, *, token: str) -> dict[str, object]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(url=url, headers=headers, method="GET")  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    try:
        with request.urlopen(req, timeout=30) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:  # pragma: no cover - network/HTTP
        raise RuntimeError(f"runtime provider fetch {url} failed: HTTP {exc.code}") from exc
    except error.URLError as exc:  # pragma: no cover - network/HTTP
        raise RuntimeError(f"runtime provider fetch {url} failed: {exc.reason}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"runtime provider payload from {url} must be a JSON object")
    return payload


def _strip_slash(value: str) -> str:
    return value.rstrip("/")


def _parse_bool_flag(value: str) -> bool | None:
    if not value:
        return None
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


if __name__ == "__main__":
    raise SystemExit(main())
