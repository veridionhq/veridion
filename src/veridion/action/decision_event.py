"""Build and persist machine-readable Veridion decision events."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


SUPPORTED_DECISION_EVENT_SCHEMA_VERSION = 1


def build_decision_event(
    decision_contract: dict[str, object],
    *,
    repository: str = "",
    pull_request_number: int | None = None,
) -> dict[str, object]:
    """Build a durable decision event from the machine-facing decision contract."""

    decision = _as_object(decision_contract.get("decision"))
    actions = _as_object(decision_contract.get("actions"))
    reasons = _as_object(decision_contract.get("reasons"))
    accepted_risk = _as_object(decision_contract.get("accepted_risk"))
    automation = _as_object(decision_contract.get("automation"))
    policy = _as_object(decision_contract.get("policy"))
    signals = _as_object(decision_contract.get("signals"))
    history = _as_object(signals.get("history"))
    runtime = _as_object(signals.get("runtime"))
    ownership = _as_object(signals.get("ownership"))

    return {
        "schema_version": SUPPORTED_DECISION_EVENT_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "source": "veridion/action",
        "event_version_source": "veridion.action.decision_event@1",
        "repository": repository,
        "pull_request_number": pull_request_number,
        "decision": {
            "verdict": decision.get("verdict", ""),
            "score": decision.get("score"),
            "confidence": decision.get("confidence", ""),
            "gate_status": decision.get("gate_status", ""),
            "decision_allowed": decision.get("decision_allowed"),
            "blocking_categories": list(_as_list(decision.get("blocking_categories"))),
        },
        "actions": {
            "required_approvals": list(_as_list(actions.get("required_approvals"))),
            "required_next_steps": list(_as_list(actions.get("required_next_steps"))),
        },
        "reasons": {
            "blocking": list(_as_list(reasons.get("blocking"))),
        },
        "accepted_risk": {
            "present": bool(accepted_risk.get("present")),
            "pending_review": _as_int(accepted_risk.get("pending_review")),
            "renewal_pending": _as_int(accepted_risk.get("renewal_pending")),
            "expiring_soon": _as_int(accepted_risk.get("expiring_soon")),
        },
        "policy": {
            "pack_id": policy.get("pack_id", ""),
            "pack_name": policy.get("pack_name", ""),
            "pack_version": policy.get("pack_version", ""),
            "pack_owner": policy.get("pack_owner", ""),
            "rollout_stage": policy.get("rollout_stage", ""),
        },
        "automation": {
            "approval_satisfaction_status": automation.get("approval_satisfaction_status", ""),
            "approvals_satisfied": automation.get("approvals_satisfied"),
            "satisfied_approvals": list(_as_list(automation.get("satisfied_approvals"))),
            "unsatisfied_approvals": list(_as_list(automation.get("unsatisfied_approvals"))),
            "approval_gate_status": automation.get("approval_gate_status", ""),
            "approval_gate_allowed": automation.get("approval_gate_allowed"),
        },
        "trust_context": {
            "repo_criticality": history.get("repo_criticality", ""),
            "service_criticality": history.get("service_criticality", ""),
            "environment": runtime.get("environment", ""),
            "public_exposure": bool(runtime.get("public_exposure")),
            "blast_radius": runtime.get("blast_radius", ""),
            "service_owner": ownership.get("service_owner", ""),
            "owning_team": ownership.get("owning_team", ""),
        },
    }


def append_decision_history(path: str | Path, event: dict[str, object]) -> None:
    """Append a decision event as newline-delimited JSON."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a Veridion decision event from veridion-decision.json")
    parser.add_argument("--decision-contract-path", required=True, help="Path to veridion-decision.json")
    parser.add_argument("--decision-event-path", required=True, help="Path to write veridion-decision-event.json")
    parser.add_argument("--decision-history-path", help="Optional NDJSON history log path")
    parser.add_argument("--repository", default="", help="Optional owner/repo identity")
    parser.add_argument("--pull-request-number", type=int, help="Optional pull request number")
    args = parser.parse_args(argv)

    contract = json.loads(Path(args.decision_contract_path).read_text())
    event = build_decision_event(
        contract,
        repository=args.repository,
        pull_request_number=args.pull_request_number,
    )
    Path(args.decision_event_path).write_text(json.dumps(event, indent=2) + "\n")
    if args.decision_history_path:
        append_decision_history(args.decision_history_path, event)
    _write_github_outputs(args.decision_event_path, args.decision_history_path)
    return 0


def _write_github_outputs(decision_event_path: str, decision_history_path: str | None) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        return
    lines = [
        f"decision_event_path={decision_event_path}",
        f"decision_history_path={decision_history_path or ''}",
    ]
    with Path(github_output).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def _as_object(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _as_int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
