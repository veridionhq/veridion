"""Analyze Veridion decision-event history for rollout and trust trends."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze Veridion decision history NDJSON")
    parser.add_argument("--history-path", required=True, help="Path to decision-history NDJSON")
    parser.add_argument("--repository", help="Optional repository filter in owner/repo format")
    parser.add_argument("--policy-pack-id", help="Optional policy pack id filter")
    parser.add_argument("--output-path", help="Optional path to write analytics JSON")
    args = parser.parse_args(argv)

    events = tuple(
        _filter_event(
            event,
            repository=args.repository,
            policy_pack_id=args.policy_pack_id,
        )
        for event in _load_history(args.history_path)
    )
    filtered = tuple(item for item in events if item is not None)

    payload = {
        "schema_version": 1,
        "source": "veridion.action.decision_history@1",
        "summary": _build_summary(filtered),
        "by_verdict": _counter_dict(item["decision"]["verdict"] for item in filtered),
        "by_gate_status": _counter_dict(item["decision"]["gate_status"] for item in filtered),
        "by_approval_gate_status": _counter_dict(item["automation"].get("approval_gate_status", "") for item in filtered),
        "by_repository": _counter_dict(item.get("repository", "") for item in filtered),
        "by_policy_pack": _pack_breakdown(filtered),
        "top_blocking_categories": _counter_pairs(item["decision"].get("blocking_categories", []) for item in filtered),
        "approval_freshness": {
            "stale_approval_events": sum(1 for item in filtered if item["automation"].get("stale_approvals")),
            "approval_blocked_events": sum(
                1 for item in filtered if item["automation"].get("approval_gate_status") in {"blocked", "stale", "unmapped"}
            ),
        },
    }
    rendered = json.dumps(payload, indent=2) + "\n"
    if args.output_path:
        Path(args.output_path).write_text(rendered)
    print(rendered, end="")
    return 0


def _load_history(path: str) -> tuple[dict[str, object], ...]:
    events: list[dict[str, object]] = []
    for lineno, raw in enumerate(Path(path).read_text().splitlines(), start=1):
        if not raw.strip():
            continue
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise RuntimeError(f"decision history line {lineno} is not a JSON object")
        events.append(payload)
    return tuple(events)


def _filter_event(
    event: dict[str, object],
    *,
    repository: str | None,
    policy_pack_id: str | None,
) -> dict[str, object] | None:
    if repository and event.get("repository") != repository:
        return None
    policy = event.get("policy")
    if policy_pack_id:
        if not isinstance(policy, dict) or policy.get("pack_id") != policy_pack_id:
            return None
    return event


def _build_summary(events: tuple[dict[str, object], ...]) -> dict[str, object]:
    return {
        "events": len(events),
        "repositories": len({item.get("repository", "") for item in events if item.get("repository", "")}),
        "policy_pack_variants": len(
            {
                (
                    _policy_value(item, "pack_id"),
                    _policy_value(item, "pack_version"),
                    _policy_value(item, "rollout_stage"),
                )
                for item in events
                if _policy_value(item, "pack_id")
            }
        ),
        "blocked_events": sum(1 for item in events if _decision_value(item, "gate_status") == "block"),
        "review_events": sum(1 for item in events if _decision_value(item, "gate_status") == "review"),
        "approval_gate_blocked_events": sum(
            1 for item in events if _automation_value(item, "approval_gate_status") in {"blocked", "stale", "unmapped"}
        ),
    }


def _pack_breakdown(events: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for event in events:
        key = (
            _policy_value(event, "pack_id"),
            _policy_value(event, "pack_version"),
            _policy_value(event, "rollout_stage"),
        )
        grouped.setdefault(key, []).append(event)

    rows: list[dict[str, object]] = []
    for (pack_id, pack_version, rollout_stage), items in sorted(grouped.items()):
        if not pack_id:
            continue
        rows.append(
            {
                "pack_id": pack_id,
                "pack_version": pack_version,
                "rollout_stage": rollout_stage,
                "events": len(items),
                "verdicts": _counter_dict(_decision_value(item, "verdict") for item in items),
                "gate_statuses": _counter_dict(_decision_value(item, "gate_status") for item in items),
                "approval_gate_statuses": _counter_dict(_automation_value(item, "approval_gate_status") for item in items),
            }
        )
    return rows


def _counter_dict(values) -> dict[str, int]:
    filtered = [item for item in values if item]
    return dict(sorted(Counter(filtered).items()))


def _counter_pairs(nested_values) -> list[dict[str, object]]:
    counts: Counter[str] = Counter()
    for values in nested_values:
        if isinstance(values, list):
            counts.update(str(item) for item in values if item)
    return [
        {"name": name, "count": count}
        for name, count in counts.most_common()
    ]


def _decision_value(event: dict[str, object], key: str) -> str:
    decision = event.get("decision")
    return decision.get(key, "") if isinstance(decision, dict) and isinstance(decision.get(key, ""), str) else ""


def _automation_value(event: dict[str, object], key: str) -> str:
    automation = event.get("automation")
    return automation.get(key, "") if isinstance(automation, dict) and isinstance(automation.get(key, ""), str) else ""


def _policy_value(event: dict[str, object], key: str) -> str:
    policy = event.get("policy")
    return policy.get(key, "") if isinstance(policy, dict) and isinstance(policy.get(key, ""), str) else ""


if __name__ == "__main__":
    raise SystemExit(main())
