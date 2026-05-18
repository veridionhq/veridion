"""Analyze Veridion decision-event history for rollout and trust trends."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze Veridion decision history from NDJSON or exported event objects")
    parser.add_argument(
        "--history-path",
        action="append",
        required=True,
        help="Path to decision-history NDJSON, decision-event JSON, or a directory of exported events",
    )
    parser.add_argument("--repository", help="Optional repository filter in owner/repo format")
    parser.add_argument("--policy-pack-id", help="Optional policy pack id filter")
    parser.add_argument("--since", help="Optional inclusive ISO-8601 lower bound for generated_at")
    parser.add_argument("--until", help="Optional inclusive ISO-8601 upper bound for generated_at")
    parser.add_argument("--output-path", help="Optional path to write analytics JSON")
    args = parser.parse_args(argv)

    since = _parse_timestamp_bound(args.since, label="since")
    until = _parse_timestamp_bound(args.until, label="until")
    payload = analyze_history(
        history_paths=tuple(args.history_path),
        repository=args.repository,
        policy_pack_id=args.policy_pack_id,
        since=args.since,
        until=args.until,
    )
    rendered = json.dumps(payload, indent=2) + "\n"
    if args.output_path:
        Path(args.output_path).write_text(rendered)
    print(rendered, end="")
    return 0


def analyze_history(
    *,
    history_paths: tuple[str, ...],
    repository: str | None = None,
    policy_pack_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, object]:
    since_bound = _parse_timestamp_bound(since, label="since")
    until_bound = _parse_timestamp_bound(until, label="until")
    events = tuple(
        _filter_event(
            event,
            repository=repository,
            policy_pack_id=policy_pack_id,
            since=since_bound,
            until=until_bound,
        )
        for event in _load_history(history_paths)
    )
    filtered = tuple(item for item in events if item is not None)
    return analyze_history_events(filtered)


def analyze_history_events(events: tuple[dict[str, object], ...]) -> dict[str, object]:
    filtered = tuple(item for item in events if item is not None)
    return {
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
        "time_series": {
            "by_day": _events_by_day(filtered),
        },
        "policy_rollout": {
            "version_adoption": _version_adoption(filtered),
            "latest_by_repository": _latest_by_repository(filtered),
            "transitions": _policy_transitions(filtered),
        },
    }


def _load_history(paths: tuple[str, ...]) -> tuple[dict[str, object], ...]:
    events: list[dict[str, object]] = []
    for path in paths:
        events.extend(_load_history_path(Path(path)))
    return tuple(events)


def _load_history_path(path: Path) -> list[dict[str, object]]:
    if path.is_dir():
        events: list[dict[str, object]] = []
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.suffix.lower() in {".json", ".ndjson"}:
                events.extend(_load_history_path(child))
        return events
    if path.suffix.lower() == ".ndjson":
        return _load_ndjson(path)
    return _load_json_events(path)


def _load_ndjson(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        if not raw.strip():
            continue
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise RuntimeError(f"decision history line {lineno} in {path} is not a JSON object")
        events.append(payload)
    return events


def _load_json_events(path: Path) -> list[dict[str, object]]:
    payload = json.loads(path.read_text())
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        objects = [item for item in payload if isinstance(item, dict)]
        if len(objects) != len(payload):
            raise RuntimeError(f"decision history JSON array in {path} must contain only objects")
        return objects
    raise RuntimeError(f"decision history file {path} must contain an object, array of objects, or NDJSON")


def _filter_event(
    event: dict[str, object],
    *,
    repository: str | None,
    policy_pack_id: str | None,
    since: datetime | None,
    until: datetime | None,
) -> dict[str, object] | None:
    if repository and event.get("repository") != repository:
        return None
    policy = event.get("policy")
    if policy_pack_id:
        if not isinstance(policy, dict) or policy.get("pack_id") != policy_pack_id:
            return None
    generated_at = _generated_at(event)
    if since and (generated_at is None or generated_at < since):
        return None
    if until and (generated_at is None or generated_at > until):
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
        "window": {
            "first_generated_at": _render_timestamp(min(filter(None, (_generated_at(item) for item in events)), default=None)),
            "last_generated_at": _render_timestamp(max(filter(None, (_generated_at(item) for item in events)), default=None)),
        },
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


def _events_by_day(events: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    counts: Counter[str] = Counter()
    for item in events:
        generated_at = _generated_at(item)
        if generated_at is not None:
            counts.update([generated_at.date().isoformat()])
    return [{"day": day, "events": count} for day, count in sorted(counts.items())]


def _version_adoption(events: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for event in events:
        key = (
            _policy_value(event, "pack_id"),
            _policy_value(event, "pack_version"),
            _policy_value(event, "rollout_stage"),
        )
        if key[0]:
            grouped.setdefault(key, []).append(event)

    rows: list[dict[str, object]] = []
    for (pack_id, pack_version, rollout_stage), items in sorted(grouped.items()):
        repos = sorted({str(item.get("repository", "")) for item in items if item.get("repository", "")})
        rows.append(
            {
                "pack_id": pack_id,
                "pack_version": pack_version,
                "rollout_stage": rollout_stage,
                "events": len(items),
                "repositories": repos,
                "repository_count": len(repos),
                "first_generated_at": _render_timestamp(min(filter(None, (_generated_at(item) for item in items)), default=None)),
                "last_generated_at": _render_timestamp(max(filter(None, (_generated_at(item) for item in items)), default=None)),
            }
        )
    return rows


def _latest_by_repository(events: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    latest: dict[str, dict[str, object]] = {}
    for event in events:
        repository = event.get("repository")
        if not isinstance(repository, str) or not repository:
            continue
        current = latest.get(repository)
        if current is None or _sort_key(event) > _sort_key(current):
            latest[repository] = event

    rows: list[dict[str, object]] = []
    for repository, event in sorted(latest.items()):
        rows.append(
            {
                "repository": repository,
                "generated_at": event.get("generated_at", ""),
                "pack_id": _policy_value(event, "pack_id"),
                "pack_version": _policy_value(event, "pack_version"),
                "rollout_stage": _policy_value(event, "rollout_stage"),
                "verdict": _decision_value(event, "verdict"),
                "gate_status": _decision_value(event, "gate_status"),
            }
        )
    return rows


def _policy_transitions(events: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    counts: Counter[tuple[str, str, str]] = Counter()
    grouped: dict[str, list[dict[str, object]]] = {}
    for event in events:
        repository = event.get("repository")
        if isinstance(repository, str) and repository:
            grouped.setdefault(repository, []).append(event)

    for items in grouped.values():
        previous: tuple[str, str, str] | None = None
        for event in sorted(items, key=_sort_key):
            current = (
                _policy_value(event, "pack_id"),
                _policy_value(event, "pack_version"),
                _policy_value(event, "rollout_stage"),
            )
            if not current[0]:
                continue
            if previous is not None and current != previous:
                counts[(f"{previous[0]}@{previous[1]}:{previous[2]}", f"{current[0]}@{current[1]}:{current[2]}", current[0])] += 1
            previous = current

    return [
        {"from": old, "to": new, "pack_id": pack_id, "repositories": count}
        for (old, new, pack_id), count in counts.most_common()
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


def _generated_at(event: dict[str, object]) -> datetime | None:
    raw = event.get("generated_at")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _render_timestamp(value: datetime | None) -> str:
    return value.isoformat().replace("+00:00", "Z") if value is not None else ""


def _parse_timestamp_bound(value: str | None, *, label: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"{label} must be a valid ISO-8601 timestamp") from exc


def _sort_key(event: dict[str, object]) -> tuple[datetime, str]:
    generated_at = _generated_at(event)
    fallback = datetime.min.replace(tzinfo=None)
    if generated_at is None:
        return (fallback, json.dumps(event, sort_keys=True))
    return (generated_at.replace(tzinfo=None), json.dumps(event, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
