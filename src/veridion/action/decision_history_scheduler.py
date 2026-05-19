"""Run configured decision-history materialization schedules."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from veridion.action.decision_history_config import HistoryServiceConfig, MaterializationSchedule, load_history_service_config
from veridion.action.decision_history_materialize import materialize_decision_history


@dataclass(frozen=True)
class ScheduleRunResult:
    schedule_id: str
    tenant_ids: tuple[str, ...]
    run_id: str
    run_path: str
    status: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run due Veridion decision-history materialization schedules")
    parser.add_argument("--config-path", required=True)
    parser.add_argument("--output-root", help="Optional override for materialization root")
    parser.add_argument("--schedule-id", action="append", default=[])
    parser.add_argument("--at", help="Optional ISO-8601 UTC timestamp for due evaluation")
    parser.add_argument("--run-all", action="store_true", help="Run all enabled schedules regardless of due state")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output-path", help="Optional JSON output path")
    args = parser.parse_args(argv)

    config = load_history_service_config(args.config_path)
    at = _parse_at(args.at)
    payload = run_configured_history_schedules(
        config=config,
        config_path=args.config_path,
        output_root=args.output_root or config.materialization_root,
        at=at,
        schedule_ids=tuple(args.schedule_id),
        run_all=args.run_all,
        dry_run=args.dry_run,
    )
    rendered = json.dumps(payload, indent=2) + "\n"
    if args.output_path:
        Path(args.output_path).write_text(rendered)
    print(rendered, end="")
    return 0


def run_configured_history_schedules(
    *,
    config: HistoryServiceConfig,
    config_path: str,
    output_root: str,
    at: datetime,
    schedule_ids: tuple[str, ...] = (),
    run_all: bool = False,
    dry_run: bool = False,
) -> dict[str, object]:
    if not output_root:
        raise RuntimeError("output_root is required for schedule execution")
    selected = tuple(
        schedule
        for schedule in config.schedules
        if schedule.enabled and (not schedule_ids or schedule.schedule_id in schedule_ids)
    )
    due = tuple(schedule for schedule in selected if run_all or schedule_is_due(schedule.cron, at))
    runs: list[dict[str, object]] = []
    for schedule in due:
        tenant_ids = tuple(schedule.tenants) if schedule.tenants else tuple(tenant.tenant_id for tenant in config.tenants)
        run_id = f"{schedule.schedule_id}-{at.strftime('%Y%m%dT%H%M%SZ')}"
        if not dry_run:
            run_dir = materialize_decision_history(
                history_paths=(),
                config_path=config_path,
                output_root=output_root,
                run_id=run_id,
                athena_database=schedule.athena_database or None,
                athena_table=schedule.athena_table,
                athena_s3_location_template=schedule.athena_s3_location_template or None,
                tenant_ids=tenant_ids,
                schedule_id=schedule.schedule_id,
            )
            run_path = str(run_dir)
        else:
            run_path = ""
        runs.append(
            {
                "schedule_id": schedule.schedule_id,
                "tenant_ids": list(tenant_ids),
                "run_id": run_id,
                "run_path": run_path,
                "status": "planned" if dry_run else "completed",
            }
        )
    return {
        "schema_version": 1,
        "source": "veridion.action.decision_history_scheduler@1",
        "evaluated_at": at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "selected_schedules": [schedule.schedule_id for schedule in selected],
        "due_schedules": [schedule.schedule_id for schedule in due],
        "runs": runs,
    }


def schedule_is_due(cron: str, at: datetime) -> bool:
    fields = cron.strip().split()
    if len(fields) != 5:
        raise RuntimeError(f"unsupported cron expression: {cron!r}")
    minute, hour, day, month, weekday = fields
    weekday_value = (at.weekday() + 1) % 7
    return all(
        [
            _cron_field_matches(minute, at.minute),
            _cron_field_matches(hour, at.hour),
            _cron_field_matches(day, at.day),
            _cron_field_matches(month, at.month),
            _cron_field_matches(weekday, weekday_value),
        ]
    )


def _cron_field_matches(field: str, value: int) -> bool:
    if field == "*":
        return True
    for token in field.split(","):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            base, step_raw = token.split("/", 1)
            step = int(step_raw)
            if base == "*" and value % step == 0:
                return True
            if "-" in base:
                start_raw, end_raw = base.split("-", 1)
                start = int(start_raw)
                end = int(end_raw)
                if start <= value <= end and (value - start) % step == 0:
                    return True
            continue
        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            if int(start_raw) <= value <= int(end_raw):
                return True
            continue
        if int(token) == value:
            return True
    return False


def _parse_at(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


if __name__ == "__main__":
    raise SystemExit(main())
