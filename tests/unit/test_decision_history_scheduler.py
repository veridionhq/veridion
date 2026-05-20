import json

from veridion.action.decision_history_config import HistoryServiceConfig, HistoryTenant, MaterializationSchedule
from veridion.action.decision_history_scheduler import run_configured_history_schedules, schedule_is_due


def test_schedule_is_due_supports_ranges_and_steps() -> None:
    from datetime import datetime, timezone

    at = datetime(2026, 5, 19, 3, 0, tzinfo=timezone.utc)
    assert schedule_is_due("0 3 * * *", at) is True
    assert schedule_is_due("*/15 3 * * *", at) is True
    assert schedule_is_due("0 2 * * *", at) is False


def test_run_configured_history_schedules_plans_due_runs(tmp_path) -> None:
    from datetime import datetime, timezone

    config_path = tmp_path / "config.json"
    output_root = tmp_path / "materialized"
    config_path.write_text(
        json.dumps(
            {
                "sqlite_path": str(tmp_path / "history.db"),
                "materialization_root": str(output_root),
                "tenants": [{"tenant_id": "acme", "history_paths": []}],
                "schedules": [{"schedule_id": "nightly", "cron": "0 3 * * *", "tenants": ["acme"]}],
            }
        )
    )
    config = HistoryServiceConfig(
        tenants=(HistoryTenant(tenant_id="acme", history_paths=()),),
        sqlite_path=str(tmp_path / "history.db"),
        materialization_root=str(output_root),
        schedules=(MaterializationSchedule(schedule_id="nightly", cron="0 3 * * *", tenants=("acme",)),),
    )

    payload = run_configured_history_schedules(
        config=config,
        config_path=str(config_path),
        output_root=str(output_root),
        at=datetime(2026, 5, 19, 3, 0, tzinfo=timezone.utc),
        dry_run=True,
    )

    assert payload["due_schedules"] == ["nightly"]
    assert payload["runs"][0]["schedule_id"] == "nightly"
    assert payload["runs"][0]["status"] == "planned"
