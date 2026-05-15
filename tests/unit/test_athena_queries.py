import json

from veridion.action.athena_queries import build_athena_query_pack, main


def test_build_athena_query_pack_includes_filtered_queries() -> None:
    payload = build_athena_query_pack(
        database="analytics",
        table="veridion_events",
        s3_location="s3://veridion-prod-events/veridion/events/",
        repository="acme/service-a",
        since="2026-05-01T00:00:00Z",
    )

    assert payload["ddl"]["create_external_table"].startswith("CREATE EXTERNAL TABLE IF NOT EXISTS analytics.veridion_events")
    assert "repo = 'acme_service-a'" in payload["queries"]["policy_pack_versions_by_repository"]
    assert "from_iso8601_timestamp('2026-05-01T00:00:00Z')" in payload["queries"]["verdicts_by_day"]


def test_athena_queries_cli_writes_json(tmp_path) -> None:
    output_path = tmp_path / "queries.json"

    exit_code = main(
        [
            "--database",
            "analytics",
            "--table",
            "veridion_events",
            "--s3-location",
            "s3://veridion-prod-events/veridion/events/",
            "--output-path",
            str(output_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text())
    assert payload["database"] == "analytics"
    assert "repair_table" in payload["ddl"]
