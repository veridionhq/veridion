"""Generate Athena-ready DDL and query templates for Veridion decision events."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Athena DDL and query templates for Veridion decision events")
    parser.add_argument("--database", default="default", help="Athena database name")
    parser.add_argument("--table", default="veridion_decision_events", help="Athena table name")
    parser.add_argument("--s3-location", required=True, help="S3 prefix holding partitioned decision-event objects")
    parser.add_argument("--repository", help="Optional repository filter for query templates")
    parser.add_argument("--since", help="Optional ISO-8601 lower bound for query templates")
    parser.add_argument("--output-path", help="Optional path to write JSON output")
    args = parser.parse_args(argv)

    payload = build_athena_query_pack(
        database=args.database,
        table=args.table,
        s3_location=args.s3_location,
        repository=args.repository or "",
        since=args.since or "",
    )
    rendered = json.dumps(payload, indent=2) + "\n"
    if args.output_path:
        Path(args.output_path).write_text(rendered)
    print(rendered, end="")
    return 0


def build_athena_query_pack(
    *,
    database: str,
    table: str,
    s3_location: str,
    repository: str = "",
    since: str = "",
) -> dict[str, object]:
    where = _query_where(repository=repository, since=since)
    qualified_table = f"{database}.{table}"
    return {
        "schema_version": 1,
        "source": "veridion.action.athena_queries@1",
        "database": database,
        "table": table,
        "s3_location": s3_location,
        "ddl": {
            "create_external_table": _create_external_table(qualified_table, s3_location),
            "repair_table": f"MSCK REPAIR TABLE {qualified_table};",
        },
        "queries": {
            "verdicts_by_day": (
                "SELECT day, verdict, COUNT(*) AS events\n"
                "FROM (\n"
                f"  SELECT day, json_extract_scalar(payload, '$.decision.verdict') AS verdict\n"
                f"  FROM {qualified_table}\n"
                f"{where}\n"
                ")\n"
                "GROUP BY 1, 2\n"
                "ORDER BY 1, 2;"
            ),
            "policy_pack_versions_by_repository": (
                "SELECT repo,\n"
                "       json_extract_scalar(payload, '$.policy.pack_id') AS pack_id,\n"
                "       json_extract_scalar(payload, '$.policy.pack_version') AS pack_version,\n"
                "       COUNT(*) AS events\n"
                f"FROM {qualified_table}\n"
                f"{where}\n"
                "GROUP BY 1, 2, 3\n"
                "ORDER BY 1, 2, 3;"
            ),
            "top_blocking_categories": (
                "SELECT category, COUNT(*) AS events\n"
                "FROM (\n"
                "  SELECT category\n"
                f"  FROM {qualified_table}\n"
                "  CROSS JOIN UNNEST(CAST(json_extract(payload, '$.decision.blocking_categories') AS ARRAY(VARCHAR))) AS t(category)\n"
                f"{where}\n"
                ")\n"
                "GROUP BY 1\n"
                "ORDER BY 2 DESC, 1 ASC;"
            ),
            "approval_gate_blockers": (
                "SELECT json_extract_scalar(payload, '$.automation.approval_gate_status') AS approval_gate_status,\n"
                "       COUNT(*) AS events\n"
                f"FROM {qualified_table}\n"
                f"{where}\n"
                "GROUP BY 1\n"
                "ORDER BY 2 DESC, 1 ASC;"
            ),
        },
    }


def _create_external_table(qualified_table: str, s3_location: str) -> str:
    return (
        f"CREATE EXTERNAL TABLE IF NOT EXISTS {qualified_table} (\n"
        "  payload string\n"
        ")\n"
        "PARTITIONED BY (\n"
        "  repo string,\n"
        "  year string,\n"
        "  month string,\n"
        "  day string,\n"
        "  verdict string\n"
        ")\n"
        "ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'\n"
        f"LOCATION '{s3_location}';"
    )


def _query_where(*, repository: str, since: str) -> str:
    clauses: list[str] = []
    if repository:
        clauses.append(f"repo = '{repository.replace('/', '_')}'")
    if since:
        clauses.append(
            "from_iso8601_timestamp(json_extract_scalar(payload, '$.generated_at')) >= "
            f"from_iso8601_timestamp('{since}')"
        )
    if not clauses:
        return ""
    return "WHERE " + " AND ".join(clauses)


if __name__ == "__main__":
    raise SystemExit(main())
