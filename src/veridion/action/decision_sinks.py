"""Pluggable delivery sinks for canonical Veridion decision events."""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)*$")
_SIMPLE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")

from veridion.action.decision_event import append_decision_history
from veridion.action.event_emitter import post_json, validate_webhook_url


@dataclass(frozen=True)
class SinkSpec:
    kind: str
    options: dict[str, str]


@dataclass(frozen=True)
class SinkDeliveryResult:
    sink: str
    status: str
    destination: str
    error: str = ""


class DecisionSinkError(RuntimeError):
    """Raised when decision sink delivery fails."""

    pass


def deliver_decision_event(
    event: dict[str, object],
    *,
    sink_specs: tuple[SinkSpec, ...],
    fail_on_error: bool = False,
) -> tuple[SinkDeliveryResult, ...]:
    """Deliver a canonical decision event to one or more sink backends."""

    results: list[SinkDeliveryResult] = []
    errors: list[str] = []
    for spec in sink_specs:
        try:
            results.append(_deliver_one(spec, event))
        except Exception as exc:
            result = SinkDeliveryResult(
                sink=spec.kind,
                status="failed",
                destination=_destination_label(spec),
                error=str(exc),
            )
            results.append(result)
            errors.append(f"{spec.kind}: {exc}")

    if fail_on_error and errors:
        raise DecisionSinkError("; ".join(errors))
    return tuple(results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deliver Veridion decision events to one or more sinks")
    parser.add_argument("--decision-event-path", required=True, help="Path to veridion-decision-event.json")
    parser.add_argument("--sink", action="append", default=[], help="Sink spec, repeatable")
    parser.add_argument("--fail-on-error", default="false", help="Whether any failed sink should fail the command")
    args = parser.parse_args(argv)

    if not args.sink:
        raise SystemExit("at least one --sink is required")

    event = json.loads(Path(args.decision_event_path).read_text())
    sink_specs = tuple(parse_sink_spec(value) for value in args.sink)
    results = deliver_decision_event(
        event,
        sink_specs=sink_specs,
        fail_on_error=args.fail_on_error.strip().lower() == "true",
    )
    _write_github_outputs(results)
    print(json.dumps([asdict(item) for item in results]))
    return 0


def parse_sink_spec(value: str) -> SinkSpec:
    raw = value.strip()
    if not raw:
        raise ValueError("sink spec must not be empty")
    if ":" not in raw:
        raise ValueError("sink spec must use KIND:key=value,... format")
    kind, rest = raw.split(":", maxsplit=1)
    normalized_kind = kind.strip().lower()
    if not normalized_kind:
        raise ValueError("sink kind must not be empty")
    options: dict[str, str] = {}
    for pair in [item for item in rest.split(",") if item.strip()]:
        if "=" not in pair:
            raise ValueError(f"invalid sink option '{pair}', expected key=value")
        key, option_value = pair.split("=", maxsplit=1)
        key = key.strip().lower()
        option_value = option_value.strip()
        if not key or not option_value:
            raise ValueError(f"invalid sink option '{pair}', expected key=value")
        options[key] = option_value
    return SinkSpec(kind=normalized_kind, options=options)


def _deliver_one(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    if spec.kind == "local-file":
        path = _require_option(spec, "path")
        Path(path).write_text(json.dumps(event, indent=2) + "\n")
        return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=path)

    if spec.kind == "local-ndjson":
        path = _require_option(spec, "path")
        append_decision_history(path, event)
        return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=path)

    if spec.kind == "webhook":
        url = validate_webhook_url(_require_option(spec, "url"))
        token = spec.options.get("token", "")
        event_type = spec.options.get("event_type", "veridion.rdi.decision_event.v1")
        payload = {
            "event_type": event_type,
            "decision_event": event,
        }
        post_json(url=url, payload=payload, token=token)
        return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=url)

    if spec.kind == "veridion-service":
        url = validate_webhook_url(_require_option(spec, "url")).rstrip("/")
        tenant = _require_option(spec, "tenant")
        token = _require_option(spec, "token")
        payload = {
            "tenant": tenant,
            "event": event,
        }
        post_json(url=f"{url}/api/v1/events", payload=payload, token=token)
        return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=f"{url}/api/v1/events")

    if spec.kind == "s3":
        return _deliver_s3(spec, event)
    if spec.kind == "postgres":
        return _deliver_postgres(spec, event)
    if spec.kind == "redshift":
        return _deliver_redshift(spec, event)
    if spec.kind == "kafka":
        return _deliver_kafka(spec, event)
    if spec.kind == "eventbridge":
        return _deliver_eventbridge(spec, event)
    if spec.kind == "pubsub":
        return _deliver_pubsub(spec, event)
    if spec.kind == "bigquery":
        return _deliver_bigquery(spec, event)
    if spec.kind == "snowflake":
        return _deliver_snowflake(spec, event)

    raise DecisionSinkError(f"unsupported sink kind: {spec.kind}")


def _deliver_s3(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    try:
        import boto3  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise DecisionSinkError("s3 sink requires boto3") from exc

    bucket = _require_option(spec, "bucket")
    key = _resolve_s3_key(spec, event)
    region = spec.options.get("region", "")
    client = boto3.client("s3", region_name=region or None)
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=(json.dumps(event, sort_keys=True) + "\n").encode("utf-8"),
        ContentType="application/json",
    )
    return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=f"s3://{bucket}/{key}")


def _resolve_s3_key(spec: SinkSpec, event: dict[str, object]) -> str:
    explicit_key = spec.options.get("key", "").strip()
    if explicit_key:
        return explicit_key
    prefix = spec.options.get("prefix", "veridion/events").strip()
    return build_default_s3_key(event, prefix=prefix)


def build_default_s3_key(event: dict[str, object], *, prefix: str = "veridion/events") -> str:
    generated_at = _parse_generated_at(event.get("generated_at"))
    repository = _repository_partition(event.get("repository"))
    pull_request_number = _event_int(event.get("pull_request_number"))
    verdict = _nested_event_str(event, "decision", "verdict").lower().replace(" ", "-") or "unknown"
    timestamp = generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    base_prefix = prefix.strip().strip("/") or "veridion/events"
    return (
        f"{base_prefix}/repo={repository}/year={generated_at:%Y}/month={generated_at:%m}/day={generated_at:%d}/"
        f"verdict={verdict}/ts={timestamp}-pr={pull_request_number or 0}.json"
    )


def _parse_generated_at(value: object) -> datetime:
    raw = value if isinstance(value, str) else ""
    if not raw:
        raise DecisionSinkError("decision event must include generated_at to derive the default s3 key")
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DecisionSinkError("decision event generated_at must be a valid ISO-8601 timestamp") from exc


def _repository_partition(value: object) -> str:
    raw = value if isinstance(value, str) else ""
    normalized = raw.strip().replace("/", "_")
    return normalized or "unknown_repo"


def _event_int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _nested_event_str(event: dict[str, object], section: str, key: str) -> str:
    payload = event.get(section)
    if not isinstance(payload, dict):
        return ""
    value = payload.get(key)
    return value if isinstance(value, str) else ""


def _deliver_postgres(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    connection, close = _open_db_connection("postgres sink requires psycopg or psycopg2", spec)
    table = _require_identifier(spec, "table", allow_qualified=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO {table} (generated_at, repository, verdict, gate_status, pack_id, pack_version, event_payload) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    event.get("generated_at", ""),
                    event.get("repository", ""),
                    _nested_str(event, "decision", "verdict"),
                    _nested_str(event, "decision", "gate_status"),
                    _nested_str(event, "policy", "pack_id"),
                    _nested_str(event, "policy", "pack_version"),
                    json.dumps(event),
                ),
            )
        connection.commit()
    finally:
        close(connection)
    return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=table)


def _deliver_redshift(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    connection, close = _open_db_connection("redshift sink requires psycopg or psycopg2", spec)
    table = _require_identifier(spec, "table", allow_qualified=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO {table} (generated_at, repository, verdict, gate_status, pack_id, pack_version, event_payload) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    event.get("generated_at", ""),
                    event.get("repository", ""),
                    _nested_str(event, "decision", "verdict"),
                    _nested_str(event, "decision", "gate_status"),
                    _nested_str(event, "policy", "pack_id"),
                    _nested_str(event, "policy", "pack_version"),
                    json.dumps(event),
                ),
            )
        connection.commit()
    finally:
        close(connection)
    return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=table)


def _deliver_kafka(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    try:
        from kafka import KafkaProducer  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise DecisionSinkError("kafka sink requires kafka-python") from exc

    bootstrap_servers = _require_option(spec, "bootstrap_servers")
    topic = _require_option(spec, "topic")
    producer = KafkaProducer(bootstrap_servers=bootstrap_servers.split(";"))
    producer.send(topic, json.dumps(event).encode("utf-8"))
    producer.flush()
    producer.close()
    return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=topic)


def _deliver_eventbridge(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    try:
        import boto3  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise DecisionSinkError("eventbridge sink requires boto3") from exc

    bus = _require_option(spec, "bus")
    region = spec.options.get("region", "")
    source = spec.options.get("source", "veridion")
    detail_type = spec.options.get("detail_type", "veridion.decision_event")
    client = boto3.client("events", region_name=region or None)
    client.put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps(event),
            }
        ]
    )
    return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=bus)


def _deliver_pubsub(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    try:
        from google.cloud import pubsub_v1  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise DecisionSinkError("pubsub sink requires google-cloud-pubsub") from exc

    project = _require_option(spec, "project")
    topic = _require_option(spec, "topic")
    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(project, topic)
    publisher.publish(topic_path, json.dumps(event).encode("utf-8")).result()
    return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=topic_path)


def _deliver_bigquery(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    try:
        from google.cloud import bigquery  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise DecisionSinkError("bigquery sink requires google-cloud-bigquery") from exc

    project = _require_option(spec, "project")
    dataset = _require_option(spec, "dataset")
    table = _require_option(spec, "table")
    client = bigquery.Client(project=project)
    table_id = f"{project}.{dataset}.{table}"
    errors = client.insert_rows_json(table_id, [event])
    if errors:
        raise DecisionSinkError(f"bigquery insert failed: {errors}")
    return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=table_id)


def _deliver_snowflake(spec: SinkSpec, event: dict[str, object]) -> SinkDeliveryResult:
    try:
        import snowflake.connector  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise DecisionSinkError("snowflake sink requires snowflake-connector-python") from exc

    account = _require_option(spec, "account")
    user = _require_option(spec, "user")
    password = _require_option(spec, "password")
    database = _require_identifier(spec, "database")
    schema = _require_identifier(spec, "schema")
    table = _require_identifier(spec, "table")
    warehouse = spec.options.get("warehouse", "")
    connection = snowflake.connector.connect(
        account=account,
        user=user,
        password=password,
        database=database,
        schema=schema,
        warehouse=warehouse or None,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO {database}.{schema}.{table} (event_payload) SELECT PARSE_JSON(%s)",
                (json.dumps(event),),
            )
    finally:
        connection.close()
    return SinkDeliveryResult(sink=spec.kind, status="delivered", destination=f"{database}.{schema}.{table}")


def _open_db_connection(error_message: str, spec: SinkSpec):
    dsn = _require_option(spec, "dsn")
    try:
        import psycopg  # type: ignore

        return psycopg.connect(dsn), lambda conn: conn.close()
    except Exception:
        try:
            import psycopg2  # type: ignore

            return psycopg2.connect(dsn), lambda conn: conn.close()
        except Exception as exc:  # pragma: no cover - import guard
            raise DecisionSinkError(error_message) from exc


def _nested_str(event: dict[str, object], section: str, key: str) -> str:
    payload = event.get(section)
    if not isinstance(payload, dict):
        return ""
    value = payload.get(key)
    return value if isinstance(value, str) else str(value or "")


def _require_option(spec: SinkSpec, key: str) -> str:
    value = spec.options.get(key, "").strip()
    if not value:
        raise DecisionSinkError(f"{spec.kind} sink requires option '{key}'")
    return value


def _require_identifier(spec: SinkSpec, key: str, *, allow_qualified: bool = False) -> str:
    value = _require_option(spec, key)
    pattern = _SAFE_IDENTIFIER_RE if allow_qualified else _SIMPLE_IDENTIFIER_RE
    if not pattern.fullmatch(value):
        hint = "qualified (schema.table) or simple identifier" if allow_qualified else "simple identifier (no dots)"
        raise DecisionSinkError(
            f"{spec.kind} sink option '{key}' must be a safe SQL {hint}: {value!r}"
        )
    return value


def _destination_label(spec: SinkSpec) -> str:
    if spec.kind in {"local-file", "local-ndjson"}:
        return spec.options.get("path", "")
    if spec.kind == "webhook":
        return spec.options.get("url", "")
    if spec.kind == "veridion-service":
        return f"{spec.options.get('url', '').rstrip('/')}/api/v1/events"
    if spec.kind == "s3":
        bucket = spec.options.get("bucket", "")
        key = spec.options.get("key", "")
        prefix = spec.options.get("prefix", "")
        if bucket and key:
            return f"s3://{bucket}/{key}"
        if bucket and prefix:
            return f"s3://{bucket}/{prefix.strip('/')}/..."
        return f"s3://{bucket}" if bucket else "s3"
    if spec.kind in {"postgres", "redshift", "bigquery", "snowflake"}:
        return spec.options.get("table", spec.kind)
    if spec.kind == "kafka":
        return spec.options.get("topic", "kafka")
    if spec.kind == "eventbridge":
        return spec.options.get("bus", "eventbridge")
    if spec.kind == "pubsub":
        return spec.options.get("topic", "pubsub")
    return spec.kind


def _write_github_outputs(results: tuple[SinkDeliveryResult, ...]) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        return
    with Path(github_output).open("a", encoding="utf-8") as handle:
        handle.write(f"sink_delivery_summary_json={json.dumps([asdict(item) for item in results])}\n")
        failed = [asdict(item) for item in results if item.status != "delivered"]
        handle.write(f"sink_delivery_failures_json={json.dumps(failed)}\n")


if __name__ == "__main__":
    raise SystemExit(main())
