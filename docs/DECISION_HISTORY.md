# Decision History

Veridion decision events are useful only if they can be queried over time.

The action can now:

- write `veridion-decision-event.json` for the current run
- append the same event to an NDJSON history log
- analyze that history for verdict, approval-gate, and policy-pack trends

## Build history over time

When you configure:

- `decision-event-path`
- `decision-history-path`

each run emits one current event and optionally appends it to the history log.

## Analyze a history log

```bash
python3 -m veridion.action.decision_history \
  --history-path veridion-decision-history.ndjson \
  --output-path decision-history-analytics.json
```

The analytics output includes:

- verdict counts
- gate-status counts
- approval-gate counts
- top blocking categories
- policy pack / version breakdown
- stale approval event counts

It also now includes rollout-oriented analytics:

- events by day
- latest policy pack/version per repository
- version-adoption summaries
- repository transitions between policy pack versions/stages

## Export analytics snapshots

You can materialize analytics snapshots for:

- the whole history set
- each repository
- each policy pack

Example:

```bash
python3 -m veridion.action.decision_history_export \
  --history-path /tmp/veridion-s3-history \
  --output-dir /tmp/veridion-history-exports
```

This writes:

- `overall.json`
- `repositories/<repo>.json`
- `policy-packs/<pack_id>.json`

These snapshots are useful for scheduled report generation and static dashboards before a long-lived backend exists.

## Materialize timestamped runs

If you want scheduled snapshots instead of one-off exports, materialize them into:

- `runs/<run_id>/...`
- `latest/...`

Example:

```bash
python3 -m veridion.action.decision_history_materialize \
  --config-path examples/aws/history-service.config.json \
  --output-root /tmp/veridion-history-materialized
```

This is the intended bridge between:

- centralized event storage
- scheduled analytics generation
- simple dashboard/report publishing

## Serve analytics over HTTP

You can also expose the same file-backed history through a small local service:

```bash
python3 -m veridion.action.decision_history_service \
  --config-path examples/aws/history-service.config.json \
  --host 127.0.0.1 \
  --port 8787
```

Endpoints:

- `/healthz`
- `/analytics`
- `/repositories`
- `/policy-rollouts`
- `/tenants`

If you configure bearer-token auth:

```bash
curl \
  -H "Authorization: Bearer replace-me-with-a-real-shared-token" \
  "http://127.0.0.1:8787/analytics?tenant=acme&since=2026-05-01T00:00:00Z"
```

Example:

```bash
curl "http://127.0.0.1:8787/analytics?tenant=acme&repository=acme/service-a&since=2026-05-01T00:00:00Z"
```

## Filter for rollout analysis

Example:

```bash
python3 -m veridion.action.decision_history \
  --history-path veridion-decision-history.ndjson \
  --repository acme/service-a \
  --policy-pack-id platform-team
```

This is the current local replay surface for pack-version rollout analysis before centralized history storage exists.

## Analyze exported object sets

`decision_history` no longer requires a single NDJSON file.

You can point it at:

- a local NDJSON history file
- a single `veridion-decision-event.json`
- a directory tree of exported decision-event JSON objects

Example:

```bash
python3 -m veridion.action.decision_history \
  --history-path /tmp/veridion-s3-history
```

That makes S3-backed replay straightforward:

1. sync a partition or prefix locally
2. run `decision_history` on the downloaded tree

Example helper:

- [examples/aws/replay-s3-history.sh](../examples/aws/replay-s3-history.sh)
- [examples/aws/build-athena-queries.sh](../examples/aws/build-athena-queries.sh)
- [examples/aws/materialize-history.sh](../examples/aws/materialize-history.sh)
- [examples/aws/run-history-service.sh](../examples/aws/run-history-service.sh)
- [examples/aws/history-service.config.json](../examples/aws/history-service.config.json)

## Time-bounded replay

You can now limit analysis windows:

```bash
python3 -m veridion.action.decision_history \
  --history-path /tmp/veridion-s3-history \
  --since 2026-05-01T00:00:00Z \
  --until 2026-05-31T23:59:59Z
```

This is the current replay surface for centralized history before a warehouse-native reader exists.
