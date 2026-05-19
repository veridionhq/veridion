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

## Persistent service backend

The hosted history layer now supports:

- SQLite for local development and small deployments
- Postgres-style DSNs for the first service-grade persistent backend
- explicit store schema migrations and status inspection

Inspect store status:

```bash
python3 -m veridion.action.decision_history_store status \
  --store-dsn postgres://user:pass@host/db
```

This returns:

- backend type
- schema version
- applied migrations
- tenant/event/materialization counts

## Persistent SQLite store

If you want a simple persistent local backend before introducing Postgres or another service database, use the SQLite history store.

Ingest centralized history into the store:

```bash
python3 -m veridion.action.decision_history_store ingest \
  --sqlite-path /tmp/veridion-history.db \
  --tenant-id acme \
  --history-path /tmp/veridion-s3-history/acme
```

Then analyze directly from the store:

```bash
python3 -m veridion.action.decision_history_store analyze \
  --sqlite-path /tmp/veridion-history.db \
  --tenant-id acme
```

This is the first persistent multi-tenant backend for the hosted-history layer.

If you want to move beyond SQLite, the same CLI and service surfaces now accept a store DSN for a Postgres-backed history store when the matching database dependency is installed.

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

When you use a SQLite-backed tenant config, materialization can also emit per-tenant Athena query packs inside each run.

## Serve analytics over HTTP

You can also expose the same file-backed history through a small local service:

```bash
python3 -m veridion.action.decision_history_service \
  --config-path examples/aws/history-service.config.json \
  --host 127.0.0.1 \
  --port 8787
```

Legacy endpoints remain available:

- `/healthz`
- `/analytics`
- `/repositories`
- `/policy-rollouts`
- `/tenants`
- `/materializations`
- `/dashboard`

The preferred service contract is now versioned under `/api/v1`:

- `/api/v1/health`
- `/api/v1/overview`
- `/api/v1/identity`
- `/api/v1/analytics`
- `/api/v1/repositories`
- `/api/v1/policy-rollouts`
- `/api/v1/tenants`
- `/api/v1/materializations`
- `/api/v1/materialization-schedules`
- `/api/v1/service/status`

Versioned endpoints return:

- `api_version`
- `route`
- `identity`
- `data`

If you configure bearer-token auth:

```bash
curl \
  -H "Authorization: Bearer replace-me-with-a-real-shared-token" \
  "http://127.0.0.1:8787/api/v1/analytics?tenant=acme&since=2026-05-01T00:00:00Z"
```

There is also a lightweight HTML view:

```bash
curl \
  -H "Authorization: Bearer replace-me-with-a-real-shared-token" \
  "http://127.0.0.1:8787/api/v1/dashboard?tenant=acme"
```

The dashboard is now a proper service surface, not just a raw JSON dump:

- summary cards
- rollout tables
- blocking-category views
- identity and API metadata
- store status, recent materializations, and schedule state

Example:

```bash
curl "http://127.0.0.1:8787/api/v1/analytics?tenant=acme&repository=acme/service-a&since=2026-05-01T00:00:00Z"
```

## Identity model

The history service now supports richer scoped identities in config:

- `token_id`
- `principal_name`
- `auth_type`
- `status`
- `tenants`
- `roles`

Roles currently drive:

- `reader`
- `materializer`
- `admin`

Inactive identities are rejected before request execution.

JWT auth is no longer limited to shared-secret mode. The service can also enforce JWT-backed access with a local JWKS file or JWKS URL in config.

## First-class schedule execution

Materialization schedules are no longer just config metadata.

You can execute due schedules directly:

```bash
python3 -m veridion.action.decision_history_scheduler \
  --config-path examples/aws/history-service.config.json
```

Run it as a long-lived worker:

```bash
python3 -m veridion.action.decision_history_scheduler \
  --config-path examples/aws/history-service.config.json \
  --daemon \
  --poll-interval-seconds 60
```

Or inspect planned runs without executing them:

```bash
python3 -m veridion.action.decision_history_scheduler \
  --config-path examples/aws/history-service.config.json \
  --dry-run
```

Example helper:

- [examples/aws/run-history-scheduler.sh](../examples/aws/run-history-scheduler.sh)

For managed Postgres deployments and migration assets:

- [docs/POSTGRES.md](POSTGRES.md)

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
- [examples/aws/ingest-history-store.sh](../examples/aws/ingest-history-store.sh)
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
