# Postgres Hosted Deployment

Use Postgres when you want Veridion history to move from local or file-backed hosting into a long-running service deployment.

This is optional.

You do not need Postgres to use:

- the deterministic release engine
- PR comments
- local decision artifacts
- local history replay

Postgres becomes useful when you want:

- persistent multi-tenant history
- service-backed analytics APIs
- managed materialization tracking
- operational database lifecycle controls

## Install the database extras

```bash
python3 -m pip install "veridion[db]"
```

From the repo:

```bash
python3 -m pip install -e ".[db]"
```

## Migration assets

Canonical SQL assets live in:

- [db/migrations/000_schema_migrations.sql](../db/migrations/000_schema_migrations.sql)
- [db/migrations/001_decision_events.sql](../db/migrations/001_decision_events.sql)
- [db/migrations/002_materialization_runs.sql](../db/migrations/002_materialization_runs.sql)

These mirror the service store schema used by:

- `veridion-history-store migrate`
- `veridion-history-service`

## Bootstrap a store

```bash
veridion-history-store migrate \
  --store-dsn postgresql://veridion:secret@db.internal/veridion_history
```

Inspect the result:

```bash
veridion-history-store status \
  --store-dsn postgresql://veridion:secret@db.internal/veridion_history
```

The status response includes:

- backend
- schema version
- applied migrations
- pending migration count
- tenant / event / materialization counts

## Ingest history

```bash
veridion-history-store ingest \
  --store-dsn postgresql://veridion:secret@db.internal/veridion_history \
  --tenant-id acme \
  --history-path /tmp/veridion-s3-history
```

## Run the service

```bash
veridion-history-service \
  --config-path examples/aws/history-service.config.json \
  --host 0.0.0.0 \
  --port 8787
```

Use `store_dsn` in the config file instead of `sqlite_path`.

## Deployment guidance

Recommended production posture:

1. Run `veridion-history-store migrate` before deploying a new service version.
2. Verify `pending_migration_count == 0` in store status.
3. Roll out the service with a scoped reader/materializer/admin identity model.
4. Run `veridion-history-scheduler --daemon` separately as a worker process.

## Worker mode

The scheduler is now a first-class worker:

```bash
veridion-history-scheduler \
  --config-path examples/aws/history-service.config.json \
  --daemon \
  --poll-interval-seconds 60
```

This continuously evaluates due schedules and records runs through the same hosted history surfaces.
