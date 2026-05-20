# Hosted Control Plane

Veridion can run in two modes:

1. embedded in a team repository or CI job
2. as a central hosted control-plane service

Both use the same deterministic decision engine.

The difference is where decision history, policy rollout analytics, and release-readiness APIs live.

## Recommended hosted shape

Use four layers:

1. repository or CI producers
2. canonical decision events
3. centralized history and analytics service
4. optional query and warehouse layer

### 1. Producers

Each team or repo runs Veridion where code changes happen:

- GitHub Actions
- GitLab CI
- Jenkins
- Buildkite
- internal delivery systems

Those producers generate:

- PR comments
- `veridion-decision.json`
- `veridion-decision-event.json`

### 2. Canonical event transport

The producer emits the decision event to one or more sinks:

- local NDJSON
- S3
- webhook
- Postgres-backed hosted service
- Veridion hosted service sink

The key point is:

- one canonical event
- many sink destinations

### 3. Central hosted service

The hosted service is the shared control-plane surface.

It provides:

- tenant-scoped history APIs
- tenant provisioning and admin APIs
- materialization tracking
- rollout analytics
- a dashboard
- an app shell for tenant, user, producer, and session state
- approval and release-readiness context for many repos

In a self-hosted deployment, that usually means:

- Postgres as the persistent service backend
- `veridion-history-service` as the API surface
- `veridion-history-scheduler --daemon` as the worker
- an auth gateway or JWT issuer in front of the service

### 4. Query layer

For broad analytics, keep S3 and Athena as the first recommended path:

- S3 as the system of record for append-only history
- Athena as the system of insight for trends and replay

The hosted service and the warehouse path are complementary:

- service for operational APIs and current state
- warehouse for longer-horizon analytics

## Identity options

Supported hosted identity modes today:

- static scoped bearer tokens
- JWT with shared secret
- JWT with local or remote JWKS
- trusted headers from a reverse proxy / auth gateway

Recommended production posture:

- JWT/JWKS when the service is reached directly by clients
- trusted headers when the service sits behind an internal auth gateway
- producer clients with ingestor tokens for remote CI/event publishers

## First GitHub producer path

The repo's `hosted-producer` workflow is the dedicated push-driven hosted producer.

It runs on:

- pushes to `develop`
- pushes to `main`
- manual dispatch

It sends `veridion-decision-event.json` directly to:

- `POST /api/v1/events`

when these are set:

- repo variable `VERIDION_HOSTED_SERVICE_URL`
- repo variable `VERIDION_HOSTED_TENANT_ID`
- repo secret `VERIDION_HOSTED_INGESTOR_TOKEN`

The repo's internal `rdi-pr-comment` workflow can also use the same sink on PR/self-test paths.

## Worker model

The scheduler is a separate worker process, not part of the API server.

That separation is intentional:

- API traffic stays responsive
- schedule execution can scale independently
- materialization cadence becomes an operations concern, not a request concern

## Example deployment bundle

The repo now includes:

- [examples/hosted/docker-compose.postgres.yml](../examples/hosted/docker-compose.postgres.yml)
- [infra/terraform/aws-hosted-alpha](../infra/terraform/aws-hosted-alpha/README.md)
- [examples/hosted/history-service.jwt.config.json](../examples/hosted/history-service.jwt.config.json)
- [examples/hosted/history-service.trusted-header.config.json](../examples/hosted/history-service.trusted-header.config.json)
- [examples/hosted/nginx-trusted-proxy.conf](../examples/hosted/nginx-trusted-proxy.conf)
- [examples/hosted/pagerduty-end-to-end.sh](../examples/hosted/pagerduty-end-to-end.sh)

This is the intended bridge from "tool in a repo" to "shared release-control service".

For the multi-tenant SaaS direction specifically:

- [docs/SAAS.md](SAAS.md)
