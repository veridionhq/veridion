# SaaS Packaging Direction

Veridion’s long-term commercial shape is a hosted multi-tenant control plane.

That does not replace the repo-local deterministic engine.

It layers on top of it.

## Product boundary

Each customer repo or CI system still runs Veridion locally to evaluate a specific change.

That local run produces:

- `veridion-decision.json`
- `veridion-decision-event.json`
- an optional PR comment

The SaaS layer receives the decision event and turns it into:

- centralized history
- rollout analytics
- service catalogs
- materialization state
- approval and runtime-readiness views across many repos

## Hosted shape

The SaaS architecture is:

1. customer-side producers
2. authenticated event ingestion
3. multi-tenant hosted history service
4. worker/materialization subsystem
5. warehouse or long-horizon analytics layer

## Ingestion

The hosted service now exposes:

- `POST /api/v1/events`

This is the canonical inbound integration point for remote producers sending `veridion-decision-event.json`.

Reference helper:

- [examples/hosted/ingest-decision-event.sh](../examples/hosted/ingest-decision-event.sh)

## Persistent SaaS models

The hosted service now persists tenant-scoped:

- organizations
- projects
- services
- managed tenants
- provider secret references
- service users
- service sessions
- producer clients
- decision events
- materialization runs

That is the minimum control-plane catalog needed for a multi-tenant product.

## API surface

Versioned management/read APIs now include:

- `/api/v1/overview`
- `/api/v1/app`
- `/api/v1/identity`
- `/api/v1/analytics`
- `/api/v1/repositories`
- `/api/v1/organizations`
- `/api/v1/projects`
- `/api/v1/services`
- `/api/v1/admin/tenants`
- `/api/v1/admin/users`
- `/api/v1/admin/provider-secrets`
- `/api/v1/admin/producer-clients`
- `/api/v1/auth/sessions`
- `/api/v1/policy-rollouts`
- `/api/v1/materializations`
- `/api/v1/materialization-schedules`
- `/api/v1/service/status`
- `/api/v1/events`

## Identity model

Production SaaS posture should be:

- OIDC/JWT with JWKS or OIDC discovery for direct API clients
- trusted-header identities only behind controlled internal gateways

Current implementation supports:

- static scoped bearer tokens
- HS256 JWT
- JWT verified through JWKS
- JWT verified through OIDC discovery to a JWKS URI
- trusted-header identities

Producer-side hosted auth now also has a persistent path:

- create a producer client in the control plane
- get a generated ingestor token
- send `veridion-decision-event.json` to `POST /api/v1/events`

Recommended first hosted infra path:

- [infra/terraform/aws-hosted-alpha](../infra/terraform/aws-hosted-alpha/README.md)

## What still becomes a true SaaS concern later

The repo now has the right foundations, but a full hosted product would still add:

- billing / plan controls
- managed background workers
- external identity federation and UI sessions
- a richer front-end application
