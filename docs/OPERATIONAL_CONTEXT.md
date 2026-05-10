# Operational Context Contract

Veridion's portable integration point is a versioned `operational-context` artifact.

The decision engine should consume this artifact regardless of where the data came from:

- GitHub Actions
- another CI system
- a deployment controller
- a service catalog exporter
- a custom internal platform

## Contract

Current schema:

```json
{
  "schema_version": 1,
  "provenance": {
    "source": "veridion-github-builder",
    "generated_at": "2026-05-10T00:00:00Z"
  },
  "metadata": {},
  "historical": {},
  "runtime": {},
  "ownership": {},
  "trust_baseline": {},
  "trust_profile_metadata": {}
}
```

## Purpose of Each Section

- `metadata`
  PR/request-scoped context such as title, body, labels, and commit metadata.
- `historical`
  Recent operational signals such as rollback rate, incidents, and change failure rate.
- `runtime`
  Deployment-time context such as target environment, rollout strategy, public exposure, and blast radius.
- `ownership`
  Ownership and coordination data such as service owner, team, review coverage, and on-call status.
- `trust_baseline`
  Longer-lived posture such as fragility, test coverage, rollback readiness, and dependency reputation.
- `trust_profile_metadata`
  Stable identity and provenance for repo, service, and team posture.

## Producer Rules

Producers should:

- emit `schema_version: 1`
- include only top-level objects for known sections
- keep request-scoped data in `metadata`
- keep durable posture in `trust_baseline` and `trust_profile_metadata`
- treat missing sections as empty objects

Producers should not:

- embed scanner findings in this artifact
- mix raw vendor-specific event payloads into top-level keys
- depend on GitHub-specific naming outside `metadata`

## Current Reference Producer

GitHub currently uses:

- [src/veridion/action/operational_context_builder.py](/Users/lseino/repos/veridion/src/veridion/action/operational_context_builder.py:1)

That builder merges:

- request-scoped PR metadata
- repo/service/team trust profile inputs

into one stable artifact before invoking the engine.

## Why This Matters

This contract is what keeps Veridion from becoming a GitHub-only tool.

If another environment can emit `operational-context.json`, it can use the same:

- analysis bundle
- policy engine
- RDI score
- decision output
- reporting layer
