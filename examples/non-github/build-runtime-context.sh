#!/usr/bin/env bash
set -euo pipefail

# Example runtime-source adapter flow for non-GitHub CI/CD systems.
# These inputs can be produced from incident systems, freeze calendars,
# rollout controllers, or deployment health checks.

python3 -m veridion.action.runtime_context_builder \
  --incident-path incident.json \
  --freeze-path freeze.json \
  --alerts-path alerts.json \
  --canary-path canary.json \
  --rollback-path rollback.json \
  --environment production \
  --deployment-window after_hours \
  --public-exposure true \
  --blast-radius high \
  --rollout-strategy canary \
  --output-path runtime.json
