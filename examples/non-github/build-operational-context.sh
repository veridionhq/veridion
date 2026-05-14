#!/usr/bin/env bash
set -euo pipefail

# Example producer for non-GitHub CI systems.
# Input files are normalized section JSON objects, not raw vendor payloads.
# Runtime inputs can include live gate fields such as:
# - deployment_freeze_active
# - active_incident / active_incident_severity
# - alert_state
# - canary_health
# - rollback_viability

python3 -m veridion.action.operational_context_builder \
  --metadata-path metadata.json \
  --historical-path historical.json \
  --runtime-path runtime.json \
  --ownership-path ownership.json \
  --trust-baseline-path trust-baseline.json \
  --trust-memory-path trust-memory.json \
  --trust-profile-metadata-path trust-profile-metadata.json \
  --source "generic-ci" \
  --output-path operational-context.json
