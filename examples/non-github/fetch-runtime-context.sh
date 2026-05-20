#!/usr/bin/env bash
set -euo pipefail

OUTPUT_PATH="${1:-runtime.json}"
INCIDENT_PROVIDER="${INCIDENT_PROVIDER:-incident-io}"
INCIDENT_BASE_URL="${INCIDENT_BASE_URL:-https://api.incident.io}"
INCIDENT_TOKEN="${INCIDENT_TOKEN:-}"
ALERTS_PROVIDER="${ALERTS_PROVIDER:-statuspage}"
ALERTS_BASE_URL="${ALERTS_BASE_URL:-https://status.example.com}"
ALERTS_TOKEN="${ALERTS_TOKEN:-}"
CANARY_PROVIDER="${CANARY_PROVIDER:-harness}"
CANARY_BASE_URL="${CANARY_BASE_URL:-https://app.harness.io}"
CANARY_TOKEN="${CANARY_TOKEN:-}"

PYTHONPATH=src .venv/bin/python3 -m veridion.action.runtime_live_fetch \
  --output-path "${OUTPUT_PATH}" \
  --incident-provider "${INCIDENT_PROVIDER}" \
  --incident-base-url "${INCIDENT_BASE_URL}" \
  --incident-token "${INCIDENT_TOKEN}" \
  --alerts-provider "${ALERTS_PROVIDER}" \
  --alerts-base-url "${ALERTS_BASE_URL}" \
  --alerts-token "${ALERTS_TOKEN}" \
  --canary-provider "${CANARY_PROVIDER}" \
  --canary-base-url "${CANARY_BASE_URL}" \
  --canary-token "${CANARY_TOKEN}" \
  --environment production \
  --deployment-window after_hours \
  --public-exposure true \
  --blast-radius high \
  --rollout-strategy canary
