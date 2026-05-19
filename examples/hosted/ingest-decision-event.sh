#!/usr/bin/env bash
set -euo pipefail

SERVICE_URL="${SERVICE_URL:-http://127.0.0.1:8787}"
TENANT_ID="${TENANT_ID:-acme}"
EVENT_PATH="${1:-/tmp/veridion-decision-event.json}"
TOKEN="${TOKEN:-replace-me-with-a-real-ingestor-token}"

EVENT_JSON="$(cat "${EVENT_PATH}")"

curl \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  "${SERVICE_URL}/api/v1/events" \
  -d "{\"tenant\":\"${TENANT_ID}\",\"event\":${EVENT_JSON}}"
