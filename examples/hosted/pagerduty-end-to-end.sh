#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-/tmp/veridion-e2e}"
RUNTIME_PATH="${OUT_DIR}/runtime.json"
INCIDENT_TOKEN="${INCIDENT_TOKEN:-}"
STATUSPAGE_TOKEN="${STATUSPAGE_TOKEN:-}"
SPINNAKER_TOKEN="${SPINNAKER_TOKEN:-}"

mkdir -p "${OUT_DIR}"

PYTHONPATH="${ROOT_DIR}/src" "${ROOT_DIR}/.venv/bin/python3" -m veridion.action.runtime_live_fetch \
  --output-path "${RUNTIME_PATH}" \
  --incident-provider pagerduty \
  --incident-base-url "${INCIDENT_BASE_URL:-https://api.pagerduty.com}" \
  --incident-token "${INCIDENT_TOKEN}" \
  --alerts-provider statuspage \
  --alerts-base-url "${ALERTS_BASE_URL:-https://status.example.com}" \
  --alerts-token "${STATUSPAGE_TOKEN}" \
  --canary-provider spinnaker \
  --canary-base-url "${CANARY_BASE_URL:-https://spinnaker.example.com}" \
  --canary-token "${SPINNAKER_TOKEN}" \
  --environment production \
  --deployment-window after_hours \
  --public-exposure true \
  --blast-radius high \
  --rollout-strategy canary

cat <<EOF
Runtime context written to:
  ${RUNTIME_PATH}

Next steps:
1. Build operational-context.json with veridion-build-operational-context.
2. Run veridion-rdi with your diff, reports, and --operational-context-path.
3. Deliver the resulting decision event to S3 or the hosted service store.
EOF
