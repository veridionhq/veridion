#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-examples/aws/history-service.config.json}"
OUTPUT_ROOT="${2:-/tmp/veridion-history-materialized}"
RUN_ID="${RUN_ID:-}"

ARGS=(
  --config-path "${CONFIG_PATH}"
  --output-root "${OUTPUT_ROOT}"
)

if [[ -n "${RUN_ID}" ]]; then
  ARGS+=(--run-id "${RUN_ID}")
fi

PYTHONPATH=src .venv/bin/python3 -m veridion.action.decision_history_materialize "${ARGS[@]}"
