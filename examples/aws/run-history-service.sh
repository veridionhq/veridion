#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-examples/aws/history-service.config.json}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8787}"
AUTH_TOKEN="${AUTH_TOKEN:-}"

ARGS=(
  --config-path "${CONFIG_PATH}"
  --host "${HOST}"
  --port "${PORT}"
)

if [[ -n "${AUTH_TOKEN}" ]]; then
  ARGS+=(--auth-token "${AUTH_TOKEN}")
fi

PYTHONPATH=src .venv/bin/python3 -m veridion.action.decision_history_service \
  "${ARGS[@]}"
