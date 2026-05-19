#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-examples/aws/history-service.config.json}"
AT="${AT:-}"
RUN_ALL="${RUN_ALL:-false}"
DRY_RUN="${DRY_RUN:-false}"
DAEMON="${DAEMON:-false}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-60}"
MAX_ITERATIONS="${MAX_ITERATIONS:-0}"

ARGS=(
  --config-path "${CONFIG_PATH}"
)

if [[ -n "${AT}" ]]; then
  ARGS+=(--at "${AT}")
fi

if [[ "${RUN_ALL}" == "true" ]]; then
  ARGS+=(--run-all)
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  ARGS+=(--dry-run)
fi

if [[ "${DAEMON}" == "true" ]]; then
  ARGS+=(--daemon --poll-interval-seconds "${POLL_INTERVAL_SECONDS}")
  if [[ "${MAX_ITERATIONS}" != "0" ]]; then
    ARGS+=(--max-iterations "${MAX_ITERATIONS}")
  fi
fi

PYTHONPATH=src .venv/bin/python3 -m veridion.action.decision_history_scheduler "${ARGS[@]}"
