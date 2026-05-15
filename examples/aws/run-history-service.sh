#!/usr/bin/env bash
set -euo pipefail

HISTORY_DIR="${1:-/tmp/veridion-s3-history}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8787}"

PYTHONPATH=src .venv/bin/python3 -m veridion.action.decision_history_service \
  --history-path "${HISTORY_DIR}" \
  --host "${HOST}" \
  --port "${PORT}"
