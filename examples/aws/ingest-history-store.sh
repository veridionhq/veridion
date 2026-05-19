#!/usr/bin/env bash
set -euo pipefail

SQLITE_PATH="${1:-/tmp/veridion-history.db}"
TENANT_ID="${2:-acme}"
HISTORY_PATH="${3:-/tmp/veridion-s3-history}"

PYTHONPATH=src .venv/bin/python3 -m veridion.action.decision_history_store ingest \
  --sqlite-path "${SQLITE_PATH}" \
  --tenant-id "${TENANT_ID}" \
  --history-path "${HISTORY_PATH}"
