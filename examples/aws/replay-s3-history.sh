#!/usr/bin/env bash
set -euo pipefail

: "${VERIDION_TEST_BUCKET:?set VERIDION_TEST_BUCKET first}"

PREFIX="${1:-veridion/events/}"
LOCAL_DIR="${2:-/tmp/veridion-s3-history}"

rm -rf "${LOCAL_DIR}"
mkdir -p "${LOCAL_DIR}"

aws s3 sync "s3://${VERIDION_TEST_BUCKET}/${PREFIX}" "${LOCAL_DIR}"

PYTHONPATH=src .venv/bin/python3 -m veridion.action.decision_history \
  --history-path "${LOCAL_DIR}"
