#!/usr/bin/env bash
set -euo pipefail

: "${VERIDION_TEST_BUCKET:?set VERIDION_TEST_BUCKET first}"
: "${AWS_REGION:?set AWS_REGION first}"

EVENT_PATH="${1:-examples/aws/sample-decision-event.json}"
KEY="veridion/events/repo=acme_service-a/year=2026/month=05/day=14/verdict=conditional-go/ts=2026-05-14T12:00:00Z-pr=42.json"

PYTHONPATH=src .venv/bin/python3 -m veridion.action.decision_sinks \
  --decision-event-path "${EVENT_PATH}" \
  --sink "s3:bucket=${VERIDION_TEST_BUCKET},prefix=veridion/events,region=${AWS_REGION}" \
  --sink "local-ndjson:path=/tmp/veridion-decision-history.ndjson"

aws s3 cp "s3://${VERIDION_TEST_BUCKET}/${KEY}" -

PYTHONPATH=src .venv/bin/python3 -m veridion.action.decision_history \
  --history-path /tmp/veridion-decision-history.ndjson
