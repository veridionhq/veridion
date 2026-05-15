#!/usr/bin/env bash
set -euo pipefail

S3_LOCATION="${1:-s3://veridion-prod-events/veridion/events/}"

PYTHONPATH=src .venv/bin/python3 -m veridion.action.athena_queries \
  --database analytics \
  --table veridion_decision_events \
  --s3-location "${S3_LOCATION}" \
  --output-path /tmp/veridion-athena-queries.json

cat /tmp/veridion-athena-queries.json
