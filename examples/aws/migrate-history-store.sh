#!/usr/bin/env bash
set -euo pipefail

: "${VERIDION_STORE_DSN:?set VERIDION_STORE_DSN to a postgres:// or postgresql:// DSN}"

veridion-history-store migrate \
  --store-dsn "$VERIDION_STORE_DSN"

veridion-history-store status \
  --store-dsn "$VERIDION_STORE_DSN"
