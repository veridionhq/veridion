#!/usr/bin/env bash
set -euo pipefail

: "${VERIDION_STORE_DSN:?VERIDION_STORE_DSN is required}"

exec veridion-history-store migrate --store-dsn "${VERIDION_STORE_DSN}"
