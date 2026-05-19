#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${VERIDION_CONFIG_PATH:-/tmp/veridion-history-service.config.json}"
PORT="${PORT:-8787}"

cat > "${CONFIG_PATH}" <<EOF
{
  "service_name": "${VERIDION_SERVICE_NAME:-Veridion Hosted Control Plane}",
  "store_dsn": "${VERIDION_STORE_DSN:-}",
  "materialization_root": "${VERIDION_MATERIALIZATION_ROOT:-/mnt/veridion-materialized}",
  "jwt": {
    "issuer": "${VERIDION_JWT_ISSUER:-}",
    "audience": "${VERIDION_JWT_AUDIENCE:-}",
    "jwks_url": "${VERIDION_JWKS_URL:-}",
    "oidc_discovery_url": "${VERIDION_OIDC_DISCOVERY_URL:-}"
  },
  "tokens": ${VERIDION_SERVICE_TOKENS_JSON:-[]},
  "tenants": ${VERIDION_TENANTS_JSON:-[]},
  "schedules": ${VERIDION_SCHEDULES_JSON:-[]}
}
EOF

exec veridion-history-service \
  --config-path "${CONFIG_PATH}" \
  --host 0.0.0.0 \
  --port "${PORT}"
