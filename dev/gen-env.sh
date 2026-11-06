#!/usr/bin/env bash
# Generate dev/.env for the development OpenCTI stack.
#
# Every secret is random and local to this machine. An existing file is left
# alone, so the admin token stays stable across restarts; delete dev/.env by
# its full path to regenerate (the volumes keep the old admin account, so
# regenerate only together with `make dev-reset`).
set -euo pipefail

env_file="$(cd "$(dirname "$0")" && pwd)/.env"

if [[ -e "$env_file" ]]; then
  echo "dev/.env already exists; leaving it unchanged"
  exit 0
fi

uuid() { uuidgen | tr '[:upper:]' '[:lower:]'; }
secret() { openssl rand -hex 24; }

umask 077
cat >"$env_file" <<EOF
OPENCTI_BASE_URL=http://localhost:8080
OPENCTI_ADMIN_EMAIL=admin@example.com
OPENCTI_ADMIN_PASSWORD=$(secret)
OPENCTI_ADMIN_TOKEN=$(uuid)
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(secret)
OPENCTI_NODE_MEMORY_MB=4096
ELASTIC_MEMORY_SIZE=2G
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=$(secret)
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=$(secret)
CONNECTOR_IMPORT_FILE_STIX_ID=$(uuid)
CONNECTOR_MITRE_ID=$(uuid)
EOF
echo "wrote dev/.env (mode 600)"
