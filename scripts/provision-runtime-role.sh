#!/usr/bin/env bash
# Create or repair the login used by the API.
set -euo pipefail

cd "$(dirname "$0")/.."

runtime_role="${COFFRE_RUNTIME_ROLE:-coffre_runtime}"
database_name="${COFFRE_DATABASE_NAME:-coffre}"

if [ -n "${COFFRE_OWNER_DATABASE_URL:-}" ]; then
    if [ -z "${COFFRE_RUNTIME_PASSWORD:-}" ]; then
        echo "ERROR: COFFRE_RUNTIME_PASSWORD is required with COFFRE_OWNER_DATABASE_URL." >&2
        exit 1
    fi
    runtime_password="$COFFRE_RUNTIME_PASSWORD"
    psql_command=(psql "$COFFRE_OWNER_DATABASE_URL")
else
    runtime_password="${COFFRE_RUNTIME_PASSWORD:-local-runtime-only}"
    psql_command=(
        docker compose exec -T postgres
        psql -U coffre_owner -d "$database_name"
    )
fi

"${psql_command[@]}" \
    -v runtime_role="$runtime_role" \
    -v runtime_password="$runtime_password" \
    < packages/db/provision-runtime-role.sql
