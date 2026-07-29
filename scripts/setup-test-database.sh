#!/usr/bin/env bash
# Recreate the isolated local database used by the serial integration suite.
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"

docker compose up -d postgres >/dev/null
until docker compose exec -T postgres \
    pg_isready -U coffre_owner -d postgres >/dev/null 2>&1; do
    sleep 1
done

docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d postgres <<'SQL' >/dev/null
DROP DATABASE IF EXISTS coffre_test WITH (FORCE);
CREATE DATABASE coffre_test;
SQL

COFFRE_DATABASE_NAME=coffre_test ./scripts/migrate.sh >/dev/null
COFFRE_DATABASE_NAME=coffre_test \
COFFRE_RUNTIME_ROLE=coffre_test_app \
COFFRE_RUNTIME_PASSWORD=test-runtime-only \
    ./scripts/provision-runtime-role.sh >/dev/null
