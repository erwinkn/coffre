#!/usr/bin/env bash
# Recreate the isolated local database used by the serial integration suite:
# coffre_test, or the one COFFRE_TEST_DATABASE names.
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
database="${COFFRE_TEST_DATABASE:-coffre_test}"

./scripts/ensure-postgres.sh

docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -v database="$database" -U coffre_owner -d postgres <<'SQL' >/dev/null
DROP DATABASE IF EXISTS :"database" WITH (FORCE);
CREATE DATABASE :"database";

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_runtime') THEN
        CREATE ROLE coffre_runtime
            LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
            PASSWORD 'local-runtime-only';
    ELSE
        ALTER ROLE coffre_runtime
            LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
            PASSWORD 'local-runtime-only';
    END IF;
END
$$;
SQL

DATABASE_URL="postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/$database" \
    pnpm --filter @coffre/server run db:migrate >/dev/null
