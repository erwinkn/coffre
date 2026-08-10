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

DATABASE_URL='postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre_test' \
    pnpm --filter @coffre/db run migrate >/dev/null
