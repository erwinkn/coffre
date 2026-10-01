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

-- The app's login and the vault's, as a deployment provisions them.
DO $$
DECLARE
    login record;
BEGIN
    FOR login IN
        SELECT * FROM (VALUES ('coffre_runtime', 'local-runtime-only'), ('coffre_vault_runtime', 'local-vault-only'))
            AS logins (name, password)
    LOOP
        EXECUTE format(
            '%s ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
            CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = login.name) THEN 'ALTER' ELSE 'CREATE' END,
            login.name,
            login.password
        );
    END LOOP;
END
$$;
SQL

DATABASE_URL="postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/$database" \
    pnpm --filter @coffre/db run db:migrate >/dev/null
