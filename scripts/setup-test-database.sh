#!/usr/bin/env bash
# Recreate and migrate a local test database, or the parallel suite's template:
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

-- The app's login, the vault's and the backups', as a deployment provisions them.
DO $$
DECLARE
    login record;
BEGIN
    -- Other checkouts provision these cluster-wide roles too. Match the
    -- lock in ensure-database.mjs rather than racing ALTER ROLE.
    PERFORM pg_advisory_xact_lock(hashtextextended('coffre:local-roles', 0));
    FOR login IN
        SELECT * FROM (VALUES ('coffre_runtime', 'local-runtime-only'), ('coffre_vault_runtime', 'local-vault-only'), ('coffre_backup_login', 'local-backup-only'))
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

DATABASE_URL="postgresql://coffre_owner:local-dev-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$database" \
    pnpm --filter @coffre/db run db:migrate --backup-login coffre_backup_login >/dev/null

# 0.15's hot path's login, which 0022 makes unable to log in: the tests log in
# as it, as a deployment's host gives it a password (docs/deploy.md).
docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d postgres <<'SQL' >/dev/null
DO $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('coffre:local-roles', 0));
    ALTER ROLE coffre_vault_hot LOGIN PASSWORD 'local-hot-only';
END
$$;
SQL

# 0.15's uses go in a partition of their day (0022), which a deployment's
# checkpointer will make ahead (plan PR 7): a run's days, made here, so that
# every clone holds them.
docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d "$database" >/dev/null <<'SQL'
SELECT make_day(current_date - 1), make_day(current_date), make_day(current_date + 1);
SQL
