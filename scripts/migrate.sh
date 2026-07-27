#!/usr/bin/env bash
# Apply migrations in filename order, each exactly once, each in one transaction.
#
# ON_ERROR_STOP is not optional: without it psql reports success after a failed
# statement, which for a schema that encodes an audit guarantee would be a very
# expensive thing to get wrong.
set -euo pipefail

cd "$(dirname "$0")/.."

psql_run() {
    docker compose exec -T postgres \
        psql -v ON_ERROR_STOP=1 -U coffre_owner -d coffre "$@"
}

# Ledger of what has already been applied. Without this, re-running the script
# fails on 0001 with "relation already exists" -- which is exactly how `pnpm dev`
# broke on every run after the first.
psql_run -q <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
    name       text PRIMARY KEY,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
SQL

# One-time adoption path for databases created before the ledger existed.
#
# Only fires when the ledger is empty AND the schema is clearly already there.
# Narrow on purpose: it must not be able to mark a genuinely un-applied
# migration as applied.
ledger_count="$(psql_run -tAc 'SELECT count(*) FROM schema_migrations')"
schema_exists="$(psql_run -tAc \
    "SELECT to_regclass('public.audit_log') IS NOT NULL")"

if [ "$ledger_count" = "0" ] && [ "$schema_exists" = "t" ]; then
    echo "==> existing schema found with an empty ledger; recording a baseline"
    for file in packages/db/migrations/*.sql; do
        psql_run -q -c "INSERT INTO schema_migrations (name, checksum) VALUES ('$(basename "$file")', '$(shasum -a 256 "$file" | cut -d' ' -f1)')"
    done
fi

applied_any=false

for file in packages/db/migrations/*.sql; do
    name="$(basename "$file")"
    checksum="$(shasum -a 256 "$file" | cut -d' ' -f1)"

    recorded="$(psql_run -tAc \
        "SELECT checksum FROM schema_migrations WHERE name = '${name}'")"

    if [ -n "$recorded" ]; then
        if [ "$recorded" != "$checksum" ]; then
            # An already-applied migration was edited. Silently ignoring that
            # would mean the live schema no longer matches the file that claims
            # to describe it.
            echo "ERROR: ${name} has changed since it was applied." >&2
            echo "  applied: ${recorded}" >&2
            echo "  on disk: ${checksum}" >&2
            echo "  Write a new migration instead of editing an applied one." >&2
            exit 1
        fi
        echo "==> ${name} already applied"
        continue
    fi

    echo "==> applying ${name}"
    # The migration and its ledger entry commit together, so a failure halfway
    # through cannot leave the ledger claiming success.
    {
        cat "$file"
        printf "\nINSERT INTO schema_migrations (name, checksum) VALUES ('%s', '%s');\n" \
            "$name" "$checksum"
    } | psql_run -q --single-transaction
    applied_any=true
done

if [ "$applied_any" = true ]; then
    echo "==> migrations applied"
else
    echo "==> schema already up to date"
fi
