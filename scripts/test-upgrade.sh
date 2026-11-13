#!/usr/bin/env bash
# The upgrade from 0.14 (docs/design/0.16.md, "Upgrade from 0.14") on a
# disposable cluster, since it sets the runtime logins NOLOGIN, which are the
# cluster's. A 0.14 database with a row of every kind is upgraded in place
# (packages/db/test/upgrade/from-0.14.ts); then three databases must have one
# schema, line for line: that one, one migrated from nothing, and one made
# from schema.ts alone, as drizzle-kit writes it.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-upgrade.XXXXXX")"
container="coffre-upgrade-${scratch##*.}"
cleanup() {
    docker rm -fv "$container" >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT
image="$(docker compose config --format json | node -e 'let input=""; for await (const chunk of process.stdin) input+=chunk; console.log(JSON.parse(input).services.postgres.image)')"
docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=local-bootstrap-only \
    -p 127.0.0.1::5432 "$image" >/dev/null
for attempt in $(seq 60); do
    if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    if ((attempt == 60)); then docker logs "$container"; exit 1; fi
    sleep 1
done
port="$(docker port "$container" 5432/tcp | cut -d: -f2)"
as_superuser() { docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -qU postgres "$@"; }
as_owner() { docker exec -i -e PGPASSWORD=local-owner-only "$container" psql -X -v ON_ERROR_STOP=1 -q -h 127.0.0.1 -U migration_owner "$@"; }
url() { echo "postgresql://migration_owner:local-owner-only@127.0.0.1:$port/$1"; }

# Managed hosts give the owner CREATEROLE, not superuser: it makes the logins, so it may set them NOLOGIN.
as_superuser -c "CREATE ROLE migration_owner LOGIN CREATEROLE CREATEDB PASSWORD 'local-owner-only'"
as_owner -d postgres <<'SQL'
CREATE ROLE coffre_runtime LOGIN PASSWORD 'local-runtime-only';
CREATE ROLE coffre_vault_runtime LOGIN PASSWORD 'local-vault-only';
CREATE DATABASE coffre_fresh;
CREATE DATABASE coffre_declared;
SQL

DATABASE_URL="$(url postgres)" node --conditions=coffre:source --test packages/db/test/upgrade/from-0.14.ts

DATABASE_URL="$(url coffre_fresh)" pnpm --filter @coffre/db run db:migrate >/dev/null
(cd packages/db && pnpm exec drizzle-kit generate --dialect postgresql --schema ./src/schema.ts --out "$scratch/declared" >/dev/null)
sed 's/--> statement-breakpoint//' "$scratch"/declared/*.sql | as_owner -d coffre_declared

for database in coffre_upgraded coffre_fresh coffre_declared; do
    as_owner -At -d "$database" < packages/db/test/upgrade/catalog.sql > "$scratch/$database.txt"
done
[[ -s "$scratch/coffre_declared.txt" ]]
diff "$scratch/coffre_declared.txt" "$scratch/coffre_fresh.txt" || { echo "a database migrated from nothing does not have schema.ts's schema (declared < > migrated)"; exit 1; }
diff "$scratch/coffre_declared.txt" "$scratch/coffre_upgraded.txt" || { echo "a database upgraded from 0.14 does not have schema.ts's schema (declared < > upgraded)"; exit 1; }
echo "upgrade from 0.14: every row converted, and $(wc -l < "$scratch/coffre_declared.txt") lines of schema agree across the three databases"
