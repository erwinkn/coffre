#!/usr/bin/env bash
# The load rig's infrastructure: a Postgres of its own, sized as Equisafe's
# (2 vCPU, 2 GB), and PgBouncer in front of it, in transaction mode, standing
# in for Hyperdrive's pool: locally, workerd's Hyperdrive binding opens a new
# Postgres connection per call, a fork and an authentication each, which the
# real one does not. Each pinned to cores of its own.
#
#   BENCH_DIR=~/scratch/<id> BENCH_PG_PORT=57120 BENCH_POOL_PORT=57121 rig.sh up|down
#   BENCH_PG_CPUS=76-81 (a quota of 2 CPUs over them) BENCH_POOL_CPUS=82
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
: "${BENCH_DIR:?}" "${BENCH_PG_PORT:?}" "${BENCH_POOL_PORT:?}"
pg_cpus="${BENCH_PG_CPUS:-76-81}"
pool_cpus="${BENCH_POOL_CPUS:-82}"
database="${BENCH_DATABASE:-coffre_bench}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:?a compose project of your own}" COFFRE_POSTGRES_PORT="$BENCH_PG_PORT"
pool="${COMPOSE_PROJECT_NAME}-pgbouncer"
mkdir -p "$BENCH_DIR/pgbouncer"

if [[ "${1:-}" == down ]]; then
  docker rm -f "$pool" >/dev/null 2>&1 || true
  (cd "$root" && docker compose -f docker-compose.yml -f "$BENCH_DIR/compose.bench.yml" down -v)
  exit 0
fi

cat > "$BENCH_DIR/compose.bench.yml" <<YML
services:
  postgres:
    command: ["postgres", "-c", "shared_preload_libraries=pg_stat_statements", "-c", "pg_stat_statements.track=top", "-c", "max_connections=200", "-c", "track_io_timing=on", "-c", "shared_buffers=512MB", "-c", "effective_cache_size=1536MB"]
    cpuset: "$pg_cpus"
    cpus: 2
    mem_limit: 2g
    memswap_limit: 2g
    shm_size: 256m
YML
(cd "$root" && docker compose -f docker-compose.yml -f "$BENCH_DIR/compose.bench.yml" up -d postgres)
for _ in $(seq 60); do
  (cd "$root" && docker compose exec -T postgres pg_isready -h 127.0.0.1 -U coffre_owner -d postgres >/dev/null 2>&1) && break
  sleep 1
done
(cd "$root" && node --conditions=coffre:source scripts/ensure-database.mjs "$database")
(cd "$root" && DATABASE_URL="postgresql://coffre_owner:local-dev-only@127.0.0.1:$BENCH_PG_PORT/$database" node --conditions=coffre:source packages/db/src/migrate-main.ts)
# After the migrations, which alter every relation of the schema they find, an extension's views too.
(cd "$root" && docker compose exec -T postgres psql -U coffre_owner -d "$database" -qc 'CREATE EXTENSION IF NOT EXISTS pg_stat_statements')

cat > "$BENCH_DIR/pgbouncer/pgbouncer.ini" <<INI
[databases]
$database = host=127.0.0.1 port=$BENCH_PG_PORT dbname=$database
${database}014 = host=127.0.0.1 port=$BENCH_PG_PORT dbname=${database}014
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = $BENCH_POOL_PORT
unix_socket_dir =
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
admin_users = coffre_owner
pool_mode = transaction
default_pool_size = 20
max_client_conn = 5000
max_prepared_statements = 500
ignore_startup_parameters = extra_float_digits,options,statement_timeout,lock_timeout,idle_in_transaction_session_timeout
INI
cat > "$BENCH_DIR/pgbouncer/userlist.txt" <<TXT
"coffre_runtime" "local-runtime-only"
"coffre_vault_runtime" "local-vault-only"
"coffre_owner" "local-dev-only"
TXT
chmod 644 "$BENCH_DIR/pgbouncer/"*
docker rm -f "$pool" >/dev/null 2>&1 || true
docker run -d --name "$pool" --network host --cpuset-cpus "$pool_cpus" --cpus 1 -m 256m \
  -v "$BENCH_DIR/pgbouncer:/etc/pgbouncer:ro" --entrypoint pgbouncer edoburu/pgbouncer:latest /etc/pgbouncer/pgbouncer.ini >/dev/null
sleep 1
PGPASSWORD=local-runtime-only psql -h 127.0.0.1 -p "$BENCH_POOL_PORT" -U coffre_runtime -d "$database" -tAc 'select 1' >/dev/null
echo "rig up: postgres :$BENCH_PG_PORT (cpus $pg_cpus), pgbouncer :$BENCH_POOL_PORT (cpu $pool_cpus)"
