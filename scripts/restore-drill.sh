#!/usr/bin/env bash
# The restore drill of docs/restore.md, on this machine: run the Workers
# example over a seeded database, back it up with pg_dump as the backup
# login, restore it with pg_restore into a new database, and run the example
# over that with the same keys and a signer whose storage is new, as a
# restore deploys: everything comes back, and the signer goes on from the
# backup's head with nothing to report. Then the example once more with the
# wrong KEK, which serves nothing.
#
#   pnpm build && ./scripts/restore-drill.sh
#
# It uses the compose Postgres and its own pg_dump and pg_restore, the dev
# IdP for sign-in and .env.dev's keys, on ports 3400 to 3402 and 8481
# (COFFRE_DEV_PORT, COFFRE_DEV_IDP_PORT), over coffre_drill and
# coffre_drill_restored (COFFRE_DRILL_DATABASE names the first). It waits a
# minute and more for the signer's first check. The databases, the
# processes and the dump go when it ends, however it ends.
set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
set -a
# shellcheck disable=SC1091
. ./.env.dev
set +a

port="${COFFRE_DEV_PORT:-3400}"
idp_port="${COFFRE_DEV_IDP_PORT:-8481}"
source_db="${COFFRE_DRILL_DATABASE:-coffre_drill}"
restored_db="${source_db}_restored"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-drill.XXXXXX")"
export COFFRE_DEV_URL="http://127.0.0.1:$port" COFFRE_DEV_IDP_URL="http://127.0.0.1:$idp_port" COFFRE_DEV_IDP_PORT="$idp_port"
# The drill's stack is never behind a tunnel, whatever the shell exports.
export COFFRE_DEV_PUBLIC_URL="$COFFRE_DEV_URL" COFFRE_DEV_IDP_PUBLIC_URL="$COFFRE_DEV_IDP_URL"
owner_url() { echo "postgresql://coffre_owner:local-dev-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$1"; }
psql_as_owner() { docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -qU coffre_owner "$@"; }
log() { printf '\n==> %s\n' "$1"; }

idp=''
coffre=''
stop_coffre() {
    if [ -n "$coffre" ]; then kill "$coffre" 2>/dev/null || true; wait "$coffre" 2>/dev/null || true; fi
    coffre=''
}
cleanup() {
    stop_coffre
    if [ -n "$idp" ]; then kill "$idp" 2>/dev/null || true; fi
    for db in "$source_db" "$restored_db"; do
        psql_as_owner -d postgres -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" || true
    done
    rm -rf "$scratch"
}
trap cleanup EXIT

# The Workers example, as `coffre init` writes it, over database $1, with
# the KEK $2: both Workers under wrangler dev, each with its own login, the
# app as it builds, behind conformance's entry for wrangler dev.
app_config=''
start_coffre() {
    local state="$scratch/state-$1-$RANDOM"
    (
        cd examples/workers
        export PUBLIC_URL="$COFFRE_DEV_URL" OWNERS="$COFFRE_OWNERS" WRANGLER_SEND_METRICS=false
        export GITHUB_CLIENT_ID=coffre-local GITHUB_CLIENT_SECRET=coffre-local-secret
        export APP_KEY="$COFFRE_APP_KEY" VAULT_KEY_ID="$COFFRE_VAULT_KEY_ID" VAULT_KEY="$2"
        export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$1"
        export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_VAULT_HYPERDRIVE="postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$1"
        exec ./node_modules/.bin/wrangler dev -c "$app_config" -c vault/wrangler.jsonc \
            --ip 127.0.0.1 --port "$port" --inspector-port "$((port + 2))" --persist-to "$state" \
            --show-interactive-dev-session=false \
            --var "GITHUB_URL:$COFFRE_DEV_IDP_URL/github" --var "GITHUB_API_URL:$COFFRE_DEV_IDP_URL/github/api"
    ) >"$scratch/coffre-$1.log" 2>&1 &
    coffre=$!
    for _ in $(seq 120); do
        if curl -sf "$COFFRE_DEV_URL/livez" >/dev/null; then return; fi
        sleep 1
    done
    cat "$scratch/coffre-$1.log" >&2
    return 1
}

log 'starting the dev IdP'
node --conditions=coffre:source dev/idp/server.ts >"$scratch/idp.log" 2>&1 &
idp=$!

log 'building the app'
(cd examples/workers && ./node_modules/.bin/vite build app >"$scratch/build.log" 2>&1) || { cat "$scratch/build.log" >&2; exit 1; }
app_config="$(node packages/conformance/src/draining.ts examples/workers/app/dist/server)"

log "a seeded instance over $source_db"
node --conditions=coffre:source scripts/ensure-database.mjs "$source_db"
DATABASE_URL="$(owner_url "$source_db")" pnpm --dir packages/db run db:migrate --backup-login coffre_backup_login >/dev/null
start_coffre "$source_db" "$COFFRE_VAULT_KEY"
DATABASE_URL="$(owner_url "$source_db")" node --conditions=coffre:source dev/seed.mjs >/dev/null
node scripts/restore-drill.mjs prepare >"$scratch/state.json"
stop_coffre

log "backing up $source_db with pg_dump, as coffre_backup_login"
# The compose server's own tools, of its version: the dump on this machine's disk.
docker compose exec -T -e PGPASSWORD=local-backup-only postgres \
    pg_dump -h 127.0.0.1 -U coffre_backup_login --format=custom --enable-row-security -d "$source_db" >"$scratch/backup.dump"

log "restoring into $restored_db with pg_restore"
node --conditions=coffre:source scripts/ensure-database.mjs "$restored_db"
docker compose exec -T postgres pg_restore -U coffre_owner --no-owner --exit-on-error --single-transaction -d "$restored_db" <"$scratch/backup.dump"
# Migrate reasserts database privileges, which a dump of one database leaves out.
DATABASE_URL="$(owner_url "$restored_db")" pnpm --dir packages/db run db:migrate --backup-login coffre_backup_login >/dev/null
COFFRE_RUNTIME_ROLE=coffre_runtime DATABASE_URL="postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$restored_db" \
    pnpm --dir packages/db run db:verify:runtime >/dev/null

log 'checking the restored instance, with the same keys and a signer whose storage is new'
start_coffre "$restored_db" "$COFFRE_VAULT_KEY"
node scripts/restore-drill.mjs check "$scratch/state.json"
log "the signer's first check, a minute on"
sleep 70
grep -F "a log begun that it did not sign, from its head" "$scratch/coffre-$restored_db.log" >/dev/null || { cat "$scratch/coffre-$restored_db.log" >&2; echo 'the signer did not say it went on from the head' >&2; exit 1; }
if grep -F "coffre's signer reports" "$scratch/coffre-$restored_db.log" >&2; then echo 'the signer found something in the restored database' >&2; exit 1; fi
# The log has no hole: one entry per number, and the head counts them all.
[[ "$(psql_as_owner -d "$restored_db" -At -c 'SELECT count(*) = max(seq) + 1 AND count(*) = (SELECT size FROM log_head) FROM log')" == t ]] || { echo 'the log has a hole, or its head does not count it' >&2; exit 1; }
echo "    the signer went on from the backup's head, found nothing, and the log has no hole"
stop_coffre

log 'once more, with the wrong KEK'
start_coffre "$restored_db" "$(openssl rand -base64 32)"
node scripts/restore-drill.mjs wrong-kek "$scratch/state.json"
stop_coffre

log 'the restore drill passed'
