#!/usr/bin/env bash
# The restore drill of docs/restore.md, on this machine: run the Workers
# example over a seeded database, back the database up with pg_dump,
# restore it into a new one, and run the example over that with the same
# keys, checking everything came back; then once more with the wrong KEK.
#
#   pnpm build && ./scripts/restore-drill.sh
#
# It uses the compose Postgres, the dev IdP for sign-in and .env.dev's keys,
# on ports 3400 to 3402 and 8481 (COFFRE_DEV_PORT, COFFRE_DEV_IDP_PORT). The
# two databases, the processes and the dump go when it ends, however it ends.
set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"
export COMPOSE_PROJECT_NAME=coffre
set -a
# shellcheck disable=SC1091
. ./.env.dev
set +a

port="${COFFRE_DEV_PORT:-3400}"
idp_port="${COFFRE_DEV_IDP_PORT:-8481}"
source_db=coffre_drill
restored_db=coffre_drill_restored
scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-drill.XXXXXX")"
export COFFRE_API_URL="http://127.0.0.1:$port" COFFRE_DEV_IDP_URL="http://127.0.0.1:$idp_port" COFFRE_DEV_IDP_PORT="$idp_port"
owner_url() { echo "postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/$1"; }
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
# the KEK $2: both Workers under wrangler dev, each with its own login.
start_coffre() {
    local state="$scratch/state-$1-$RANDOM"
    (
        cd examples/workers
        export PUBLIC_URL="$COFFRE_API_URL" ROOT_ADMINS="$COFFRE_ROOT_ADMINS" WRANGLER_SEND_METRICS=false
        export GITHUB_CLIENT_ID=coffre-local GITHUB_CLIENT_SECRET=coffre-local-secret
        export APP_KEY="$COFFRE_APP_KEY" VAULT_KEY_ID="$COFFRE_VAULT_KEY_ID" VAULT_KEY="$2"
        export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432/$1"
        export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_VAULT_HYPERDRIVE="postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:55432/$1"
        exec ./node_modules/.bin/wrangler dev -c app/wrangler.jsonc -c vault/wrangler.jsonc \
            --ip 127.0.0.1 --port "$port" --inspector-port "$((port + 2))" --persist-to "$state" \
            --show-interactive-dev-session=false \
            --var "GITHUB_URL:$COFFRE_DEV_IDP_URL/github" --var "GITHUB_API_URL:$COFFRE_DEV_IDP_URL/github/api"
    ) >"$scratch/coffre-$1.log" 2>&1 &
    coffre=$!
    for _ in $(seq 120); do
        if curl -sf "$COFFRE_API_URL/livez" >/dev/null; then return; fi
        sleep 1
    done
    cat "$scratch/coffre-$1.log" >&2
    return 1
}

log 'starting the dev IdP'
node --conditions=coffre:source dev/idp/server.ts >"$scratch/idp.log" 2>&1 &
idp=$!

log "a seeded instance over $source_db"
node scripts/ensure-database.mjs "$source_db"
DATABASE_URL="$(owner_url "$source_db")" pnpm --dir packages/db run db:migrate >/dev/null
start_coffre "$source_db" "$COFFRE_VAULT_KEY"
DATABASE_URL="$(owner_url "$source_db")" node dev/seed.mjs >/dev/null
node scripts/restore-drill.mjs prepare >"$scratch/state.json"
stop_coffre

log "backing up $source_db with pg_dump"
docker compose exec -T postgres pg_dump -U coffre_owner --format=custom --dbname="$source_db" >"$scratch/backup.dump"

log "restoring into $restored_db"
# The logins and their passwords, which a dump of one database leaves out.
node scripts/ensure-database.mjs "$restored_db"
docker compose exec -T postgres pg_restore -U coffre_owner --dbname="$restored_db" --exit-on-error <"$scratch/backup.dump"
# Migrate reasserts database privileges, which a dump of one database leaves out.
DATABASE_URL="$(owner_url "$restored_db")" pnpm --dir packages/db run db:migrate >/dev/null
COFFRE_RUNTIME_ROLE=coffre_runtime DATABASE_URL="postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432/$restored_db" \
    pnpm --dir packages/db run db:verify:runtime >/dev/null

log 'checking the restored instance, with the same keys'
start_coffre "$restored_db" "$COFFRE_VAULT_KEY"
node scripts/restore-drill.mjs check "$scratch/state.json"
COFFRE_TOKEN="$(node -p "JSON.parse(require('fs').readFileSync('$scratch/state.json')).token")" \
COFFRE_CONFORMANCE_CANARY="$(node -p "JSON.parse(require('fs').readFileSync('$scratch/state.json')).canary")" \
    node --conditions=coffre:source packages/cli/src/main.ts verify instance "$COFFRE_API_URL" --canary market/prod/DRILL_CANARY
stop_coffre

log 'once more, with the wrong KEK'
start_coffre "$restored_db" "$(openssl rand -base64 32)"
node scripts/restore-drill.mjs wrong-kek "$scratch/state.json"
stop_coffre

log 'the restore drill passed'
