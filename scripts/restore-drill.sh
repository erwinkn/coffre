#!/usr/bin/env bash
# The restore drill of docs/restore.md, on this machine: run the Workers
# example over a seeded database, back the database up with `coffre backup`,
# restore it into a new one with `coffre restore --keys`, and run the
# example over that with the same keys, checking everything came back; then
# `coffre verify backup` with the wrong vault key, and the example once more
# with the wrong KEK.
#
#   pnpm build && ./scripts/restore-drill.sh
#
# It uses the compose Postgres, the dev IdP for sign-in and .env.dev's keys,
# on ports 3400 to 3402 and 8481 (COFFRE_DEV_PORT, COFFRE_DEV_IDP_PORT), over
# coffre_drill, coffre_drill_restored and coffre_drill_scratch
# (COFFRE_DRILL_DATABASE names the first), and PostgreSQL's pg_dump and
# pg_restore on PATH, of the compose server's major version, 16. The
# databases, the processes and the dump go when it ends, however it ends.
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
scratch_db="${source_db}_scratch"
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
    for db in "$source_db" "$restored_db" "$scratch_db"; do
        psql_as_owner -d postgres -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" || true
    done
    rm -rf "$scratch"
}
trap cleanup EXIT

# The Workers example, as `coffre init` writes it, over database $1, with
# the KEK $2: both Workers under wrangler dev, each with its own login, the
# app as it builds, behind conformance's entry for wrangler dev. Each start
# keeps its Durable Objects' storage apart: the checkpointer's memory starts
# empty, as docs/restore.md resets it after a restore ("On 0.15's log").
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
        export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HOT_HYPERDRIVE="postgresql://coffre_vault_hot:local-hot-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$1"
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

# Every connection string and key reaches the CLI on stdin, as in a pipeline; never an argument.
cli() { HOME="$scratch/home" node --conditions=coffre:source packages/cli/src/main.ts "$@"; }
mkdir -p "$scratch/home"

log "backing up $source_db with coffre backup, as coffre_backup_login"
backup_url="postgresql://coffre_backup_login:local-backup-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$source_db"
printf '%s' "$backup_url" | cli backup "$scratch/backup.dump"

log "restoring into $restored_db with coffre restore, checked with the keys"
# The logins and their passwords, which a dump of one database leaves out.
node --conditions=coffre:source scripts/ensure-database.mjs "$restored_db"
printf '%s\n%s\n%s\n' "$(owner_url "$restored_db")" "$COFFRE_VAULT_KEY" "$COFFRE_APP_KEY" | cli restore "$scratch/backup.dump" --keys

log 'checking the backup again, with the wrong vault key'
node --conditions=coffre:source scripts/ensure-database.mjs "$scratch_db"
if printf '%s\n%s\n%s\n' "$(owner_url "$scratch_db")" "$(openssl rand -base64 32)" "$COFFRE_APP_KEY" | cli verify backup "$scratch/backup.dump" --keys >"$scratch/wrong-key.log" 2>&1; then
    cat "$scratch/wrong-key.log" >&2
    echo 'coffre verify backup passed with the wrong vault key' >&2
    exit 1
fi
grep "none of the vault keys given is this instance's" "$scratch/wrong-key.log" || { cat "$scratch/wrong-key.log" >&2; exit 1; }

# Migrate reasserts database privileges, which a dump of one database leaves out.
DATABASE_URL="$(owner_url "$restored_db")" pnpm --dir packages/db run db:migrate --backup-login coffre_backup_login >/dev/null
COFFRE_RUNTIME_ROLE=coffre_runtime DATABASE_URL="postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$restored_db" \
    pnpm --dir packages/db run db:verify:runtime >/dev/null

log 'checking the restored instance, with the same keys'
start_coffre "$restored_db" "$COFFRE_VAULT_KEY"
node scripts/restore-drill.mjs check "$scratch/state.json"
# As CI does: the token piped to `coffre login --token`, in a home of the
# drill's own, then the canary's value to the check; never an argument.
state() { node -p "JSON.parse(require('fs').readFileSync('$scratch/state.json')).$1"; }
state token | cli login "$COFFRE_DEV_URL" --token >/dev/null
state canary | cli verify instance "$COFFRE_DEV_URL" --canary market/prod/DRILL_CANARY
stop_coffre

log 'once more, with the wrong KEK'
start_coffre "$restored_db" "$(openssl rand -base64 32)"
node scripts/restore-drill.mjs wrong-kek "$scratch/state.json"
stop_coffre

log 'the restore drill passed'
