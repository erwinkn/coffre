#!/usr/bin/env bash
# Bring the whole local stack up: Postgres, dev IdP, coffre and its vault as
# two Workers under `vite dev` (deployment/), and seed data. coffre signs
# people in with its own page, the dev IdP standing in for GitHub and for an
# OpenID Connect provider.
#
# A second stack can run beside the first, on its own ports and database:
#
#   COFFRE_DEV_PORT=3080 COFFRE_DEV_IDP_PORT=3081 COFFRE_DEV_DATABASE=coffre_two \
#   COFFRE_STATE_DIR=/tmp/coffre-two pnpm dev
#
# Everything here is local. No Cloudflare calls, no real KMS.
set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"
set -a
# Local fixtures, none of them secret; see the file.
# shellcheck disable=SC1091
. ./.env.dev
set +a

port="${COFFRE_DEV_PORT:-3000}"
idp_port="${COFFRE_DEV_IDP_PORT:-8081}"
database="${COFFRE_DEV_DATABASE:-coffre}"
state_dir="${COFFRE_STATE_DIR:-$root/dev/.wrangler/state}"
owner_url="postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/$database"

# What deployment/app/src/server.ts, the dev IdP, the seed and the CLI read. The app's
# Hyperdrive binding reaches Postgres as the restricted runtime login, and
# the vault's as its own.
export COFFRE_PUBLIC_URL="http://127.0.0.1:$port"
export COFFRE_API_URL="$COFFRE_PUBLIC_URL"
export COFFRE_DEV_IDP_URL="http://127.0.0.1:$idp_port"
export COFFRE_DEV_IDP_PORT="$idp_port"
export COFFRE_STATE_DIR="$state_dir"
export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432/$database"
export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_VAULT_HYPERDRIVE="postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:55432/$database"

log() { printf '\n==> %s\n' "$1"; }

# Fail early and legibly if a previous run is still holding a port. Otherwise
# the first symptom is an EADDRINUSE stack trace from whichever service lost
# the race, several steps after the real problem.
busy=''
for p in "$idp_port" "$port"; do
    if lsof -iTCP:"$p" -sTCP:LISTEN -t >/dev/null 2>&1; then
        busy="${busy} ${p}"
    fi
done
if [ -n "$busy" ]; then
    echo "ERROR: port(s) already in use:${busy}" >&2
    echo "  Another coffre stack is probably still running. Stop it with:" >&2
    echo "    kill \$(lsof -iTCP:$idp_port -iTCP:$port -sTCP:LISTEN -t)" >&2
    exit 1
fi

cleanup() {
    log 'stopping'
    job_pids=()
    while IFS= read -r job_pid; do
        job_pids+=("$job_pid")
    done < <(jobs -p)
    if ((${#job_pids[@]} > 0)); then
        kill "${job_pids[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

log 'starting Postgres'
./scripts/ensure-postgres.sh

log "applying migrations to $database"
node scripts/ensure-database.mjs "$database"
DATABASE_URL="$owner_url" pnpm --dir packages/db run db:migrate >/dev/null

# Service logs go to files rather than stdout so the seed output stays legible.
logs="$root/.logs"
mkdir -p "$logs"

log "starting dev IdP on :$idp_port"
node --conditions=coffre:source dev/idp/server.ts >"$logs/dev-idp.log" 2>&1 &
sleep 1

log "starting coffre and its vault on :$port"
# The packages' sources, for the Vite config's own imports (@coffre/ui/vite) as for the app's.
NODE_OPTIONS="--conditions=coffre:source ${NODE_OPTIONS:-}" ./dev/node_modules/.bin/vite dev dev/deployment/app --port "$port" --strictPort >"$logs/web.log" 2>&1 &
until curl -sf "$COFFRE_PUBLIC_URL/livez" >/dev/null 2>&1; do sleep 1; done

log 'seeding'
DATABASE_URL="$owner_url" node dev/seed.mjs

cli="node --conditions=coffre:source packages/cli/src/main.ts"
cat <<BANNER

  coffre is up.

    web + API   $COFFRE_PUBLIC_URL   (either button, then admin@acme.example
                or another persona)
    vault       beside it, reached only through the app's VAULT binding
    dev IdP     $COFFRE_DEV_IDP_URL

  CLI (a device login: approve it in the browser):
    $cli login $COFFRE_PUBLIC_URL
    $cli run market/dev -- printenv

  Logs:
    tail -f $logs/web.log $logs/dev-idp.log

  Ctrl-C to stop.

BANNER

wait
