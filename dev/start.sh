#!/usr/bin/env bash
# Bring the whole local stack up: Postgres, dev IdP, coffre and its vault as
# two Workers under `vite dev` (deployment/), and seed data.
#
#   pnpm dev          dev mode: the dev IdP's persona picker stands in for
#                     Cloudflare Access
#   pnpm dev:signin   coffre's own sign-in page, with the dev IdP standing in
#                     for GitHub and for an OpenID Connect provider
#
# A second stack can run beside the first, on its own ports and database:
#
#   COFFRE_DEV_PORT=3080 COFFRE_DEV_IDP_PORT=3081 COFFRE_DEV_DATABASE=coffre_two \
#   COFFRE_STATE_DIR=/tmp/coffre-two pnpm dev
#
# Everything here is local. No Cloudflare calls, no real KMS.
set -euo pipefail

mode="${1:-dev}"
case "$mode" in
    dev | signin) ;;
    *)
        echo "usage: $0 [signin]" >&2
        exit 2
        ;;
esac

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

# What deployment/app.ts, the dev IdP, the seed and the CLI read. The app's
# Hyperdrive binding reaches Postgres as the restricted runtime login.
export COFFRE_AUTH_MODE="$mode"
export COFFRE_PUBLIC_URL="http://127.0.0.1:$port"
export COFFRE_API_URL="$COFFRE_PUBLIC_URL"
export COFFRE_DEV_IDP_URL="http://127.0.0.1:$idp_port"
export COFFRE_DEV_IDP_PORT="$idp_port"
export COFFRE_STATE_DIR="$state_dir"
export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432/$database"

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
DATABASE_URL="$owner_url" pnpm --dir packages/server run db:migrate >/dev/null

# Service logs go to files rather than stdout so the seed output stays legible.
logs="$root/.logs"
mkdir -p "$logs"

log "starting dev IdP on :$idp_port"
COFFRE_AUTH_MODE=dev node dev/idp/src/server.ts >"$logs/dev-idp.log" 2>&1 &
sleep 1

# The seed starts the app's database over, so the vault starts over with it:
# its grants and audit checkpoints describe that database and no other.
if [ "$mode" = dev ]; then
    rm -rf "$state_dir/v3/do/coffre-dev-vault-VaultObject"
fi

log "starting coffre and its vault on :$port ($mode)"
./dev/node_modules/.bin/vite dev --config dev/vite.config.ts --port "$port" --strictPort >"$logs/web.log" 2>&1 &
until curl -sf "$COFFRE_PUBLIC_URL/livez" >/dev/null 2>&1; do sleep 1; done

# The seed writes through the API with dev IdP tokens, which only dev mode
# accepts. Sign-in mode keeps whatever the last `pnpm dev` left, or starts
# empty, as a new deployment does.
if [ "$mode" = dev ]; then
    log 'seeding'
    DATABASE_URL="$owner_url" node dev/seed.mjs
fi

cli="node packages/cli/src/main.ts"
if [ "$mode" = signin ]; then
    cat <<BANNER

  coffre is up, with its own sign-in page, and the data \`pnpm dev\` last
  seeded (not seeded again here).

    web + API   $COFFRE_PUBLIC_URL   (either button, then admin@acme.example)
    vault       beside it, reached only through the app's VAULT binding
    dev IdP     $COFFRE_DEV_IDP_URL

  CLI (a device login: approve it in the browser):
    $cli login $COFFRE_PUBLIC_URL
    $cli run market/dev -- printenv
BANNER
else
    cat <<BANNER

  coffre is up.

    web + API   $COFFRE_PUBLIC_URL   (sign in as admin@acme.example)
    vault       beside it, reached only through the app's VAULT binding
    dev IdP     $COFFRE_DEV_IDP_URL

  CLI:
    COFFRE_API_URL=$COFFRE_API_URL COFFRE_DEV_IDP_URL=$COFFRE_DEV_IDP_URL \\
      node --env-file=.env.dev packages/cli/src/main.ts login --email admin@acme.example
    … then \`run market/dev -- printenv\` or \`verify\` the same way
BANNER
fi
cat <<BANNER

  Logs:
    tail -f $logs/web.log $logs/dev-idp.log

  Ctrl-C to stop.

BANNER

wait
