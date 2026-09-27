#!/usr/bin/env bash
# Bring the whole local stack up: Postgres, dev IdP, the web app, and seed data.
#
#   pnpm dev          dev mode: the dev IdP's persona picker stands in for
#                     Cloudflare Access
#   pnpm dev:signin   coffre's own sign-in page, with the dev IdP standing in
#                     for GitHub and for an OpenID Connect provider
#
# Everything here is local. No Scaleway calls, no Cloudflare calls, no real KMS.
set -euo pipefail

# The Wrangler environment in apps/web/wrangler.jsonc.
mode="${1:-development}"
case "$mode" in
    development | signin) ;;
    *)
        echo "usage: $0 [signin]" >&2
        exit 2
        ;;
esac

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
set -a
# Local developer configuration is intentionally untracked.
# shellcheck disable=SC1091
. ./.env.dev
set +a

log() { printf '\n==> %s\n' "$1"; }

# Fail early and legibly if a previous run is still holding a port. Otherwise
# the first symptom is an EADDRINUSE stack trace from whichever service lost
# the race, several steps after the real problem.
busy=''
for port in 8081 3000; do
    if lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
        busy="${busy} ${port}"
    fi
done
if [ -n "$busy" ]; then
    echo "ERROR: port(s) already in use:${busy}" >&2
    echo "  Another coffre stack is probably still running. Stop it with:" >&2
    echo "    kill \$(lsof -iTCP:8081 -iTCP:3000 -sTCP:LISTEN -t)" >&2
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
docker compose up -d postgres
until docker compose exec -T postgres pg_isready -U coffre_owner -d coffre >/dev/null 2>&1; do
    sleep 1
done

log 'applying migrations'
# Production creates this login in Terraform. Local development creates the
# same narrowly-scoped login before Drizzle validates and grants membership.
if ! docker compose exec -T postgres psql -U coffre_owner -d postgres -tAc \
    "SELECT 1 FROM pg_roles WHERE rolname = 'coffre_runtime'" | grep -q 1; then
    docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U coffre_owner -d postgres \
        -c "CREATE ROLE coffre_runtime LOGIN PASSWORD 'local-runtime-only'" >/dev/null
fi
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U coffre_owner -d postgres \
    -c "ALTER ROLE coffre_runtime LOGIN PASSWORD 'local-runtime-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS" >/dev/null
DATABASE_URL='postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre' \
    pnpm --dir packages/db run migrate >/dev/null

# Service logs go to files rather than stdout so the seed output stays legible.
mkdir -p .logs

log 'starting dev IdP on :8081'
node apps/dev-idp/src/server.ts > .logs/dev-idp.log 2>&1 &
sleep 1

log "starting web app on :3000 ($mode)"
export CLOUDFLARE_ENV="$mode"
export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="$DATABASE_URL"
# The dev IdP and the seed refuse anything but dev mode, so only the web app
# is told otherwise, and sign-in mode refuses a dev IdP URL.
web_env=(env)
if [ "$mode" = signin ]; then
    web_env=(env -u COFFRE_DEV_IDP_URL COFFRE_AUTH_MODE=signin)
fi
(cd apps/web && "${web_env[@]}" ./node_modules/.bin/vite dev) > .logs/web.log 2>&1 &
until curl -sf http://127.0.0.1:3000/livez >/dev/null 2>&1; do sleep 1; done

# The seed writes through the API with dev IdP tokens, which only dev mode
# accepts. Sign-in mode keeps whatever the last `pnpm dev` left, or starts
# empty, as a new deployment does.
if [ "$mode" = development ]; then
    log 'seeding'
    DATABASE_URL='postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre' \
        node scripts/seed.mjs
fi

if [ "$mode" = signin ]; then
    cat <<'BANNER'

  coffre is up, with its own sign-in page, and the data `pnpm dev` last
  seeded (not seeded again here).

    web + API   http://127.0.0.1:3000   (either button, then admin@acme.example)
    dev IdP     http://127.0.0.1:8081

  CLI (a device login: approve it in the browser):
    node apps/cli/src/main.ts login http://127.0.0.1:3000
    node apps/cli/src/main.ts run market/dev -- printenv
BANNER
else
    cat <<'BANNER'

  coffre is up.

    web + API   http://127.0.0.1:3000   (sign in as admin@acme.example)
    dev IdP     http://127.0.0.1:8081

  CLI:
    node --env-file=.env.dev apps/cli/src/main.ts login --email admin@acme.example
    node --env-file=.env.dev apps/cli/src/main.ts run market/dev -- printenv
    node --env-file=.env.dev apps/cli/src/main.ts verify
BANNER
fi
cat <<'BANNER'

  Logs:
    tail -f .logs/web.log .logs/dev-idp.log

  Ctrl-C to stop.

BANNER

wait
