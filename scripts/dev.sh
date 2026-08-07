#!/usr/bin/env bash
# Bring the whole local stack up: Postgres, dev IdP, the web app, and seed data.
#
# Everything here is local. No Scaleway calls, no Cloudflare calls, no real KMS.
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
set -a && . ./.env.dev && set +a

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
    kill $(jobs -p) 2>/dev/null || true
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
    pnpm --dir packages/db migrate >/dev/null

# Service logs go to files rather than stdout so the seed output stays legible.
mkdir -p .logs

log 'starting dev IdP on :8081'
node apps/dev-idp/src/server.ts > .logs/dev-idp.log 2>&1 &
sleep 1

log 'starting web app on :3000'
(cd apps/web && ./node_modules/.bin/vite dev) > .logs/web.log 2>&1 &
until curl -sf http://127.0.0.1:3000/livez >/dev/null 2>&1; do sleep 1; done

log 'seeding'
DATABASE_URL='postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre' \
    node scripts/seed.mjs

cat <<'BANNER'

  coffre is up.

    web + API   http://127.0.0.1:3000   (sign in as erwin@equisafe.io)
    dev IdP     http://127.0.0.1:8081

  CLI:
    node --env-file=.env.dev apps/cli/src/main.ts login --email erwin@equisafe.io
    node --env-file=.env.dev apps/cli/src/main.ts run market/dev -- printenv
    node --env-file=.env.dev apps/cli/src/main.ts verify

  Logs:
    tail -f .logs/web.log .logs/dev-idp.log

  Ctrl-C to stop.

BANNER

wait
