#!/usr/bin/env bash
# Bring the whole local stack up: Postgres, dev IdP, API, admin UI, and seed data.
#
# Everything here is local. No Scaleway calls, no Cloudflare calls, no real KMS.
set -euo pipefail

cd "$(dirname "$0")/.."
set -a && . ./.env.dev && set +a

log() { printf '\n==> %s\n' "$1"; }

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
./scripts/migrate.sh >/dev/null

log 'starting dev IdP on :8081'
node apps/dev-idp/src/server.ts &
sleep 1

log 'starting API on :8080'
node apps/api/src/server.ts &
until curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; do sleep 1; done

log 'seeding'
node scripts/seed.mjs

log 'starting admin UI on :3000'
(cd apps/admin && ./node_modules/.bin/next dev -p 3000) &

cat <<'BANNER'

  coffre is up.

    admin UI    http://127.0.0.1:3000   (sign in as erwin@equisafe.io)
    API         http://127.0.0.1:8080
    dev IdP     http://127.0.0.1:8081

  CLI:
    node apps/cli/src/main.ts login --email erwin@equisafe.io
    node apps/cli/src/main.ts run market/dev -- printenv

  Ctrl-C to stop.

BANNER

wait
