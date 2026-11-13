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
# Reaching it from another machine (a tunnel such as `bb connect expose`): name
# the URLs a browser uses, and sign in there.
#
#   COFFRE_DEV_PUBLIC_URL=https://app.example COFFRE_DEV_IDP_PUBLIC_URL=https://idp.example pnpm dev
#
# coffre then takes its cookies, redirect URIs and origin checks from the first,
# and the dev IdP sends browsers, and names itself as its issuer, at the second.
# What one service calls another (the app reaching the IdP, the seed reaching
# the API) stays on loopback, so a tunnel that only lets a person's browser
# through is fine. Each is optional; unset, nothing changes. The dev IdP signs
# anyone in as anyone: expose it only behind a tunnel that gates who may open it.
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
owner_url="postgresql://coffre_owner:local-dev-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$database"

# What deployment/app/src/server.ts, the dev IdP and the seed read. The app's
# Hyperdrive binding reaches Postgres as the restricted runtime login, and
# the vault's as its own.
local_url="http://127.0.0.1:$port"
export COFFRE_DEV_URL="$local_url"
export COFFRE_DEV_IDP_URL="http://127.0.0.1:$idp_port"
# What a browser uses: the tunnels' URLs when given, else the loopback ones.
export COFFRE_DEV_PUBLIC_URL="${COFFRE_DEV_PUBLIC_URL:-$local_url}"
export COFFRE_DEV_IDP_PUBLIC_URL="${COFFRE_DEV_IDP_PUBLIC_URL:-$COFFRE_DEV_IDP_URL}"
COFFRE_DEV_PUBLIC_URL="${COFFRE_DEV_PUBLIC_URL%/}"
COFFRE_DEV_IDP_PUBLIC_URL="${COFFRE_DEV_IDP_PUBLIC_URL%/}"
for public in "$COFFRE_DEV_PUBLIC_URL" "$COFFRE_DEV_IDP_PUBLIC_URL"; do
    if ! [[ "$public" =~ ^https?://[^/?#@]+$ ]]; then
        echo "ERROR: $public is not an origin: expected scheme://host[:port], with no path, query or credentials" >&2
        exit 1
    fi
done
# A tunnel to one service is no use signed in to through the other's loopback address.
if [ "$COFFRE_DEV_PUBLIC_URL" = "$local_url" ] && [ "$COFFRE_DEV_IDP_PUBLIC_URL" != "$COFFRE_DEV_IDP_URL" ] ||
    [ "$COFFRE_DEV_PUBLIC_URL" != "$local_url" ] && [ "$COFFRE_DEV_IDP_PUBLIC_URL" = "$COFFRE_DEV_IDP_URL" ]; then
    echo "warning: only one of COFFRE_DEV_PUBLIC_URL and COFFRE_DEV_IDP_PUBLIC_URL is set; sign-in from another machine needs both" >&2
fi
export COFFRE_PUBLIC_URL="$COFFRE_DEV_PUBLIC_URL"
export COFFRE_DEV_IDP_PORT="$idp_port"
export COFFRE_STATE_DIR="$state_dir"
export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$database"
export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_VAULT_HYPERDRIVE="postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}/$database"

# The dev IdP's GitHub App's private key, PKCS #1 as GitHub downloads one:
# made once, local, and handed to the dev IdP and to the app.
github_app_key="$state_dir/github-app.pem"
if [ ! -f "$github_app_key" ]; then
    mkdir -p "$state_dir"
    node -e 'process.stdout.write(require("node:crypto").generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" }))' >"$github_app_key"
fi
COFFRE_DEV_GITHUB_APP_KEY="$(cat "$github_app_key")"
export COFFRE_DEV_GITHUB_APP_KEY

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
node --conditions=coffre:source scripts/ensure-database.mjs "$database"
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
until curl -sf "$COFFRE_DEV_URL/livez" >/dev/null 2>&1; do sleep 1; done

log 'seeding'
DATABASE_URL="$owner_url" node --conditions=coffre:source dev/seed.mjs

cli="node --conditions=coffre:source packages/cli/src/main.ts"
cat <<BANNER

  coffre is up.

    web + API   $COFFRE_DEV_PUBLIC_URL   (either button, then admin@acme.example
                or another persona)
    vault       beside it, reached only through the app's VAULT binding
    dev IdP     $COFFRE_DEV_IDP_PUBLIC_URL

  CLI, on this machine (a device login: approve it in the browser):
    $cli login $COFFRE_DEV_URL
    $cli run market/dev -- printenv

  Logs:
    tail -f $logs/web.log $logs/dev-idp.log

  Ctrl-C to stop.

BANNER

wait
