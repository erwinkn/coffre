#!/usr/bin/env bash
# The upgrade Equisafe will make, on a Postgres of the script's own: from
# 0.14.5 through 0.15.0 to this checkout, on Workers (state-rows.md, section 6,
# "How it is tested"; Node is not checked in 0.16.0, D198).
#
#   pnpm build && pnpm upgrade:check [--port <n>] [<dir>]
#
#   1. 0.14.5, as `coffre init --workers` writes it, from npm, filled by its
#      own conformance on a database kept for the run; the suite stops before
#      the checks that break the log for good (upgrade-check.mjs, `fill`).
#   2. 0.15.0, as `init` writes it: its `coffre migrate`, then its first
#      request cuts the log over.
#   3. On 0.15.0, as the Owner: `coffre verify log` green, a beat, then the
#      audit API's pages (heartbeats and checkpoints left out) and every
#      removed member's offboarding report, saved.
#   4. What this checkout's migrations would lose refused first (`lists`),
#      then its `coffre migrate`, and its Workers example started on the
#      same database, keys and Durable Objects' storage.
#   5. The same entries in the same order, the same reports, a use through
#      the credential proxy, a change, and `coffre verify log` green.
#
# It checks the data, not the deployment's files: each version is a fresh
# `init`, and the last this checkout's example, where Equisafe runs `coffre
# update` and `coffre setup` on its own folder (both ask questions and touch
# Cloudflare). `pnpm test:consumer` holds what `init` writes.
#
# About 4 minutes, 3 of them 0.14.5's conformance. It needs network (npm),
# Docker and this checkout built. It starts a Postgres of its own (a compose
# project and a free port, never the shared :55432), uses ports <n> to <n>+2
# (3282 by default) and a temporary directory, or <dir>, which is kept for a
# look and cleared on the next run; every CLI runs with a home inside it and
# `--url`, never yours. The Postgres, every process it started and the
# temporary directory go when it ends, however it ends but SIGKILL.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
from=0.14.5
through=0.15.0
port=3282
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --port) port="${2:?--port needs a number}"; shift 2 ;;
        *) echo "upgrade-check: unknown option $1" >&2; exit 2 ;;
    esac
done
if ! [[ "$port" =~ ^[0-9]{4,5}$ ]] || ((port < 1024 || port + 2 > 65535)); then
    echo "upgrade-check: --port takes a port from 1024 to 65533, the first of three" >&2
    exit 2
fi
started=$SECONDS
caller_home="$HOME"
log() { printf '==> [%dm%02ds] %s\n' $(((SECONDS - started) / 60)) $(((SECONDS - started) % 60)) "$1"; }

# Every process the script started, however deep (conformance's wrangler and
# workerd, the IdP, a deployment): a signal that ends the script reaches none
# of them by itself.
descendants() {
    local table
    table="$(ps -eo pid=,ppid=)"
    awk -v root=$$ '{ parent[$1] = $2 } END {
        for (p in parent) { q = p; while (q in parent && q != root) q = parent[q]; if (q == root && p != root) print p }
    }' <<<"$table"
}
# Processes, or process groups as -<pid>: TERM, then KILL what is left after 5 s.
stop() {
    (($#)) || return 0
    kill -TERM -- "$@" 2>/dev/null || true
    for _ in $(seq 50); do
        kill -0 -- "$@" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -KILL -- "$@" 2>/dev/null || true
}
work=''
keep=false
postgres=false
finish() {
    local result=$? newest pids
    set +eu
    mapfile -t pids < <(descendants)
    stop "${pids[@]}"
    # As the caller, whose HOME holds docker's compose plugin.
    if [[ "$postgres" == true ]]; then
        (cd "$root" && HOME="$caller_home" docker compose down --volumes --remove-orphans) >/dev/null 2>&1 ||
            echo "upgrade-check: could not remove Postgres $COMPOSE_PROJECT_NAME; COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME docker compose down --volumes" >&2
    fi
    if ((result != 0)); then
        # The step that failed wrote last.
        newest="$(ls -t "$work"/*.log 2>/dev/null | head -n 1)"
        [[ -z "$newest" ]] || printf -- '--- %s, last lines\n%s\n' "$newest" "$(tail -n 40 "$newest")" >&2
        echo "upgrade check failed after $((SECONDS - started)) s" >&2
    fi
    [[ "$keep" == true || -z "$work" ]] || rm -rf -- "$work"
}
trap finish EXIT

if [[ -n "${1:-}" ]]; then
    work="$1"
    keep=true
else
    work="$(mktemp -d "${TMPDIR:-/tmp}/coffre-upgrade.XXXXXX")"
fi
case "$work" in
"$root" | "$root"/*)
    echo "upgrade-check: $work is inside the workspace; give it a directory outside" >&2
    keep=true
    exit 2
    ;;
esac
mkdir -p "$work"
work="$(cd "$work" && pwd)"
# A kept directory's last run: its Durable Objects' storage and CLI home would meet a new database.
rm -rf -- "$work/state" "$work/home"

export COFFRE_POSTGRES_PORT
COFFRE_POSTGRES_PORT="$(node -e "const s = require('node:net').createServer().listen(0, '127.0.0.1', () => { console.log(s.address().port); s.close(); })")"
[[ "$COFFRE_POSTGRES_PORT" != 55432 ]] || { echo "upgrade-check: picked the shared Postgres port" >&2; exit 1; }
export COMPOSE_PROJECT_NAME="coffre_upgrade_$(openssl rand -hex 4)"
database=coffre_upgrade
pg="127.0.0.1:$COFFRE_POSTGRES_PORT"
owner="postgresql://coffre_owner:local-dev-only@$pg"
runtime="postgresql://coffre_runtime:local-runtime-only@$pg/$database"
vault_runtime="postgresql://coffre_vault_runtime:local-vault-only@$pg/$database"
hot_runtime="postgresql://coffre_vault_hot:local-hot-only@$pg/$database"
# localhost, not 127.0.0.1, from 0.15.0 on, as a deploy keeps its URL: this
# checkout refuses passkeys at an IP address, and wrangler, on 127.0.0.1, answers it.
origin="http://localhost:$port"
idp_origin="http://127.0.0.1:$((port + 1))"
store="$(pnpm --dir "$root" store path)"
# shellcheck source=compat/release.sh
. "$root/scripts/compat/release.sh"

log "Postgres $COMPOSE_PROJECT_NAME on :$COFFRE_POSTGRES_PORT"
postgres=true
"$root/scripts/ensure-postgres.sh"
# The logins the deployments run as, made once for the cluster.
node --conditions=coffre:source "$root/scripts/ensure-database.mjs" coffre >/dev/null
export HOME="$work/home" npm_config_update_notifier=false
mkdir -p "$HOME"

build() ( cd "$1" && ./node_modules/.bin/vite build app )

# A deployment of $1 serving $database, on conformance's keys and Owner, as
# its harness runs one: both Workers under wrangler dev, the app as it
# builds, and the Durable Objects' storage in $work/state, kept from one
# version to the next, as a deploy keeps it (0.14.5's conformance writes it
# there too, `fill`).
coffre=''
serve() {
    local project="$1" config
    quietly "building $(basename "$project")'s app" "$work/$(basename "$project")-build.log" build "$project"
    config="$(node "$root/packages/conformance/src/draining.ts" "$project/app/dist/server")"
    (
        cd "$project"
        # conformance's keys, which 0.14.5's conformance filled the database with.
        eval "$(node --input-type=module -e "
            const { KEYS } = await import('$root/packages/conformance/src/fixtures.ts');
            for (const [name, value] of Object.entries(KEYS)) console.log(\`export \${name}='\${value}'\`);
        ")"
        export PUBLIC_URL="$origin" OWNERS=root@conformance.example WRANGLER_SEND_METRICS=false
        export GITHUB_CLIENT_ID=coffre-local GITHUB_CLIENT_SECRET=coffre-local-secret
        export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="$runtime"
        export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_VAULT_HYPERDRIVE="$vault_runtime"
        export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HOT_HYPERDRIVE="$hot_runtime"
        exec setsid ./node_modules/.bin/wrangler dev -c "$config" -c vault/wrangler.jsonc \
            --ip 127.0.0.1 --port "$port" --inspector-port "$((port + 2))" --persist-to "$work/state" \
            --show-interactive-dev-session=false \
            --var "GITHUB_URL:$idp_origin/github" --var "GITHUB_API_URL:$idp_origin/github/api"
    ) >"$work/$(basename "$project").log" 2>&1 &
    coffre=$!
    for _ in $(seq 120); do
        if curl -sf "http://localhost:$port/livez" >/dev/null; then return; fi # pins: local
        kill -0 "$coffre" 2>/dev/null || break
        sleep 1
    done
    echo "upgrade-check: $(basename "$project") did not start; see $work/$(basename "$project").log" >&2
    exit 1
}

# `coffre migrate`, as a deployment's pipeline runs it, in its folder ($1), the owner's URL
# piped in: the rest is the CLI, which refuses a folder that pins another version.
migrate() {
    local dir=$1
    shift
    (cd "$dir" && echo "$owner/$database" | "$@" migrate --yes)
}

log "coffre $from, as init writes it (--workers), filled by its own conformance on $database"
release "$from" workers "$work/coffre-$from"
node "$root/scripts/upgrade-check.mjs" fill "$work/coffre-$from/node_modules/@coffre/conformance/dist/main.js" "$database" "$work/state"
quietly "coffre $from's conformance" "$work/coffre-$from-conformance.log" \
    pnpm --dir "$work/coffre-$from" conformance --postgres "$owner" --runtime "${runtime%/*}" --vault-runtime "${vault_runtime%/*}" --port "$port"
tail -n 1 "$work/coffre-$from-conformance.log" | sed 's/^/    /'

log "coffre $through, as init writes it: migrated, then cut over by its first request"
release "$through" workers "$work/coffre-$through"
quietly "coffre $through's migrate" "$work/coffre-$through-migrate.log" \
    migrate "$work/coffre-$through" ./node_modules/.bin/coffre
# This checkout's dev IdP signs the Owner in from here on: a GitHub account is the same for any IdP, by its email.
env -u COFFRE_DEV_PUBLIC_URL -u COFFRE_DEV_IDP_PUBLIC_URL COFFRE_DEV_IDP_PORT=$((port + 1)) \
    setsid node --conditions=coffre:source "$root/dev/idp/server.ts" >"$work/idp.log" 2>&1 &
serve "$work/coffre-$through"
node --conditions=coffre:source "$root/scripts/upgrade-check.mjs" before "$origin" "$idp_origin" "$work/before.json" -- \
    "$work/coffre-$through/node_modules/.bin/coffre"
stop "-$coffre"
wait "$coffre" 2>/dev/null || true
coffre=''

log "this checkout: what its migrations would lose refused, its migrate, and its Workers example on the same database"
node --conditions=coffre:source "$root/scripts/upgrade-check.mjs" lists "$owner/$database"
cli=(node --conditions=coffre:source "$root/packages/cli/src/main.ts")
quietly "this checkout's migrate" "$work/migrate.log" migrate "$root/examples/workers" "${cli[@]}"
serve "$root/examples/workers"
node --conditions=coffre:source "$root/scripts/upgrade-check.mjs" after "$origin" "$idp_origin" "$work/before.json" -- "${cli[@]}"

log "the upgrade check passed, in $((SECONDS - started)) s"
