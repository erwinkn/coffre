#!/usr/bin/env bash
# Exercise the built Worker and its vault, Hyperdrive's local binding, the Cron
# heartbeat and its signed checkpoint, and the auth boundary.
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"

./scripts/setup-test-database.sh >/dev/null

# vite preview serves the last Worker build. Docs and CI treat this script as
# self-contained, so produce that build when it is missing.
if [[ ! -f apps/web/.wrangler/deploy/config.json ]]; then
    echo '==> building Worker (vite preview needs apps/web/.wrangler/deploy/config.json)'
    pnpm --dir apps/web build
fi

# vite preview prefers dist/server/.dev.vars over the process environment.
# A shell that sourced .env.dev (or a prior `vite build`) bakes the HTTP
# local issuer into that file; production auth then 500s /livez.
# Write the smoke contract there so preview cannot inherit the dev IdP.
# The vault Worker reads its own file, beside its own build, and holds every
# key: the app is handed none.
mkdir -p apps/web/dist/server apps/web/dist/coffre_vault
cat >apps/web/dist/server/.dev.vars <<'EOF'
COFFRE_ACCESS_ISSUER=https://coffre-smoke.cloudflareaccess.com
COFFRE_ACCESS_JWKS_URL=https://coffre-smoke.cloudflareaccess.com/cdn-cgi/access/certs
COFFRE_ACCESS_AUD=coffre-smoke-aud
COFFRE_AUDIT_CHAIN_KEY=Y29mZnJlLWxvY2FsLWF1ZGl0LWNoYWluLWtleS0zMmI=
EOF
cat >apps/web/dist/coffre_vault/.dev.vars <<'EOF'
COFFRE_ROOT_ADMINS=smoke.admin@example.com
COFFRE_KEK_LOCAL=Y29mZnJlLWxvY2FsLWRldi1rZWstMzItYnl0ZXMhISE=
COFFRE_KEK_ID=coffre-smoke-1
COFFRE_VAULT_SIGNING_KEY=Y29mZnJlLXNtb2tlLXZhdWx0LXNpZ25pbmctc2VlZCE=
EOF

smoke_port="${SMOKE_PORT:-4173}"
smoke_host="${SMOKE_HOST:-127.0.0.1}"
smoke_base="http://${smoke_host}:${smoke_port}"
smoke_tmp="$(mktemp -d "${TMPDIR:-/tmp}/coffre-worker-smoke.XXXXXX")"
server_pid=''

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf -- "$smoke_tmp"
    exit "$status"
}
trap cleanup EXIT INT TERM

if lsof -iTCP:"$smoke_port" -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "Smoke port $smoke_port is already in use" >&2
    exit 1
fi

# Prove readiness depends on the Cron-driven database signal, not process
# startup. The scheduled handler must turn this deliberately stale row fresh.
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U coffre_owner -d coffre_test \
    -c "UPDATE audit_heartbeat SET last_beat_at = now() - interval '1 hour' WHERE only_row" \
    >/dev/null

cd apps/web
# Drop inherited local-dev auth: cloudflare mode rejects COFFRE_DEV_IDP_URL,
# and wrangler.jsonc already sets COFFRE_AUTH_MODE=cloudflare. Drop the
# vault's inherited keys too, so only its .dev.vars can supply them.
#
# COFFRE_STATE_DIR gives this run's vault an empty store: coffre_test was
# just recreated, and a vault that checkpointed an older log would rightly
# refuse to sign this one.
env -u COFFRE_DEV_IDP_URL -u COFFRE_AUTH_MODE \
    -u COFFRE_ROOT_ADMINS -u COFFRE_KEK_LOCAL -u COFFRE_KEK_ID -u COFFRE_VAULT_SIGNING_KEY \
    COFFRE_STATE_DIR="$smoke_tmp/state" \
    CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE='postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432/coffre_test' \
    COFFRE_ACCESS_ISSUER=https://coffre-smoke.cloudflareaccess.com \
    COFFRE_ACCESS_JWKS_URL=https://coffre-smoke.cloudflareaccess.com/cdn-cgi/access/certs \
    COFFRE_ACCESS_AUD=coffre-smoke-aud \
    COFFRE_AUDIT_CHAIN_KEY=Y29mZnJlLWxvY2FsLWF1ZGl0LWNoYWluLWtleS0zMmI= \
    ./node_modules/.bin/vite preview --host "$smoke_host" --port "$smoke_port" --strictPort \
    >"$smoke_tmp/server.log" 2>&1 &
server_pid=$!

started=false
for _ in {1..100}; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo 'Worker preview exited before it became ready:' >&2
        cat "$smoke_tmp/server.log" >&2
        exit 1
    fi
    if curl --fail --silent "$smoke_base/livez" >/dev/null; then
        started=true
        break
    fi
    sleep 0.1
done

if [[ "$started" != true ]]; then
    echo "Worker preview did not become ready at $smoke_base/livez:" >&2
    curl --silent --show-error --output "$smoke_tmp/livez.body" \
        --write-out 'livez HTTP %{http_code}\n' "$smoke_base/livez" >&2 || true
    cat "$smoke_tmp/livez.body" >&2 || true
    echo >&2
    cat "$smoke_tmp/server.log" >&2
    exit 1
fi

status="$(curl --silent --output "$smoke_tmp/stale.json" --write-out '%{http_code}' "$smoke_base/readyz")"
if [[ "$status" != 503 ]]; then
    echo "Stale audit heartbeat unexpectedly reported ready ($status)" >&2
    cat "$smoke_tmp/stale.json" >&2
    exit 1
fi

curl --fail --silent --show-error \
    "$smoke_base/cdn-cgi/local/scheduled?cron=*/5+*+*+*+*" >/dev/null
curl --fail --silent --show-error "$smoke_base/readyz" >/dev/null

# Each beat also has the vault sign the log's head, and fails (a 500 here)
# if it will not. The second checkpoint must extend the first.
curl --fail --silent --show-error \
    "$smoke_base/cdn-cgi/local/scheduled?cron=*/5+*+*+*+*" >/dev/null

status="$(curl --silent --output "$smoke_tmp/unauthenticated.json" \
    --dump-header "$smoke_tmp/unauthenticated.headers" --write-out '%{http_code}' "$smoke_base/api/me")"
if [[ "$status" != 401 ]] ||
    ! grep -Fq '"error":"unauthenticated"' "$smoke_tmp/unauthenticated.json"; then
    echo 'The production /api boundary did not fail closed without Access:' >&2
    cat "$smoke_tmp/unauthenticated.json" >&2
    exit 1
fi

# Every response, a refusal included, carries the security headers.
if ! grep -Eiq "^content-security-policy: .*script-src 'self' 'nonce-" "$smoke_tmp/unauthenticated.headers" ||
    ! grep -Fiq "frame-ancestors 'none'" "$smoke_tmp/unauthenticated.headers" ||
    ! grep -Fiq 'x-content-type-options: nosniff' "$smoke_tmp/unauthenticated.headers"; then
    echo 'The production Worker did not send its security headers:' >&2
    cat "$smoke_tmp/unauthenticated.headers" >&2
    exit 1
fi

echo "Worker production smoke passed: $smoke_base; Hyperdrive, Cron readiness, vault checkpoints, auth and security headers behaved as expected"
