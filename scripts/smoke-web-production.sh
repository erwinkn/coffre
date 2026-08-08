#!/usr/bin/env bash
# Exercise the built Worker, Hyperdrive's local binding, Cron heartbeat, and auth boundary.
set -euo pipefail

cd "$(dirname "$0")/.."
./scripts/setup-test-database.sh >/dev/null

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
    -c "UPDATE audit_heartbeat SET last_beat_at = now() - interval '10 minutes' WHERE only_row" \
    >/dev/null

cd apps/web
CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE='postgresql://coffre_runtime:test-runtime-only@127.0.0.1:55432/coffre_test' \
    COFFRE_ACCESS_ISSUER=https://coffre-smoke.cloudflareaccess.com \
    COFFRE_ACCESS_JWKS_URL=https://coffre-smoke.cloudflareaccess.com/cdn-cgi/access/certs \
    COFFRE_ACCESS_AUD=coffre-smoke-aud \
    COFFRE_ROOT_ADMINS=smoke.admin@example.com \
    COFFRE_KEK_LOCAL=Y29mZnJlLWxvY2FsLWRldi1rZWstMzItYnl0ZXMhISE= \
    COFFRE_KEK_ID=coffre-smoke-1 \
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
    echo "Worker preview did not start at $smoke_base:" >&2
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

status="$(curl --silent --output "$smoke_tmp/unauthenticated.json" --write-out '%{http_code}' "$smoke_base/api/me")"
if [[ "$status" != 401 ]] ||
    ! grep -Fq '"error":"cloudflare_access_required"' "$smoke_tmp/unauthenticated.json"; then
    echo 'The production /api boundary did not fail closed without Access:' >&2
    cat "$smoke_tmp/unauthenticated.json" >&2
    exit 1
fi

echo "Worker production smoke passed: $smoke_base; Hyperdrive, Cron readiness, and auth behaved as expected"
