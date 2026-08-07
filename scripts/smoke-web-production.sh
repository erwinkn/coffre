#!/usr/bin/env bash
# Exercise the built single service, its health contract, auth boundary, and shutdown.
set -euo pipefail

cd "$(dirname "$0")/.."
./scripts/setup-test-database.sh >/dev/null
cd apps/web

smoke_port="${SMOKE_PORT:-0}"
smoke_host="${SMOKE_HOST:-127.0.0.1}"
smoke_tmp="$(mktemp -d "${TMPDIR:-/tmp}/coffre-web-smoke.XXXXXX")"
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

PORT="$smoke_port" HOST="$smoke_host" \
    NITRO_PORT="$smoke_port" NITRO_HOST="$smoke_host" TEST='' \
    DATABASE_URL='postgresql://coffre_runtime:test-runtime-only@127.0.0.1:55432/coffre_test' \
    COFFRE_AUTH_MODE=cloudflare \
    COFFRE_ACCESS_ISSUER=https://coffre-smoke.cloudflareaccess.com \
    COFFRE_ACCESS_JWKS_URL=https://coffre-smoke.cloudflareaccess.com/cdn-cgi/access/certs \
    COFFRE_ACCESS_AUD=coffre-smoke-aud COFFRE_DEV_IDP_URL='' \
    COFFRE_ROOT_ADMINS=smoke.admin@example.com \
    COFFRE_KEK_LOCAL=Y29mZnJlLWxvY2FsLWRldi1rZWstMzItYnl0ZXMhISE= \
    COFFRE_AUDIT_CHAIN_KEY=Y29mZnJlLWxvY2FsLWF1ZGl0LWNoYWluLWtleS0zMmI= \
    node ../../scripts/start-web-production.mjs \
    >"$smoke_tmp/server.log" 2>&1 &
server_pid=$!

ready=false
smoke_base=''
for _ in {1..100}; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo 'Web production server exited before it became ready:' >&2
        cat "$smoke_tmp/server.log" >&2
        exit 1
    fi

    smoke_base="$(
        sed -n 's/.*Listening on: \(http[^ ]*\).*/\1/p' "$smoke_tmp/server.log" |
            tail -1
    )"
    smoke_base="${smoke_base%/}"
    if [[ -n "$smoke_base" ]] &&
        curl --fail --silent --show-error "$smoke_base/livez" >/dev/null &&
        curl --fail --silent --show-error "$smoke_base/readyz" >/dev/null; then
        ready=true
        break
    fi
    sleep 0.1
done

if [[ "$ready" != true ]]; then
    echo "Web production server did not become ready at $smoke_base:" >&2
    cat "$smoke_tmp/server.log" >&2
    exit 1
fi

status="$(curl --silent --output "$smoke_tmp/unauthenticated.json" --write-out '%{http_code}' "$smoke_base/api/me")"
if [[ "$status" != 401 ]] ||
    ! grep -Fq '"error":"cloudflare_access_required"' "$smoke_tmp/unauthenticated.json"; then
    echo 'The production /api boundary did not fail closed without Access:' >&2
    cat "$smoke_tmp/unauthenticated.json" >&2
    exit 1
fi

assigned_port="$(node -e 'console.log(new URL(process.argv[1]).port)' "$smoke_base")"
if PORT="$assigned_port" HOST="$smoke_host" \
    NITRO_PORT="$assigned_port" NITRO_HOST="$smoke_host" TEST='' \
    DATABASE_URL='postgresql://coffre_runtime:test-runtime-only@127.0.0.1:55432/coffre_test' \
    COFFRE_AUTH_MODE=cloudflare \
    COFFRE_ACCESS_ISSUER=https://coffre-smoke.cloudflareaccess.com \
    COFFRE_ACCESS_JWKS_URL=https://coffre-smoke.cloudflareaccess.com/cdn-cgi/access/certs \
    COFFRE_ACCESS_AUD=coffre-smoke-aud COFFRE_DEV_IDP_URL='' \
    COFFRE_ROOT_ADMINS=smoke.admin@example.com \
    COFFRE_KEK_LOCAL=Y29mZnJlLWxvY2FsLWRldi1rZWstMzItYnl0ZXMhISE= \
    COFFRE_AUDIT_CHAIN_KEY=Y29mZnJlLWxvY2FsLWF1ZGl0LWNoYWluLWtleS0zMmI= \
    node ../../scripts/start-web-production.mjs \
    >"$smoke_tmp/collision.log" 2>&1; then
    echo 'A second production server reported success on the occupied smoke port:' >&2
    cat "$smoke_tmp/collision.log" >&2
    exit 1
fi

kill -TERM "$server_pid"
if ! wait "$server_pid"; then
    echo 'Web production server did not shut down cleanly on SIGTERM:' >&2
    cat "$smoke_tmp/server.log" >&2
    exit 1
fi
server_pid=''

echo "Web production smoke passed: $smoke_base; auth, collision, and SIGTERM behaved as expected"
