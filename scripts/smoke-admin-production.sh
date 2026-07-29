#!/usr/bin/env bash
# Prove the built admin bundle is an HTTP server, not only a fetch handler.
set -euo pipefail

cd "$(dirname "$0")/../apps/admin"

smoke_port="${SMOKE_PORT:-0}"
smoke_host="${SMOKE_HOST:-127.0.0.1}"
smoke_tmp="$(mktemp -d "${TMPDIR:-/tmp}/coffre-admin-smoke.XXXXXX")"
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
    COFFRE_AUTH_MODE=cloudflare \
    COFFRE_ACCESS_ISSUER=https://coffre-smoke.cloudflareaccess.com \
    COFFRE_ACCESS_JWKS_URL=https://coffre-smoke.cloudflareaccess.com/cdn-cgi/access/certs \
    COFFRE_ACCESS_AUD=coffre-smoke-aud COFFRE_DEV_IDP_URL='' \
    COFFRE_API_URL=https://api-smoke.example.test \
    node ../../scripts/start-admin-production.mjs \
    >"$smoke_tmp/server.log" 2>&1 &
server_pid=$!

ready=false
smoke_url=''
for _ in {1..100}; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo 'Admin production server exited before it became ready:' >&2
        cat "$smoke_tmp/server.log" >&2
        exit 1
    fi

    listening_url="$(
        sed -n 's/.*Listening on: \(http[^ ]*\).*/\1/p' "$smoke_tmp/server.log" |
            tail -1
    )"
    if [[ -n "$listening_url" ]]; then
        smoke_url="${listening_url%/}/login"
    fi

    if [[ -n "$smoke_url" ]] &&
        curl --fail --silent --show-error "$smoke_url" \
        --output "$smoke_tmp/login.html" 2>/dev/null; then
        if grep -Fq '<h1>Cloudflare Access required</h1>' "$smoke_tmp/login.html"; then
            ready=true
            break
        fi
    fi

    sleep 0.1
done

if [[ "$ready" != true ]]; then
    echo "Admin production server did not serve the login page at $smoke_url:" >&2
    cat "$smoke_tmp/server.log" >&2
    exit 1
fi

assigned_port="$(node -e 'console.log(new URL(process.argv[1]).port)' "$smoke_url")"
if PORT="$assigned_port" HOST="$smoke_host" \
    NITRO_PORT="$assigned_port" NITRO_HOST="$smoke_host" TEST='' \
    COFFRE_AUTH_MODE=cloudflare \
    COFFRE_ACCESS_ISSUER=https://coffre-smoke.cloudflareaccess.com \
    COFFRE_ACCESS_JWKS_URL=https://coffre-smoke.cloudflareaccess.com/cdn-cgi/access/certs \
    COFFRE_ACCESS_AUD=coffre-smoke-aud COFFRE_DEV_IDP_URL='' \
    COFFRE_API_URL=https://api-smoke.example.test \
    node ../../scripts/start-admin-production.mjs \
    >"$smoke_tmp/collision.log" 2>&1; then
    echo 'A second production server reported success on the occupied smoke port:' >&2
    cat "$smoke_tmp/collision.log" >&2
    exit 1
fi

echo "Admin production smoke passed: $smoke_url; occupied port failed as expected"
