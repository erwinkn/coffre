#!/usr/bin/env bash
# Migrate the private Coffre database from its dedicated self-hosted runner and
# verify that the application role remains restricted.
set -euo pipefail

cd "$(dirname "$0")/.."

required=(
  COFFRE_DATABASE_CA_CERTIFICATE
  COFFRE_DATABASE_IP
  COFFRE_DATABASE_PORT
  COFFRE_OWNER_DATABASE_URL
  COFFRE_RUNTIME_PASSWORD
  COFFRE_RUNTIME_ROLE
)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    printf 'missing required migration environment variable: %s\n' "$name" >&2
    exit 1
  fi
done

if [[ "$COFFRE_RUNTIME_ROLE" != 'coffre_runtime' ]]; then
  printf 'COFFRE_RUNTIME_ROLE must be coffre_runtime; the database grants name this fixed role\n' >&2
  exit 1
fi
if [[ ! "$COFFRE_DATABASE_IP" =~ ^[0-9.]+$ ]]; then
  printf 'COFFRE_DATABASE_IP must be an IPv4 address\n' >&2
  exit 1
fi
if [[ "$COFFRE_DATABASE_PORT" != '5432' ]]; then
  printf 'COFFRE_DATABASE_PORT must be 5432\n' >&2
  exit 1
fi

for command in node pnpm timeout; do
  command -v "$command" >/dev/null || {
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 1
  }
done

work_directory="$(mktemp -d "${RUNNER_TEMP:-/tmp}/coffre-private-migration.XXXXXX")"
chmod 700 "$work_directory"

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM

  if command -v shred >/dev/null; then
    find "$work_directory" -type f -exec shred --remove {} + 2>/dev/null || true
  fi
  find "$work_directory" -type f -exec chmod u+w {} + 2>/dev/null || true
  find "$work_directory" -type f -delete 2>/dev/null || true
  find "$work_directory" -depth -type d -delete 2>/dev/null || true

  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! timeout 10 bash -c ">/dev/tcp/${COFFRE_DATABASE_IP}/${COFFRE_DATABASE_PORT}"; then
  printf 'Coffre database is not reachable from the migration runner at %s:%s\n' \
    "$COFFRE_DATABASE_IP" "$COFFRE_DATABASE_PORT" >&2
  exit 1
fi

printf '%s' "$COFFRE_DATABASE_CA_CERTIFICATE" >"$work_directory/database-ca.crt"
chmod 600 "$work_directory/database-ca.crt"

OWNER_DATABASE_URL="$COFFRE_OWNER_DATABASE_URL" \
DATABASE_PRIVATE_IP="$COFFRE_DATABASE_IP" \
DATABASE_PORT="$COFFRE_DATABASE_PORT" \
DATABASE_CA_PATH="$work_directory/database-ca.crt" \
RUNTIME_PASSWORD="$COFFRE_RUNTIME_PASSWORD" \
RUNTIME_ROLE="$COFFRE_RUNTIME_ROLE" \
node scripts/prepare-private-migration.mjs \
  "$work_directory/owner-url" "$work_directory/runtime-url"

owner_url="$(<"$work_directory/owner-url")"
runtime_url="$(<"$work_directory/runtime-url")"

DATABASE_URL="$owner_url" pnpm --dir packages/db run migrate
DATABASE_URL="$runtime_url" \
COFFRE_RUNTIME_ROLE="$COFFRE_RUNTIME_ROLE" \
node packages/db/src/verify-runtime.ts

printf 'private database migration and runtime privilege verification succeeded\n'
