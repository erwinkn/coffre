#!/usr/bin/env bash
# Enrol this ephemeral CI runner in Cloudflare One, migrate the private Coffre
# database, verify the restricted runtime role, and remove the registration.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly WARP_VERSION='2026.6.880.0'
readonly WARP_KEY_FINGERPRINT='C068A2B5771775193CBE1F2F6E2DD2174FA1C3BA'
readonly WARP_MDM_PATH='/var/lib/cloudflare-warp/mdm.xml'

required=(
  CLOUDFLARE_WARP_CLIENT_ID
  CLOUDFLARE_WARP_CLIENT_SECRET
  CLOUDFLARE_WARP_DEVICE_PROFILE_ID
  CLOUDFLARE_WARP_ORGANIZATION
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
if [[ ! "$CLOUDFLARE_WARP_CLIENT_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
  printf 'CLOUDFLARE_WARP_CLIENT_ID contains unsupported characters\n' >&2
  exit 1
fi
if [[ ! "$CLOUDFLARE_WARP_CLIENT_SECRET" =~ ^[A-Za-z0-9._-]+$ ]]; then
  printf 'CLOUDFLARE_WARP_CLIENT_SECRET contains unsupported characters\n' >&2
  exit 1
fi
if [[ ! "$CLOUDFLARE_WARP_ORGANIZATION" =~ ^[a-z0-9-]+$ ]]; then
  printf 'CLOUDFLARE_WARP_ORGANIZATION must be a Cloudflare team-name slug\n' >&2
  exit 1
fi
if [[ ! "$CLOUDFLARE_WARP_DEVICE_PROFILE_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  printf 'CLOUDFLARE_WARP_DEVICE_PROFILE_ID must be a UUID\n' >&2
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

for command in curl gpg node pnpm sudo timeout; do
  command -v "$command" >/dev/null || {
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 1
  }
done

work_directory="$(mktemp -d "${RUNNER_TEMP:-/tmp}/coffre-warp-migration.XXXXXX")"
chmod 700 "$work_directory"
warp_configured=false

cleanup() {
  local exit_code=$?
  local cleanup_failed=false
  trap - EXIT INT TERM

  if [[ "$warp_configured" == true ]]; then
    sudo rm -f "$WARP_MDM_PATH"
    sudo warp-cli --accept-tos disconnect >/dev/null 2>&1 || true
    if ! sudo warp-cli --accept-tos registration delete >/dev/null 2>&1; then
      printf 'failed to delete this runner WARP registration; scheduled cleanup must remove it\n' >&2
      cleanup_failed=true
    fi
    sudo systemctl stop warp-svc >/dev/null 2>&1 || true
  fi

  if command -v shred >/dev/null; then
    find "$work_directory" -type f -exec shred --remove {} + 2>/dev/null || true
  fi
  find "$work_directory" -type f -exec chmod u+w {} + 2>/dev/null || true
  find "$work_directory" -type f -delete 2>/dev/null || true
  find "$work_directory" -depth -type d -delete 2>/dev/null || true

  if [[ "$cleanup_failed" == true && "$exit_code" == 0 ]]; then
    exit_code=1
  fi
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  https://pkg.cloudflareclient.com/pubkey.gpg \
  >"$work_directory/cloudflare-warp.gpg"
mapfile -t actual_fingerprints < <(
  gpg --show-keys --with-colons --fingerprint "$work_directory/cloudflare-warp.gpg" 2>/dev/null \
    | awk -F: '$1 == "fpr" { print $10 }'
)
if [[ "${#actual_fingerprints[@]}" -ne 1 \
  || "${actual_fingerprints[0]}" != "$WARP_KEY_FINGERPRINT" ]]; then
  printf 'Cloudflare WARP package key fingerprint mismatch\n' >&2
  exit 1
fi

sudo gpg --batch --yes --dearmor \
  --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
  "$work_directory/cloudflare-warp.gpg"
printf '%s\n' \
  'deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ noble main' \
  | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null
sudo apt-get update --quiet
sudo apt-get install --yes --no-install-recommends "cloudflare-warp=$WARP_VERSION"

installed_version="$(dpkg-query --show --showformat='${Version}' cloudflare-warp)"
if [[ "$installed_version" != "$WARP_VERSION" ]]; then
  printf 'unexpected Cloudflare WARP version: %s\n' "$installed_version" >&2
  exit 1
fi

sudo install -d -m 700 /var/lib/cloudflare-warp
sudo install -m 600 /dev/null "$WARP_MDM_PATH"
sudo tee "$WARP_MDM_PATH" >/dev/null <<EOF
<dict>
  <key>auth_client_id</key>
  <string>${CLOUDFLARE_WARP_CLIENT_ID}</string>
  <key>auth_client_secret</key>
  <string>${CLOUDFLARE_WARP_CLIENT_SECRET}</string>
  <key>auto_connect</key>
  <integer>1</integer>
  <key>onboarding</key>
  <false/>
  <key>organization</key>
  <string>${CLOUDFLARE_WARP_ORGANIZATION}</string>
  <key>service_mode</key>
  <string>warp</string>
</dict>
EOF
warp_configured=true
sudo systemctl restart warp-svc

connected=false
for _ in {1..60}; do
  if sudo warp-cli --accept-tos status 2>/dev/null | grep -Fq 'Connected'; then
    connected=true
    break
  fi
  sleep 2
done
if [[ "$connected" != true ]]; then
  printf 'Cloudflare One Client did not connect within 120 seconds\n' >&2
  sudo warp-cli --accept-tos status >&2 || true
  exit 1
fi

active_profile_id=''
for _ in {1..30}; do
  active_profile_id="$({
    sudo warp-cli --accept-tos settings 2>/dev/null \
      | sed -n 's/^[[:space:]]*Profile ID:[[:space:]]*//p' \
      | head -n 1
  } || true)"
  if [[ "$active_profile_id" == "$CLOUDFLARE_WARP_DEVICE_PROFILE_ID" ]]; then
    break
  fi
  sleep 2
done
if [[ "$active_profile_id" != "$CLOUDFLARE_WARP_DEVICE_PROFILE_ID" ]]; then
  printf 'unexpected Cloudflare One device profile: %s\n' "${active_profile_id:-unavailable}" >&2
  exit 1
fi

if ! timeout 10 bash -c ">/dev/tcp/${COFFRE_DATABASE_IP}/${COFFRE_DATABASE_PORT}"; then
  printf 'Coffre database is not reachable through WARP at %s:%s\n' \
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
node scripts/prepare-warp-migration.mjs \
  "$work_directory/owner-url" "$work_directory/runtime-url"

owner_url="$(<"$work_directory/owner-url")"
runtime_url="$(<"$work_directory/runtime-url")"

DATABASE_URL="$owner_url" pnpm --dir packages/db run migrate
DATABASE_URL="$runtime_url" \
COFFRE_RUNTIME_ROLE="$COFFRE_RUNTIME_ROLE" \
node packages/db/src/verify-runtime.ts

printf 'migration over Cloudflare WARP and runtime privilege verification succeeded\n'
