#!/usr/bin/env bash
# Run the owner migration from an ephemeral Scaleway instance on Coffre's
# private network, verify the runtime role, and remove the instance again.
set -euo pipefail

cd "$(dirname "$0")/.."

required=(
  COFFRE_DATABASE_CA_CERTIFICATE
  COFFRE_OWNER_DATABASE_URL
  COFFRE_RUNTIME_PASSWORD
  COFFRE_RUNTIME_ROLE
  SCW_DEFAULT_ZONE
)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    printf 'missing required migration environment variable: %s\n' "$name" >&2
    exit 1
  fi
done

for command in curl docker gzip jq node scp scw ssh ssh-keygen; do
  command -v "$command" >/dev/null || {
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 1
  }
done

migration_ref="${GITHUB_SHA:-$(git rev-parse HEAD)}"
migration_tag="coffre-migration:${migration_ref}"
work_directory="$(mktemp -d /tmp/coffre-migration.XXXXXX)"
chmod 700 "$work_directory"
server_id=''
security_group_id=''

cleanup() {
  local exit_code=$?
  local cleanup_failed=false
  trap - EXIT INT TERM
  if [[ -n "$server_id" ]]; then
    if ! scw instance server delete "$server_id" \
      force-shutdown=true with-volumes=all with-ip=true --wait >/dev/null 2>&1; then
      printf 'failed to delete ephemeral migration instance %s\n' "$server_id" >&2
      cleanup_failed=true
    fi
  fi
  if [[ -n "$security_group_id" ]]; then
    security_group_deleted=false
    for _ in {1..12}; do
      if scw instance security-group delete "$security_group_id" >/dev/null 2>&1; then
        security_group_deleted=true
        break
      fi
      sleep 5
    done
    if [[ "$security_group_deleted" != true ]]; then
      printf 'failed to delete ephemeral security group %s\n' "$security_group_id" >&2
      cleanup_failed=true
    fi
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

ssh-keygen -q -t ed25519 -N '' -f "$work_directory/id_ed25519"
public_key="$(<"$work_directory/id_ed25519.pub")"
cat >"$work_directory/cloud-init.yaml" <<EOF
#cloud-config
users:
  - default
  - name: coffre-migrate
    groups: [docker]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${public_key}
ssh_pwauth: false
package_update: true
packages:
  - docker.io
runcmd:
  - [systemctl, enable, --now, docker]
EOF

printf '%s' "$COFFRE_DATABASE_CA_CERTIFICATE" >"$work_directory/database-ca.crt"
chmod 600 "$work_directory/database-ca.crt"

OWNER_DATABASE_URL="$COFFRE_OWNER_DATABASE_URL" \
RUNTIME_PASSWORD="$COFFRE_RUNTIME_PASSWORD" \
RUNTIME_ROLE="$COFFRE_RUNTIME_ROLE" \
node <<'NODE' >"$work_directory/runtime.env"
const url = new URL(process.env.OWNER_DATABASE_URL);
url.username = process.env.RUNTIME_ROLE;
url.password = process.env.RUNTIME_PASSWORD;
process.stdout.write(`DATABASE_URL=${url.toString()}\nCOFFRE_RUNTIME_ROLE=${process.env.RUNTIME_ROLE}\n`);
NODE
printf 'DATABASE_URL=%s\n' "$COFFRE_OWNER_DATABASE_URL" >"$work_directory/owner.env"
chmod 600 "$work_directory/owner.env" "$work_directory/runtime.env"

docker build --file deploy/migration.Dockerfile --tag "$migration_tag" .
docker save "$migration_tag" | gzip -1 >"$work_directory/migration-image.tar.gz"

runner_ip="$(curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://api.ipify.org)"
RUNNER_IP="$runner_ip" node <<'NODE'
import { isIP } from 'node:net';
if (isIP(process.env.RUNNER_IP) !== 4) throw new Error('runner public address is not IPv4');
NODE

private_network_name="${COFFRE_PRIVATE_NETWORK_NAME:-equisafe-coffre}"
private_network_region="${SCW_DEFAULT_ZONE%-*}"
private_network_id="${COFFRE_PRIVATE_NETWORK_ID:-}"
if [[ -z "$private_network_id" ]]; then
  private_network_id="$(
    scw vpc private-network list \
      name="$private_network_name" \
      region="$private_network_region" \
      -o json | jq -er --arg name "$private_network_name" '
        map(select(.name == $name))
        | if length == 1 then .[0].id
          else error("expected exactly one matching private network")
          end
      '
  )"
fi

resource_name="coffre-migrate-${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-1}"
security_group_id="$(
  scw instance security-group create \
    name="$resource_name" \
    description='Ephemeral Coffre migration runner' \
    inbound-default-policy=drop \
    outbound-default-policy=accept \
    stateful=true \
    -o json | jq -er '.id'
)"
scw instance security-group create-rule \
  security-group-id="$security_group_id" \
  protocol=TCP direction=inbound action=accept \
  ip-range="$runner_ip/32" dest-port-from=22 >/dev/null

server_id="$(
  scw instance server create \
    name="$resource_name" \
    type=DEV1-S \
    image=ubuntu_jammy \
    ip=new \
    stopped=true \
    security-group-id="$security_group_id" \
    cloud-init="@$work_directory/cloud-init.yaml" \
    -o json | jq -er '.id'
)"
scw instance private-nic create \
  server-id="$server_id" \
  private-network-id="$private_network_id" >/dev/null
scw instance server start "$server_id" --wait >/dev/null

server_json="$(scw instance server get "$server_id" -o json)"
server_ip="$(jq -er '.public_ip.address // .public_ips[0].address' <<<"$server_json")"
ssh_options=(
  -i "$work_directory/id_ed25519"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="$work_directory/known_hosts"
)

for attempt in {1..60}; do
  if ssh "${ssh_options[@]}" "coffre-migrate@$server_ip" \
    'cloud-init status --wait >/dev/null && docker version >/dev/null' 2>/dev/null; then
    break
  fi
  if [[ "$attempt" == 60 ]]; then
    printf 'ephemeral migration instance did not become ready\n' >&2
    exit 1
  fi
  sleep 5
done

scp "${ssh_options[@]}" \
  "$work_directory/migration-image.tar.gz" \
  "$work_directory/database-ca.crt" \
  "$work_directory/owner.env" \
  "$work_directory/runtime.env" \
  "coffre-migrate@$server_ip:/tmp/"

ssh "${ssh_options[@]}" "coffre-migrate@$server_ip" \
  bash -s -- "$migration_tag" <<'REMOTE'
set -euo pipefail
migration_tag=$1
sudo install -d -m 700 /run/secrets
sudo install -m 600 /tmp/database-ca.crt /run/secrets/coffre-database-ca.crt
gzip -dc /tmp/migration-image.tar.gz | sudo docker load >/dev/null
sudo docker run --rm --network host \
  --user 0:0 \
  --env-file /tmp/owner.env \
  --volume /run/secrets/coffre-database-ca.crt:/run/secrets/coffre-database-ca.crt:ro \
  "$migration_tag"
sudo docker run --rm --network host \
  --user 0:0 \
  --env-file /tmp/runtime.env \
  --volume /run/secrets/coffre-database-ca.crt:/run/secrets/coffre-database-ca.crt:ro \
  "$migration_tag" node src/verify-runtime.ts
sudo shred --remove /tmp/owner.env /tmp/runtime.env /tmp/database-ca.crt \
  /run/secrets/coffre-database-ca.crt
rm -f /tmp/migration-image.tar.gz
REMOTE

printf 'migration and runtime privilege verification succeeded\n'
