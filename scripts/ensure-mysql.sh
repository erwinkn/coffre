#!/usr/bin/env bash
# Start the compose MySQL only when nothing answers on :53306 yet.
#
# As with ensure-postgres.sh, a server that already answers is left exactly
# as it is, whoever started it.
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"

answers() {
    (exec 3<>/dev/tcp/127.0.0.1/53306) 2>/dev/null
}

answers && exit 0
docker compose --profile mysql up -d mysql >/dev/null
# The image initialises with networking off, so a TCP ping means ready.
until docker compose exec -T mysql \
    mysqladmin ping -h 127.0.0.1 -u root -plocal-dev-only --silent >/dev/null 2>&1; do
    sleep 1
done
