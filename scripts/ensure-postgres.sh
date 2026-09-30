#!/usr/bin/env bash
# Start the compose Postgres only when nothing answers yet.
#
# Several worktrees share one container. `docker compose up` compares the
# running container with this checkout's compose config and recreates it on
# any difference, which drops every other checkout's connections mid-test.
# A container that already answers is left exactly as it is.
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"

# Over TCP, not the socket: on a fresh volume the image first runs a
# temporary server on the socket alone, to create the database, then stops
# it and starts the real one. A socket check can pass in between, and the
# next psql finds nothing there.
ready() {
    docker compose exec -T postgres pg_isready -h 127.0.0.1 -U coffre_owner -d postgres >/dev/null 2>&1
}

ready && exit 0
docker compose up -d postgres >/dev/null
until ready; do
    sleep 1
done
