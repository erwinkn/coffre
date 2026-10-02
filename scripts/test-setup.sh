#!/usr/bin/env bash
# `coffre setup` against a disposable cluster: as its superuser, and as an
# owner such as managed hosts give, with CREATEROLE but not superuser. Roles
# are cluster-wide, and setup creates coffre's and sets their passwords, so
# never against the shared dev cluster.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
container="coffre-setup-$(node -e 'console.log(crypto.randomUUID().slice(0, 8))')"
trap 'docker rm -fv "$container" >/dev/null 2>&1 || true' EXIT
image="$(docker compose config --format json | node -e 'let input=""; for await (const chunk of process.stdin) input+=chunk; console.log(JSON.parse(input).services.postgres.image)')"
docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=local-setup-only \
    -p 127.0.0.1::5432 "$image" >/dev/null
for attempt in $(seq 60); do
    if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    if ((attempt == 60)); then docker logs "$container"; exit 1; fi
    sleep 1
done
port="$(docker port "$container" 5432/tcp | cut -d: -f2)"
COFFRE_TEST_SETUP_CLUSTER="postgresql://postgres:local-setup-only@127.0.0.1:$port" \
    node --conditions=coffre:source --test --test-concurrency=1 packages/cli/test/setup.test.ts
