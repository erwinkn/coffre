#!/usr/bin/env bash
# `coffre setup` and `coffre migrate` against disposable clusters: as a superuser, and as an
# owner such as managed hosts give, with CREATEROLE but not superuser. Roles
# are cluster-wide, and setup creates coffre's and sets their passwords, so
# never against the shared dev cluster. A second cluster holds a second
# deployment's database, as a second server would; a third lets in only 15
# connections, too few for two Hyperdrive configs.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
id="$(node -e 'console.log(crypto.randomUUID().slice(0, 8))')"
containers=("coffre-setup-$id" "coffre-setup-$id-other" "coffre-setup-$id-small")
trap 'docker rm -fv "${containers[@]}" >/dev/null 2>&1 || true' EXIT
image="$(docker compose config --format json | node -e 'let input=""; for await (const chunk of process.stdin) input+=chunk; console.log(JSON.parse(input).services.postgres.image)')"
for container in "${containers[@]}"; do
    settings=()
    if [[ "$container" == *-small ]]; then settings=(-c max_connections=15); fi
    docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=local-setup-only \
        -p 127.0.0.1::5432 "$image" "${settings[@]}" >/dev/null
done
urls=()
for container in "${containers[@]}"; do
    for attempt in $(seq 60); do
        if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
        if ((attempt == 60)); then docker logs "$container"; exit 1; fi
        sleep 1
    done
    urls+=("postgresql://postgres:local-setup-only@127.0.0.1:$(docker port "$container" 5432/tcp | cut -d: -f2)")
done
COFFRE_TEST_SETUP_CLUSTER="${urls[0]}" COFFRE_TEST_SETUP_OTHER_CLUSTER="${urls[1]}" COFFRE_TEST_SETUP_SMALL_CLUSTER="${urls[2]}" \
    node --conditions=coffre:source --test --test-concurrency=1 packages/cli/test/setup.test.ts packages/cli/test/setup-workers.test.ts packages/cli/test/setup-domain.test.ts packages/cli/test/migrate.test.ts
