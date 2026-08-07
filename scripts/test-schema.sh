#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"

./scripts/setup-test-database.sh

docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d coffre_test \
    < packages/db/test/schema-fixture.sql

docker compose exec -T \
    -e PGPASSWORD=test-runtime-only \
    postgres \
    psql -v ON_ERROR_STOP=1 -h 127.0.0.1 \
        -U coffre_runtime -d coffre_test \
    < packages/db/test/schema-guarantees.sql
