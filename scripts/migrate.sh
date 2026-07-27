#!/usr/bin/env bash
# Apply migrations in filename order, each in its own transaction.
#
# ON_ERROR_STOP is not optional: without it psql reports success after a failed
# statement, which for a schema that encodes an audit guarantee would be a very
# expensive thing to get wrong.
set -euo pipefail

cd "$(dirname "$0")/.."

for file in packages/db/migrations/*.sql; do
    name="$(basename "$file")"
    echo "==> applying ${name}"
    docker compose exec -T postgres \
        psql -v ON_ERROR_STOP=1 --single-transaction -U coffre_owner -d coffre \
        < "$file"
done

echo "==> migrations applied"
