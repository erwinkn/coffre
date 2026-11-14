#!/usr/bin/env bash
# The standalone property files share one random scratch database. The normal
# suite still runs each on a private clone via test-database-worker.mjs.
set -euo pipefail
cd "$(dirname "$0")/.."
for argument in "$@"; do
    if [[ "$argument" != --long && ! "$argument" =~ ^--seed=[0-9]+$ ]]; then
        echo 'Usage: pnpm test:properties:server [--long] [--seed=<unsigned integer>]' >&2
        exit 2
    fi
done
trap 'exit 130' INT
trap 'exit 143' TERM
export COFFRE_TEST_DATABASE="$(node --input-type=module -e '
    import { randomBytes } from "node:crypto";
    const base = (process.env.COFFRE_TEST_DATABASE || "coffre_properties").replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 32);
    console.log(`${base}_${randomBytes(8).toString("hex")}`);
')"
trap 'node --conditions=coffre:source scripts/test-databases.mjs cleanup "$COFFRE_TEST_DATABASE"' EXIT
./scripts/setup-test-database.sh
node --conditions=coffre:source packages/server/test/operations-properties.test.ts "$@"
node --conditions=coffre:source packages/server/test/forks-properties.test.ts "$@"
node --conditions=coffre:source packages/server/test/natures-properties.test.ts "$@"
# Its growth property, and its fixed budgets beside it.
node --conditions=coffre:source packages/server/test/request-cost.test.ts "$@"
