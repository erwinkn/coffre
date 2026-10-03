#!/usr/bin/env bash
# The standalone property file owns one random scratch database. The normal
# suite still runs it on a private clone via test-database-worker.mjs.
set -euo pipefail
cd "$(dirname "$0")/.."
for argument in "$@"; do
    if [[ "$argument" != --long && ! "$argument" =~ ^--seed=[0-9]+$ ]]; then
        echo 'Usage: pnpm test:properties:server [--long] [--seed=<unsigned integer>]' >&2
        exit 2
    fi
done
export COFFRE_TEST_ENGINE="${COFFRE_TEST_ENGINE:-postgres}"
trap 'exit 130' INT
trap 'exit 143' TERM
case "$COFFRE_TEST_ENGINE" in
    postgres)
        export COFFRE_TEST_DATABASE="$(node --input-type=module -e '
            import { randomBytes } from "node:crypto";
            const base = (process.env.COFFRE_TEST_DATABASE || "coffre_properties").replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 32);
            console.log(`${base}_${randomBytes(8).toString("hex")}`);
        ')"
        trap 'node --conditions=coffre:source scripts/test-databases.mjs cleanup "$COFFRE_TEST_DATABASE"' EXIT
        ./scripts/setup-test-database.sh
        ;;
    sqlite)
        scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-properties.XXXXXX")"
        trap 'rm -rf "$scratch"' EXIT
        export COFFRE_TEST_DATABASE_URL="file:$scratch/coffre_test.db"
        node --conditions=coffre:source packages/server/test/db/create-database.ts "$COFFRE_TEST_DATABASE_URL"
        ;;
    *) echo 'COFFRE_TEST_ENGINE must be postgres or sqlite' >&2; exit 2 ;;
esac
node --conditions=coffre:source packages/server/test/operations-properties.test.ts "$@"
