#!/usr/bin/env bash
# Each test process gets a clone of one migrated template. Cases within a
# file still run sequentially and retain all their resets and transaction guards.
# COFFRE_TEST_DATABASE is the base name; a random suffix isolates each run.
set -euo pipefail

cd "$(dirname "$0")/.."
export COFFRE_TEST_ENGINE="${COFFRE_TEST_ENGINE:-postgres}"
trap 'exit 130' INT
trap 'exit 143' TERM

case "$COFFRE_TEST_ENGINE" in
    postgres)
        export COFFRE_TEST_DATABASE="$(node --input-type=module -e '
            import { randomBytes } from "node:crypto";
            const base = (process.env.COFFRE_TEST_DATABASE || "coffre_test").replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 32);
            console.log(`${base}_${randomBytes(8).toString("hex")}`);
        ')"
        trap 'node --conditions=coffre:source scripts/test-databases.mjs cleanup "$COFFRE_TEST_DATABASE"' EXIT
        ./scripts/setup-test-database.sh
        ;;
    sqlite)
        scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-test.XXXXXX")"
        trap 'rm -rf "$scratch"' EXIT
        export COFFRE_TEST_DATABASE_URL="file:$scratch/coffre_test.db"
        node --conditions=coffre:source packages/server/test/db/create-database.ts "$COFFRE_TEST_DATABASE_URL"
        ;;
    *)
        echo "COFFRE_TEST_ENGINE must be postgres or sqlite" >&2
        exit 2
        ;;
esac

node --conditions=coffre:source --import ./scripts/test-database-worker.mjs --test --test-concurrency=4 "$@" "scripts/*.test.mjs" "packages/*/test/**/*.test.ts" "dev/**/test/*.test.ts" "examples/**/test/*.test.ts"
