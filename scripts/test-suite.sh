#!/usr/bin/env bash
# Each test process gets a clone of one migrated template. Cases within a
# file still run sequentially and retain all their resets and transaction guards.
# COFFRE_TEST_DATABASE is the base name; a random suffix isolates each run.
# `--files <file>...` runs only those files, on the same footing: the use
# matrices (`pnpm test:matrices`), which CI runs in shards (`scripts/matrix-shard.ts`).
# Without it, the files that must run alone (`*.alone.ts`) run after the rest.
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

files=("scripts/*.test.mjs" "packages/*/test/**/*.test.ts" "dev/**/test/*.test.ts" "examples/**/test/*.test.ts")
if [ "${1:-}" = --files ]; then
    shift
    node --conditions=coffre:source --import ./scripts/test-database-worker.mjs --test --test-concurrency=4 "$@"
    exit
fi
# Then the files that run alone (`*.alone.ts`), one at a time, once the others are done: those that hold one
# backend's work to the same call by call, and so its caches. A commit of thousands of catalog changes anywhere in
# the cluster (a test's migration, in a database of its own) overflows Postgres's invalidation queue, 4,096 messages
# shared by every database, and resets every backend's caches: the call it lands in plans everything again, as a
# connection's first does (use-days.alone.ts). Both runs run; either failing fails the suite.
status=0
node --conditions=coffre:source --import ./scripts/test-database-worker.mjs --test --test-concurrency=4 "$@" "${files[@]}" || status=$?
node --conditions=coffre:source --import ./scripts/test-database-worker.mjs --test --test-concurrency=1 "$@" "packages/*/test/*.alone.ts" || status=$?
exit "$status"
