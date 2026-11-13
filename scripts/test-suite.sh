#!/usr/bin/env bash
# Each test process gets a clone of one migrated template. Cases within a
# file still run sequentially and retain all their resets and transaction guards.
# COFFRE_TEST_DATABASE is the base name; a random suffix isolates each run.
# `--files <file>...` runs only those files, on the same footing: the use
# matrices (`pnpm test:matrices`), which CI runs in shards (`scripts/matrix-shard.ts`),
# and the files `pnpm validate` picks; `--serial --files <file>...` runs them one at a time.
# `--skip-full` leaves out the cases whose name says `[full]`: a growth, heap or large-N check
# that `pnpm validate` runs only with `--full`, as `pnpm test` and CI always do.
# Without `--files`, the files that must run alone (`*.alone.ts`) run after the rest.
set -euo pipefail

cd "$(dirname "$0")/.."
trap 'exit 130' INT
trap 'exit 143' TERM

export COFFRE_TEST_DATABASE="$(node --input-type=module -e '
    import { randomBytes } from "node:crypto";
    const base = (process.env.COFFRE_TEST_DATABASE || "coffre_test").replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 32);
    console.log(`${base}_${randomBytes(8).toString("hex")}`);
')"
trap 'node --conditions=coffre:source scripts/test-databases.mjs cleanup "$COFFRE_TEST_DATABASE"' EXIT
./scripts/setup-test-database.sh

# A case that never ends (asleep on a socket, or awaiting in a loop) fails after 10 minutes, by name, unless it
# sets its own timeout: the longest case without one, on a loaded host, took 5. A file whose process outlives
# its tests fails 2 minutes after them (test-file-exits.mjs).
node_test=(node --conditions=coffre:source --import ./scripts/test-database-worker.mjs --import ./scripts/test-file-exits.mjs --test --test-timeout=600000)
files=("scripts/*.test.mjs" "packages/*/test/**/*.test.ts" "dev/**/test/*.test.ts" "examples/**/test/*.test.ts")
concurrency=4
skip=()
while :; do
    case "${1:-}" in
        --serial) concurrency=1 ;;
        --skip-full) skip=(--test-skip-pattern='\[full\]') ;;
        *) break ;;
    esac
    shift
done
if [ "${1:-}" = --files ]; then
    shift
    # The files side by side share Postgres's connections, each a share of them while it runs
    # (scripts/matrix-connections.ts): how many there are, how many run at once, and where each says it ended.
    shopt -s nullglob globstar
    # shellcheck disable=SC2206 # the patterns expand here as node's --test expands them
    matched=($@)
    shopt -u nullglob globstar
    export COFFRE_TEST_FILES="${#matched[@]}" COFFRE_TEST_CONCURRENCY="$concurrency"
    COFFRE_TEST_FILES_ENDED="$(mktemp -d "${TMPDIR:-/tmp}/coffre-ended.XXXXXX")"
    export COFFRE_TEST_FILES_ENDED
    status=0
    "${node_test[@]}" --test-concurrency="$concurrency" "${skip[@]}" "$@" || status=$?
    rm -rf "$COFFRE_TEST_FILES_ENDED"
    exit "$status"
fi
# Then the files that run alone (`*.alone.ts`), one at a time, once the others are done: those that hold a
# statement's work to a budget or to the same call by call, and so its backend's caches. A commit of thousands of
# catalog changes anywhere in the cluster (a test's migration, in a database of its own) overflows Postgres's
# invalidation queue, 4,096 messages shared by every database, and resets every backend's caches: the call it lands
# in plans everything again, as a connection's first does (use-days.alone.ts, request-cost.alone.ts). Both runs run;
# either failing fails the suite.
status=0
"${node_test[@]}" --test-concurrency="$concurrency" "${skip[@]}" "$@" "${files[@]}" || status=$?
"${node_test[@]}" --test-concurrency=1 "${skip[@]}" "$@" "packages/*/test/*.alone.ts" || status=$?
exit "$status"
