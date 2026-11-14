#!/usr/bin/env bash
# Each test process gets a clone of one migrated template. Cases within a
# file still run sequentially and retain all their resets and transaction guards.
# COFFRE_TEST_DATABASE is the base name; a random suffix isolates each run.
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

# Every test file but 0.14's that do not build on 0.16 yet, which packages/server/tsconfig.json lists.
# Listed first, so that its failure stops the run (set -e) rather than leave node
# --test with no file, which would discover every test, the excluded too. A read
# loop, not mapfile: macOS's Bash 3.2 has none.
list="$(node scripts/test-files.mjs "scripts/*.test.mjs" "packages/*/test/**/*.test.ts" "dev/**/test/*.test.ts" "examples/**/test/*.test.ts")"
files=()
while IFS= read -r file; do files+=("$file"); done <<< "$list"

node --conditions=coffre:source --import ./scripts/test-database-worker.mjs --test --test-concurrency=4 "$@" "${files[@]}"
