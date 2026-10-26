#!/usr/bin/env bash
# What vault decisions cost under concurrent load, through a relay as slow as
# Hyperdrive (packages/vault/test/bench/decisions.ts), on a migrated scratch
# database of its own, dropped after. Arguments go to the bench:
#
#   pnpm bench:decisions [--rtt 20] [--calls 20] [--keys 1] [--callers 1,5,10,20]
set -euo pipefail

cd "$(dirname "$0")/.."
export COFFRE_TEST_ENGINE=postgres
COFFRE_TEST_DATABASE="coffre_bench_$(node -e 'console.log(require("node:crypto").randomBytes(8).toString("hex"))')"
export COFFRE_TEST_DATABASE
trap 'node --conditions=coffre:source scripts/test-databases.mjs cleanup "$COFFRE_TEST_DATABASE"' EXIT
./scripts/setup-test-database.sh
node --conditions=coffre:source packages/vault/test/bench/decisions.ts "$@"
