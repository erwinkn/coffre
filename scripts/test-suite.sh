#!/usr/bin/env bash
# Run the integration suite on the engine COFFRE_TEST_ENGINE names:
# postgres (the default), mysql or sqlite.
#
#   postgres  coffre_test in the compose Postgres, recreated
#   mysql     coffre_test in a MySQL 8.4 on :53306, recreated
#   sqlite    a file in a temporary directory, deleted afterwards
#
# COFFRE_TEST_DATABASE names another database than coffre_test, for a second
# run beside the first. Tests import the other packages' sources, under the
# `coffre:source` condition in their `exports`.
set -euo pipefail

cd "$(dirname "$0")/.."
export COFFRE_TEST_ENGINE="${COFFRE_TEST_ENGINE:-postgres}"
database="${COFFRE_TEST_DATABASE:-coffre_test}"

case "$COFFRE_TEST_ENGINE" in
    postgres)
        ./scripts/setup-test-database.sh
        ;;
    mysql)
        ./scripts/ensure-mysql.sh
        export COFFRE_TEST_DATABASE_URL="mysql://root:local-dev-only@127.0.0.1:53306/$database"
        node --conditions=coffre:source packages/server/test/db/create-database.ts "$COFFRE_TEST_DATABASE_URL"
        ;;
    sqlite)
        scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-test.XXXXXX")"
        trap 'rm -rf "$scratch"' EXIT
        export COFFRE_TEST_DATABASE_URL="file:$scratch/coffre_test.db"
        node --conditions=coffre:source packages/server/test/db/create-database.ts "$COFFRE_TEST_DATABASE_URL"
        ;;
    *)
        echo "COFFRE_TEST_ENGINE must be postgres, mysql or sqlite" >&2
        exit 2
        ;;
esac

node --conditions=coffre:source --test --test-concurrency=1 "scripts/*.test.mjs" "packages/*/test/**/*.test.ts" "dev/**/test/*.test.ts" "examples/**/test/*.test.ts"
