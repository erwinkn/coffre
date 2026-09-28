#!/usr/bin/env bash
# Run the integration suite on the engine COFFRE_TEST_ENGINE names:
# postgres (the default), mysql or sqlite.
#
#   postgres  coffre_test in the compose Postgres, recreated
#   mysql     coffre_test in a MySQL 8.4 on :53306, recreated
#   sqlite    a file in a temporary directory, deleted afterwards
set -euo pipefail

cd "$(dirname "$0")/.."
export COFFRE_TEST_ENGINE="${COFFRE_TEST_ENGINE:-postgres}"

case "$COFFRE_TEST_ENGINE" in
    postgres)
        ./scripts/setup-test-database.sh
        ;;
    mysql)
        ./scripts/ensure-mysql.sh
        export COFFRE_TEST_DATABASE_URL='mysql://root:local-dev-only@127.0.0.1:53306/coffre_test'
        node packages/db/test/create-database.ts "$COFFRE_TEST_DATABASE_URL"
        ;;
    sqlite)
        scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-test.XXXXXX")"
        trap 'rm -rf "$scratch"' EXIT
        export COFFRE_TEST_DATABASE_URL="file:$scratch/coffre_test.db"
        node packages/db/test/create-database.ts "$COFFRE_TEST_DATABASE_URL"
        ;;
    *)
        echo "COFFRE_TEST_ENGINE must be postgres, mysql or sqlite" >&2
        exit 2
        ;;
esac

node --test --test-concurrency=1 "scripts/*.test.mjs" "packages/**/test/*.test.ts" "apps/**/test/*.test.ts"
