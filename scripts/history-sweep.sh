#!/usr/bin/env bash
# The history sweep (R48; docs/history-sweep.md): the sweep's request paths
# (packages/server/test/history.sweep.ts) on an instance whose history is
# `--size` entries long in each of its shapes, then ten times that, each run's
# statements logged by auto_explain on the runtime logins; then the statements
# whose cost grew between the two (scripts/history-sweep.mjs). Exits 1 when
# one did. On a Postgres of your own only: it turns auto_explain on for its
# databases and reads the server's log.
#
#   COMPOSE_PROJECT_NAME=coffre_mine COFFRE_POSTGRES_PORT=56432 scripts/history-sweep.sh [--size 2000] [--out <dir>]
set -euo pipefail

cd "$(dirname "$0")/.."
size=2000
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        --size) size="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        *) echo "usage: scripts/history-sweep.sh [--size <n>] [--out <dir>]" >&2; exit 2 ;;
    esac
done
if [ "${COMPOSE_PROJECT_NAME:-coffre}" = coffre ] || [ "${COFFRE_POSTGRES_PORT:-55432}" = 55432 ]; then
    echo "the sweep reads the server's log and logs every plan: set COMPOSE_PROJECT_NAME and COFFRE_POSTGRES_PORT to a Postgres of your own" >&2
    exit 2
fi
if [ -z "$out" ]; then
    out="$(mktemp -d "${TMPDIR:-/tmp}/coffre-sweep.XXXXXX")"
fi
mkdir -p "$out"
./scripts/ensure-postgres.sh

# A run that fails fails the sweep: its statements stop where it did, and the comparison would miss the rest.
failed=0
for n in "$size" "$((size * 10))"; do
    since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "sweeping at $n entries of each shape"
    status=0
    COFFRE_SWEEP_SIZE="$n" COFFRE_TEST_DATABASE=coffre_sweep ./scripts/test-suite.sh --files packages/server/test/history.sweep.ts > "$out/$n.out" 2>&1 || status=$?
    grep -E '^(# (pass|fail)|not ok|sweep outcomes)' "$out/$n.out" | cut -c1-400 || true
    docker compose logs --no-log-prefix --since "$since" postgres > "$out/$n.log" 2>&1
    if [ "$status" -ne 0 ]; then
        echo "the run at $n entries failed (exit $status): $out/$n.out" >&2
        failed=1
    fi
done
echo "logs in $out"
compared=0
node scripts/history-sweep.mjs "$out/$size.log" "$out/$((size * 10)).log" "$out/$size.out" "$out/$((size * 10)).out" || compared=$?
if [ "$failed" -ne 0 ]; then exit 1; fi
exit "$compared"
