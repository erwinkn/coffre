#!/usr/bin/env bash
# The growth sweep (R48; docs/growth-sweep.md): the sweep's request paths
# (packages/server/test/growth.sweep.ts) on an instance whose history is
# `--size` entries long in each of its shapes, then ten times that, each run's
# statements logged by auto_explain on the runtime logins; then the statements
# whose cost grew between the two (scripts/growth-sweep.mjs). Exits 1 when
# one grew that scripts/growth-sweep-known.txt does not list, or when the two
# runs did not go the same way; `--write-known` rewrites that list with what
# grew. On a Postgres of your own only: it turns auto_explain on for its
# databases and reads the server's log.
#
#   COMPOSE_PROJECT_NAME=coffre_mine COFFRE_POSTGRES_PORT=56432 pnpm sweep:growth [--size 2000] [--out <dir>] [--write-known]
set -euo pipefail

cd "$(dirname "$0")/.."
size=2000
out=""
write=()
while [ $# -gt 0 ]; do
    case "$1" in
        --size) size="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --write-known) write=(--write-known scripts/growth-sweep-known.txt); shift ;;
        *) echo "usage: scripts/growth-sweep.sh [--size <n>] [--out <dir>] [--write-known]" >&2; exit 2 ;;
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
    COFFRE_SWEEP_SIZE="$n" COFFRE_SWEEP_OUTCOMES="$out/$n.outcomes.json" COFFRE_TEST_DATABASE=coffre_sweep ./scripts/test-suite.sh --files packages/server/test/growth.sweep.ts > "$out/$n.out" 2>&1 || status=$?
    grep -E '^(# (pass|fail)|not ok)' "$out/$n.out" | cut -c1-400 || true
    docker compose logs --no-log-prefix --since "$since" postgres > "$out/$n.log" 2>&1
    if [ "$status" -ne 0 ]; then
        echo "the run at $n entries failed (exit $status): $out/$n.out" >&2
        failed=1
    fi
done
echo "logs in $out"
compared=0
node scripts/growth-sweep.mjs "$out/$size.log" "$out/$((size * 10)).log" "$out/$size.outcomes.json" "$out/$((size * 10)).outcomes.json" \
    --known scripts/growth-sweep-known.txt "${write[@]}" || compared=$?
if [ "$failed" -ne 0 ]; then exit 1; fi
exit "$compared"
