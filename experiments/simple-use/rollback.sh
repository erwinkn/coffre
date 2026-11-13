#!/usr/bin/env bash
# Review r2 finding 1: a mover that rolls back must not lose the key's move. A moves K to period P and holds, B and C
# wait on it; A rolls back; one of B and C must move K (R42's election, as 0085's T127). Then: A moves K to an older
# period than B's and commits; B's period must win.
set -euo pipefail
C=${C:-coffre_thr_qx8qf2k5yv_rig}
psql() { docker exec -i $C psql -U coffre_owner -d coffre -v ON_ERROR_STOP=1 -Atq "$@"; }
read -r CRED PRINC SECRET VERSION OBJS < <(psql -F' ' -c "SELECT c.id, c.principal, s.id, s.current_version_id,
    ARRAY[log_object('credential', c.id::text), log_object('secret', s.id::text)]::uuid[]::text
  FROM credentials c JOIN grants g ON g.principal = c.principal JOIN secrets s ON s.environment_id = g.environment_id AND s.current_version_id IS NOT NULL LIMIT 1")
read -r ASOF MAC < <(psql -F' ' -c "SELECT number, encode(mac, 'hex') FROM log_changes ORDER BY number DESC LIMIT 1")
now() { NOW=$(psql -c "SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint"); }
call() { # $1 period, $2 request
  echo "SELECT state, number IS NOT NULL AS wrote FROM use_move(ROW(NULL, $NOW, $2, '$CRED', '$SECRET', 4::smallint, '\\x$(openssl rand -hex 16)'::bytea, NULL::uuid, NULL::text, true)::log_uses,
    '$VERSION', $ASOF, '\\x$MAC'::bytea, '$OBJS'::uuid[], $NOW + 3000, '$PRINC', $1, 910000);"
}
round() { # $1 A's period, $2 A's end, $3 B's and C's period, each as an offset from now
  now; local a=$((NOW + $1)) b=$((NOW + $3))
  psql -c "INSERT INTO bulk_cap (principal, secret, last) VALUES ('$PRINC', '$SECRET', $NOW - 120000)
    ON CONFLICT (principal, secret) DO UPDATE SET last = EXCLUDED.last"
  { echo "BEGIN;"; call $a $RANDOM$RANDOM; echo "SELECT pg_sleep(2); $2;"; } | psql | sed 's/^/A: /' &
  sleep 0.5
  { echo "BEGIN;"; call $b $RANDOM$RANDOM; echo "COMMIT;"; } | psql | sed 's/^/B: /' &
  { echo "BEGIN;"; call $b $RANDOM$RANDOM; echo "COMMIT;"; } | psql | sed 's/^/C: /' &
  wait
  local last; last=$(psql -c "SELECT last FROM bulk_cap WHERE principal = '$PRINC' AND secret = '$SECRET'")
  if [ "$last" = "$b" ]; then echo "ok: the row is at B's period"; else echo "FAIL: the row is at $((last - NOW)), B's period is $(($b - NOW))"; exit 1; fi
}
echo "== A moves to P and rolls back; B and C move to P"; round 0 ROLLBACK 0
echo "== A moves to P-60000 and commits; B and C move to P"; round -60000 COMMIT 0
