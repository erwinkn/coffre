#!/usr/bin/env bash
# W201: the brief's fence, `(SELECT n FROM revision) = $rev`, in an append that waits for the head's lock,
# against the revision kept in the head row. A change holds the head, raises the revision, commits.
set -u
D=${1:?usage: epq.sh postgresql://user:password@host:port (a server where a scratch database may be made)}
psql $D/lanes -qAtc "DROP DATABASE IF EXISTS w201_epq" -c "CREATE DATABASE w201_epq" >/dev/null
E=$D/w201_epq
psql $E -qAt <<'SQL'
CREATE TABLE head (only_row boolean PRIMARY KEY, next_seq int, rev int);
CREATE TABLE revision (n int);
CREATE TABLE log (seq int, rev int);
INSERT INTO head VALUES (true, 1, 0); INSERT INTO revision VALUES (0);
SQL
for fence in "separate table: (SELECT n FROM revision) = 0" "head row: h.rev = 0"; do
  psql $E -qAtc "UPDATE head SET rev = 0; UPDATE revision SET n = 0; TRUNCATE log" >/dev/null
  # The change: takes the head, holds it 1 s, raises the revision, commits.
  psql $E -qAt -c "BEGIN" -c "SELECT 1 FROM head FOR UPDATE" -c "SELECT pg_sleep(1)" -c "UPDATE revision SET n = 1" -c "UPDATE head SET rev = 1, next_seq = next_seq + 1" -c "COMMIT" >/dev/null &
  sleep 0.3
  # The use's append, which read revision 0, starts while the change holds the head.
  if [[ $fence == separate* ]]; then cond="(SELECT n FROM revision) = 0"; else cond="h.rev = 0"; fi
  got=$(psql $E -qAtc "WITH h AS (SELECT next_seq, rev FROM head WHERE only_row FOR UPDATE) INSERT INTO log SELECT h.next_seq, 0 FROM h WHERE $cond RETURNING seq")
  wait
  echo "fence in the $fence -> use appended: ${got:-nothing} (after the change committed revision 1)"
done
psql $D/lanes -qAtc "DROP DATABASE w201_epq" >/dev/null
