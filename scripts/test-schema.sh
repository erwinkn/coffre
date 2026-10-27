#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
database="${COFFRE_TEST_DATABASE:-coffre_test}"

./scripts/setup-test-database.sh

docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d "$database" \
    < packages/db/test/schema-fixture.sql

docker compose exec -T \
    -e PGPASSWORD=local-runtime-only \
    postgres \
    psql -v ON_ERROR_STOP=1 -h 127.0.0.1 \
        -U coffre_runtime -d "$database" \
    < packages/db/test/schema-guarantees.sql

# The vault's login, against the same fixture.
docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d "$database" \
    < packages/db/test/schema-fixture.sql

docker compose exec -T \
    -e PGPASSWORD=local-vault-only \
    postgres \
    psql -v ON_ERROR_STOP=1 -h 127.0.0.1 \
        -U coffre_vault_runtime -d "$database" \
    < packages/db/test/vault-guarantees.sql

# 0.15's log, as the vault's login, against a fixture of its own.
docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d "$database" \
    < packages/db/test/schema-fixture.sql
docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d "$database" \
    < packages/db/test/log-fixture.sql
docker compose exec -T \
    -e PGPASSWORD=local-vault-only \
    postgres \
    psql -v ON_ERROR_STOP=1 -h 127.0.0.1 \
        -U coffre_vault_runtime -d "$database" \
    < packages/db/test/log-guarantees.sql

docker compose exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U coffre_owner -d "$database" \
    < packages/db/test/log-owner.sql

# The fence across sessions. Each holder sleeps far longer than its checks
# take, and goes when the script does, however it ends. Advisory locks are
# the database's: each check counts and ends this database's alone.
owner_psql() { docker compose exec -T postgres psql -X -q -v ON_ERROR_STOP=1 -U coffre_owner -d "$database" "$@"; }
vault_psql() { docker compose exec -T -e PGPASSWORD=local-vault-only postgres psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U coffre_vault_runtime -d "$database" "$@"; }
scratch="$(mktemp -d)"
holders=()
let_go() {
    # Each holder's backend gone, its locks with it, before the next check: psql exits before its backend has.
    owner_psql -c "SELECT pg_terminate_backend(pid, 10000) FROM pg_stat_activity WHERE datname = current_database() AND query LIKE '%coffre-test-holder%' AND pid <> pg_backend_pid()" >/dev/null 2>&1 || true
    for holder in "${holders[@]}"; do wait "$holder" 2>/dev/null || true; done
    holders=()
}
trap 'let_go; rm -rf "$scratch"' EXIT
# held <class> [<key>]: the advisory lock granted, by its two keys where the
# check knows both (the fence and the issue lock are one class).
held() {
    for attempt in $(seq 100); do
        # This database's: another run may share the server.
        [[ "$(owner_psql -At -c "SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid = l.database WHERE d.datname = current_database() AND l.locktype = 'advisory' AND l.classid = $1 ${2:+AND l.objid = $2} AND l.granted")" == 1 ]] && return 0
        sleep 0.1
    done
    echo "the lock $1${2:+, $2} was never held" >&2
    exit 1
}

# OldWritesFence (formal/Migration015.tla): 0.14's writes take the 0.15 fence,
# its reads and sign-ins never (a token.exchange issues a credential nobody
# holds yet: 0026, ExchangeOnlyIssues): with the fence held, a revoke's entry
# waits, a read's does not.
owner_psql -c 'SELECT pg_advisory_lock(1668244070, 0), pg_sleep(300) /* coffre-test-holder */' >/dev/null 2>&1 &
holders+=($!)
held 1668244070 0
entry() {
    echo "BEGIN; SET LOCAL lock_timeout = '1s';
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    VALUES (900, '$1', 'fixture', 0, 'system:fixture', '$2', 'allow', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'));
    ROLLBACK;"
}
for read in 'vault secret.read' 'app credential.use' 'app sign_in' 'app token.exchange' 'app secret.version'; do
    entry ${read} | owner_psql >/dev/null || { echo "0.14's ${read#* } waited on the 0.15 fence" >&2; exit 1; }
done
for write in 'vault access.revoke' 'app token.revoke' 'vault secret.write' 'app sign_out'; do
    if entry ${write} | owner_psql >/dev/null 2>"$scratch/fenced" || ! grep -q 'lock timeout' "$scratch/fenced"; then
        cat "$scratch/fenced" >&2; echo "0.14's ${write#* } did not wait on the 0.15 fence" >&2; exit 1
    fi
done
let_go

# IssueBeforeFence (0026): the trigger takes the issue lock before the fence.
# With the issue lock held exclusive, as the barrier holds it, a revoke's entry
# waits there; a token.exchange's takes neither lock.
owner_psql -c 'SELECT pg_advisory_lock(1668244070, 1), pg_sleep(300) /* coffre-test-holder */' >/dev/null 2>&1 &
holders+=($!)
held 1668244070 1
entry app token.exchange | owner_psql >/dev/null || { echo "0.14's token.exchange waited on the issue lock" >&2; exit 1; }
if entry app token.revoke | owner_psql >/dev/null 2>"$scratch/fenced" || ! grep -q 'lock timeout' "$scratch/fenced"; then
    cat "$scratch/fenced" >&2; echo "0.14's token.revoke did not wait on the issue lock" >&2; exit 1
fi
let_go

# RowFirst and ChangeHeadFirst (formal/Migration015.tla), the order row, head,
# fence: with 0.14's vault holding a
# member's queue and row, then taking the head and the fence (its revoke's
# entry), a change to that member waits for it and passes, rather than
# holding the fence and deadlocking on the row.
owner_psql >"$scratch/old.log" 2>&1 <<'SQL' &
BEGIN;
SELECT pg_advisory_xact_lock(1668245101, hashtext(principal)) FROM vault_members WHERE principal = 'token:deploy' FOR NO KEY UPDATE;
SELECT pg_sleep(2) /* coffre-test-holder */;
SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE;
INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
VALUES (901, 'vault', 'fixture', 0, 'system:fixture', 'access.revoke', 'allow', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'));
ROLLBACK;
SQL
old=$!
held 1668245101
vault_psql -At >"$scratch/change.log" 2>&1 <<'SQL' || { cat "$scratch/change.log" >&2; echo 'a 0.15 change did not pass a 0.14 write in flight' >&2; exit 1; }
SET lock_timeout = '10s';
SELECT change_input('principal', 'token:deploy', 'reseal-under-0.14', 1, 'system:test', '{"op":"genesis"}', NULL,
    (SELECT seal FROM vault_members WHERE principal = 'token:deploy'), decode(repeat('5f', 16), 'hex'), decode(repeat('ee', 16), 'hex')) IS NOT NULL;
SQL
wait "$old" || { cat "$scratch/old.log" >&2; echo "0.14's write failed beside a 0.15 change" >&2; exit 1; }
[[ "$(cat "$scratch/change.log")" == t ]] || { cat "$scratch/change.log" >&2; exit 1; }

# And a 0.14 decision that only reads the member (its queue shared, its row
# FOR SHARE, then the head and a read's entry) beside a 0.15 change to that
# member's credential: the change waits behind it, then passes.
owner_psql >"$scratch/old.log" 2>&1 <<'SQL' &
BEGIN;
SELECT pg_advisory_xact_lock_shared(1668245101, hashtext(principal)) FROM vault_members WHERE principal = 'token:deploy' FOR SHARE;
SELECT pg_sleep(2) /* coffre-test-holder */;
SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE;
INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
VALUES (902, 'vault', 'fixture', 0, 'system:fixture', 'secret.read', 'allow', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'));
ROLLBACK;
SQL
old=$!
held 1668245101
vault_psql -At >"$scratch/change.log" 2>&1 <<'SQL' || { cat "$scratch/change.log" >&2; echo "a 0.15 credential change did not pass a 0.14 decision in flight" >&2; exit 1; }
SET lock_timeout = '10s';
SELECT change_input('credential', '33333333-3333-3333-3333-333333333333', 'reseal-credential-under-0.14', 1, 'system:test', '{"op":"genesis"}', NULL,
    (SELECT seal FROM log_changes WHERE object = log_object('credential', '33333333-3333-3333-3333-333333333333') ORDER BY number DESC LIMIT 1),
    decode(repeat('5f', 16), 'hex'), decode(repeat('ee', 16), 'hex')) IS NOT NULL;
SQL
wait "$old" || { cat "$scratch/old.log" >&2; echo "0.14's decision failed beside a 0.15 change" >&2; exit 1; }
[[ "$(cat "$scratch/change.log")" == t ]] || { cat "$scratch/change.log" >&2; exit 1; }

# A use that waits for its principal's lock past its deadline writes nothing.
owner_psql -c "SELECT pg_advisory_lock(1668244066, hashtext('token:deploy')), pg_sleep(300) /* coffre-test-holder */" >/dev/null 2>&1 &
holders+=($!)
held 1668244066
vault_psql -At >"$scratch/late.log" 2>&1 <<'SQL' &
SELECT use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444442', 40, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 1500) ->> 'state'
  FROM (SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint AS t) now;
SQL
late=$!
sleep 2.5
let_go
wait "$late" || true
[[ "$(cat "$scratch/late.log")" == late && "$(owner_psql -At -c 'SELECT count(*) FROM log_uses WHERE request_id = 40')" == 0 ]] \
    || { cat "$scratch/late.log" >&2; echo 'a use that waited past its deadline wrote an entry' >&2; exit 1; }

# Two calls for one day at once, as two checkpointers may: the second waits
# for the first, finds the day it made, and answers its name too.
vault_psql -At -c "SELECT make_day(date '2031-01-01'); SELECT pg_sleep(1) /* coffre-test-holder */" >"$scratch/day-1.log" 2>&1 &
first=$!
sleep 0.3
vault_psql -At -c "SELECT make_day(date '2031-01-01')" >"$scratch/day-2.log" 2>&1 || { cat "$scratch/day-2.log" >&2; echo 'a day made at once failed' >&2; exit 1; }
wait "$first" || { cat "$scratch/day-1.log" >&2; exit 1; }
[[ "$(head -1 "$scratch/day-1.log")" == log_uses_20310101 && "$(cat "$scratch/day-2.log")" == log_uses_20310101 ]] \
    || { cat "$scratch/day-1.log" "$scratch/day-2.log" >&2; echo 'two calls for one day disagree' >&2; exit 1; }

# Managed hosts give the owner CREATEROLE, not superuser.
./scripts/test-schema-owner.sh

# The backup role dumps everything and writes nothing, on a cluster of its own.
./scripts/test-backup-role.sh

# And `coffre setup`, which makes the logins and migrates, on one of its own.
./scripts/test-setup.sh
