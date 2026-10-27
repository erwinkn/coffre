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

# 0.14's writes take the 0.15 fence, its reads never: with the fence held, a
# revoke's entry waits, a read's does not.
owner_psql() { docker compose exec -T postgres psql -X -q -v ON_ERROR_STOP=1 -U coffre_owner -d "$database" "$@"; }
owner_psql -c 'SELECT pg_advisory_lock(1668244070, 0), pg_sleep(20)' >/dev/null 2>&1 &
holder=$!
for attempt in $(seq 100); do
    [[ "$(owner_psql -At -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = 1668244070 AND granted")" == 1 ]] && break
    if ((attempt == 100)); then echo 'the fence was never held' >&2; exit 1; fi
    sleep 0.1
done
fenced="$(mktemp)"
trap 'rm -f "$fenced"' EXIT
entry() {
    echo "BEGIN; SET LOCAL lock_timeout = '1s';
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    VALUES (900, '$1', 'fixture', 0, 'system:fixture', '$2', 'allow', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'));
    ROLLBACK;"
}
for read in 'vault secret.read' 'app credential.use' 'app token.exchange'; do
    entry ${read} | owner_psql >/dev/null || { echo "0.14's ${read#* } waited on the 0.15 fence" >&2; exit 1; }
done
for write in 'vault access.revoke' 'app token.revoke' 'vault secret.write'; do
    if entry ${write} | owner_psql >/dev/null 2>"$fenced" || ! grep -q 'lock timeout' "$fenced"; then
        cat "$fenced" >&2; echo "0.14's ${write#* } did not wait on the 0.15 fence" >&2; exit 1
    fi
done
owner_psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(20)%' AND pid <> pg_backend_pid()" >/dev/null
wait "$holder" || true

# Managed hosts give the owner CREATEROLE, not superuser.
./scripts/test-schema-owner.sh

# The backup role dumps everything and writes nothing, on a cluster of its own.
./scripts/test-backup-role.sh

# And `coffre setup`, which makes the logins and migrates, on one of its own.
./scripts/test-setup.sh
