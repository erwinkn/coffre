#!/usr/bin/env bash
# Migrate as a managed Postgres owner, without superuser or special memberships.
# Roles are cluster-wide, so use a disposable cluster rather than the shared dev one.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-schema-owner.XXXXXX")"
container="coffre-schema-owner-${scratch##*.}"
cleanup() {
    docker rm -fv "$container" >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT
image="$(docker compose config --format json | node -e 'let input=""; for await (const chunk of process.stdin) input+=chunk; console.log(JSON.parse(input).services.postgres.image)')"
docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=local-bootstrap-only \
    -e POSTGRES_INITDB_ARGS='--locale=C --encoding=UTF8' \
    -p 127.0.0.1::5432 "$image" >/dev/null
for attempt in $(seq 60); do
    if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    if ((attempt == 60)); then docker logs "$container"; exit 1; fi
    sleep 1
done
port="$(docker port "$container" 5432/tcp | cut -d: -f2)"
psql_owner() {
    docker exec -i -e PGPASSWORD=local-owner-only "$container" \
        psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -U migration_owner "$@"
}
docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres <<'SQL'
CREATE ROLE migration_owner LOGIN CREATEROLE CREATEDB PASSWORD 'local-owner-only';
SQL
psql_owner -d postgres <<'SQL'
DO $$ BEGIN
    IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'test owner must not be a superuser or a member of any role';
    END IF;
END $$;
CREATE ROLE coffre_runtime LOGIN PASSWORD 'local-runtime-only';
CREATE ROLE coffre_vault_runtime LOGIN PASSWORD 'local-vault-only';
SQL

migrate() {
    DATABASE_URL="postgresql://migration_owner:local-owner-only@127.0.0.1:$port/$1" \
        pnpm --filter @coffre/db run db:migrate
}
guarantees() {
    local database="$1"
    psql_owner -d "$database" < packages/db/test/schema-fixture.sql
    docker exec -i -e PGPASSWORD=local-runtime-only "$container" \
        psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -U coffre_runtime -d "$database" \
        < packages/db/test/schema-guarantees.sql
    psql_owner -d "$database" < packages/db/test/schema-fixture.sql
    docker exec -i -e PGPASSWORD=local-vault-only "$container" \
        psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -U coffre_vault_runtime -d "$database" \
        < packages/db/test/vault-guarantees.sql
    psql_owner -d "$database" < packages/db/test/schema-fixture.sql
    psql_owner -d "$database" < packages/db/test/log-fixture.sql
    docker exec -i -e PGPASSWORD=local-vault-only "$container" \
        psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -U coffre_vault_runtime -d "$database" \
        < packages/db/test/log-guarantees.sql
    psql_owner -d "$database" < packages/db/test/log-owner.sql
}

# The first migration creates the groups; the next must harden existing groups.
for database in fresh existing; do
    psql_owner -d postgres -c "CREATE DATABASE $database"
    if [[ "$database" == existing ]]; then
        psql_owner -d postgres <<'SQL'
ALTER ROLE coffre_app LOGIN NOINHERIT CREATEDB CREATEROLE;
ALTER ROLE coffre_vault LOGIN NOINHERIT CREATEDB CREATEROLE;
ALTER ROLE coffre_backup LOGIN NOINHERIT CREATEDB CREATEROLE;
SQL
    fi
    migrate "$database"
    # A restore loses database privileges: the same owner must reassert them.
    psql_owner -d "$database" -c "GRANT CREATE, TEMPORARY ON DATABASE $database TO PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime, coffre_backup"
    migrate "$database"
    psql_owner -d "$database" <<'SQL'
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname IN ('coffre_app', 'coffre_vault', 'coffre_backup')
        AND (rolcanlogin OR NOT rolinherit OR rolcreatedb OR rolcreaterole OR rolsuper OR rolreplication OR rolbypassrls)
    ) THEN RAISE EXCEPTION 'group roles were not hardened'; END IF;
    IF EXISTS (
        SELECT 1 FROM unnest(ARRAY['coffre_app', 'coffre_backup', 'coffre_runtime', 'coffre_vault', 'coffre_vault_runtime']) AS role
        WHERE has_database_privilege(role, current_database(), 'CREATE')
           OR has_database_privilege(role, current_database(), 'TEMPORARY')
    ) THEN RAISE EXCEPTION 'database privileges were not restricted'; END IF;
    -- As a non-superuser owner, which only a login with ADMIN on them may do.
    IF EXISTS (
        SELECT 1 FROM unnest(ARRAY['coffre_runtime', 'coffre_vault_runtime', 'coffre_vault_hot']) AS login
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_db_role_setting s WHERE s.setrole = login::regrole AND s.setdatabase = 0 AND s.setconfig @> ARRAY['jit=off']
        )
    ) THEN RAISE EXCEPTION 'the runtime logins were not set to jit off'; END IF;
END $$;
SQL
    guarantees "$database"
done

# A member of the owner may migrate (a managed Postgres's admin login, say): a function it makes is its own, one it
# replaces keeps its owner, and `use_credential` runs as its owner. Hand the member 0045's and 0051's helpers, as if it
# had made them (the owner's grant moves with each), then replay 0057 as the member, which makes `use_covered` and
# replaces `use_credential`: its owner must still execute every function the uses call, found from their bodies (T187).
docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres <<'SQL'
CREATE ROLE migration_member LOGIN INHERIT IN ROLE migration_owner PASSWORD 'local-member-only';
SQL
psql_owner -d postgres -c "CREATE DATABASE member"
migrate member
docker exec -i "$container" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d member <<'SQL'
ALTER FUNCTION use_stands(uuid, uuid, smallint, bigint, jsonb) OWNER TO migration_member;
ALTER FUNCTION use_admits(jsonb, text) OWNER TO migration_member;
ALTER FUNCTION use_stands_personal(uuid, uuid, bigint, jsonb) OWNER TO migration_member;
ALTER FUNCTION use_scope_holds(uuid, uuid, text, jsonb) OWNER TO migration_member;
SQL
{
    echo "DROP FUNCTION use_covered(bigint, bigint, bigint, uuid, uuid, smallint, uuid);"
    cat packages/db/src/migrations/postgres/0057_use_covered.sql
} | docker exec -i -e PGPASSWORD=local-member-only "$container" \
    psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U migration_member -d member
psql_owner -d member <<'SQL'
DO $$
DECLARE v_missing text;
BEGIN
    IF (SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND pg_get_userbyid(proowner) = 'migration_member'
          AND proname IN ('use_covered', 'use_stands', 'use_admits', 'use_stands_personal', 'use_scope_holds')) <> 5 THEN
        RAISE EXCEPTION 'the replay did not leave the use''s helpers the member''s';
    END IF;
    WITH RECURSIVE called (oid) AS (
        SELECT oid FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname IN ('use_credential', 'use_batch', 'use_named_batch')
        UNION
        SELECT g.oid FROM called c JOIN pg_proc f ON f.oid = c.oid
          JOIN pg_proc g ON g.pronamespace = 'public'::regnamespace AND f.prosrc ~ ('\m' || g.proname || '\s*\(')
    )
    SELECT string_agg(oid::regprocedure::text, ', ') INTO v_missing FROM called WHERE NOT has_function_privilege(current_user, oid, 'EXECUTE');
    IF v_missing IS NOT NULL THEN
        RAISE EXCEPTION 'use_credential''s owner cannot execute %', v_missing;
    END IF;
    PERFORM use_covered(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
END $$;
SQL

# Unsafe groups must fail clearly, rather than trying a forbidden ALTER ROLE.
for attribute in SUPERUSER REPLICATION BYPASSRLS; do
    database="unsafe_${attribute,,}"
    psql_owner -d postgres -c "CREATE DATABASE $database"
    docker exec "$container" psql -X -v ON_ERROR_STOP=1 -U postgres \
        -c "ALTER ROLE coffre_app $attribute"
    accepted=false
    if migrate "$database" >"$scratch/unsafe.log" 2>&1; then accepted=true; fi
    # Restore before checking the result, even if the migrator or assertion fails.
    # The exit trap removes this cluster if the process is interrupted.
    docker exec "$container" psql -X -v ON_ERROR_STOP=1 -U postgres \
        -c "ALTER ROLE coffre_app NO$attribute"
    if [[ "$accepted" == true ]]; then
        echo "migration accepted a group with $attribute" >&2
        exit 1
    fi
    if ! grep -Fq 'coffre_app has unsafe role attributes' "$scratch/unsafe.log"; then
        cat "$scratch/unsafe.log" >&2
        exit 1
    fi
done

# Node's default CA set must verify both trust and the hostname. Add the local
# test CA at process startup, as a deployment adds its own trusted roots.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost \
    -keyout "$scratch/server.key" -out "$scratch/server.crt" >"$scratch/openssl.log" 2>&1
docker cp "$scratch/server.key" "$container:/tmp/server.key" >/dev/null
docker cp "$scratch/server.crt" "$container:/tmp/server.crt" >/dev/null
docker exec "$container" sh -c 'chown postgres:postgres /tmp/server.key /tmp/server.crt; chmod 600 /tmp/server.key'
docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres <<'SQL'
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/tmp/server.crt';
ALTER SYSTEM SET ssl_key_file = '/tmp/server.key';
SELECT pg_reload_conf();
SQL
# Reload is asynchronous. Wait until new connections see the certificate.
for attempt in $(seq 60); do
    if docker exec -e PGPASSWORD=local-owner-only "$container" \
        psql -X -At 'postgresql://migration_owner@127.0.0.1/existing?sslmode=require' \
        -c 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()' 2>/dev/null | grep -qx t; then break; fi
    if ((attempt == 60)); then docker logs "$container"; exit 1; fi
    sleep 1
done
url="postgresql://migration_owner:local-owner-only@localhost:$port/existing?sslrootcert=system"
for parameters in '' '&sslmode=verify-full' '&sslmode=verify-full&uselibpqcompat=true'; do
    NODE_EXTRA_CA_CERTS="$scratch/server.crt" node --conditions=coffre:source \
        packages/db/scripts/check-postgres-tls.ts "$url$parameters"
done
env -u NODE_EXTRA_CA_CERTS node --conditions=coffre:source \
    packages/db/scripts/check-postgres-tls.ts "$url" DEPTH_ZERO_SELF_SIGNED_CERT
NODE_EXTRA_CA_CERTS="$scratch/server.crt" node --conditions=coffre:source \
    packages/db/scripts/check-postgres-tls.ts "${url/localhost/127.0.0.1}" ERR_TLS_CERT_ALTNAME_INVALID

NODE_EXTRA_CA_CERTS="$scratch/server.crt" COFFRE_RUNTIME_ROLE=coffre_runtime \
    DATABASE_URL="postgresql://coffre_runtime:local-runtime-only@localhost:$port/existing?sslrootcert=system&sslmode=verify-full" \
    pnpm --filter @coffre/db run db:verify:runtime
