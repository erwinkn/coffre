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
# replaces keeps its owner, and each use function runs as its owner. So the owner migrates up to 0056, the member the
# rest: 0057 makes `use_covered` and replaces `use_credential` (T187), 0058 makes both again and `use_route` (T186 PR C),
# while 0048's `use_batch`, 0055's `use_named_batch` and 0045's and 0051's helpers stay the owner's. Each use function's
# owner must then execute every use function it calls, through those that run as their caller, read from their bodies.
docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres <<'SQL'
CREATE ROLE migration_member LOGIN INHERIT IN ROLE migration_owner PASSWORD 'local-member-only';
SQL
psql_owner -d postgres -c "CREATE DATABASE member"
before="$scratch/migrations-0056"
cp -r packages/db/src/migrations/postgres "$before"
node -e 'const fs = require("fs"), path = require("path"), tree = process.argv[1], f = path.join(tree, "meta/_journal.json"), j = JSON.parse(fs.readFileSync(f, "utf8"));
const cut = j.entries.find((e) => e.tag === "0057_use_covered").idx;
for (const e of j.entries.filter((e) => e.idx >= cut)) { fs.rmSync(path.join(tree, `${e.tag}.sql`)); fs.rmSync(path.join(tree, "meta", `${String(e.idx).padStart(4, "0")}_snapshot.json`), { force: true }); }
j.entries = j.entries.filter((e) => e.idx < cut); fs.writeFileSync(f, JSON.stringify(j))' "$before"
(cd packages/db && node --conditions=coffre:source --input-type=module -e '
    const { postgresClient } = await import("./src/postgres.ts");
    const { createDatabase } = await import("./src/database.ts");
    const { migrate } = await import("drizzle-orm/postgres-js/migrator");
    const client = postgresClient(process.argv[1], { max: 1 });
    await migrate(createDatabase(client), { migrationsFolder: process.argv[2] });
    await client.end();
' "postgresql://migration_owner:local-owner-only@127.0.0.1:$port/member" "$before")
DATABASE_URL="postgresql://migration_member:local-member-only@127.0.0.1:$port/member" \
    pnpm --filter @coffre/db run db:migrate
psql_owner -d member <<'SQL'
DO $$
DECLARE
    v_call record;
    v_calls integer := 0;
BEGIN
    IF (SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname = 'use_credential') <> 'migration_member'
       OR (SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname = 'use_batch') <> 'migration_owner' THEN
        RAISE EXCEPTION 'the member did not make use_credential, or the owner did not keep use_batch';
    END IF;
    FOR v_call IN
        WITH RECURSIVE uses AS (
            SELECT oid, proname, prosecdef, proowner, prosrc FROM pg_proc
             WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'use\_%'
        ), calls(caller, runner, callee) AS (
            SELECT c.oid, c.proowner, e.oid FROM uses c JOIN uses e ON e.oid <> c.oid AND c.prosrc ~ ('[^a-z_]' || e.proname || '\s*\(')
             WHERE c.prosecdef
            UNION
            SELECT k.caller, k.runner, e.oid FROM calls k JOIN uses c ON c.oid = k.callee AND NOT c.prosecdef
              JOIN uses e ON e.oid <> c.oid AND c.prosrc ~ ('[^a-z_]' || e.proname || '\s*\(')
        )
        SELECT caller::regprocedure AS caller, pg_get_userbyid(runner) AS runner, callee::regprocedure AS callee FROM calls
    LOOP
        v_calls := v_calls + 1;
        IF NOT has_function_privilege(v_call.runner, v_call.callee, 'EXECUTE') THEN
            RAISE EXCEPTION '%, running as %, cannot execute %', v_call.caller, v_call.runner, v_call.callee;
        END IF;
    END LOOP;
    -- use_batch, use_named_batch and use_route call use_credential; it calls use_covered, use_stands and
    -- use_stands_personal, and they use_admits and use_scope_holds as its owner.
    IF v_calls < 8 THEN RAISE EXCEPTION 'read % calls between the use functions, fewer than they make', v_calls; END IF;
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
