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
    -- No planner setting of the runtime logins', server-wide or for this database (T207): they run at the server's.
    IF EXISTS (
        SELECT 1 FROM pg_db_role_setting s, unnest(s.setconfig) AS setting
         WHERE s.setrole IN ('coffre_runtime'::regrole, 'coffre_vault_runtime'::regrole, 'coffre_vault_hot'::regrole)
           AND split_part(setting, '=', 1) ~ '^(jit|plan_cache_mode|enable_.*)$'
    ) THEN RAISE EXCEPTION 'a runtime login has a planner setting of its own'; END IF;
END $$;
SQL
    guarantees "$database"
done

# A member of the owner may migrate (a managed Postgres's admin login, say). Under drizzle's migrator, as below, what it
# made stayed its own, and databases it migrated so stay as it left them: a function it made is its own, one it
# replaced kept its owner, and each use function runs as its owner, its helpers (which are not SECURITY DEFINER) as
# their caller. So the owner migrates up to 0056, and 0045's and 0051's helpers are handed to the member, as if it had
# made them (the owner's grant moves with each). The member then runs the rest, one migration at a time, since each
# meets the running code: 0057 makes `use_covered` and replaces `use_credential`, which stays the owner's and must be
# granted the member's helpers; 0058 makes both again, the member's now, and `use_route`, while
# 0048's `use_batch` and 0055's `use_named_batch` stay the owner's and must be granted `use_credential`; 0059 replaces
# `use_credential` and `use_route`, which keep their owner, and adds an attribute to `use_row`. After each,
# every use function's runner must execute every use function it calls, read from their bodies.
docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres <<'SQL'
CREATE ROLE migration_member LOGIN INHERIT IN ROLE migration_owner PASSWORD 'local-member-only';
SQL
psql_owner -d postgres -c "CREATE DATABASE member"
# migrate_through <database> <login> <password> <last tag>: drizzle's migrator over the journal up to that tag, as coffre
# migrated before it had its own migrator. Never past `$before_t193`, the newest migration then (0074): every later one only coffre's own migrator
# has applied (`db:migrate`), and only it can, since it builds 0082's indexes CONCURRENTLY after its transaction commits
# (`online-indexes.ts`), where drizzle's runs every statement inside it.
before_t193=0074_bulk_phase
# The fixtures stop at 0073 (`p_passkeys`), whose owners they check; a checkpoint at 0074 would be as valid.
fixture_at=0073_passkeys_in_vault
migrate_through() {
    node -e 'const j = require("./packages/db/src/migrations/postgres/meta/_journal.json"), [last, bound] = process.argv.slice(1), idx = (t) => j.entries.find((e) => e.tag === t)?.idx;
if (idx(last) === undefined || idx(last) > idx(bound)) { console.error(`drizzle migrates only through ${bound}, not ${last}: the rest is for coffre\u2019s own migrator (db:migrate)`); process.exit(1); }' "${4:-}" "$before_t193"
    local tree="$scratch/migrations-$4"
    rm -rf "$tree"
    cp -r packages/db/src/migrations/postgres "$tree"
    node -e 'const fs = require("fs"), path = require("path"), [tree, last] = process.argv.slice(1), f = path.join(tree, "meta/_journal.json"), j = JSON.parse(fs.readFileSync(f, "utf8"));
const cut = j.entries.find((e) => e.tag === last).idx;
for (const e of j.entries.filter((e) => e.idx > cut)) { fs.rmSync(path.join(tree, `${e.tag}.sql`)); fs.rmSync(path.join(tree, "meta", `${String(e.idx).padStart(4, "0")}_snapshot.json`), { force: true }); }
j.entries = j.entries.filter((e) => e.idx <= cut); fs.writeFileSync(f, JSON.stringify(j))' "$tree" "$4"
    (cd packages/db && node --conditions=coffre:source --input-type=module -e '
        const { postgresClient } = await import("./src/postgres.ts");
        const { createDatabase } = await import("./src/database.ts");
        const { migrate } = await import("drizzle-orm/postgres-js/migrator");
        const client = postgresClient(process.argv[1], { max: 1 });
        await migrate(createDatabase(client), { migrationsFolder: process.argv[2] });
        await client.end();
    ' "postgresql://$2:$3@127.0.0.1:$port/$1" "$tree")
}
# use_grants <database> <fewest calls>: each use function's runner may execute each use function it calls.
use_grants() {
    psql_owner -d "$1" -v calls="$2" <<'SQL'
SELECT set_config('use_grants.calls', :'calls', false);
DO $$
DECLARE
    v_call record;
    v_calls integer := 0;
    v_missing text[] := '{}';
BEGIN
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
            v_missing := v_missing || format('%s, running as %s, cannot execute %s', v_call.caller, v_call.runner, v_call.callee);
        END IF;
    END LOOP;
    IF cardinality(v_missing) > 0 THEN RAISE EXCEPTION '%', array_to_string(v_missing, E';\n'); END IF;
    IF v_calls < current_setting('use_grants.calls')::integer THEN
        RAISE EXCEPTION 'read % calls between the use functions, fewer than they make', v_calls;
    END IF;
END $$;
SQL
}
owners() {
    psql_owner -d member -Atc "SELECT string_agg(proname || '=' || pg_get_userbyid(proowner), ' ' ORDER BY proname) FROM pg_proc
        WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'use\_%'"
}
migrate_through member migration_owner local-owner-only 0056_proxy_definitions
docker exec -i "$container" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d member <<'SQL'
ALTER FUNCTION use_stands(uuid, uuid, smallint, bigint, jsonb) OWNER TO migration_member;
ALTER FUNCTION use_admits(jsonb, text) OWNER TO migration_member;
ALTER FUNCTION use_stands_personal(uuid, uuid, bigint, jsonb) OWNER TO migration_member;
ALTER FUNCTION use_scope_holds(uuid, uuid, text, jsonb) OWNER TO migration_member;
SQL
migrate_through member migration_member local-member-only 0057_use_covered
expected="use_admits=migration_member use_batch=migration_owner use_covered=migration_member use_credential=migration_owner"
expected+=" use_named_batch=migration_owner use_scope_holds=migration_member use_stands=migration_member use_stands_personal=migration_member"
[[ "$(owners)" == "$expected" ]] || { echo "after 0057, the use functions' owners: $(owners)" >&2; exit 1; }
# use_batch and use_named_batch call use_credential; it calls use_covered, use_stands and use_stands_personal, and they
# call use_admits, use_scope_holds and use_stands as its owner.
use_grants member 7
migrate_through member migration_member local-member-only 0058_route_uses
expected="use_admits=migration_member use_batch=migration_owner use_covered=migration_member use_credential=migration_member"
expected+=" use_named_batch=migration_owner use_route=migration_member use_scope_holds=migration_member use_stands=migration_member"
expected+=" use_stands_personal=migration_member"
[[ "$(owners)" == "$expected" ]] || { echo "after 0058, the use functions' owners: $(owners)" >&2; exit 1; }
# use_route calls use_credential too.
use_grants member 8
migrate_through member migration_member local-member-only 0072_passkeys_principal
[[ "$(owners)" == "$expected" ]] || { echo "after 0059, the use functions' owners: $(owners)" >&2; exit 1; }
use_grants member 8
# 0073 makes `use_credential` and `use_named_batch` again, with `p_passkeys`: both the member's now, while
# 0048's `use_batch` stays the owner's and must be granted the new `use_credential`, which the drop took from it.
migrate_through member migration_member local-member-only "$fixture_at"
expected="${expected/use_named_batch=migration_owner/use_named_batch=migration_member}"
[[ "$(owners)" == "$expected" ]] || { echo "after 0073, the use functions' owners: $(owners)" >&2; exit 1; }
use_grants member 8
# 0064 makes `issue_token`'s overload, the member's, and replaces 0036's signature with a wrapper calling it, which keeps
# its owner and runs as it. The previous release's vault, which calls that signature during a rollout, must
# still be answered: for a person who is no member, `moved`, never a permission error.
issuers="$(psql_owner -d member -Atc "SELECT string_agg(pronargs || '=' || pg_get_userbyid(proowner), ' ' ORDER BY pronargs) FROM pg_proc
    WHERE pronamespace = 'public'::regnamespace AND proname = 'issue_token'")"
[[ "$issuers" == "28=migration_owner 29=migration_member" ]] || { echo "after 0064, issue_token's owners: $issuers" >&2; exit 1; }
answer="$(docker exec -i -e PGPASSWORD=local-vault-only "$container" \
    psql -X -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -U coffre_vault_runtime -d member -c "SELECT issue_token(
        'r', 0, 'nobody', '{}', '\x00', '\x00', 'nobody', 1, 0, 1, 0, NULL, NULL, NULL, 0, '{}', '{}', 'k',
        gen_random_uuid(), 'personal', '\x00', '\x00', 'h', 'l', 'nobody', 'all', NULL, 0) ->> 'state'")"
[[ "$answer" == moved ]] || { echo "the previous release's issue_token answered: $answer" >&2; exit 1; }

# The same split one step later: the owner migrates through 0062, so `write_request` (0061) and `admit_read` (0062)
# are its, and the member runs the rest, so `passkeys` (0063) is the member's. 0073 has the two read it, as
# they run, as their owner: each must be granted it, or every key write and member add fails with a permission error.
psql_owner -d postgres -c "CREATE DATABASE split"
migrate_through split migration_owner local-owner-only 0062_admit_inputs
migrate_through split migration_member local-member-only "$fixture_at"
# split_holds <after what>: what the owner's functions read and write, the member's tables, they may.
split_holds() {
psql_owner -d split <<'SQL'
DO $$
DECLARE
    v_missing text;
BEGIN
    -- Every function that runs as its owner and reads a table the member made after 0062, `passkeys` (0063) and T178's
    -- `policy` and `roles` (0081), itself or through a helper that runs as its caller, read from their bodies.
    -- Those there yet: 0081's come with coffre's migrator, after the check at 0073.
    WITH made(tbl) AS (SELECT t FROM (VALUES ('passkeys'), ('policy'), ('roles')) AS v(t) WHERE to_regclass('public.' || t) IS NOT NULL),
    helpers AS (
        SELECT proname, prosrc FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND NOT prosecdef
    )
    SELECT string_agg(format('%s, running as %s, cannot read %s', p.oid::regprocedure, pg_get_userbyid(p.proowner), m.tbl), E';\n')
      INTO v_missing
      FROM pg_proc p CROSS JOIN made m
     WHERE p.pronamespace = 'public'::regnamespace AND p.prosecdef
       AND (p.prosrc ~ ('public\.' || m.tbl || '([^a-z_]|$)')
            OR EXISTS (SELECT 1 FROM helpers h WHERE p.prosrc ~ ('public\.' || h.proname || '\s*\(')
                                                 AND h.prosrc ~ ('public\.' || m.tbl || '([^a-z_]|$)')))
       AND NOT has_table_privilege(p.proowner, 'public.' || m.tbl, 'SELECT');
    IF v_missing IS NOT NULL THEN RAISE EXCEPTION '%', v_missing; END IF;
    -- And each one that writes them (`change_input`), what it writes.
    WITH made(tbl) AS (SELECT t FROM (VALUES ('policy'), ('roles')) AS v(t) WHERE to_regclass('public.' || t) IS NOT NULL),
    writes(privilege, pattern) AS (VALUES ('INSERT', 'INSERT INTO public\.'), ('UPDATE', 'UPDATE public\.'), ('DELETE', 'DELETE FROM public\.'))
    SELECT string_agg(format('%s, running as %s, cannot %s %s', p.oid::regprocedure, pg_get_userbyid(p.proowner), w.privilege, m.tbl), E';\n')
      INTO v_missing
      FROM pg_proc p CROSS JOIN made m CROSS JOIN writes w
     WHERE p.pronamespace = 'public'::regnamespace AND p.prosecdef AND p.prosrc ~ (w.pattern || m.tbl || '([^a-z_]|$)')
       AND NOT has_table_privilege(p.proowner, 'public.' || m.tbl, w.privilege);
    IF v_missing IS NOT NULL THEN RAISE EXCEPTION '%', v_missing; END IF;
    IF pg_get_userbyid((SELECT proowner FROM pg_proc WHERE oid = 'public.write_request(bigint, bytea, text, text, text[])'::regprocedure))
       <> 'migration_owner' THEN
        RAISE EXCEPTION 'write_request is no longer the owner''s: the split tests nothing';
    END IF;
END $$;
SQL
# And both answer the vault, as the previous release's calls them.
now="(extract(epoch FROM clock_timestamp()) * 1000)::bigint"
token="'\x$(printf '00%.0s' {1..32})'::bytea"
for call in "write_request($now, $token, 'p', 'e', '{k}')" "admit_read($now, $token, 'user:nobody', '{}')"; do
    answer="$(docker exec -i -e PGPASSWORD=local-vault-only "$container" \
        psql -X -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -U coffre_vault_runtime -d split -c "SELECT $call ->> 'state'")"
    [[ "$answer" == read ]] || { echo "after $1, ${call%%(*} answered: $answer" >&2; exit 1; }
done
}
split_holds 0073
# Then coffre's migrator, as the member, the rest (0081's `policy` and `roles` among them), handing what the member made
# over to the owner: the owner's functions still read and write all of it.
DATABASE_URL="postgresql://migration_member:local-member-only@127.0.0.1:$port/split" pnpm --filter @coffre/db run db:migrate
split_holds "coffre's migrator"

# The above is how a member migrated by drizzle's migrator, which leaves what it makes the member's, and
# what the shipped migrations' grants must still answer. coffre's own migrator, as the member, applies the rest of the
# database the member migrated through 0058 above, whose helpers and `use_credential` are the member's, then, before
# it commits, hands the owner each of coffre's objects the member's (the ACLs with them, a grant to the owner of what
# was the member's folded into its own). Afterwards every one of coffre's objects is the owner's, and the guarantees
# hold.
psql_owner -d postgres -c "CREATE DATABASE handover"
migrate_through handover migration_owner local-owner-only 0056_proxy_definitions
docker exec -i "$container" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d handover <<'SQL'
ALTER FUNCTION use_stands(uuid, uuid, smallint, bigint, jsonb) OWNER TO migration_member;
ALTER FUNCTION use_admits(jsonb, text) OWNER TO migration_member;
ALTER FUNCTION use_stands_personal(uuid, uuid, bigint, jsonb) OWNER TO migration_member;
ALTER FUNCTION use_scope_holds(uuid, uuid, text, jsonb) OWNER TO migration_member;
SQL
migrate_through handover migration_member local-member-only 0058_route_uses
# A day made by the member's own `make_day`, as its partition: the owner's afterwards too.
docker exec -i "$container" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d handover <<'SQL'
ALTER FUNCTION make_day(date) OWNER TO migration_member;
SET ROLE migration_member;
SELECT make_day(date '2031-01-01');
SQL
DATABASE_URL="postgresql://migration_member:local-member-only@127.0.0.1:$port/handover" pnpm --filter @coffre/db run db:migrate
foreign="$(psql_owner -d handover -Atc "SELECT string_agg(kind || ' ' || name || '=' || owner, ', ' ORDER BY kind, name) FROM (
    SELECT 'relation' AS kind, c.oid::regclass::text AS name, pg_get_userbyid(c.relowner) AS owner FROM pg_class c
     WHERE c.relnamespace IN ('public'::regnamespace, 'drizzle'::regnamespace) AND c.relowner <> 'migration_owner'::regrole
    UNION ALL
    SELECT 'function', p.oid::regprocedure::text, pg_get_userbyid(p.proowner) FROM pg_proc p
     WHERE p.pronamespace = 'public'::regnamespace AND p.proowner <> 'migration_owner'::regrole
    UNION ALL
    SELECT 'type', t.oid::regtype::text, pg_get_userbyid(t.typowner) FROM pg_type t
     WHERE t.typnamespace = 'public'::regnamespace AND t.typowner <> 'migration_owner'::regrole
    UNION ALL
    SELECT 'statistics', s.stxname::text, pg_get_userbyid(s.stxowner) FROM pg_statistic_ext s
     WHERE s.stxnamespace IN ('public'::regnamespace, 'drizzle'::regnamespace) AND s.stxowner <> 'migration_owner'::regrole
) AS objects")"
[[ -z "$foreign" ]] || { echo "after the member migrated as the owner, objects not the owner's: $foreign" >&2; exit 1; }
# No grant names the member, as grantee or grantor: each moved to the owner with its object, a grant to the owner of
# what was the member's (0057's, 0058's) folded into the owner's own.
leftover="$(psql_owner -d handover -Atc "SELECT string_agg(name || ' ' || entry, ', ') FROM (
    SELECT p.oid::regprocedure::text AS name, a::text AS entry FROM pg_proc p, unnest(p.proacl) AS a WHERE p.pronamespace = 'public'::regnamespace
    UNION ALL
    SELECT c.oid::regclass::text, a::text FROM pg_class c, unnest(c.relacl) AS a WHERE c.relnamespace IN ('public'::regnamespace, 'drizzle'::regnamespace)
) AS grants WHERE entry LIKE '%migration_member%'")"
[[ -z "$leftover" ]] || { echo "after the hand-over, grants naming the member: $leftover" >&2; exit 1; }
use_grants handover 8
DATABASE_URL="postgresql://migration_member:local-member-only@127.0.0.1:$port/handover" pnpm --filter @coffre/db run db:migrate
guarantees handover

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
