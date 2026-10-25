#!/usr/bin/env bash
# The backup role (docs/restore.md) on a disposable cluster, since roles are
# cluster-wide: coffre_backup, the group 0019_backup_role.sql makes, and
# coffre_backup_login, provisioned outside the migrations, which every
# migrate grants the group. The login, made after the migrations, gets the
# group at the next run; runs with nothing to apply, two at once, change
# nothing; it then dumps the whole database, every audit entry included, the
# dump restores to the same rows, and it writes nothing. A login that may not
# grant the group says so, and the run still succeeds.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-coffre}"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/coffre-backup-role.XXXXXX")"
container="coffre-backup-role-${scratch##*.}"
cleanup() {
    docker rm -fv "$container" >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT
image="$(docker compose config --format json | node -e 'let input=""; for await (const chunk of process.stdin) input+=chunk; console.log(JSON.parse(input).services.postgres.image)')"
docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=local-bootstrap-only \
    -p 127.0.0.1::5432 "$image" >/dev/null
for attempt in $(seq 60); do
    if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    if ((attempt == 60)); then docker logs "$container"; exit 1; fi
    sleep 1
done
port="$(docker port "$container" 5432/tcp | cut -d: -f2)"
as_superuser() { docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -qU postgres "$@"; }
as_owner() { docker exec -i -e PGPASSWORD=local-owner-only "$container" psql -X -v ON_ERROR_STOP=1 -q -h 127.0.0.1 -U migration_owner "$@"; }
as_backup() { docker exec -i -e PGPASSWORD=local-backup-only "$container" "$@" -h 127.0.0.1 -U coffre_backup_login; }
migrate() {
    DATABASE_URL="postgresql://migration_owner:local-owner-only@127.0.0.1:$port/$1" \
        pnpm --filter @coffre/db run db:migrate
}
# A login that migrates as a member of the owner, as the CLI's NotOwner advice makes one: its privileges, never its CREATEROLE.
as_member() { docker exec -i -e PGPASSWORD=local-member-only "$container" psql -X -v ON_ERROR_STOP=1 -q -h 127.0.0.1 -U migration_member "$@"; }
migrate_as_member() {
    DATABASE_URL="postgresql://migration_member:local-member-only@127.0.0.1:$port/$1" \
        pnpm --filter @coffre/db run db:migrate
}

# Managed hosts give the owner CREATEROLE, not superuser.
as_superuser -c "CREATE ROLE migration_owner LOGIN CREATEROLE CREATEDB PASSWORD 'local-owner-only'"
as_owner -d postgres <<'SQL'
CREATE ROLE coffre_runtime LOGIN PASSWORD 'local-runtime-only';
CREATE ROLE coffre_vault_runtime LOGIN PASSWORD 'local-vault-only';
SQL

as_superuser <<'SQL'
CREATE ROLE migration_member LOGIN PASSWORD 'local-member-only';
GRANT migration_owner TO migration_member WITH INHERIT TRUE;
SQL

# The migration's first statement, as such a login: refused, saying why,
# while it would have to make the group; done, with nothing to alter, once
# a login with CREATEROLE has made it.
sed '/--> statement-breakpoint/q' packages/db/src/migrations/postgres/0019_backup_role.sql >"$scratch/0019-role.sql"
if as_member -d postgres <"$scratch/0019-role.sql" >"$scratch/member.log" 2>&1 \
    || ! grep -Fq 'migration_member may not create roles, and this migration makes coffre_backup' "$scratch/member.log"; then
    cat "$scratch/member.log" >&2
    exit 1
fi
as_owner -d postgres -c 'CREATE ROLE coffre_backup NOLOGIN'
as_member -d postgres <"$scratch/0019-role.sql"

# A group with any of these rights is refused, and nothing changes.
for attribute in SUPERUSER REPLICATION BYPASSRLS; do
    database="unsafe_${attribute,,}"
    as_owner -d postgres -c "CREATE DATABASE $database"
    as_superuser -c "ALTER ROLE coffre_backup $attribute"
    accepted=false
    if migrate "$database" >"$scratch/unsafe.log" 2>&1; then accepted=true; fi
    as_superuser -c "ALTER ROLE coffre_backup NO$attribute"
    if [[ "$accepted" == true ]]; then
        echo "migration accepted a backup group with $attribute" >&2
        exit 1
    fi
    if ! grep -Fq 'coffre_backup has unsafe role attributes' "$scratch/unsafe.log"; then
        cat "$scratch/unsafe.log" >&2
        exit 1
    fi
done

# A group that is a member of another role would pass that role's
# privileges on to the backup login: refused too.
as_owner -d postgres -c 'CREATE DATABASE unsafe_member'
as_superuser -c 'GRANT pg_write_all_data TO coffre_backup'
accepted=false
if migrate unsafe_member >"$scratch/unsafe.log" 2>&1; then accepted=true; fi
as_superuser -c 'REVOKE pg_write_all_data FROM coffre_backup'
if [[ "$accepted" == true ]] || ! grep -Fq 'coffre_backup is a member of another role' "$scratch/unsafe.log"; then
    cat "$scratch/unsafe.log" >&2
    exit 1
fi

# Nor one that has members besides the backup login, who would read every row.
as_owner -d postgres -c 'CREATE DATABASE unsafe_members'
as_superuser -c 'CREATE ROLE mallory NOLOGIN' -c 'GRANT coffre_backup TO mallory'
accepted=false
if migrate unsafe_members >"$scratch/unsafe.log" 2>&1; then accepted=true; fi
as_superuser -c 'REVOKE coffre_backup FROM mallory'
if [[ "$accepted" == true ]] || ! grep -Fq 'coffre_backup has members other than coffre_backup_login' "$scratch/unsafe.log"; then
    cat "$scratch/unsafe.log" >&2
    exit 1
fi

# Databases at 0018, the schema before this migration, whose public holds a
# table of another role, as migrate.test.ts's reporting table, and in which
# the group was granted a write. 0019 then grants coffre's tables, and only
# them, whoever migrates, the superuser included, and revokes the write.
tree="$scratch/migrations-0018"
cp -r packages/db/src/migrations/postgres "$tree"
rm "$tree/0019_backup_role.sql" "$tree/meta/0019_snapshot.json"
node -e 'const fs = require("fs"), f = process.argv[1], j = JSON.parse(fs.readFileSync(f, "utf8")); j.entries = j.entries.filter((e) => e.tag !== "0019_backup_role"); fs.writeFileSync(f, JSON.stringify(j))' "$tree/meta/_journal.json"
as_superuser -c 'CREATE ROLE reporting NOLOGIN'
for login in migration_owner:local-owner-only postgres:local-bootstrap-only; do
    database="at_0018_${login%%:*}"
    url="postgresql://$login@127.0.0.1:$port/$database"
    as_superuser -c "CREATE DATABASE $database OWNER ${login%%:*}"
    (cd packages/db && node --input-type=module -e '
        const { default: pg } = await import("pg");
        const { drizzle } = await import("drizzle-orm/node-postgres");
        const { migrate } = await import("drizzle-orm/node-postgres/migrator");
        const client = new pg.Client(process.argv[1]);
        await client.connect();
        await migrate(drizzle(client), { migrationsFolder: process.argv[2] });
        await client.end();
    ' "$url" "$tree")
    as_superuser -d "$database" <<'SQL'
CREATE TABLE public.reporting_rows (n integer);
ALTER TABLE public.reporting_rows OWNER TO reporting;
GRANT INSERT ON projects TO coffre_backup;
SQL
    DATABASE_URL="$url" pnpm --filter @coffre/db run db:migrate >"$scratch/at_0018.log" 2>&1 || { cat "$scratch/at_0018.log" >&2; exit 1; }
    [[ "$(as_superuser -d "$database" -At -c "SELECT has_table_privilege('coffre_backup', 'projects', 'SELECT') AND NOT has_table_privilege('coffre_backup', 'projects', 'INSERT')")" == t ]] \
        || { echo "0019, as ${login%%:*}, did not leave the group exactly SELECT on projects" >&2; exit 1; }
    [[ "$(as_superuser -d "$database" -At -c "SELECT has_table_privilege('coffre_backup', 'reporting_rows', 'SELECT')")" == f ]] \
        || { echo "0019, as ${login%%:*}, granted the group another role's table" >&2; exit 1; }
done

# A table a later migration makes as the member, whose CREATE TABLE names it
# as one of coffre's (capped_alerts, made again here): its next run grants
# the group it, and still not the other role's table.
as_member -d at_0018_migration_owner -c 'DROP TABLE capped_alerts; CREATE TABLE capped_alerts (service text)'
migrate_as_member at_0018_migration_owner >/dev/null
[[ "$(as_superuser -d at_0018_migration_owner -At -c "SELECT has_table_privilege('coffre_backup', 'capped_alerts', 'SELECT') AND NOT has_table_privilege('coffre_backup', 'reporting_rows', 'SELECT')")" == t ]] \
    || { echo "migrate did not grant the group exactly coffre's table the member made" >&2; exit 1; }

# Before the login exists, each run says there is none to back up as.
as_owner -d postgres -c 'CREATE DATABASE backed_up'
migrate backed_up >"$scratch/migrate.log"
grep -Fq 'no backup login: coffre_backup_login does not exist' "$scratch/migrate.log" || { cat "$scratch/migrate.log" >&2; exit 1; }

# Rows in every table the fixture fills, and entries by both authors.
as_owner -d backed_up < packages/db/test/schema-fixture.sql
as_owner -d backed_up <<'SQL'
INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
SELECT seq, CASE WHEN seq % 2 = 0 THEN 'app' ELSE 'vault' END, 'fixture', seq, 'system:fixture', 'secret.read', 'allow',
       sha256(int8send(seq - 1)), sha256(int8send(seq)), sha256(int8send(seq))
  FROM generate_series(1, 40) AS seq;
SQL

# The login, made after the migrations by someone else, as a deployment's
# Terraform makes it: the next run grants it the group, and says nothing of
# its absence.
as_superuser -c "CREATE ROLE coffre_backup_login LOGIN PASSWORD 'local-backup-only'"
migrate backed_up >"$scratch/migrate.log"
if grep -Fq 'no backup login' "$scratch/migrate.log"; then cat "$scratch/migrate.log" >&2; exit 1; fi

# Everything the run may change, and the roles: a run after changes none of it.
catalog() {
    as_owner -d "$1" -At <<'SQL'
SELECT c.oid::regclass::text, c.relkind, c.relrowsecurity, c.relacl::text
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname IN ('public', 'drizzle') ORDER BY 1;
SELECT n.nspname, n.nspacl::text FROM pg_namespace n WHERE n.nspname IN ('public', 'drizzle') ORDER BY 1;
SELECT tablename, policyname, cmd, roles::text, qual, with_check FROM pg_policies ORDER BY 1, 2;
SELECT pg_get_userbyid(defaclrole), defaclnamespace::regnamespace::text, defaclobjtype, defaclacl::text FROM pg_default_acl ORDER BY 1, 2, 3;
SELECT tgrelid::regclass::text, tgname, tgenabled FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1, 2;
SQL
}
roles() {
    as_superuser -d postgres -At <<'SQL'
SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
  FROM pg_roles WHERE rolname LIKE 'coffre%' ORDER BY 1;
SELECT roleid::regrole, member::regrole, grantor::regrole, admin_option, inherit_option, set_option
  FROM pg_auth_members WHERE member::regrole::text LIKE 'coffre%' ORDER BY 1, 2, 3;
SELECT datname, datacl::text FROM pg_database WHERE datname = 'backed_up';
SQL
}
# Each catalog row's version: a GRANT that changes nothing still writes one.
versions() {
    as_superuser -d "$1" -At <<'SQL'
SELECT 'class', c.oid::regclass::text, c.xmin FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname IN ('public', 'drizzle') ORDER BY 2;
SELECT 'namespace', nspname, xmin FROM pg_namespace WHERE nspname IN ('public', 'drizzle') ORDER BY 2;
SELECT 'policy', polname, xmin FROM pg_policy ORDER BY 2;
SELECT 'proc', p.oid::regprocedure::text, p.xmin FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname IN ('public', 'drizzle') ORDER BY 2;
SELECT 'member', roleid::regrole, member::regrole, xmin FROM pg_auth_members WHERE member::regrole::text LIKE 'coffre%' ORDER BY 2, 3;
SELECT 'role', rolname, xmin FROM pg_authid WHERE rolname LIKE 'coffre%' ORDER BY 2;
SQL
}
# Every row's version and place: an insert, update or delete changes them.
physical() {
    as_owner -d "$1" -At <<'SQL'
SELECT format('SELECT %L, count(*), md5(coalesce(string_agg(xmin::text || '':'' || ctid::text, '','' ORDER BY ctid), '''')) FROM %s', c.oid::regclass, c.oid::regclass)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname IN ('public', 'drizzle') AND c.relkind IN ('r', 'p')
 ORDER BY 1
\gexec
SQL
}
catalog backed_up >"$scratch/before.catalog"
roles >"$scratch/before.roles"
physical backed_up >"$scratch/before.physical"
versions backed_up >"$scratch/before.versions"
# As two deploys' builds may, both Workers' each: with the migration lock
# held (packages/db/src/migrate.ts), both runs queue on it, then each takes
# its turn, and both succeed.
as_owner -d backed_up -c 'SELECT pg_advisory_lock(7165058122361679213), pg_sleep(30)' >/dev/null 2>&1 &
holder=$!
migrate backed_up >"$scratch/first.log" 2>&1 &
first=$!
migrate backed_up >"$scratch/second.log" 2>&1 &
second=$!
waiting() {
    as_owner -d backed_up -At -c "SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid = l.database
        WHERE d.datname = 'backed_up' AND l.locktype = 'advisory' AND NOT l.granted"
}
for attempt in $(seq 100); do
    [[ "$(waiting)" == 2 ]] && break
    if ((attempt == 100)); then echo 'the two runs did not both queue on the migration lock' >&2; exit 1; fi
    sleep 0.2
done
as_superuser -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'backed_up' AND query LIKE '%pg_sleep(30)%' AND pid <> pg_backend_pid()" >/dev/null
wait "$holder" || true
failed=false
wait "$first" || failed=true
wait "$second" || failed=true
if [[ "$failed" == true ]]; then cat "$scratch/first.log" "$scratch/second.log" >&2; exit 1; fi
catalog backed_up >"$scratch/after.catalog"
roles >"$scratch/after.roles"
physical backed_up >"$scratch/after.physical"
versions backed_up >"$scratch/after.versions"
diff "$scratch/before.catalog" "$scratch/after.catalog"
diff "$scratch/before.roles" "$scratch/after.roles"
diff "$scratch/before.physical" "$scratch/after.physical"
diff "$scratch/before.versions" "$scratch/after.versions"
grep -qx 'coffre_backup|f|t|f|f|f|f|f' "$scratch/after.roles" || { echo 'coffre_backup is not a group with no login and no unsafe rights' >&2; exit 1; }
grep -qx 'coffre_backup|coffre_backup_login|migration_owner|f|t|f' "$scratch/after.roles" || { echo 'migrate did not grant coffre_backup_login its group' >&2; exit 1; }

entries="$(as_owner -d backed_up -At -c 'SELECT count(*) FROM audit_log')"
as_backup psql -X -v ON_ERROR_STOP=1 -q -v entries="$entries" -d backed_up < packages/db/test/backup-guarantees.sql

# The backup, exactly as docs/restore.md takes it, restored as that page does.
as_backup pg_dump --enable-row-security --format=custom --dbname=backed_up >"$scratch/backup.dump"
as_owner -d postgres -c 'CREATE DATABASE restored'
docker exec -i -e PGPASSWORD=local-owner-only "$container" \
    pg_restore --exit-on-error -h 127.0.0.1 -U migration_owner --dbname=restored <"$scratch/backup.dump"
migrate restored >/dev/null

# Every row of every table came back, and every grant, policy and trigger.
rows() {
    as_owner -d "$1" -At <<'SQL'
SELECT format('SELECT %L, count(*), md5(coalesce(string_agg(row::text, E''\n'' ORDER BY row::text), '''')) FROM %s AS row', c.oid::regclass, c.oid::regclass)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname IN ('public', 'drizzle') AND c.relkind IN ('r', 'p')
 ORDER BY 1
\gexec
SQL
}
rows backed_up >"$scratch/backed_up.rows"
rows restored >"$scratch/restored.rows"
diff "$scratch/backed_up.rows" "$scratch/restored.rows"
grep -qx "audit_log|$entries|.*" "$scratch/restored.rows" || { echo 'the restore lacks audit entries' >&2; exit 1; }
catalog restored >"$scratch/restored.catalog"
diff "$scratch/after.catalog" "$scratch/restored.catalog"
grep -q '^audit_log|audit_log_backup_read|SELECT|{coffre_backup}|true|$' "$scratch/restored.catalog" || { echo 'the restore lacks the backup read policy' >&2; exit 1; }
# An owner without ADMIN OPTION on the group, which someone else took away:
# the run cannot grant the login, says so, and succeeds.
as_superuser -c 'REVOKE ADMIN OPTION FOR coffre_backup FROM migration_owner GRANTED BY postgres CASCADE'
[[ "$(as_superuser -d postgres -At -c "SELECT pg_has_role('coffre_backup_login', 'coffre_backup', 'USAGE')")" == f ]] \
    || { echo 'the login kept its group' >&2; exit 1; }
migrate backed_up >"$scratch/refused.log" 2>&1 || { cat "$scratch/refused.log" >&2; exit 1; }
grep -Fq 'coffre_backup_login does not inherit coffre_backup, and this login may not grant it' "$scratch/refused.log" \
    || { cat "$scratch/refused.log" >&2; exit 1; }
echo 'coffre_backup_login dumps every row, the audit log whole, and writes nothing'
