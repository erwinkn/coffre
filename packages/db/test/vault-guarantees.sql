-- Adversarial checks through the vault's login, coffre_vault_runtime, a
-- member of coffre_vault.
--
-- In 0.16 the vault writes every row (docs/design/0.16.md, "Four rules"):
-- 0022_smaller_vault.sql grants coffre_vault SELECT, INSERT, UPDATE and
-- DELETE on each of 0.16's tables, SELECT alone on audit_archive, 0.14's log,
-- never written again, and the use of log_pending's sequence. Every block
-- below asserts that it holds exactly that, and that what it must NOT be
-- able to do fails. A passing run prints only 'PASS' lines.

\set ON_ERROR_STOP on
\set QUIET on

\echo '--- running through the vault login ---'

-- 1. Exactly these tables write, every other only reads, and none truncates,
-- references or triggers: a table added changes this list in the same change.
DO $$
DECLARE
    writes constant text[] := ARRAY[
        'projects', 'environments', 'secrets', 'secret_versions', 'dismissed_keys',
        'principals', 'grants', 'roles', 'policy',
        'identities', 'bindings', 'credentials',
        'device_logins', 'enrollment_codes', 'spent_id_tokens', 'oauth_clients', 'mcp_approvals',
        'log_pending', 'log', 'log_index', 'log_tiles', 'log_head', 'exposures'];
    relation record;
    writable boolean;
BEGIN
    IF EXISTS (SELECT 1 FROM unnest(writes) AS name WHERE to_regclass('public.' || name) IS NULL) THEN
        RAISE EXCEPTION 'FAIL: a table the vault writes is missing: %',
            (SELECT string_agg(name, ', ') FROM unnest(writes) AS name WHERE to_regclass('public.' || name) IS NULL);
    END IF;
    FOR relation IN
        SELECT c.oid::regclass AS name, c.relname
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
    LOOP
        IF NOT has_table_privilege(relation.name, 'SELECT') THEN
            RAISE EXCEPTION 'FAIL: coffre_vault cannot read %', relation.name;
        END IF;
        EXECUTE format('SELECT count(*) FROM %s', relation.name);
        writable := relation.relname = ANY (writes);
        IF has_table_privilege(relation.name, 'INSERT') <> writable
           OR has_table_privilege(relation.name, 'UPDATE') <> writable
           OR has_table_privilege(relation.name, 'DELETE') <> writable
           OR has_any_column_privilege(relation.name, 'INSERT, UPDATE') <> writable THEN
            RAISE EXCEPTION 'FAIL: coffre_vault % write %', CASE WHEN writable THEN 'cannot' ELSE 'may' END, relation.name;
        END IF;
        IF has_table_privilege(relation.name, 'TRUNCATE, REFERENCES, TRIGGER')
           OR has_any_column_privilege(relation.name, 'REFERENCES') THEN
            RAISE EXCEPTION 'FAIL: coffre_vault may truncate, reference or trigger on %', relation.name;
        END IF;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_vault reads every table, writes exactly 0.16''s, and truncates none';
END
$$;

-- 2. Tried: no table truncates, and 0.14's archive takes no write.
DO $$
DECLARE
    relation record;
    attempt text;
BEGIN
    FOR relation IN
        SELECT c.oid::regclass AS name
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind = 'r'
    LOOP
        BEGIN
            EXECUTE format('TRUNCATE %s', relation.name);
            RAISE EXCEPTION 'FAIL: coffre_vault truncated %', relation.name;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    FOREACH attempt IN ARRAY ARRAY[
        'INSERT INTO audit_archive DEFAULT VALUES',
        'UPDATE audit_archive SET actor = ''user:someone.else@acme.example''',
        'DELETE FROM audit_archive'
    ] LOOP
        BEGIN
            EXECUTE attempt;
            RAISE EXCEPTION 'FAIL: coffre_vault ran %', attempt;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_vault empties no table, and leaves 0.14''s archive as the upgrade wrote it';
END
$$;

-- 3. It numbers what it appends through log_pending's sequence, and sets no
-- sequence; and runs no function as its owner.
DO $$
BEGIN
    IF NOT has_sequence_privilege('log_pending_id_seq', 'USAGE') THEN
        RAISE EXCEPTION 'FAIL: coffre_vault cannot append to log_pending';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(c.oid, 'UPDATE') ELSE false END
    ) THEN
        RAISE EXCEPTION 'FAIL: coffre_vault may set a sequence';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname IN ('public', 'drizzle') AND p.prosecdef AND has_function_privilege(p.oid, 'EXECUTE')
    ) THEN
        RAISE EXCEPTION 'FAIL: coffre_vault may run a SECURITY DEFINER function';
    END IF;
    RAISE NOTICE 'PASS: coffre_vault appends through log_pending''s sequence, and runs no function as its owner';
END
$$;

-- 4. What a change writes, as the vault writes it: admit a member, set their
-- role and scope, grant, revoke, append an entry; rolled back.
DO $$
BEGIN
    BEGIN
        INSERT INTO principals (id, status, role, generation, created_at, created_by, status_changed_at, status_changed_by)
        VALUES ('user:ada@acme.example', 'active', 'member', 0, now(), 'user:admin@acme.example', now(), 'user:admin@acme.example');
        UPDATE principals SET role = 'developer', scope = '{"projects":"all","environments":{"only":["dev"]}}' WHERE id = 'user:ada@acme.example';
        INSERT INTO grants (id, principal, generation, environment_id, role, granted_at, granted_by)
        VALUES (gen_random_uuid(), 'user:ada@acme.example', 0, '22222222-2222-2222-2222-222222222222', 'viewer', now(), 'user:admin@acme.example');
        DELETE FROM grants WHERE principal = 'user:ada@acme.example';
        INSERT INTO log_pending (kept, body, mac) VALUES (true, '{}', decode(repeat('00', 36), 'hex'));
        RAISE EXCEPTION 'written' USING ERRCODE = 'C0FFE';
    EXCEPTION
        WHEN SQLSTATE 'C0FFE' THEN NULL;
    END;
    RAISE NOTICE 'PASS: coffre_vault admits, sets a role and its scope, grants, revokes and appends';
END
$$;

-- 5. A grant names exactly one place, and a role by its id: which roles a
-- place takes is the vault's to decide (docs/design/roles.md), the table
-- holds a grant to a role named by an id and nothing else.
DO $$
DECLARE
    attempt text;
BEGIN
    FOREACH attempt IN ARRAY ARRAY[
        'INSERT INTO grants (id, principal, generation, project_id, environment_id, role, granted_at, granted_by)
         VALUES (gen_random_uuid(), ''user:admin@acme.example'', 0, ''11111111-1111-1111-1111-111111111111'',
                 ''22222222-2222-2222-2222-222222222222'', ''viewer'', now(), ''user:admin@acme.example'')',
        'INSERT INTO grants (id, principal, generation, role, granted_at, granted_by)
         VALUES (gen_random_uuid(), ''user:admin@acme.example'', 0, ''viewer'', now(), ''user:admin@acme.example'')',
        'INSERT INTO grants (id, principal, generation, environment_id, role, granted_at, granted_by)
         VALUES (gen_random_uuid(), ''user:admin@acme.example'', 0, ''22222222-2222-2222-2222-222222222222'',
                 ''Not a role'', now(), ''user:admin@acme.example'')'
    ] LOOP
        BEGIN
            EXECUTE attempt;
            RAISE EXCEPTION 'FAIL: a grant was accepted: %', attempt;
        EXCEPTION
            WHEN check_violation THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: a grant names exactly one place, and a role by its id';
END
$$;

-- 6. A secret cannot claim an environment that belongs to another project.
DO $$
DECLARE
    other_project uuid := gen_random_uuid();
BEGIN
    INSERT INTO projects (id, slug, name, created_at) VALUES (other_project, 'other', 'Other', now());
    INSERT INTO secrets (id, project_id, environment_id, key, created_at, updated_at, versions)
    VALUES (gen_random_uuid(), other_project, '22222222-2222-2222-2222-222222222222', 'DATABASE_URL', now(), now(), 0);
    RAISE EXCEPTION 'FAIL: a secret referenced an environment outside its project';
EXCEPTION
    WHEN foreign_key_violation THEN
        RAISE NOTICE 'PASS: environment must belong to the secret''s project';
END
$$;

-- 7. The vault login cannot create database objects.
DO $$
BEGIN
    CREATE TABLE vault_must_not_create_objects (id integer);
    RAISE EXCEPTION 'FAIL: coffre_vault was able to run DDL';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot run DDL';
END
$$;

DO $$
BEGIN
    CREATE TEMP TABLE vault_must_not_create_temp (id integer);
    RAISE EXCEPTION 'FAIL: coffre_vault was able to create a temporary table';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot create temporary tables';
END
$$;

-- 8. Nor become the app, or the backups.
DO $$
DECLARE
    statement text;
BEGIN
    FOREACH statement IN ARRAY ARRAY['SET ROLE coffre_app', 'SET ROLE coffre_backup'] LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION 'FAIL: coffre_vault was able to run: %', statement;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_vault acts as no one else';
END
$$;

\echo '--- all vault guarantees held ---'
