-- Adversarial checks through the same login used by the API tests.
--
-- Every block below asserts that something the application must NOT be able to
-- do actually fails. A passing run prints only 'PASS' lines.

\set ON_ERROR_STOP on
\set QUIET on

\echo '--- running through restricted runtime login ---'

-- 1. The application may append to the audit log.
INSERT INTO audit_log (seq, actor_type, actor_id, action, decision, prev_hash, hash)
VALUES (1, 'user', 'admin@acme.example', 'secret.read', 'allow',
        decode(repeat('aa', 32), 'hex'), decode(repeat('bb', 32), 'hex'));
\echo 'PASS: coffre_app can append to audit_log'

-- 2. The application may NOT rewrite an audit row.
DO $$
BEGIN
    UPDATE audit_log SET actor_id = 'someone.else@acme.example' WHERE seq = 0;
    RAISE EXCEPTION 'FAIL: coffre_app was able to UPDATE audit_log';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot UPDATE audit_log';
END
$$;

-- 3. The application may not delete or truncate any application table.
DO $$
DECLARE
    unsafe_table text;
BEGIN
    SELECT c.relname INTO unsafe_table
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND (
           has_table_privilege(current_user, c.oid, 'DELETE')
           OR has_table_privilege(current_user, c.oid, 'TRUNCATE')
       )
     LIMIT 1;

    IF unsafe_table IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: runtime login can delete or truncate %', unsafe_table;
    END IF;

    RAISE NOTICE 'PASS: runtime login cannot DELETE or TRUNCATE application tables';
END
$$;

-- 4. Direct attempts fail as well as the privilege introspection above.
DO $$
BEGIN
    DELETE FROM projects WHERE id = '11111111-1111-1111-1111-111111111111';
    RAISE EXCEPTION 'FAIL: runtime login was able to DELETE';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: runtime login cannot DELETE';
END
$$;

-- 5. Secret versions are immutable: no UPDATE, no DELETE.
DO $$
BEGIN
    UPDATE secret_versions SET ciphertext = '\x00'::bytea;
    RAISE EXCEPTION 'FAIL: coffre_app was able to UPDATE secret_versions';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot UPDATE secret_versions';
END
$$;

DO $$
BEGIN
    DELETE FROM secret_versions;
    RAISE EXCEPTION 'FAIL: coffre_app was able to DELETE from secret_versions';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot DELETE from secret_versions';
END
$$;

-- 6. The runtime login cannot create database objects.
DO $$
BEGIN
    CREATE TABLE runtime_must_not_create_objects (id integer);
    RAISE EXCEPTION 'FAIL: runtime login was able to run DDL';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: runtime login cannot run DDL';
END
$$;

DO $$
BEGIN
    CREATE TEMP TABLE runtime_must_not_create_temp_objects (id integer);
    RAISE EXCEPTION 'FAIL: runtime login was able to create a temporary table';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: runtime login cannot create temporary tables';
END
$$;

-- 7. A secret cannot claim an environment that belongs to another project.
DO $$
DECLARE
    other_project uuid;
BEGIN
    INSERT INTO projects (slug, name) VALUES ('other', 'Other') RETURNING id INTO other_project;

    INSERT INTO secrets (project_id, environment_id, key)
    VALUES (other_project, '22222222-2222-2222-2222-222222222222', 'DATABASE_URL');

    RAISE EXCEPTION 'FAIL: a secret referenced an environment outside its project';
EXCEPTION
    WHEN foreign_key_violation THEN
        RAISE NOTICE 'PASS: environment must belong to the secret''s project';
END
$$;

-- 8. Duplicate seq values are rejected, so a forked chain cannot be stored.
DO $$
BEGIN
    INSERT INTO audit_log (seq, actor_type, actor_id, action, decision, prev_hash, hash)
    VALUES (1, 'user', 'x@acme.example', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('cc', 32), 'hex'));
    RAISE EXCEPTION 'FAIL: duplicate audit seq was accepted';
EXCEPTION
    WHEN unique_violation THEN
        RAISE NOTICE 'PASS: duplicate audit seq is rejected';
END
$$;

-- 9. A malformed hash length is rejected.
DO $$
BEGIN
    INSERT INTO audit_log (seq, actor_type, actor_id, action, decision, prev_hash, hash)
    VALUES (2, 'user', 'x@acme.example', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode('deadbeef', 'hex'));
    RAISE EXCEPTION 'FAIL: a short chain hash was accepted';
EXCEPTION
    WHEN check_violation THEN
        RAISE NOTICE 'PASS: a malformed chain hash is rejected';
END
$$;

-- 10. An unknown actor_type is rejected.
DO $$
BEGIN
    INSERT INTO audit_log (seq, actor_type, actor_id, action, decision, prev_hash, hash)
    VALUES (3, 'anonymous', 'x', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('dd', 32), 'hex'));
    RAISE EXCEPTION 'FAIL: an unknown actor_type was accepted';
EXCEPTION
    WHEN check_violation THEN
        RAISE NOTICE 'PASS: unknown actor_type is rejected';
END
$$;

\echo '--- all schema guarantees held ---'
