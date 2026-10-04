-- Adversarial checks through the vault's login, coffre_vault_runtime.
--
-- The vault writes members and grants, appends to the audit log as itself,
-- and reads what it decides on. Every block below asserts something it must
-- NOT be able to do fails. A passing run prints only 'PASS' lines.

\set ON_ERROR_STOP on
\set QUIET on

\echo '--- running through the vault login ---'

-- 1. The vault may append to the audit log, as itself.
INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
VALUES (1, 'vault', 'vault:fixture', 0, 'user:admin@acme.example', 'secret.read', 'allow',
        decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('bb', 32), 'hex'));
\echo 'PASS: coffre_vault can append to audit_log'

-- 2. Only as itself.
DO $$
BEGIN
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    VALUES (2, 'app', 'app:fixture', 0, 'user:x@acme.example', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('cc', 32), 'hex'));
    RAISE EXCEPTION 'FAIL: coffre_vault appended an entry as the app';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot append as the app';
END
$$;

-- 3. The vault may not rewrite or remove an entry.
DO $$
BEGIN
    UPDATE audit_log SET actor = 'user:someone.else@acme.example' WHERE seq = 0;
    RAISE EXCEPTION 'FAIL: coffre_vault was able to UPDATE audit_log';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot UPDATE audit_log';
END
$$;

DO $$
BEGIN
    DELETE FROM audit_log;
    RAISE EXCEPTION 'FAIL: coffre_vault was able to DELETE from audit_log';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot DELETE from audit_log';
END
$$;

-- 4. The vault writes members and grants, and deletes only a grant.
INSERT INTO vault_members (principal, status, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
VALUES ('user:ada@acme.example', 'active', 0, 'user:admin@acme.example', 0, 'user:admin@acme.example', 1,
        decode(repeat('00', 32), 'hex'));
UPDATE vault_members SET status = 'removed', generation = generation + 1 WHERE principal = 'user:ada@acme.example';
INSERT INTO vault_grants (principal, environment_id, role, granted_at, granted_by)
VALUES ('user:ada@acme.example', '22222222-2222-2222-2222-222222222222', 'viewer', 0, 'user:admin@acme.example');
DELETE FROM vault_grants WHERE principal = 'user:ada@acme.example';
\echo 'PASS: coffre_vault can admit, remove, grant and revoke'

DO $$
BEGIN
    DELETE FROM vault_members;
    RAISE EXCEPTION 'FAIL: coffre_vault was able to delete a member';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot delete a member';
END
$$;

DO $$
BEGIN
    UPDATE vault_members SET principal = 'user:eve@acme.example';
    RAISE EXCEPTION 'FAIL: coffre_vault was able to change who a member is';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot change who a member is';
END
$$;

-- 5. A grant names exactly one place, and a role the catalogue allows there.
DO $$
BEGIN
    INSERT INTO vault_grants (principal, project_id, environment_id, role, granted_at, granted_by)
    VALUES ('user:ada@acme.example', '11111111-1111-1111-1111-111111111111',
            '22222222-2222-2222-2222-222222222222', 'viewer', 0, 'user:admin@acme.example');
    RAISE EXCEPTION 'FAIL: a grant named two places';
EXCEPTION
    WHEN check_violation THEN
        RAISE NOTICE 'PASS: a grant names exactly one place';
END
$$;

DO $$
BEGIN
    INSERT INTO vault_grants (principal, environment_id, role, granted_at, granted_by)
    VALUES ('user:ada@acme.example', '22222222-2222-2222-2222-222222222222', 'owner', 0, 'user:admin@acme.example');
    RAISE EXCEPTION 'FAIL: a project role was granted on an environment';
EXCEPTION
    WHEN check_violation THEN
        RAISE NOTICE 'PASS: a project role cannot be granted on an environment';
END
$$;

-- 6. The vault reads what it decides on, and writes none of it.
SELECT count(*) FROM projects;
SELECT count(*) FROM secret_versions;
DO $$
BEGIN
    UPDATE projects SET name = 'renamed';
    RAISE EXCEPTION 'FAIL: coffre_vault was able to change a project';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot change a project';
END
$$;

DO $$
BEGIN
    INSERT INTO secret_versions (secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek,
                                 kek_provider, kek_id, kek_version, created_by)
    VALUES (gen_random_uuid(), 1, 1, '\x00', decode(repeat('00', 12), 'hex'), decode(repeat('00', 16), 'hex'),
            '\x00', 'local', 'k', '1', 'user:x@acme.example');
    RAISE EXCEPTION 'FAIL: coffre_vault was able to write a secret version';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot write a secret version';
END
$$;

-- 7. Nor the app's sign-in rows, nor any table of its own.
DO $$
BEGIN
    DELETE FROM credentials;
    RAISE EXCEPTION 'FAIL: coffre_vault was able to touch credentials';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot touch credentials';
END
$$;

DO $$
BEGIN
    CREATE TABLE vault_must_not_create_objects (id integer);
    RAISE EXCEPTION 'FAIL: coffre_vault was able to run DDL';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_vault cannot run DDL';
END
$$;

-- 8. Nor read the app's sign-in rows, empty any table, rewrite a
-- grant, become the app, or create temporary objects. It may restore a
-- member's created_at and created_by, from its own log, when it starts a
-- tampered member over.
DO $$
DECLARE
    statement text;
BEGIN
    FOREACH statement IN ARRAY ARRAY[
        'SELECT * FROM identities',
        'SELECT * FROM credentials',
        'SELECT * FROM device_authorizations',
        'SELECT * FROM service_bindings',
        'SELECT * FROM consumed_tokens',
            'DELETE FROM identities',
        'DELETE FROM device_authorizations',
        'TRUNCATE vault_members',
        'TRUNCATE vault_grants',
        'TRUNCATE audit_log',
        'UPDATE vault_grants SET role = role',
        'SET ROLE coffre_app',
        'CREATE TEMP TABLE vault_must_not_create_temp (id integer)'
    ] LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION 'FAIL: coffre_vault was able to run: %', statement;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_vault reads no sign-in row, empties nothing, rewrites no grant, and acts as no one else';
END
$$;

\echo '--- all vault guarantees held ---'
