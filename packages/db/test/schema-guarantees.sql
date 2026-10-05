-- Adversarial checks through the same login used by the API tests.
--
-- Every block below asserts that something the application must NOT be able to
-- do actually fails. A passing run prints only 'PASS' lines.

\set ON_ERROR_STOP on
\set QUIET on

\echo '--- running through restricted runtime login ---'

-- 1. The application may append to the audit log.
INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
VALUES (1, 'app', 'app:fixture', 0, 'user:admin@acme.example', 'secret.read', 'allow',
        decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('bb', 32), 'hex'));
\echo 'PASS: coffre_app can append to audit_log'

-- 2. The application may NOT rewrite an audit row.
DO $$
BEGIN
    UPDATE audit_log SET actor = 'user:someone.else@acme.example' WHERE seq = 0;
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

-- 5. Secret versions are immutable but for being erased: their ciphertext and
-- wrapped key emptied, nothing else. Each block writes a version of its own and
-- rolls it back, so the checks below see the fixture as it was.
DO $$
DECLARE
    version_id uuid := gen_random_uuid();
    secret_id uuid := gen_random_uuid();
    attempt text;
BEGIN
    FOREACH attempt IN ARRAY ARRAY[
        'UPDATE secret_versions SET ciphertext = ''\x00''::bytea WHERE id = $1',
        'UPDATE secret_versions SET ciphertext = ''''::bytea, wrapped_dek = ''\x01''::bytea WHERE id = $1',
        'UPDATE secret_versions SET iv = iv WHERE id = $1',
        'UPDATE secret_versions SET version = 2 WHERE id = $1'
    ] LOOP
        BEGIN
            INSERT INTO secrets (id, project_id, environment_id, key)
            VALUES (secret_id, '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'ERASE_PROBE');
            INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek,
                                         kek_provider, kek_id, kek_version, created_by)
            VALUES (version_id, secret_id, 1, 1, '\x00', decode(repeat('00', 12), 'hex'), decode(repeat('00', 16), 'hex'),
                    '\x00', 'local', 'k', '1', 'user:admin@acme.example');
            EXECUTE attempt USING version_id;
            RAISE EXCEPTION 'FAIL: coffre_app could %', attempt;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_app cannot rewrite a secret version';

    BEGIN
        INSERT INTO secrets (id, project_id, environment_id, key)
        VALUES (secret_id, '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'ERASE_PROBE');
        INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek,
                                     kek_provider, kek_id, kek_version, created_by)
        VALUES (version_id, secret_id, 1, 1, '\x00', decode(repeat('00', 12), 'hex'), decode(repeat('00', 16), 'hex'),
                '\x00', 'local', 'k', '1', 'user:admin@acme.example');
        UPDATE secret_versions SET ciphertext = ''::bytea, wrapped_dek = ''::bytea WHERE id = version_id;
        RAISE EXCEPTION 'erased' USING ERRCODE = 'raise_exception';
    EXCEPTION
        WHEN raise_exception THEN
            RAISE NOTICE 'PASS: coffre_app can erase a secret version';
    END;
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
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    VALUES (1, 'app', 'app:fixture', 0, 'user:x@acme.example', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('cc', 32), 'hex'));
    RAISE EXCEPTION 'FAIL: duplicate audit seq was accepted';
EXCEPTION
    WHEN unique_violation THEN
        RAISE NOTICE 'PASS: duplicate audit seq is rejected';
END
$$;

-- 9. A malformed hash length is rejected.
DO $$
BEGIN
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    VALUES (2, 'app', 'app:fixture', 0, 'user:x@acme.example', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode('deadbeef', 'hex'));
    RAISE EXCEPTION 'FAIL: a short chain hash was accepted';
EXCEPTION
    WHEN check_violation THEN
        RAISE NOTICE 'PASS: a malformed chain hash is rejected';
END
$$;

-- 10. An actor that is not a principal is rejected.
DO $$
BEGIN
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    VALUES (3, 'app', 'app:fixture', 0, 'anonymous', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('dd', 32), 'hex'));
    RAISE EXCEPTION 'FAIL: an actor with no kind was accepted';
EXCEPTION
    WHEN check_violation THEN
        RAISE NOTICE 'PASS: an actor with no kind is rejected';
END
$$;

-- 11. An unknown author is rejected: for a login, by row-level security
-- before the table's check, which holds for the owner, who passes it.
DO $$
BEGIN
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    VALUES (3, 'nobody', 'app:fixture', 0, 'user:x@acme.example', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('dd', 32), 'hex'));
    RAISE EXCEPTION 'FAIL: an unknown author was accepted';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: unknown author is rejected';
END
$$;

-- 12. The application appends only as itself: the vault's entries are the vault's.
DO $$
BEGIN
    INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
    VALUES (4, 'vault', 'vault:fixture', 0, 'user:x@acme.example', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('ee', 32), 'hex'));
    RAISE EXCEPTION 'FAIL: coffre_app appended an entry as the vault';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot append as the vault';
END
$$;

-- 13. The application reads members and grants, and writes neither.
SELECT count(*) FROM vault_members;
SELECT count(*) FROM vault_grants;
DO $$
BEGIN
    INSERT INTO vault_members (principal, status, created_at, created_by, status_changed_at, status_changed_by)
    VALUES ('user:x@acme.example', 'active', 0, 'user:x@acme.example', 0, 'user:x@acme.example');
    RAISE EXCEPTION 'FAIL: coffre_app was able to add a member';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot add a member';
END
$$;

DO $$
BEGIN
    UPDATE vault_members SET owner = true;
    RAISE EXCEPTION 'FAIL: coffre_app was able to change a member';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot change a member';
END
$$;

DO $$
BEGIN
    INSERT INTO vault_grants (principal, project_id, role, granted_at, granted_by)
    VALUES ('user:x@acme.example', '11111111-1111-1111-1111-111111111111', 'owner', 0, 'user:x@acme.example');
    RAISE EXCEPTION 'FAIL: coffre_app was able to grant';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot grant';
END
$$;

-- 14. Nor delete or empty them, nor become the vault.
DO $$
DECLARE
    statement text;
BEGIN
    FOREACH statement IN ARRAY ARRAY[
        'DELETE FROM vault_members',
        'TRUNCATE vault_members',
        'DELETE FROM vault_grants',
        'TRUNCATE vault_grants',
        'UPDATE vault_grants SET role = role',
        'SET ROLE coffre_vault'
    ] LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION 'FAIL: coffre_app was able to run: %', statement;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_app cannot delete, empty or update members and grants, nor act as the vault';
END
$$;

-- 15. A trust binding is never changed in place: only its label, last use and
-- revocation, with the MAC that covers them. Nor deleted.
DO $$
DECLARE
    statement text;
BEGIN
    FOREACH statement IN ARRAY ARRAY[
        'UPDATE service_bindings SET claims = claims',
        'UPDATE service_bindings SET issuer = issuer',
        'UPDATE service_bindings SET jwks_uri = jwks_uri',
        'UPDATE service_bindings SET profile = profile',
        'UPDATE service_bindings SET principal = principal',
        'UPDATE service_bindings SET generation = generation',
        'UPDATE service_bindings SET id = id',
        'DELETE FROM service_bindings',
        'TRUNCATE service_bindings'
    ] LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION 'FAIL: coffre_app was able to run: %', statement;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    UPDATE service_bindings SET label = label, last_used_at = last_used_at, revoked_at = revoked_at, revoked_by = revoked_by, auth_mac = auth_mac;
    RAISE NOTICE 'PASS: coffre_app changes a binding only where its MAC allows, and never deletes one';
END
$$;

-- 16. A token once exchanged stays spent: its record is never changed or deleted.
DO $$
DECLARE
    statement text;
BEGIN
    FOREACH statement IN ARRAY ARRAY[
        'UPDATE consumed_tokens SET hash = hash',
        'UPDATE consumed_tokens SET consumed_at = consumed_at',
        'DELETE FROM consumed_tokens',
        'TRUNCATE consumed_tokens'
    ] LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION 'FAIL: coffre_app was able to run: %', statement;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_app records a spent token and never unspends one';
END
$$;

\echo '--- all schema guarantees held ---'
