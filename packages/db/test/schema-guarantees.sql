-- Adversarial checks against the schema itself, run as the application role.
--
-- Every block below asserts that something the application must NOT be able to
-- do actually fails. A passing run prints only 'PASS' lines.

\set ON_ERROR_STOP on
\set QUIET on

-- Seed a minimal object graph as the owner.
--
-- Reset fully rather than upserting: this file pins fixed UUIDs, and an
-- ON CONFLICT DO NOTHING would silently skip the insert when a project of the
-- same slug already exists, leaving the fixed UUID dangling.
DELETE FROM audit_log;
UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex');
UPDATE secrets SET current_version_id = NULL;
DELETE FROM secret_versions;
DELETE FROM secrets;
DELETE FROM grants;
DELETE FROM environments;
DELETE FROM projects;

INSERT INTO projects (id, slug, name)
VALUES ('11111111-1111-1111-1111-111111111111', 'market', 'Equisafe Market');

INSERT INTO environments (id, project_id, slug, name)
VALUES ('22222222-2222-2222-2222-222222222222',
        '11111111-1111-1111-1111-111111111111', 'prod', 'Production');

INSERT INTO audit_log (seq, actor_type, actor_id, action, decision, prev_hash, hash)
VALUES (0, 'user', 'erwin@equisafe.io', 'secret.read', 'allow',
        decode(repeat('00', 32), 'hex'), decode(repeat('aa', 32), 'hex'));

SET ROLE coffre_app;

\echo '--- running as coffre_app ---'

-- 1. The application may append to the audit log.
INSERT INTO audit_log (seq, actor_type, actor_id, action, decision, prev_hash, hash)
VALUES (1, 'user', 'erwin@equisafe.io', 'secret.read', 'allow',
        decode(repeat('aa', 32), 'hex'), decode(repeat('bb', 32), 'hex'));
\echo 'PASS: coffre_app can append to audit_log'

-- 2. The application may NOT rewrite an audit row.
DO $$
BEGIN
    UPDATE audit_log SET actor_id = 'someone.else@equisafe.io' WHERE seq = 0;
    RAISE EXCEPTION 'FAIL: coffre_app was able to UPDATE audit_log';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot UPDATE audit_log';
END
$$;

-- 3. The application may NOT delete an audit row.
DO $$
BEGIN
    DELETE FROM audit_log WHERE seq = 0;
    RAISE EXCEPTION 'FAIL: coffre_app was able to DELETE from audit_log';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot DELETE from audit_log';
END
$$;

-- 4. The application may NOT truncate the audit log.
DO $$
BEGIN
    TRUNCATE audit_log;
    RAISE EXCEPTION 'FAIL: coffre_app was able to TRUNCATE audit_log';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: coffre_app cannot TRUNCATE audit_log';
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

-- 6. A secret cannot claim an environment that belongs to another project.
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

-- 7. Duplicate seq values are rejected, so a forked chain cannot be stored.
DO $$
BEGIN
    INSERT INTO audit_log (seq, actor_type, actor_id, action, decision, prev_hash, hash)
    VALUES (1, 'user', 'x@equisafe.io', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode(repeat('cc', 32), 'hex'));
    RAISE EXCEPTION 'FAIL: duplicate audit seq was accepted';
EXCEPTION
    WHEN unique_violation THEN
        RAISE NOTICE 'PASS: duplicate audit seq is rejected';
END
$$;

-- 8. A malformed hash length is rejected.
DO $$
BEGIN
    INSERT INTO audit_log (seq, actor_type, actor_id, action, decision, prev_hash, hash)
    VALUES (2, 'user', 'x@equisafe.io', 'secret.read', 'allow',
            decode(repeat('aa', 32), 'hex'), decode('deadbeef', 'hex'));
    RAISE EXCEPTION 'FAIL: a short chain hash was accepted';
EXCEPTION
    WHEN check_violation THEN
        RAISE NOTICE 'PASS: a malformed chain hash is rejected';
END
$$;

-- 9. An unknown actor_type is rejected.
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

RESET ROLE;
\echo '--- all schema guarantees held ---'
