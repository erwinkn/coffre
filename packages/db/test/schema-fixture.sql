\set ON_ERROR_STOP on

-- Run as the owner: every table emptied, then one project and its
-- environment, a member, an entry of the log and one of 0.14's archive, for
-- the logins' guarantees to read and write against.
DO $$
BEGIN
    EXECUTE (
        SELECT 'TRUNCATE ' || string_agg(c.oid::regclass::text, ', ') || ' RESTART IDENTITY'
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind = 'r'
    );
END
$$;

INSERT INTO projects (id, slug, name, created_at)
VALUES ('11111111-1111-1111-1111-111111111111', 'market', 'Acme Market', now());

INSERT INTO environments (id, project_id, slug, name, created_at, protected, frozen_credentials)
VALUES ('22222222-2222-2222-2222-222222222222',
        '11111111-1111-1111-1111-111111111111', 'prod', 'Production', now(), false, '{}');

INSERT INTO principals (id, status, role, generation, created_at, created_by, status_changed_at, status_changed_by)
VALUES ('user:admin@acme.example', 'active', 'owner', 0, now(), 'system:fixture', now(), 'system:fixture');

INSERT INTO log (seq, kept, leaf, body) VALUES (0, true, 0, '{"action":"fixture"}');

INSERT INTO audit_archive (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
VALUES (0, 'app', 'app:fixture', 0, 'user:admin@acme.example', 'secret.read', 'allow', '{}',
        decode(repeat('00', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('aa', 32), 'hex'));
