\set ON_ERROR_STOP on

DELETE FROM secret_references;
-- The log refuses deletions from everyone; the fixture lifts that for itself.
ALTER TABLE audit_log DISABLE TRIGGER USER;
DELETE FROM audit_log;
ALTER TABLE audit_log ENABLE TRIGGER USER;
UPDATE audit_chain_head
   SET next_seq = 0,
       head_hash = decode(repeat('00', 32), 'hex');
DELETE FROM vault_grants;
DELETE FROM vault_members;
DELETE FROM dismissed_keys;
DELETE FROM secret_folders;
DELETE FROM project_folders;
UPDATE secrets SET current_version_id = NULL;
DELETE FROM secret_versions;
DELETE FROM secrets;
DELETE FROM environments;
DELETE FROM projects;

INSERT INTO projects (id, slug, name)
VALUES ('11111111-1111-1111-1111-111111111111', 'market', 'Acme Market');

INSERT INTO environments (id, project_id, slug, name)
VALUES ('22222222-2222-2222-2222-222222222222',
        '11111111-1111-1111-1111-111111111111', 'prod', 'Production');

INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
VALUES (0, 'app', 'app:fixture', 0, 'user:admin@acme.example', 'secret.read', 'allow',
        decode(repeat('00', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('aa', 32), 'hex'));
