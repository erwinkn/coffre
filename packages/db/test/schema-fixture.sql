\set ON_ERROR_STOP on

DELETE FROM audit_log;
UPDATE audit_chain_head
   SET next_seq = 0,
       head_hash = decode(repeat('00', 32), 'hex');
UPDATE secrets SET current_version_id = NULL;
DELETE FROM secret_versions;
DELETE FROM secrets;
DELETE FROM grants;
DELETE FROM principals;
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
