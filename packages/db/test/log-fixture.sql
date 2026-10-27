\set ON_ERROR_STOP on

-- What log-guarantees.sql decides on, as the owner, after schema-fixture.sql:
-- a service account with a token and a trust binding, and two secrets in the fixture's
-- environment. Nothing is sealed yet; the vault seals it there.
DELETE FROM log_bulk;
DELETE FROM log_changes;
TRUNCATE log_uses;
DELETE FROM log_config;
DELETE FROM log_checkpoints;
DELETE FROM log_tiles;
UPDATE log_fence SET at_floor = (extract(epoch FROM clock_timestamp()) * 1000)::bigint - 3000;
DELETE FROM credentials;
DELETE FROM service_bindings;
UPDATE secrets SET current_version_id = NULL;
DELETE FROM secret_versions;
DELETE FROM secrets;
DELETE FROM vault_grants;
DELETE FROM vault_members;

INSERT INTO vault_members (principal, status, owner, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
VALUES ('token:deploy', 'active', false, 1, 1, 'user:admin@acme.example', 1, 'user:admin@acme.example', 1, decode(repeat('01', 32), 'hex'));

INSERT INTO vault_grants (principal, project_id, role, granted_at, granted_by)
VALUES ('token:deploy', '11111111-1111-1111-1111-111111111111', 'viewer', 1, 'user:admin@acme.example');

INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at)
VALUES ('33333333-3333-3333-3333-333333333333', 'service', decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'),
        'coffre_svc_…abcd', 1, 'token:deploy', 'user:admin@acme.example', now() + interval '1 day');

INSERT INTO service_bindings (id, auth_mac, principal, generation, profile, issuer, jwks_uri, claims, created_by)
VALUES ('66666666-6666-6666-6666-666666666666', decode(repeat('04', 32), 'hex'), 'token:deploy', 1, 'github',
        'https://token.actions.githubusercontent.com', 'https://token.actions.githubusercontent.com/.well-known/jwks', '{}', 'user:admin@acme.example');

INSERT INTO secrets (id, project_id, environment_id, key)
VALUES ('44444444-4444-4444-4444-444444444441', '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'API_KEY'),
       ('44444444-4444-4444-4444-444444444442', '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'DB_URL');

INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by)
SELECT ('55555555-5555-5555-5555-55555555555' || n)::uuid, ('44444444-4444-4444-4444-44444444444' || n)::uuid, 1, 1,
       decode('c1', 'hex'), decode(repeat('0c', 12), 'hex'), decode(repeat('0d', 16), 'hex'), decode('d0', 'hex'),
       'local', 'fixture', '1', 'user:admin@acme.example'
  FROM generate_series(1, 2) AS n;

UPDATE secrets SET current_version_id = ('55555555-5555-5555-5555-55555555555' || right(id::text, 1))::uuid, current_version = 1;

-- Two references, each held by a key with no version of its own, to API_KEY (0029's end_reference): one standing, one
-- whose holder is archived. Their `reference.create` stand-ins: the fixture's first entry, and one more.
INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
VALUES (1, 'app', 'app:fixture', 0, 'user:admin@acme.example', 'secret.read', 'allow',
        decode(repeat('aa', 32), 'hex'), decode(repeat('99', 32), 'hex'), decode(repeat('ab', 32), 'hex'));
-- The standing one's holder is sealed (0.15's log holds it); an unsealed one, 0.14's alone, would end by its row.
INSERT INTO secrets (id, project_id, environment_id, key, archived_at, seal)
VALUES ('44444444-4444-4444-4444-444444444443', '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'HELD', NULL, decode(repeat('ee', 16), 'hex')),
       ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'HELD_ARCHIVED', now(), NULL);
INSERT INTO secret_references (id, project_id, environment_id, secret_id, source_project_id, source_environment_id, source_secret_id, created_seq, created_by)
SELECT ('88888888-8888-8888-8888-88888888888' || n)::uuid, '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222',
       ('44444444-4444-4444-4444-44444444444' || (n + 2))::uuid, '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222',
       '44444444-4444-4444-4444-444444444441', n - 1, 'user:admin@acme.example'
  FROM generate_series(1, 2) AS n;

-- A key no window counts any more: prune_bulk's.
INSERT INTO log_bulk (principal, secret, last) VALUES ('token:gone', '77777777-7777-7777-7777-777777777777', 0);
