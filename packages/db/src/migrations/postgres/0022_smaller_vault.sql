-- 0.16 (docs/design/0.16.md, "Upgrade from 0.14"): 0.14's tables become 0.16's, in place and in one transaction. This
-- migration removes and tightens, which no other may: 0.14's code cannot run on these tables, so coffre is offline for
-- it, and the way back is the backup taken before. It does what SQL can without a key. Every row that turns into
-- access is left with an empty MAC, which verifies under no key, until the vault adopts the database at its first call.

-- A database that holds an instance converts only with coffre offline: every login of its two groups set NOLOGIN, the
-- runtime logins and any other a host gave their rights, and none of their sessions open. A pipeline run without
-- that step fails here, having changed nothing. A new database passes.
DO $$
DECLARE
    online text;
    tampered text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM vault_members) THEN
        RETURN;
    END IF;
    -- Whoever is a member of the app's or the vault's group, directly or through another role, inheriting or not. Not
    -- the login that migrates, nor one that administers roles (a superuser, or one with CREATEROLE): Postgres 16 makes
    -- a role's creator its member, which a host may have inherit, and coffre never runs as such a login, which its
    -- first migration refuses for a runtime login.
    SELECT string_agg(login.rolname, ', ' ORDER BY login.rolname) INTO online
      FROM pg_roles login
     WHERE login.rolcanlogin AND NOT login.rolsuper AND NOT login.rolcreaterole AND login.rolname <> current_user
       AND (pg_has_role(login.oid, 'coffre_app', 'MEMBER') OR pg_has_role(login.oid, 'coffre_vault', 'MEMBER'));
    IF online IS NOT NULL THEN
        RAISE EXCEPTION 'this database holds a 0.14 instance, and coffre is still online: the upgrade to 0.16 converts it with coffre offline. Set % NOLOGIN, end their sessions, back up, then migrate (docs/design/0.16.md, "Upgrade from 0.14")', online;
    END IF;
    SELECT string_agg(DISTINCT login.rolname, ', ') INTO online
      FROM pg_stat_activity session
      JOIN pg_roles login ON login.rolname = session.usename
     WHERE session.datname = current_database() AND NOT login.rolsuper AND NOT login.rolcreaterole AND login.rolname <> current_user
       AND (pg_has_role(login.oid, 'coffre_app', 'MEMBER') OR pg_has_role(login.oid, 'coffre_vault', 'MEMBER'));
    IF online IS NOT NULL THEN
        RAISE EXCEPTION '% still has a session open on this database: end it (pg_terminate_backend), back up, then migrate (docs/design/0.16.md, "Upgrade from 0.14")', online;
    END IF;
    -- A member whose row 0.14's vault found changed around it, and its report (`vault.tampered`) still stands: it is
    -- newer than the newest change to what they hold. The row may check out again since, a genuine one put back, and
    -- the member be in use; the report stands all the same, as 0.14's members page says, until they are removed.
    -- 0.16 would take their row as it is, and this migration holds no key to check it.
    SELECT string_agg(found.subject_principal, ', ') INTO tampered
      FROM (
        SELECT subject_principal, max(seq) AS seq FROM audit_log
         WHERE author = 'vault' AND action = 'vault.tampered' AND code IN ('mac', 'stale') AND subject_principal IS NOT NULL
         GROUP BY subject_principal
      ) AS found
     WHERE found.seq > coalesce((
        SELECT max(changed.seq) FROM audit_log changed
         WHERE changed.author = 'vault' AND changed.decision = 'allow' AND changed.subject_principal = found.subject_principal
           AND changed.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke')
     ), -1);
    IF tampered IS NOT NULL THEN
        RAISE EXCEPTION 'on 0.14, the vault reported the member row of % changed around it, and that report stands: remove each one on 0.14.7, and add them again if they should stay, then upgrade', tampered;
    END IF;
    IF EXISTS (SELECT 1 FROM vault_grants WHERE project_id IS NULL AND environment_id IS NULL) THEN
        RAISE EXCEPTION 'vault_grants still holds a grant on every project, of 0.4, which 0.14''s vault converts when their member next signs in, and never for a member it refuses: on 0.14.7, have them sign in, or remove them, then upgrade';
    END IF;
END
$$;
--> statement-breakpoint

-- 1. What 0.14 kept only in its log becomes rows, while the log's indexes are still there to find it.

-- A reference, as 0.14 reads one: a secret with no value of its own is its newest reference that the vault sealed
-- (`reference.create`, which names the holder and the source), and that reference is live while no `reference.end`
-- names it. A newer one that ended leaves no older one standing.
ALTER TABLE secrets ADD COLUMN source_id uuid;
--> statement-breakpoint
UPDATE secrets AS holder SET source_id = newest.source_id
  FROM (
    SELECT DISTINCT ON (reference.secret_id) reference.secret_id, reference.created_seq, source.id AS source_id
      FROM secret_references reference
      JOIN audit_log seal ON seal.seq = reference.created_seq AND seal.author = 'vault' AND seal.action = 'reference.create' AND seal.decision = 'allow'
       AND seal.project_id IS NOT NULL AND seal.environment_id IS NOT NULL
       AND seal.metadata::jsonb ->> 'reference' = reference.id::text AND seal.metadata::jsonb ->> 'secretId' = reference.secret_id::text
       AND seal.metadata::jsonb -> 'also' ->> 'projectId' <> '' AND seal.metadata::jsonb -> 'also' ->> 'environmentId' <> ''
      LEFT JOIN secrets source ON source.id::text = seal.metadata::jsonb -> 'also' ->> 'secretId'
     ORDER BY reference.secret_id, reference.created_seq DESC
  ) AS newest
 WHERE newest.secret_id = holder.id AND holder.current_version_id IS NULL AND newest.source_id <> holder.id
   AND NOT EXISTS (
        SELECT 1 FROM audit_log ended
         WHERE ended.related_seq = newest.created_seq AND ended.author = 'vault' AND ended.action = 'reference.end' AND ended.decision = 'allow'
   );
--> statement-breakpoint

-- A binding's tombstone, the app's `token.unbind` naming it, becomes its revocation.
UPDATE service_bindings AS binding SET revoked_at = to_timestamp(unbound.occurred_at / 1000.0), revoked_by = unbound.actor
  FROM (
    SELECT DISTINCT ON (metadata::jsonb ->> 'bindingId') metadata::jsonb ->> 'bindingId' AS binding_id, occurred_at, actor
      FROM audit_log
     WHERE author = 'app' AND action = 'token.unbind' AND decision = 'allow'
     ORDER BY metadata::jsonb ->> 'bindingId', seq
  ) AS unbound
 WHERE unbound.binding_id = binding.id::text AND binding.revoked_at IS NULL;
--> statement-breakpoint

-- A freeze: a target is frozen while its newest allowed freeze or lift is a freeze (docs/design/workload-access.md,
-- section 8.2). Each becomes a field of the row it stops: the policy's for the instance, a service account's, a
-- binding's, a session's, and for an upstream credential, its environment's list of names. The policy row is the
-- vault's to write when it adopts, so the instance's freeze is its to read then, from the archive.
ALTER TABLE vault_members ADD COLUMN frozen_at timestamp(3) with time zone;
--> statement-breakpoint
ALTER TABLE service_bindings ADD COLUMN frozen_at timestamp(3) with time zone;
--> statement-breakpoint
ALTER TABLE credentials ADD COLUMN frozen_at timestamp(3) with time zone;
--> statement-breakpoint
ALTER TABLE environments ADD COLUMN frozen_credentials text[] NOT NULL DEFAULT '{}';
--> statement-breakpoint
CREATE TABLE frozen_014 AS
SELECT target, to_timestamp(occurred_at / 1000.0)::timestamp(3) with time zone AS frozen_at
  FROM (
    SELECT DISTINCT ON (metadata::jsonb ->> 'target') metadata::jsonb ->> 'target' AS target, action, occurred_at
      FROM audit_log
     WHERE author = 'app' AND action IN ('workload.freeze', 'workload.unfreeze') AND decision = 'allow'
     ORDER BY metadata::jsonb ->> 'target', seq DESC
  ) AS newest
 WHERE action = 'workload.freeze' AND target IS NOT NULL;
--> statement-breakpoint
UPDATE vault_members AS service SET frozen_at = frozen.frozen_at FROM frozen_014 frozen
 WHERE frozen.target = service.principal AND service.principal LIKE 'token:%';
--> statement-breakpoint
UPDATE service_bindings AS binding SET frozen_at = frozen.frozen_at FROM frozen_014 frozen WHERE frozen.target = 'binding:' || binding.id::text;
--> statement-breakpoint
UPDATE credentials AS session SET frozen_at = frozen.frozen_at FROM frozen_014 frozen WHERE frozen.target = 'session:' || session.id::text;
--> statement-breakpoint
UPDATE environments AS environment SET frozen_credentials = names.names
  FROM (
    SELECT split_part(substr(target, 12), '/', 1) AS environment_id, array_agg(substr(target, 12 + 37) ORDER BY substr(target, 12 + 37)) AS names
      FROM frozen_014
     WHERE target ~ '^credential:[0-9a-f-]{36}/.'
     GROUP BY 1
  ) AS names
 WHERE names.environment_id = environment.id::text;
--> statement-breakpoint

-- A code a promote superseded: the app's `enrollment.supersede` naming it.
ALTER TABLE enrollments ADD COLUMN superseded_at timestamp(3) with time zone;
--> statement-breakpoint
UPDATE enrollments AS code SET superseded_at = to_timestamp(superseded.occurred_at / 1000.0)
  FROM (
    SELECT DISTINCT ON (metadata::jsonb ->> 'enrollmentId') metadata::jsonb ->> 'enrollmentId' AS enrollment_id, occurred_at
      FROM audit_log
     WHERE author = 'app' AND action = 'enrollment.supersede' AND decision = 'allow'
     ORDER BY metadata::jsonb ->> 'enrollmentId', seq
  ) AS superseded
 WHERE superseded.enrollment_id = code.id::text;
--> statement-breakpoint

-- The run a credential was issued for: its exchange's entry, by the credential's ID.
ALTER TABLE credentials ADD COLUMN run text;
--> statement-breakpoint
UPDATE credentials AS credential SET run = (exchange.metadata::jsonb -> 'run')::text
  FROM audit_log exchange
 WHERE exchange.author = 'app' AND exchange.action = 'token.exchange' AND exchange.decision = 'allow'
   AND exchange.metadata::jsonb ->> 'credentialId' = credential.id::text
   AND jsonb_typeof(exchange.metadata::jsonb -> 'run') = 'object';
--> statement-breakpoint

-- Who has seen which key, and when last, from every release the vault logged: 0.14's `vault_releases` kept only a day
-- of them. An entry names its secret, or lists the secrets of a read at one place.
CREATE TABLE exposures (
    principal text NOT NULL,
    secret_id uuid NOT NULL,
    seen_at timestamp(3) with time zone NOT NULL,
    CONSTRAINT exposures_pkey PRIMARY KEY (principal, secret_id)
);
--> statement-breakpoint
-- Room in each page for the next version of its rows: a use moves a row's time on in place (a HOT update).
ALTER TABLE exposures SET (fillfactor = 50);
--> statement-breakpoint
INSERT INTO exposures (principal, secret_id, seen_at)
SELECT released.actor, secret.id, to_timestamp(max(released.occurred_at) / 1000.0)
  FROM (
    SELECT entry.actor, entry.occurred_at, coalesce(entry.secret_id::text, CASE jsonb_typeof(one -> 'secretId') WHEN 'string' THEN one ->> 'secretId' END) AS secret_id
      FROM audit_log entry
      LEFT JOIN LATERAL jsonb_path_query(CASE WHEN entry.secret_id IS NULL THEN entry.metadata::jsonb END, 'strict $.secrets ? (@.type() == "array")[*]', '{}', true) AS one ON true
     WHERE entry.author = 'vault' AND entry.action = 'secret.read' AND entry.decision = 'allow'
  ) AS released
  JOIN secrets secret ON secret.id::text = released.secret_id
  JOIN vault_members member ON member.principal = released.actor
 GROUP BY released.actor, secret.id;
--> statement-breakpoint
DROP TABLE frozen_014;
--> statement-breakpoint

-- 2. 0.14's history becomes the archive: the same rows, with no index but its key, never written again.

DROP TRIGGER audit_log_releases ON audit_log;
--> statement-breakpoint
DROP TRIGGER audit_log_no_change ON audit_log;
--> statement-breakpoint
DROP TRIGGER audit_log_no_truncate ON audit_log;
--> statement-breakpoint
DROP TRIGGER secret_versions_erase_only ON secret_versions;
--> statement-breakpoint
DROP FUNCTION vault_releases_keep(), audit_log_append_only(), secret_versions_erase_only(), prune_consumed_tokens(integer), prune_vault_releases(integer);
--> statement-breakpoint
DROP POLICY audit_log_read ON audit_log;
--> statement-breakpoint
DROP POLICY audit_log_app_appends ON audit_log;
--> statement-breakpoint
DROP POLICY audit_log_vault_appends ON audit_log;
--> statement-breakpoint
DROP POLICY audit_log_backup_read ON audit_log;
--> statement-breakpoint
ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY;
--> statement-breakpoint
DROP TABLE secret_references, audit_chain_head, capped_alerts, vault_releases, device_authorizations;
--> statement-breakpoint
-- One index stays, by action: it finds the vault the newest policy and settings when it adopts.
DO $$
DECLARE
    name text;
BEGIN
    FOR name IN SELECT conname FROM pg_constraint WHERE conrelid = 'audit_log'::regclass AND contype IN ('f', 'c') LOOP
        EXECUTE format('ALTER TABLE audit_log DROP CONSTRAINT %I', name);
    END LOOP;
    FOR name IN SELECT indexrelid::regclass::text FROM pg_index WHERE indrelid = 'audit_log'::regclass AND NOT indisprimary AND indexrelid <> 'audit_log_action_idx'::regclass LOOP
        EXECUTE format('DROP INDEX %s', name);
    END LOOP;
END
$$;
--> statement-breakpoint
ALTER TABLE audit_log RENAME TO audit_archive;
--> statement-breakpoint
ALTER INDEX audit_log_action_idx RENAME TO audit_archive_action_idx;
--> statement-breakpoint
ALTER TABLE audit_archive RENAME CONSTRAINT audit_log_pkey TO audit_archive_pkey;
--> statement-breakpoint
ALTER TABLE audit_archive ALTER COLUMN metadata DROP DEFAULT;
--> statement-breakpoint

-- 3. Secrets.

-- 0.14 said two things of a secret: the number of its newest version (`current_version`), and which version is its
-- value, if any (`current_version_id`: the newest, or null for a reference and for a secret whose reference ended).
-- Both stay, as numbers: a secret with no value of its own does not get back the one it held before.
ALTER TABLE secrets RENAME COLUMN current_version TO versions;
--> statement-breakpoint
-- 0.14's app could write the count: one below its secret's newest version, written around coffre, would have the
-- next write take a number already used.
UPDATE secrets AS secret SET versions = newest.version
  FROM (SELECT secret_id, max(version) AS version FROM secret_versions GROUP BY secret_id) AS newest
 WHERE newest.secret_id = secret.id AND secret.versions < newest.version;
--> statement-breakpoint
UPDATE secrets SET versions = 0 WHERE versions < 0;
--> statement-breakpoint
ALTER TABLE secrets ADD COLUMN current_version integer;
--> statement-breakpoint
UPDATE secrets AS secret SET current_version = version.version
  FROM secret_versions version
 WHERE version.id = secret.current_version_id AND version.secret_id = secret.id AND version.version = secret.versions;
--> statement-breakpoint
ALTER TABLE secrets DROP COLUMN current_version_id;
--> statement-breakpoint
-- How its current value is kept and was made moves to the secret's row, which carries a MAC, so that a change reads it:
-- its nature, which its version's row keeps too, as the version's encryption names it, and its recipe and pair, which
-- leave the versions. Taken here as 0.14's rows say them; the vault's adoption writes the nature again from the value it
-- opens (docs/design/0.16.md, "The steps").
ALTER TABLE secrets ADD COLUMN nature text, ADD COLUMN recipe text, ADD COLUMN pair_id uuid, ADD COLUMN pair_half text;
--> statement-breakpoint
UPDATE secrets AS secret
   SET nature = CASE WHEN version.sensitive THEN 'sensitive' WHEN version.plaintext IS NOT NULL THEN 'plain' ELSE 'secret' END,
       recipe = version.recipe, pair_id = version.pair_id, pair_half = version.pair_half
  FROM secret_versions version
 WHERE version.secret_id = secret.id AND version.version = secret.current_version;
--> statement-breakpoint
ALTER TABLE secret_versions DROP COLUMN recipe, DROP COLUMN pair_id, DROP COLUMN pair_half;
--> statement-breakpoint
-- When each version's value was first written to its key, which a restore copies from its source: the member report
-- holds each person's last sight of a key to its current value's. 0.14 told equal values apart as it restored them, by
-- their encryption: a restore copied its source's ciphertext, IV and tag, and wrapped its data key again. So a
-- version's is the first among its key's versions with its IV and tag; an erasure leaves both. The adoption wraps
-- each data key again and leaves the three as they are.
ALTER TABLE secret_versions ADD COLUMN first_written_at timestamp(3) with time zone;
--> statement-breakpoint
UPDATE secret_versions AS version SET first_written_at = equal.first
  FROM (SELECT id, min(created_at) OVER (PARTITION BY secret_id, iv, auth_tag) AS first FROM secret_versions) AS equal
 WHERE equal.id = version.id;
--> statement-breakpoint
ALTER TABLE secret_versions ALTER COLUMN first_written_at SET NOT NULL;
--> statement-breakpoint
DROP INDEX secrets_lookup_idx, secret_versions_secret_idx;
--> statement-breakpoint
ALTER TABLE secrets
    ADD CONSTRAINT secrets_versions_check CHECK (versions >= 0 AND (current_version IS NULL OR (current_version = versions AND versions > 0))),
    ADD CONSTRAINT secrets_source_check CHECK (source_id IS NULL OR (source_id <> id AND current_version IS NULL)),
    ADD CONSTRAINT secrets_nature_check CHECK ((nature IS NULL) = (current_version IS NULL) AND (nature IS NULL OR nature IN ('plain', 'secret', 'sensitive'))),
    ADD CONSTRAINT secrets_recipe_check CHECK ((recipe IS NULL AND pair_id IS NULL) OR current_version IS NOT NULL),
    ADD CONSTRAINT secrets_pair_check CHECK ((pair_id IS NULL) = (pair_half IS NULL) AND (pair_half IS NULL OR pair_half IN ('private', 'public'))),
    ADD CONSTRAINT secrets_source_id_fkey FOREIGN KEY (source_id) REFERENCES secrets (id) ON DELETE RESTRICT;
--> statement-breakpoint
CREATE INDEX secrets_source_idx ON secrets (source_id) WHERE source_id IS NOT NULL;
--> statement-breakpoint
ALTER TABLE secret_versions
    ADD CONSTRAINT secret_versions_plain_check CHECK (plaintext IS NULL OR NOT sensitive);
--> statement-breakpoint
-- Whether an environment is protected is the newest `policy.change`'s to say, which the vault reads when it adopts.
ALTER TABLE environments ADD COLUMN protected boolean NOT NULL DEFAULT false;
--> statement-breakpoint

-- 4. Access.

ALTER TABLE vault_members RENAME TO principals;
--> statement-breakpoint
ALTER TABLE principals RENAME COLUMN principal TO id;
--> statement-breakpoint
-- A row no vault of 0.5 wrote has no role, and its `owner` says whether they are an Admin.
UPDATE principals SET role = CASE WHEN owner THEN 'admin' ELSE 'member' END WHERE role IS NULL;
--> statement-breakpoint
ALTER TABLE principals
    DROP CONSTRAINT vault_members_owner_check,
    DROP CONSTRAINT vault_members_mac_check,
    DROP CONSTRAINT vault_members_principal_check,
    DROP CONSTRAINT vault_members_user_lowercase,
    DROP CONSTRAINT vault_members_status_check,
    DROP CONSTRAINT vault_members_generation_check,
    DROP COLUMN owner,
    DROP COLUMN access_seq,
    DROP COLUMN mac,
    ALTER COLUMN role SET NOT NULL,
    ALTER COLUMN generation DROP DEFAULT,
    ALTER COLUMN created_at TYPE timestamp(3) with time zone USING to_timestamp(created_at / 1000.0),
    ALTER COLUMN status_changed_at TYPE timestamp(3) with time zone USING to_timestamp(status_changed_at / 1000.0);
--> statement-breakpoint
ALTER TABLE principals RENAME CONSTRAINT vault_members_pkey TO principals_pkey;
--> statement-breakpoint
ALTER TABLE principals
    ADD CONSTRAINT principals_id_check CHECK (id ~ '^(user|token):[^[:space:]:][^[:space:]]*$'),
    ADD CONSTRAINT principals_user_lowercase CHECK (id NOT LIKE 'user:%' OR id = lower(id)),
    ADD CONSTRAINT principals_status_check CHECK (status IN ('active', 'removed')),
    ADD CONSTRAINT principals_role_check CHECK (role ~ '^[a-z][a-z0-9-]{1,31}$'),
    ADD CONSTRAINT principals_generation_check CHECK (generation >= 0),
    ADD CONSTRAINT principals_frozen_check CHECK (frozen_at IS NULL OR id LIKE 'token:%');
--> statement-breakpoint
CREATE INDEX principals_services_idx ON principals (id) WHERE status = 'active' AND id LIKE 'token:%';
--> statement-breakpoint

ALTER TABLE vault_grants RENAME TO grants;
--> statement-breakpoint
DROP INDEX vault_grants_on_every_project;
--> statement-breakpoint
ALTER TABLE grants
    DROP CONSTRAINT vault_grants_one_place,
    DROP CONSTRAINT vault_grants_environment_slug_check,
    DROP CONSTRAINT vault_grants_role_check,
    DROP COLUMN environment_slug,
    ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN generation integer,
    ALTER COLUMN expires_at TYPE timestamp(3) with time zone USING to_timestamp(expires_at / 1000.0),
    ALTER COLUMN granted_at TYPE timestamp(3) with time zone USING to_timestamp(granted_at / 1000.0);
--> statement-breakpoint
-- A grant counts only in its member's generation: one carried over is of the generation its member is in now.
UPDATE grants SET generation = principals.generation FROM principals WHERE principals.id = grants.principal;
--> statement-breakpoint
ALTER TABLE grants
    ALTER COLUMN id DROP DEFAULT,
    ALTER COLUMN generation SET NOT NULL,
    ADD CONSTRAINT grants_pkey PRIMARY KEY (id),
    ADD CONSTRAINT grants_one_place CHECK ((project_id IS NULL) <> (environment_id IS NULL)),
    ADD CONSTRAINT grants_role_check CHECK (role ~ '^[a-z][a-z0-9-]{1,31}$');
--> statement-breakpoint
ALTER TABLE grants RENAME CONSTRAINT vault_grants_on_project TO grants_on_project;
--> statement-breakpoint
ALTER TABLE grants RENAME CONSTRAINT vault_grants_on_environment TO grants_on_environment;
--> statement-breakpoint
ALTER TABLE grants RENAME CONSTRAINT vault_grants_principal_fkey TO grants_principal_fkey;
--> statement-breakpoint
ALTER TABLE grants RENAME CONSTRAINT vault_grants_project_id_fkey TO grants_project_id_fkey;
--> statement-breakpoint
ALTER TABLE grants RENAME CONSTRAINT vault_grants_environment_id_fkey TO grants_environment_id_fkey;
--> statement-breakpoint
CREATE INDEX grants_project_idx ON grants (project_id);
--> statement-breakpoint
CREATE INDEX grants_environment_idx ON grants (environment_id);
--> statement-breakpoint

-- The roles and the policy have no row until the vault adopts: it writes the roles as they ship, as the newest
-- `policy.change` edited them, and the settings the newest `settings.change` holds.
CREATE TABLE roles (
    instance boolean NOT NULL,
    id text NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    permissions text[] NOT NULL,
    protected text[] NOT NULL,
    mac bytea DEFAULT '\x'::bytea NOT NULL,
    CONSTRAINT roles_pkey PRIMARY KEY (instance, id),
    CONSTRAINT roles_id_check CHECK (id ~ '^[a-z][a-z0-9-]{1,31}$'),
    CONSTRAINT roles_mac_check CHECK (octet_length(mac) IN (0, 36))
);
--> statement-breakpoint
CREATE TABLE policy (
    only_row boolean PRIMARY KEY DEFAULT true NOT NULL,
    service_accounts text NOT NULL,
    workloads_frozen_at timestamp(3) with time zone,
    changed_at timestamp(3) with time zone NOT NULL,
    changed_by text NOT NULL,
    mac bytea DEFAULT '\x'::bytea NOT NULL,
    CONSTRAINT policy_only_row_check CHECK (only_row),
    CONSTRAINT policy_service_accounts_check CHECK (service_accounts::jsonb IS NOT NULL),
    CONSTRAINT policy_mac_check CHECK (octet_length(mac) IN (0, 36))
);
--> statement-breakpoint

-- 5. Sign-in.

-- `active_subject` is computed from `revoked_at`, whose type section 8 changes: it goes here and comes back there.
DROP INDEX identities_active_subject;
--> statement-breakpoint
ALTER TABLE identities DROP CONSTRAINT identities_auth_mac_check, DROP COLUMN auth_mac, DROP COLUMN active_subject;
--> statement-breakpoint

-- An account bound before its member's last removal is dead. 0.14 revoked it in a transaction after the removal's, and
-- again at the member's next sign-in, so one that failed in between left it live. 0.16 is to revoke it with the removal,
-- and at no other time, and one left live would hold the account for good: nobody could sign in with it again.
UPDATE identities AS account SET revoked_at = now(), revoked_by = 'system:signin'
  FROM principals AS member
 WHERE member.id = account.principal AND account.generation < member.generation AND account.revoked_at IS NULL;
--> statement-breakpoint

ALTER TABLE service_bindings RENAME TO bindings;
--> statement-breakpoint
DROP INDEX service_bindings_principal_idx;
--> statement-breakpoint
ALTER INDEX service_bindings_live_idx RENAME TO bindings_live_idx;
--> statement-breakpoint
ALTER TABLE bindings DROP CONSTRAINT service_bindings_auth_mac_check, DROP COLUMN auth_mac;
--> statement-breakpoint
ALTER TABLE bindings RENAME CONSTRAINT service_bindings_pkey TO bindings_pkey;
--> statement-breakpoint
ALTER TABLE bindings RENAME CONSTRAINT service_bindings_principal_check TO bindings_principal_check;
--> statement-breakpoint
ALTER TABLE bindings RENAME CONSTRAINT service_bindings_claims_check TO bindings_claims_check;
--> statement-breakpoint
ALTER TABLE bindings RENAME CONSTRAINT service_bindings_principal_fkey TO bindings_principal_fkey;
--> statement-breakpoint

ALTER TABLE enrollments RENAME TO enrollment_codes;
--> statement-breakpoint
ALTER INDEX enrollments_binding_idx RENAME TO enrollment_codes_binding_idx;
--> statement-breakpoint
ALTER TABLE enrollment_codes DROP CONSTRAINT enrollments_auth_mac_check, DROP COLUMN auth_mac;
--> statement-breakpoint
ALTER TABLE enrollment_codes RENAME CONSTRAINT enrollments_pkey TO enrollment_codes_pkey;
--> statement-breakpoint
ALTER TABLE enrollment_codes RENAME CONSTRAINT enrollments_code_hash_key TO enrollment_codes_code_hash_key;
--> statement-breakpoint
ALTER TABLE enrollment_codes RENAME CONSTRAINT enrollments_code_hash_check TO enrollment_codes_code_hash_check;
--> statement-breakpoint
ALTER TABLE enrollment_codes RENAME CONSTRAINT enrollments_scope_check TO enrollment_codes_scope_check;
--> statement-breakpoint
ALTER TABLE enrollment_codes RENAME CONSTRAINT enrollments_binding_id_fkey TO enrollment_codes_binding_id_fkey;
--> statement-breakpoint

-- Credentials: a row a day past its expiry is one the minute's upkeep would delete, and goes here. An MCP connection
-- becomes a credential: one still live, its refresh token its token. One whose code was never redeemed, or that was
-- revoked or has expired, goes, with the approvals it asked for.
DELETE FROM credentials WHERE expires_at < now() - interval '1 day';
--> statement-breakpoint
-- Who a row names, as 0.16 names a member. 0.14.7's app wrote the caller's bare id in every column of its own:
-- `ada@acme.example` for a person, `ci-deploy` for a service account; its vault, and 0.16, write the principal,
-- `user:ada@acme.example` or `token:ci-deploy`, which every reader of these columns compares with. Resolved by
-- membership alone, removed members included: the id as it is if that is a member, which keeps a principal an
-- older release or a binding's tombstone above wrote whole, though a service be named `user:ada@acme.example`;
-- else `user:` and the lowercase id if that is one, else `token:` and the id if that is one, else the id as it is.
-- A service named exactly as a member's email, or as a member's principal, is taken for the member: the member
-- report then over-asks for the person and under-asks for the service. A column's literals are no member and are never resolved: a service account named
-- `binding:<id>` must not turn a binding's credential into one that stands without it (`created_by`, which the
-- vault reads to tell), and one named `coffre` must not claim the key rotation's revocations. Only rows that change
-- are written. After the expired credentials go, and after a binding's tombstone set who revoked it.
CREATE FUNCTION pg_temp.member_014(id text) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN EXISTS (SELECT 1 FROM principals WHERE principals.id = member_014.id) THEN member_014.id
    WHEN EXISTS (SELECT 1 FROM principals WHERE principals.id = 'user:' || lower(member_014.id)) THEN 'user:' || lower(member_014.id)
    WHEN EXISTS (SELECT 1 FROM principals WHERE principals.id = 'token:' || member_014.id) THEN 'token:' || member_014.id
    ELSE member_014.id
  END
$$;
--> statement-breakpoint
UPDATE secret_versions SET created_by = pg_temp.member_014(created_by)
 WHERE pg_temp.member_014(created_by) <> created_by;
--> statement-breakpoint
UPDATE dismissed_keys SET dismissed_by = pg_temp.member_014(dismissed_by), restored_by = pg_temp.member_014(restored_by)
 WHERE pg_temp.member_014(dismissed_by) <> dismissed_by OR pg_temp.member_014(restored_by) IS DISTINCT FROM restored_by;
--> statement-breakpoint
UPDATE identities SET created_by = pg_temp.member_014(created_by),
       revoked_by = CASE WHEN revoked_by LIKE 'system:%' THEN revoked_by ELSE pg_temp.member_014(revoked_by) END
 WHERE pg_temp.member_014(created_by) <> created_by
    OR (revoked_by NOT LIKE 'system:%' AND pg_temp.member_014(revoked_by) <> revoked_by);
--> statement-breakpoint
UPDATE bindings SET created_by = pg_temp.member_014(created_by), revoked_by = pg_temp.member_014(revoked_by)
 WHERE pg_temp.member_014(created_by) <> created_by OR pg_temp.member_014(revoked_by) IS DISTINCT FROM revoked_by;
--> statement-breakpoint
UPDATE credentials SET created_by = CASE WHEN created_by LIKE 'binding:%' THEN created_by ELSE pg_temp.member_014(created_by) END,
       revoked_by = CASE WHEN revoked_by = 'coffre' OR revoked_by LIKE 'system:%' THEN revoked_by ELSE pg_temp.member_014(revoked_by) END
 WHERE (created_by NOT LIKE 'binding:%' AND pg_temp.member_014(created_by) <> created_by)
    OR (revoked_by <> 'coffre' AND revoked_by NOT LIKE 'system:%' AND pg_temp.member_014(revoked_by) <> revoked_by);
--> statement-breakpoint
DROP FUNCTION pg_temp.member_014(text);
--> statement-breakpoint
-- Built after the rewrite above, so once: the member report reads a member's own writes through it.
CREATE INDEX secret_versions_created_by_idx ON secret_versions (created_by, secret_id);
--> statement-breakpoint
DROP INDEX credentials_principal_idx;
--> statement-breakpoint
ALTER TABLE credentials
    DROP CONSTRAINT credentials_auth_mac_check,
    DROP CONSTRAINT credentials_kind_check,
    DROP COLUMN auth_mac,
    ALTER COLUMN token_hint DROP NOT NULL,
    ADD COLUMN previous_token_hash bytea,
    ADD COLUMN code_hash bytea,
    ADD COLUMN client text,
    ADD COLUMN challenge text;
--> statement-breakpoint
ALTER TABLE credentials
    ADD CONSTRAINT credentials_kind_check CHECK (kind IN ('browser', 'cli', 'service', 'personal', 'handle', 'workload', 'mcp')),
    ADD CONSTRAINT credentials_mcp_client_check CHECK ((kind = 'mcp') = (client IS NOT NULL) AND (challenge IS NULL OR kind = 'mcp')),
    ADD CONSTRAINT credentials_previous_token_hash_check CHECK (previous_token_hash IS NULL OR octet_length(previous_token_hash) = 32),
    ADD CONSTRAINT credentials_code_hash_key UNIQUE (code_hash),
    ADD CONSTRAINT credentials_code_hash_check CHECK (code_hash IS NULL OR (kind = 'mcp' AND octet_length(code_hash) = 32));
--> statement-breakpoint
INSERT INTO credentials (id, kind, token_hash, previous_token_hash, code_hash, generation, principal, label, created_at, created_by, expires_at, last_used_at, last_used_ip, client)
SELECT id, 'mcp', refresh_hash, refresh_previous_hash, code_hash, generation, principal, client_name, created_at, principal, expires_at, last_used_at, last_used_ip,
       jsonb_build_object('id', client_id, 'host', client_host, 'registration', registration, 'redirectUri', redirect_uri, 'scopes', scopes)::text
  FROM mcp_connections
 WHERE refresh_hash IS NOT NULL AND revoked_at IS NULL AND expires_at > now();
--> statement-breakpoint
DELETE FROM mcp_approvals WHERE connection_id NOT IN (SELECT id FROM credentials WHERE kind = 'mcp');
--> statement-breakpoint
ALTER TABLE mcp_approvals
    DROP CONSTRAINT mcp_approvals_connection_fkey,
    ADD CONSTRAINT mcp_approvals_connection_fkey FOREIGN KEY (connection_id) REFERENCES credentials (id) ON DELETE CASCADE,
    ALTER COLUMN status DROP DEFAULT;
--> statement-breakpoint
DROP TABLE mcp_connections;
--> statement-breakpoint
CREATE INDEX credentials_previous_token_idx ON credentials (previous_token_hash) WHERE previous_token_hash IS NOT NULL;
--> statement-breakpoint
CREATE INDEX credentials_client_idx ON credentials ((client::jsonb ->> 'id')) WHERE client IS NOT NULL;
--> statement-breakpoint
CREATE INDEX credentials_expiry_idx ON credentials (expires_at);
--> statement-breakpoint

-- 6. One-shot rows. A device login under way starts again; an ID token spent over two hours ago guards nothing.

CREATE TABLE device_logins (
    id uuid PRIMARY KEY NOT NULL,
    device_code_hash bytea NOT NULL,
    user_code text NOT NULL,
    client_label text,
    client_ip text,
    created_at timestamp(3) with time zone NOT NULL,
    expires_at timestamp(3) with time zone NOT NULL,
    decided_at timestamp(3) with time zone,
    decision text,
    generation integer DEFAULT 0 NOT NULL,
    principal text,
    consumed_at timestamp(3) with time zone,
    mac bytea DEFAULT '\x'::bytea NOT NULL,
    CONSTRAINT device_logins_device_code_hash_key UNIQUE (device_code_hash),
    CONSTRAINT device_logins_user_code_key UNIQUE (user_code),
    CONSTRAINT device_logins_mac_check CHECK (octet_length(mac) IN (0, 36)),
    CONSTRAINT device_logins_decision_check CHECK (decision IS NULL OR decision IN ('approved', 'denied')),
    CONSTRAINT device_logins_approval_names_principal CHECK (
        (decision IS NULL AND decided_at IS NULL AND principal IS NULL AND generation = 0 AND consumed_at IS NULL)
        OR (decision IS NOT NULL AND decided_at IS NOT NULL AND (
          (decision = 'denied' AND principal IS NULL AND generation = 0 AND consumed_at IS NULL)
          OR (decision = 'approved' AND principal IS NOT NULL AND principal LIKE 'user:%')
        ))),
    CONSTRAINT device_logins_principal_fkey FOREIGN KEY (principal) REFERENCES principals (id) ON DELETE RESTRICT
);
--> statement-breakpoint
CREATE INDEX device_logins_expiry_idx ON device_logins (expires_at);
--> statement-breakpoint

ALTER TABLE consumed_tokens RENAME TO spent_id_tokens;
--> statement-breakpoint
ALTER TABLE spent_id_tokens RENAME COLUMN consumed_at TO spent_at;
--> statement-breakpoint
ALTER TABLE spent_id_tokens RENAME CONSTRAINT consumed_tokens_pkey TO spent_id_tokens_pkey;
--> statement-breakpoint
ALTER TABLE spent_id_tokens RENAME CONSTRAINT consumed_tokens_hash_check TO spent_id_tokens_hash_check;
--> statement-breakpoint
DELETE FROM spent_id_tokens WHERE spent_at < now() - interval '2 hours';
--> statement-breakpoint
CREATE INDEX spent_id_tokens_spent_idx ON spent_id_tokens (spent_at);
--> statement-breakpoint

ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_auth_mac_check, DROP COLUMN auth_mac;
--> statement-breakpoint

-- 7. The log.

CREATE TABLE log_pending (
    id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    kept boolean NOT NULL,
    body text NOT NULL,
    mac bytea NOT NULL,
    CONSTRAINT log_pending_mac_check CHECK (octet_length(mac) = 36)
);
--> statement-breakpoint
CREATE TABLE log (
    seq bigint PRIMARY KEY NOT NULL,
    kept boolean NOT NULL,
    leaf bigint NOT NULL,
    body text NOT NULL,
    CONSTRAINT log_leaf_key UNIQUE (kept, leaf),
    CONSTRAINT log_seq_check CHECK (seq >= 0 AND leaf >= 0 AND leaf <= seq)
);
--> statement-breakpoint
CREATE TABLE log_index (
    object text NOT NULL,
    seq bigint NOT NULL,
    CONSTRAINT log_index_pkey PRIMARY KEY (object, seq)
);
--> statement-breakpoint
CREATE TABLE log_tiles (
    kept boolean NOT NULL,
    level smallint NOT NULL,
    number bigint NOT NULL,
    hashes bytea NOT NULL,
    CONSTRAINT log_tiles_pkey PRIMARY KEY (kept, level, number),
    CONSTRAINT log_tiles_hashes_check CHECK (octet_length(hashes) BETWEEN 32 AND 8192 AND octet_length(hashes) % 32 = 0),
    CONSTRAINT log_tiles_place_check CHECK (level >= 0 AND number >= 0)
);
--> statement-breakpoint
CREATE TABLE log_head (
    only_row boolean PRIMARY KEY DEFAULT true NOT NULL,
    size bigint NOT NULL,
    kept_size bigint NOT NULL,
    kept_root bytea NOT NULL,
    aging_size bigint NOT NULL,
    aging_root bytea NOT NULL,
    aging_from bigint NOT NULL,
    signed_at timestamp(3) with time zone NOT NULL,
    mac bytea NOT NULL,
    CONSTRAINT log_head_only_row_check CHECK (only_row),
    CONSTRAINT log_head_sizes_check CHECK (kept_size >= 0 AND aging_size >= 0 AND size = kept_size + aging_size AND aging_from BETWEEN 0 AND aging_size),
    CONSTRAINT log_head_roots_check CHECK (octet_length(kept_root) = 32 AND octet_length(aging_root) = 32),
    CONSTRAINT log_head_mac_check CHECK (octet_length(mac) = 36)
);
--> statement-breakpoint
CREATE INDEX exposures_secret_idx ON exposures (secret_id);
--> statement-breakpoint

-- 8. Every time is a timestamptz(3), which the vault supplies, as it supplies each row's id; and each row that turns
-- into access has its MAC, empty until the vault adopts it.
DO $$
DECLARE
    col record;
    starred text;
BEGIN
    FOR col IN
        SELECT c.table_name, c.column_name, c.column_default
          FROM information_schema.columns c
         WHERE c.table_schema = 'public' AND c.table_name <> 'audit_archive'
           AND (c.data_type = 'timestamp with time zone' OR c.column_default IN ('now()', 'gen_random_uuid()'))
    LOOP
        IF col.column_default IN ('now()', 'gen_random_uuid()') THEN
            EXECUTE format('ALTER TABLE %I ALTER COLUMN %I DROP DEFAULT', col.table_name, col.column_name);
        END IF;
        IF EXISTS (
            SELECT 1 FROM information_schema.columns c
             WHERE c.table_schema = 'public' AND c.table_name = col.table_name AND c.column_name = col.column_name
               AND c.data_type = 'timestamp with time zone' AND c.datetime_precision <> 3
        ) THEN
            EXECUTE format('ALTER TABLE %I ALTER COLUMN %I TYPE timestamp(3) with time zone', col.table_name, col.column_name);
        END IF;
    END LOOP;
    FOREACH starred IN ARRAY ARRAY['projects', 'environments', 'secrets', 'dismissed_keys', 'principals', 'grants', 'identities', 'bindings', 'credentials', 'enrollment_codes', 'oauth_clients'] LOOP
        EXECUTE format('ALTER TABLE %I ADD COLUMN mac bytea DEFAULT ''\x''::bytea NOT NULL', starred);
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (octet_length(mac) IN (0, 36))', starred, starred || '_mac_check');
    END LOOP;
END
$$;
--> statement-breakpoint
ALTER TABLE identities ADD COLUMN active_subject text GENERATED ALWAYS AS (CASE WHEN revoked_at IS NULL THEN subject END) STORED;
--> statement-breakpoint
CREATE UNIQUE INDEX identities_active_subject ON identities (provider, issuer_hash, active_subject);
--> statement-breakpoint
ALTER TABLE environments ALTER COLUMN protected DROP DEFAULT, ALTER COLUMN frozen_credentials DROP DEFAULT;
--> statement-breakpoint
ALTER TABLE secrets ALTER COLUMN versions DROP DEFAULT;
--> statement-breakpoint
ALTER TABLE secret_versions ALTER COLUMN sensitive DROP DEFAULT;
--> statement-breakpoint

-- 9. Privileges: the vault's login writes, and the app's reads. What a privilege held of 0.14's goes with it.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM coffre_app, coffre_vault, coffre_backup;
--> statement-breakpoint
GRANT SELECT ON
    projects, environments, secrets, secret_versions, dismissed_keys,
    principals, grants, roles, policy,
    identities, bindings, credentials,
    device_logins, enrollment_codes, spent_id_tokens, oauth_clients, mcp_approvals,
    log_pending, log, log_index, log_tiles, log_head, exposures,
    audit_archive
TO coffre_app, coffre_vault, coffre_backup;
--> statement-breakpoint
GRANT INSERT, UPDATE, DELETE ON
    projects, environments, secrets, secret_versions, dismissed_keys,
    principals, grants, roles, policy,
    identities, bindings, credentials,
    device_logins, enrollment_codes, spent_id_tokens, oauth_clients, mcp_approvals,
    log_pending, log, log_index, log_tiles, log_head, exposures
TO coffre_vault;
--> statement-breakpoint
GRANT USAGE ON SEQUENCE log_pending_id_seq TO coffre_vault;
--> statement-breakpoint
GRANT SELECT ON SEQUENCE log_pending_id_seq TO coffre_backup;
