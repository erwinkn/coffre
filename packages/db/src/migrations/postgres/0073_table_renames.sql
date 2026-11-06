-- 0.16.0, T178: the tables renamed as Erwin approved them (2026-10-31): the vault's members are principals, people and
-- service accounts alike, and their grants are grants; the one-shot sign-in tables say what each row is (a terminal's
-- login, an enrollment code, a CI run's ID token spent); the bulk cap's rows and the checkpoints' fence are named for
-- what they hold. Each constraint and index takes its table's new name. Nothing else changes: no column, no row, no grant.
-- Expand (AGENTS.md, "Migrations: expand, then contract"): 0.15.0's code serves on this schema until the deploy, and
-- names the tables as it knows them. Each old name stays one release as a plain view of its table, which Postgres
-- writes through (an automatically updatable view: inserts, upserts by their columns, updates, deletes, row locks,
-- RETURNING and row counts as on the table). `security_invoker`: a login reads and writes through it only what the
-- table grants it, and the view grants each login what the table does, column by column, so neither is wider. The
-- release after 0.16.0 drops the views. The functions that name these tables are made again with the new names, each as
-- its last migration left it but for them; the use's and the route's warm-up marks move to `0073`, so that a session
-- warmed by the last ones plans these before the fence (T131). `CREATE OR REPLACE` keeps their owners and grants.
ALTER TABLE "vault_members" RENAME TO "principals";--> statement-breakpoint
ALTER TABLE "vault_grants" RENAME TO "grants";--> statement-breakpoint
ALTER TABLE "device_authorizations" RENAME TO "device_logins";--> statement-breakpoint
ALTER TABLE "enrollments" RENAME TO "enrollment_codes";--> statement-breakpoint
ALTER TABLE "consumed_tokens" RENAME TO "spent_id_tokens";--> statement-breakpoint
ALTER TABLE "log_bulk" RENAME TO "bulk_cap";--> statement-breakpoint
ALTER TABLE "log_fence" RENAME TO "checkpoint_fence";--> statement-breakpoint
ALTER TABLE "principals" RENAME CONSTRAINT "vault_members_pkey" TO "principals_pkey";--> statement-breakpoint
ALTER TABLE "principals" RENAME CONSTRAINT "vault_members_generation_check" TO "principals_generation_check";--> statement-breakpoint
ALTER TABLE "principals" RENAME CONSTRAINT "vault_members_mac_check" TO "principals_mac_check";--> statement-breakpoint
ALTER TABLE "principals" RENAME CONSTRAINT "vault_members_owner_check" TO "principals_owner_check";--> statement-breakpoint
ALTER TABLE "principals" RENAME CONSTRAINT "vault_members_principal_check" TO "principals_principal_check";--> statement-breakpoint
ALTER TABLE "principals" RENAME CONSTRAINT "vault_members_seal_check" TO "principals_seal_check";--> statement-breakpoint
ALTER TABLE "principals" RENAME CONSTRAINT "vault_members_status_check" TO "principals_status_check";--> statement-breakpoint
ALTER TABLE "principals" RENAME CONSTRAINT "vault_members_user_lowercase" TO "principals_user_lowercase";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_environment_id_fkey" TO "grants_environment_id_fkey";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_environment_slug_check" TO "grants_environment_slug_check";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_on_environment" TO "grants_on_environment";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_on_environment_slug" TO "grants_on_environment_slug";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_on_project" TO "grants_on_project";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_one_place" TO "grants_one_place";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_principal_fkey" TO "grants_principal_fkey";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_project_id_fkey" TO "grants_project_id_fkey";--> statement-breakpoint
ALTER TABLE "grants" RENAME CONSTRAINT "vault_grants_role_check" TO "grants_role_check";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_approval_names_principal" TO "device_logins_approval_names_principal";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_auth_mac_check" TO "device_logins_auth_mac_check";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_decision_check" TO "device_logins_decision_check";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_device_code_hash_key" TO "device_logins_device_code_hash_key";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_passkey_check" TO "device_logins_passkey_check";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_passkey_id_fkey" TO "device_logins_passkey_id_fkey";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_pkey" TO "device_logins_pkey";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_principal_fkey" TO "device_logins_principal_fkey";--> statement-breakpoint
ALTER TABLE "device_logins" RENAME CONSTRAINT "device_authorizations_user_code_key" TO "device_logins_user_code_key";--> statement-breakpoint
ALTER TABLE "enrollment_codes" RENAME CONSTRAINT "enrollments_auth_mac_check" TO "enrollment_codes_auth_mac_check";--> statement-breakpoint
ALTER TABLE "enrollment_codes" RENAME CONSTRAINT "enrollments_binding_id_fkey" TO "enrollment_codes_binding_id_fkey";--> statement-breakpoint
ALTER TABLE "enrollment_codes" RENAME CONSTRAINT "enrollments_code_hash_check" TO "enrollment_codes_code_hash_check";--> statement-breakpoint
ALTER TABLE "enrollment_codes" RENAME CONSTRAINT "enrollments_code_hash_key" TO "enrollment_codes_code_hash_key";--> statement-breakpoint
ALTER TABLE "enrollment_codes" RENAME CONSTRAINT "enrollments_pkey" TO "enrollment_codes_pkey";--> statement-breakpoint
ALTER TABLE "enrollment_codes" RENAME CONSTRAINT "enrollments_scope_check" TO "enrollment_codes_scope_check";--> statement-breakpoint
ALTER TABLE "spent_id_tokens" RENAME CONSTRAINT "consumed_tokens_hash_check" TO "spent_id_tokens_hash_check";--> statement-breakpoint
ALTER TABLE "spent_id_tokens" RENAME CONSTRAINT "consumed_tokens_pkey" TO "spent_id_tokens_pkey";--> statement-breakpoint
ALTER TABLE "bulk_cap" RENAME CONSTRAINT "log_bulk_pkey" TO "bulk_cap_pkey";--> statement-breakpoint
ALTER TABLE "checkpoint_fence" RENAME CONSTRAINT "log_fence_only_row_check" TO "checkpoint_fence_only_row_check";--> statement-breakpoint
ALTER TABLE "checkpoint_fence" RENAME CONSTRAINT "log_fence_pkey" TO "checkpoint_fence_pkey";--> statement-breakpoint
ALTER INDEX "vault_grants_on_every_project" RENAME TO "grants_on_every_project";--> statement-breakpoint
ALTER INDEX "enrollments_binding_idx" RENAME TO "enrollment_codes_binding_idx";--> statement-breakpoint
-- The old names, one release, each granting what its table grants.
DO $$
DECLARE
    t record;
    g record;
BEGIN
    FOR t IN SELECT * FROM (VALUES ('principals', 'vault_members'), ('grants', 'vault_grants'), ('device_logins', 'device_authorizations'), ('enrollment_codes', 'enrollments'), ('spent_id_tokens', 'consumed_tokens'), ('bulk_cap', 'log_bulk'), ('checkpoint_fence', 'log_fence')) AS v (name, old) LOOP
        EXECUTE format('CREATE VIEW public.%I WITH (security_invoker = true) AS SELECT * FROM public.%I', t.old, t.name);
        FOR g IN SELECT a.privilege_type, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS grantee
                   FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
                  WHERE c.oid = format('public.%I', t.name)::regclass AND a.grantee <> c.relowner LOOP
            EXECUTE format('GRANT %s ON public.%I TO %s', g.privilege_type, t.old, g.grantee);
        END LOOP;
        FOR g IN SELECT a.privilege_type, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS grantee, c.attname
                   FROM pg_attribute c CROSS JOIN LATERAL aclexplode(c.attacl) a
                  WHERE c.attrelid = format('public.%I', t.name)::regclass AND c.attnum > 0 AND NOT c.attisdropped LOOP
            EXECUTE format('GRANT %s (%I) ON public.%I TO %s', g.privilege_type, g.attname, t.old, g.grantee);
        END LOOP;
    END LOOP;
END
$$;--> statement-breakpoint
-- The functions that name them, by their new names.
CREATE OR REPLACE FUNCTION public.admit_inputs(p_token_hash bytea, p_principal text, p_scope text[])
 RETURNS text
 LANGUAGE plpgsql
 STABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
 SET "TimeZone" TO 'UTC'
AS $function$
DECLARE
    v jsonb;
BEGIN
    SELECT jsonb_build_object(
        'credential', CASE WHEN c.id IS NOT NULL THEN jsonb_build_object(
            'row', to_jsonb(c) - 'last_used_at' - 'last_used_ip',
            'expires', floor(extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint,
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('credential', c.id::text) ORDER BY x.number DESC LIMIT 1)) END,
        'identity', to_jsonb(i) - 'last_sign_in_at',
        'principal', CASE WHEN c.id IS NOT NULL THEN jsonb_build_object(
            'row', to_jsonb(m),
            -- Every grant, lapsed ones too, an environment's with its project, in one order (`write_inputs`'s).
            'grants', (SELECT coalesce(jsonb_agg(to_jsonb(g) || jsonb_build_object('resolved_project', coalesce(g.project_id, ge.project_id))
                                 ORDER BY g.project_id, g.environment_id, g.environment_slug, g.role, g.expires_at), '[]'::jsonb)
                         FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id WHERE g.principal = c.principal),
            -- 0.14's newest access entry about the caller (UsesSeeOldWrites), as a use reads it.
            'access', (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = c.principal AND a.decision = 'allow'
                AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('principal', c.principal) ORDER BY x.number DESC LIMIT 1)) END,
        'roles', jsonb_build_object('value', cfg.r_value, 'seal', cfg.r_seal,
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('roles', 'instance') ORDER BY x.number DESC LIMIT 1)),
        'policy', jsonb_build_object('value', cfg.p_value, 'seal', cfg.p_seal,
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1)),
        'policy14', (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1),
        -- The member asked for, whatever the token resolves to: none, for a first add. An add that committed first makes
        -- its row, its object's newest change and its 0.14 entry, each of which moves the digest (AddsFlip).
        'subject', jsonb_build_object(
            'row', to_jsonb(sm),
            'grants', (SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY g.project_id, g.environment_id, g.environment_slug, g.role, g.expires_at), '[]'::jsonb)
                         FROM public.grants g WHERE g.principal = p_principal),
            'access', (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = p_principal AND a.decision = 'allow'
                AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('principal', p_principal) ORDER BY x.number DESC LIMIT 1)),
        -- Each project the role's scope names, by its slug, in the order asked: standing slugs only, as `app_read`
        -- resolves them (a tombstone's is no project). A rename, and another made under the old slug, moves what a slug
        -- finds (Writing.tla's `scope`): the digest with it.
        'projects', (SELECT coalesce(jsonb_agg(jsonb_build_object('slug', k.slug, 'row', to_jsonb(p)) ORDER BY k.ord), '[]'::jsonb)
              FROM unnest(coalesce(p_scope, '{}'::text[])) WITH ORDINALITY k (slug, ord)
              LEFT JOIN LATERAL (SELECT * FROM public.projects x WHERE x.slug = k.slug AND x.slug NOT LIKE '%~%' LIMIT 1) p ON true)
    ) INTO v
      FROM (SELECT 1) one
      LEFT JOIN public.credentials c ON c.token_hash = p_token_hash
      LEFT JOIN public.identities i ON i.id = c.identity_id
      LEFT JOIN public.principals m ON m.principal = c.principal
      LEFT JOIN public.principals sm ON sm.principal = p_principal
      LEFT JOIN LATERAL (
          SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                 max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
            FROM public.log_config g
      ) cfg ON true;
    RETURN v::text;
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.change_bindings(p_at bigint, p_actor text, p_make boolean, p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint, p_via uuid, p_via_seal bytea, p_via_end bigint, p_connection uuid, p_connection_generation integer, p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text, p_max integer, p_live uuid[], p_read_keys uuid[], p_read_names text[], p_id uuid, p_auth_mac bytea, p_profile text, p_issuer text, p_jwks_uri text, p_jwks text, p_claims text, p_scope text, p_policy text, p_origin text, p_label text, p_created_by text, p_created_at bigint, p_seal bytea, p_ends uuid[], p_end_mac_from bytea[], p_end_seal_from bytea[], p_end_auth_mac bytea[], p_end_seal bytea[], p_creds uuid[], p_cred_binding uuid[], p_cred_mac_from bytea[], p_cred_seal_from bytea[], p_cred_auth_mac bytea[], p_cred_seal bytea[], p_revoked_at bigint, p_revoked_by text, p_change_request text[], p_change_object uuid[], p_change_payload text[], p_change_seal bytea[], p_change_mac bytea[])
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET lock_timeout TO '1s'
AS $function$
DECLARE
    n bigint;
    -- A value, not `clock_timestamp()` in a predicate: volatile there, it bounds no index.
    now_ts timestamptz := clock_timestamp();
    ended timestamptz := timestamptz 'epoch' + p_revoked_at * interval '1 millisecond';
BEGIN
    IF p_make = (p_id IS NULL) OR (NOT p_make AND cardinality(p_ends) = 0) OR cardinality(p_creds) <> cardinality(p_cred_binding)
       OR p_make = (p_live IS NULL) OR cardinality(p_read_keys) <> cardinality(p_read_names)
       OR cardinality(p_change_request) <> (CASE WHEN p_make THEN 1 ELSE 0 END) + (SELECT count(*) FROM unnest(p_end_seal) AS s WHERE s IS NOT NULL)
                                          + (SELECT count(*) FROM unnest(p_cred_seal) AS s WHERE s IS NOT NULL) THEN
        RAISE EXCEPTION 'a change of bindings makes one, ends some, or both, with a change for each object' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_make THEN
        -- IssuerLocked, IssuerCAS, as `issue_token`, by principal: the account's row first (`token:` sorts before `user:`),
        -- its update lock, so that two binds of it take turns over its count of bindings (a sign-in through one of its
        -- bindings waits for the statement too); then the maker's, shared. Then both compared.
        IF p_principal >= p_actor THEN RAISE EXCEPTION 'a binding is a service account''s, made by a person' USING ERRCODE = 'invalid_parameter_value'; END IF;
        PERFORM 1 FROM public.principals m WHERE m.principal = p_principal FOR NO KEY UPDATE;
        PERFORM 1 FROM public.principals m WHERE m.principal = p_actor FOR SHARE;
        -- 0.14's head, when it ends any, after the members' rows and before any row of the app's (row, head, issue lock, fence).
        IF cardinality(p_ends) > 0 THEN PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE; END IF;
        IF NOT EXISTS (SELECT 1 FROM public.principals m WHERE m.principal = p_actor AND m.status = 'active' AND m.generation = p_actor_generation AND m.access_seq = p_actor_seq)
           OR NOT EXISTS (SELECT 1 FROM public.principals m WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation AND m.access_seq = p_principal_seq) THEN
            RETURN json_build_object('state', 'moved');
        END IF;
        IF p_via IS NOT NULL THEN
            PERFORM 1 FROM public.credentials c WHERE c.id = p_via FOR SHARE;
            IF NOT EXISTS (SELECT 1 FROM public.credentials c
                            WHERE c.id = p_via AND c.principal = p_actor AND c.revoked_at IS NULL AND c.seal = p_via_seal
                              AND floor(extract(epoch FROM least(c.expires_at, coalesce(c.not_after, c.expires_at))) * 1000)::bigint = p_via_end)
               -- The clock once the locks are had, not when the statement began: one that ended while it waited has ended.
               OR p_via_end <= (extract(epoch FROM clock_timestamp()) * 1000)::bigint
               OR p_via_seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('credential', p_via::text) ORDER BY c.number DESC LIMIT 1) THEN
                RETURN json_build_object('state', 'ended');
            END IF;
        END IF;
        -- The MCP connection it came through, still connected at the caller's generation (as `credentialStill`): shared,
        -- so a disconnect waits for this, or is seen (review r3).
        IF p_connection IS NOT NULL THEN
            PERFORM 1 FROM public.mcp_connections k WHERE k.id = p_connection AND k.revoked_at IS NULL AND k.generation = p_connection_generation FOR SHARE;
            IF NOT FOUND THEN RETURN json_build_object('state', 'ended'); END IF;
        END IF;
        -- An id the log holds already is no binding to make, even once its row is gone: its object stands (review r3).
        IF EXISTS (SELECT 1 FROM public.log_changes l WHERE l.object = public.log_object('binding', p_id::text)) THEN
            RETURN json_build_object('state', 'stale');
        END IF;
    END IF;
    -- An unbind alone: 0.14's head first, as above.
    IF NOT p_make THEN PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE; END IF;
    -- The bindings it ends, then the credentials they issued: each row locked, by id, then held to its MAC and seal as
    -- read. Every live credential they issued must be named, so one that a sign-in made meanwhile is read again (`moved`),
    -- never left live.
    PERFORM 1 FROM public.service_bindings b WHERE b.id = ANY(p_ends) ORDER BY b.id FOR UPDATE;
    IF (SELECT count(*) FROM unnest(p_ends, p_end_mac_from, p_end_seal_from) AS e(id, mac, seal)
          JOIN public.service_bindings b ON b.id = e.id AND b.principal = p_principal AND b.revoked_at IS NULL AND b.auth_mac = e.mac AND b.seal IS NOT DISTINCT FROM e.seal)
       <> cardinality(p_ends) THEN
        RETURN json_build_object('state', 'moved');
    END IF;
    -- A credential 0.14 made, or one written around the vault, has no seal: ended with its binding all the same, its row
    -- revoked with no change, the log holding no object of it.
    PERFORM 1 FROM public.credentials c WHERE c.id = ANY(p_creds) ORDER BY c.id FOR UPDATE;
    IF (SELECT count(*) FROM unnest(p_creds, p_cred_binding, p_cred_mac_from, p_cred_seal_from) AS x(id, binding, mac, seal)
          JOIN public.credentials c ON c.id = x.id AND x.binding = ANY(p_ends) AND c.created_by = 'binding:' || x.binding::text
                                   AND c.revoked_at IS NULL AND c.auth_mac = x.mac AND c.seal IS NOT DISTINCT FROM x.seal)
       <> cardinality(p_creds)
       OR EXISTS (SELECT 1 FROM unnest(p_ends) AS e(id) JOIN public.credentials c
                    ON c.principal = p_principal AND c.created_by = 'binding:' || e.id::text AND c.revoked_at IS NULL AND c.expires_at > now_ts
                   WHERE NOT (c.id = ANY(p_creds))) THEN
        RETURN json_build_object('state', 'moved');
    END IF;
    IF p_make THEN
        -- The account's live bindings as the app read them, which it weighed this one beside (an issuer's keys moved, the
        -- bindings it replaces): another made or ended since is read again. Under the account's row's lock, which every
        -- bind takes, so two binds take turns. At most `p_max`, those it ends left out.
        IF ARRAY(SELECT b.id FROM public.service_bindings b WHERE b.principal = p_principal AND b.generation = p_generation AND b.revoked_at IS NULL ORDER BY b.id)
           IS DISTINCT FROM ARRAY(SELECT l FROM unnest(p_live) AS l ORDER BY l) THEN
            RETURN json_build_object('state', 'moved');
        END IF;
        IF cardinality(p_live) - (SELECT count(*) FROM unnest(p_live) AS l WHERE l = ANY(p_ends)) >= p_max THEN
            RETURN json_build_object('state', 'full');
        END IF;
    END IF;
    -- IssuePolicyHeld: the issue lock, shared; then, under it, the policy and the slugs this change was weighed on, and the numbers.
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    IF (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1)
            IS DISTINCT FROM p_policy_seq
        OR EXISTS (
            SELECT 1 FROM unnest(p_protected, p_slugs) AS p(id, slug)
             WHERE (SELECT e.slug FROM public.environments e JOIN public.projects q ON q.id = e.project_id
                     WHERE e.id = p.id AND strpos(e.slug, '~') = 0 AND strpos(q.slug, '~') = 0) IS DISTINCT FROM p.slug
        ) THEN
        RETURN json_build_object('state', 'policy');
    END IF;
    IF EXISTS (SELECT 1 FROM public.audit_log a WHERE a.author = 'app' AND a.subject_principal = p_app_key AND a.action IN ('key.reseal', 'key.rotate')) THEN
        RETURN json_build_object('state', 'retired');
    END IF;
    -- What it ends is a use's input: the fence exclusive (RevokeTakesFence), after the issue lock (PolicyIssueFirst), for
    -- the statement's work only. A bind that ends nothing takes none.
    IF cardinality(p_ends) > 0 THEN PERFORM pg_advisory_xact_lock(1668244070, 0); END IF;
    -- The keys a binding it makes reads, by the names they were asked by: still those names (a rename meanwhile names
    -- another). Compared, not locked (a key's writer takes the fence before its row: a share lock here, held into the
    -- fence, would be a cycle; review r3), and once the fence is had, which a rename takes too: one that committed while
    -- this waited is seen (review r4). With no fence, one that commits after this is a rename after the bind.
    IF p_make AND (SELECT count(*) FROM unnest(p_read_keys, p_read_names) AS r(id, name) JOIN public.secrets x ON x.id = r.id AND x.key = r.name) <> cardinality(p_read_keys) THEN
        RETURN json_build_object('state', 'moved');
    END IF;
    -- ChangeChecksSeal: each row it ends is its object's newest change's; one put back is stale. A row with no seal is one
    -- the log never held, or none at all once a seal it had was cleared around the vault: that one is stale too, so the
    -- log's binding is never ended with no change of it (review r2).
    IF EXISTS (SELECT 1 FROM unnest(p_ends, p_end_seal_from) AS e(id, seal)
                WHERE e.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = public.log_object('binding', e.id::text) ORDER BY l.number DESC LIMIT 1))
       OR EXISTS (SELECT 1 FROM unnest(p_creds, p_cred_seal_from) AS x(id, seal)
                WHERE x.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = public.log_object('credential', x.id::text) ORDER BY l.number DESC LIMIT 1)) THEN
        RETURN json_build_object('state', 'stale');
    END IF;
    IF p_make THEN
        -- Again, now that no lock is left to wait for: a make of the same id that committed meanwhile, its row deleted since,
        -- is seen; one not yet committed holds the id's key, which this insert then waits for and fails on (review r4).
        IF EXISTS (SELECT 1 FROM public.log_changes l WHERE l.object = public.log_object('binding', p_id::text)) THEN
            RETURN json_build_object('state', 'stale');
        END IF;
        INSERT INTO public.service_bindings (id, auth_mac, principal, generation, profile, issuer, jwks_uri, jwks, claims, scope, policy, origin, label, created_by, created_at, seal)
            VALUES (p_id, p_auth_mac, p_principal, p_generation, p_profile, p_issuer, p_jwks_uri, p_jwks, p_claims, p_scope, p_policy, p_origin, p_label, p_created_by,
                    timestamptz 'epoch' + p_created_at * interval '1 millisecond', p_seal);
    END IF;
    UPDATE public.service_bindings b SET revoked_at = ended, revoked_by = p_revoked_by, auth_mac = e.mac, seal = e.seal
      FROM unnest(p_ends, p_end_auth_mac, p_end_seal) AS e(id, mac, seal) WHERE b.id = e.id;
    UPDATE public.credentials c SET revoked_at = ended, revoked_by = p_revoked_by, auth_mac = x.mac, seal = x.seal
      FROM unnest(p_creds, p_cred_auth_mac, p_cred_seal) AS x(id, mac, seal) WHERE c.id = x.id;
    -- Each object's change, numbered in the order named: the binding made, those ended, their credentials.
    FOR i IN 1 .. cardinality(p_change_request) LOOP
        INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
            VALUES (nextval('public.log_number'), p_at, p_change_request[i], p_change_object[i], p_actor, p_change_payload[i], p_change_seal[i], p_change_mac[i])
            RETURNING number INTO n;
    END LOOP;
    -- Only rows the log never held, ended: no change, nothing to seal.
    RETURN json_build_object('number', coalesce(n::text, '0'));
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.change_input(p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_value text, p_seal_from bytea, p_seal bytea, p_mac bytea)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
    op jsonb := p_payload::jsonb;
    v jsonb := p_value::jsonb;
    change text := op ->> 'op';
    target uuid := public.log_object(p_kind, p_id);
    n bigint;
    done integer;
    member text;
    held bytea;
    newest bytea;
    config jsonb;
BEGIN
    -- Its locks in the order 0.14's writers take theirs, so that none waits on the other in a circle until 0.16 (row,
    -- head, fence: Migration015.tla's RowFirst, ChangeHeadFirst): the member's queue (MEMBER_QUEUE, 0x636f666d) and row
    -- first, a principal's own or a credential's (0.14's vault locks them before the head, lockMembers; a change made
    -- inside a 0.14 decision holds them already), then 0.14's head (its app takes it before its rows), then the fence
    -- (0.14's appends take it after the head, audit_log_fence). The head held, no 0.14 write lands between this change
    -- and its entry.
    member := CASE p_kind
        WHEN 'principal' THEN p_id
        WHEN 'credential' THEN coalesce(
            (SELECT c.principal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.principal FROM public.service_bindings b WHERE b.id = p_id::uuid))
        WHEN 'connection' THEN (SELECT k.principal FROM public.mcp_connections k WHERE k.id = p_id::uuid)
    END;
    IF member IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(1668245101, hashtext(m.principal)) FROM public.principals m WHERE m.principal = member FOR NO KEY UPDATE;
    END IF;
    PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE;
    -- ChangeLocks: exclusive, so that it waits for every use in flight, and every use after it waits for its commit.
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request;
    IF FOUND THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.log_changes c
             WHERE c.request_id = p_request AND c.object = target AND c.payload = p_payload AND c.seal IS NOT DISTINCT FROM p_seal
        ) THEN
            RAISE EXCEPTION 'request % names another change', p_request USING ERRCODE = 'unique_violation';
        END IF;
        RETURN n;
    END IF;
    IF NOT (change = 'genesis'
        OR (p_kind = 'principal' AND change IN ('member.add', 'member.role', 'member.remove', 'member.restore', 'access.grant', 'access.revoke'))
        OR (p_kind = 'environment' AND change IN ('environment.protect', 'environment.rename', 'environment.archive'))
        OR (p_kind = 'secret' AND change IN ('secret.write', 'secret.delete'))
        OR (p_kind = 'roles' AND change = 'role.define')
        OR (p_kind = 'policy' AND change = 'bulk.limit')
        OR (p_kind = 'proxy' AND change IN ('proxy.save', 'proxy.code'))
        OR (p_kind = 'proxy-reserved' AND change IN ('proxy.code', 'proxy.release'))) THEN
        RAISE EXCEPTION 'this schema knows no change % to a %', coalesce(change, 'without an op'), p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The proxy's objects are 0.16's, after every cutover: each is made by its first change, never a genesis.
    IF change = 'genesis' AND p_kind IN ('proxy', 'proxy-reserved') THEN
        RAISE EXCEPTION 'a % object has no genesis', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The payload names its object (`ref`), so that a replay knows what each change is to: the column holds only its
    -- key. The cutover's genesis may leave it out, its value naming it.
    IF (change <> 'genesis' OR op ? 'ref') AND (op -> 'ref' ->> 'kind' IS DISTINCT FROM p_kind OR op -> 'ref' ->> 'id' IS DISTINCT FROM p_id) THEN
        RAISE EXCEPTION 'a change names the object it is to: %, %', p_kind, p_id USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A value is the object as this function writes it: an environment's, which a genesis may leave out to seal the
    -- row as it is; a key's, the end of its reference (`secret.write`, the one change of a key the vault makes), and
    -- none at its genesis; the roles' and the policy's, but at their genesis, whose payload holds it. The others' rows
    -- are written by whoever keeps them, and carry none.
    IF (CASE
        WHEN p_kind = 'environment' THEN change <> 'genesis' AND v IS NULL
        WHEN p_kind = 'secret' THEN (change = 'secret.write') = (v IS NULL)
        WHEN p_kind IN ('roles', 'policy') THEN (change = 'genesis') = (v IS NOT NULL)
        WHEN p_kind IN ('proxy', 'proxy-reserved') THEN v IS NULL
        ELSE v IS NOT NULL
    END) THEN
        RAISE EXCEPTION 'a % change % carries the object it leaves exactly when this function writes it', p_kind, change USING ERRCODE = 'invalid_parameter_value';
    END IF;
    newest := (SELECT c.seal FROM public.log_changes c WHERE c.object = target ORDER BY c.number DESC LIMIT 1);
    -- ChangeChecksSeal: the row's seal is its object's newest change's, or the object has neither yet (one probe, as
    -- a use makes). A row deleted outright, or a seal no change wrote, is stale too. Not the proxy's (0.16): the vault
    -- writes each of its rows whole from its value, so a row a writer moved is replaced, never carried on; its change
    -- moves only from the newest change's seal (below), which the vault decided on.
    held := CASE p_kind
        WHEN 'principal' THEN (SELECT m.seal FROM public.principals m WHERE m.principal = p_id)
        WHEN 'credential' THEN coalesce(
            (SELECT c.seal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.seal FROM public.service_bindings b WHERE b.id = p_id::uuid))
        WHEN 'connection' THEN (SELECT k.seal FROM public.mcp_connections k WHERE k.id = p_id::uuid)
        WHEN 'environment' THEN (SELECT e.seal FROM public.environments e WHERE e.id = p_id::uuid)
        WHEN 'secret' THEN (SELECT x.seal FROM public.secrets x WHERE x.id = p_id::uuid)
        WHEN 'policy' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'policy')
        WHEN 'roles' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'roles')
        WHEN 'proxy' THEN newest
        WHEN 'proxy-reserved' THEN newest
    END;
    IF held IS DISTINCT FROM newest THEN
        RAISE EXCEPTION 'the % object''s row is not its newest change''s: stale', p_kind USING ERRCODE = 'data_corrupted';
    END IF;
    -- ChangeCAS: each write moves the row only from the seal the vault read.
    CASE p_kind
        WHEN 'principal' THEN
            UPDATE public.principals SET seal = p_seal WHERE principal = p_id AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'credential' THEN
            -- A token's row, or a trust binding's: one kind of object, ids that never meet.
            UPDATE public.credentials SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            GET DIAGNOSTICS done = ROW_COUNT;
            IF done = 0 THEN
                UPDATE public.service_bindings SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            END IF;
        WHEN 'connection' THEN
            -- An MCP connection's genesis, the cutover's (T147): its row sealed as it is. The app's changes make and end the others.
            UPDATE public.mcp_connections SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'environment' THEN
            IF v IS NULL THEN
                UPDATE public.environments SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            ELSE
                -- A deleted environment's row keeps its tombstone, `dev~deleted-…` (@coffre/core/schemas's isTombstone),
                -- and its object the slug before it (objects.ts, environmentObject): an environment deleted stays so,
                -- its slug is never written again, and none is deleted here; an object's slug holds no tombstone.
                UPDATE public.environments e
                   SET slug = CASE WHEN strpos(e.slug, '~') > 0 THEN e.slug ELSE v ->> 'slug' END,
                       protected = (v ->> 'protected')::boolean,
                       archived_at = CASE WHEN (v ->> 'archived')::boolean THEN coalesce(e.archived_at, to_timestamp(p_at / 1000.0)) END,
                       seal = p_seal
                 WHERE e.id = p_id::uuid AND e.seal IS NOT DISTINCT FROM p_seal_from
                   AND v ->> 'kind' = 'environment' AND v ->> 'id' = p_id
                   AND e.project_id = (v ->> 'projectId')::uuid
                   AND e.parent_id IS NOT DISTINCT FROM (v ->> 'parentId')::uuid
                   AND e.owner IS NOT DISTINCT FROM v ->> 'owner'
                   AND (strpos(e.slug, '~') > 0) = (v ->> 'deleted')::boolean
                   -- Its project's archival is the project's row's, which the app writes, and none once deleted (objects.ts): held,
                   -- never written here.
                   AND (v ->> 'projectArchived')::boolean = (strpos(e.slug, '~') = 0 AND EXISTS (SELECT 1 FROM public.projects p WHERE p.id = e.project_id AND p.archived_at IS NOT NULL))
                   AND strpos(v ->> 'slug', '~') = 0
                   AND (NOT (v ->> 'deleted')::boolean OR split_part(e.slug, '~', 1) = v ->> 'slug');
            END IF;
        WHEN 'secret' THEN
            IF v IS NULL THEN
                UPDATE public.secrets SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            ELSE
                -- A reference's end, in the vault's decision that appends 0.14's `reference.end` (EndInRow, EndWithEntry:
                -- formal/SealedObjects.tla): the holder, a key with no version of its own, left with no source. Live, from
                -- its seal, its newest reference row ended. That row must stand: its seal, which the check above held to
                -- the newest change, says the holder reads its source; a row ended or gone under it is not the log's.
                -- Archived, from none (EndWhileArchived): the object its unarchive would restore, ended, then deleted
                -- again by the next call (`secret.delete`); its row was ended by its id (`end_reference`).
                UPDATE public.secrets x SET seal = p_seal
                 WHERE x.id = p_id::uuid AND x.seal IS NOT DISTINCT FROM p_seal_from AND (x.archived_at IS NULL) = (p_seal_from IS NOT NULL)
                   AND x.current_version_id IS NULL
                   AND v ->> 'kind' = 'secret' AND v ->> 'id' = p_id AND x.project_id = (v ->> 'projectId')::uuid AND x.environment_id = (v ->> 'environmentId')::uuid
                   AND v ->> 'version' = '' AND v ->> 'nature' = 'secret' AND v -> 'key' = 'null'::jsonb AND v -> 'digest' = 'null'::jsonb AND v -> 'source' = 'null'::jsonb
                   AND v -> 'reference' = 'null'::jsonb;
                GET DIAGNOSTICS done = ROW_COUNT;
                IF done > 0 AND p_seal_from IS NOT NULL THEN
                    UPDATE public.secret_references y SET ended_at = to_timestamp(p_at / 1000.0)
                     WHERE y.id = (SELECT CASE WHEN z.secret_id = p_id::uuid THEN z.id END FROM public.secret_references z
                                   WHERE z.secret_id <= p_id::uuid ORDER BY z.secret_id DESC, z.created_seq DESC LIMIT 1) AND y.ended_at IS NULL;
                    GET DIAGNOSTICS done = ROW_COUNT;
                    IF done = 0 THEN
                        RAISE EXCEPTION 'the secret object''s reference has no standing row: stale' USING ERRCODE = 'data_corrupted';
                    END IF;
                END IF;
            END IF;
        WHEN 'policy', 'roles' THEN
            config := CASE change WHEN 'genesis' THEN op -> 'value' ELSE v END;
            IF p_id <> 'instance' OR config IS NULL OR jsonb_typeof(config) <> 'object' OR (change = 'genesis' AND p_seal_from IS NOT NULL) THEN
                RAISE EXCEPTION 'the % object is one, made once from its value and changed from its seal', p_kind USING ERRCODE = 'invalid_parameter_value';
            END IF;
            -- Made by its first change (genesis, or the first role defined, the first cap set); moved after from its seal.
            IF p_seal_from IS NULL THEN
                INSERT INTO public.log_config (name, value, seal) VALUES (p_kind, config::text, p_seal) ON CONFLICT (name) DO NOTHING;
            ELSE
                UPDATE public.log_config SET value = config::text, seal = p_seal WHERE log_config.name = p_kind AND seal = p_seal_from;
            END IF;
        WHEN 'proxy', 'proxy-reserved' THEN
            -- An environment's proxy definitions, or the instance's reserved names (0.16, T186; docs/design/proxy-ui.md,
            -- section 2): the whole row from its value, and only from the newest change's seal (ChangeCAS on the log, not
            -- the row): one the vault did not decide on is no change of its. An environment's, its items by name and
            -- their index, which its seal covers; the reserved set's, the whole set.
            IF p_seal_from IS DISTINCT FROM newest THEN RETURN NULL; END IF;
            IF p_kind = 'proxy' THEN
                IF jsonb_typeof(v -> 'items') IS DISTINCT FROM 'object' OR jsonb_typeof(v -> 'digests') IS DISTINCT FROM 'string' THEN
                    RAISE EXCEPTION 'a proxy object is its items and their index' USING ERRCODE = 'invalid_parameter_value';
                END IF;
                INSERT INTO public.proxy_definitions AS d (environment_id, items, digests, seal)
                    VALUES (p_id::uuid, v -> 'items', decode(v ->> 'digests', 'base64'), p_seal)
                    ON CONFLICT (environment_id) DO UPDATE SET items = EXCLUDED.items, digests = EXCLUDED.digests, seal = EXCLUDED.seal;
            ELSE
                IF p_id <> 'instance' OR jsonb_typeof(v -> 'names') IS DISTINCT FROM 'array' THEN
                    RAISE EXCEPTION 'the reserved names are one object, the whole set' USING ERRCODE = 'invalid_parameter_value';
                END IF;
                INSERT INTO public.proxy_reserved AS r (id, names, seal) VALUES (1, v -> 'names', p_seal)
                    ON CONFLICT (id) DO UPDATE SET names = EXCLUDED.names, seal = EXCLUDED.seal;
            END IF;
        ELSE
            RAISE EXCEPTION 'no object kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END CASE;
    -- A row gone, a row whose seal is no longer the one read, an environment that is not what the value says it
    -- stays, or an object made already: nothing was done.
    GET DIAGNOSTICS done = ROW_COUNT;
    IF done = 0 THEN RETURN NULL; END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN n;
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.close_one()
 RETURNS TABLE(upto bigint, at_floor bigint, floor_found bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
    found_floor bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(1668244070, 1);
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    SELECT f.at_floor INTO found_floor FROM public.checkpoint_fence f WHERE f.only_row;
    UPDATE public.checkpoint_fence f SET at_floor = greatest(f.at_floor, (extract(epoch FROM clock_timestamp()) * 1000)::bigint - public.deadline_max()) WHERE f.only_row;
    RETURN QUERY SELECT pg_sequence_last_value('public.log_number'), f.at_floor, found_floor FROM public.checkpoint_fence f WHERE f.only_row;
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.issue_token(p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea, p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint, p_via uuid, p_via_seal bytea, p_via_end bigint, p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text, p_id uuid, p_kind text, p_auth_mac bytea, p_token_hash bytea, p_token_hint text, p_label text, p_created_by text, p_scope text, p_places text, p_expires bigint, p_passkey uuid)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET lock_timeout TO '1s'
AS $function$
DECLARE
    n bigint;
BEGIN
    IF p_kind NOT IN ('service', 'personal', 'handle') OR (p_kind = 'service') = (p_principal = p_actor) THEN
        RAISE EXCEPTION 'the vault issues a service account a token, or a person one of their own' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_passkey IS NOT NULL AND p_via IS NULL THEN
        RAISE EXCEPTION 'a passkey is carried from the credential an issue came in on' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- FactorFirst: the issuer's factor lock, before any row's. A change to their passkeys holds it from before it reads
    -- what to end until it commits: it commits before this reads `via`, which it then finds revoked, or waits for this
    -- issue's commit and reads what it wrote.
    PERFORM pg_advisory_xact_lock(1717658484, hashtext(p_actor));
    -- IssuerLocked: the members' rows, then the credential's, shared; a lock not had within `lock_timeout` raises `lock_not_available`, busy.
    PERFORM 1 FROM public.principals m WHERE m.principal IN (p_actor, p_principal) ORDER BY m.principal FOR SHARE;
    -- IssuerCAS, once the locks are had.
    IF NOT EXISTS (SELECT 1 FROM public.principals m WHERE m.principal = p_actor AND m.status = 'active' AND m.generation = p_actor_generation AND m.access_seq = p_actor_seq)
       OR NOT EXISTS (SELECT 1 FROM public.principals m WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation AND m.access_seq = p_principal_seq) THEN
        RETURN json_build_object('state', 'moved');
    END IF;
    IF p_via IS NOT NULL THEN
        PERFORM 1 FROM public.credentials c WHERE c.id = p_via FOR SHARE;
        -- Its end as the vault authenticated it (`p_via_end`, the earlier of its expiry and its hard end, which its seal
        -- covers): the columns still say so, and it is still ahead. A seal compares bytes, never the columns it was made of.
        -- And the passkey it names, the one this issue carries, still the actor's at the generation checked above, and not
        -- removed: live as `passkeys_live_idx` defines it (a member's removal moves their generation past their passkeys).
        IF NOT EXISTS (SELECT 1 FROM public.credentials c
                        WHERE c.id = p_via AND c.principal = p_actor AND c.revoked_at IS NULL AND c.seal = p_via_seal
                          AND floor(extract(epoch FROM least(c.expires_at, coalesce(c.not_after, c.expires_at))) * 1000)::bigint = p_via_end
                          AND c.passkey_id IS NOT DISTINCT FROM p_passkey)
           OR p_via_end <= (extract(epoch FROM clock_timestamp()) * 1000)::bigint
           OR p_via_seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('credential', p_via::text) ORDER BY c.number DESC LIMIT 1)
           OR (p_passkey IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.passkeys k WHERE k.id = p_passkey AND k.principal = p_actor AND k.generation = p_actor_generation AND k.removed_at IS NULL)) THEN
            RETURN json_build_object('state', 'ended');
        END IF;
    END IF;
    -- IssuePolicyHeld: the issue lock shared before the policy is compared, and the number under it. A policy change, or a
    -- write that moves a protected environment's slug, takes it exclusive before the fence (`holdIssues`): it commits
    -- before this compares, and is seen, or waits for this issue's commit.
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    IF (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1)
            IS DISTINCT FROM p_policy_seq
        OR EXISTS (
            SELECT 1 FROM unnest(p_protected, p_slugs) AS p(id, slug)
             WHERE (SELECT e.slug FROM public.environments e JOIN public.projects q ON q.id = e.project_id
                     WHERE e.id = p.id AND strpos(e.slug, '~') = 0 AND strpos(q.slug, '~') = 0) IS DISTINCT FROM p.slug
        ) THEN
        RETURN json_build_object('state', 'policy');
    END IF;
    IF EXISTS (SELECT 1 FROM public.audit_log a WHERE a.author = 'app' AND a.subject_principal = p_app_key AND a.action IN ('key.reseal', 'key.rotate')) THEN
        RETURN json_build_object('state', 'retired');
    END IF;
    IF p_expires <= (extract(epoch FROM clock_timestamp()) * 1000)::bigint THEN
        RETURN json_build_object('state', 'expired');
    END IF;
    INSERT INTO public.credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, identity_id, scope, places, label, created_by,
                                    expires_at, revoked_at, seal, passkey_id)
        VALUES (p_id, p_kind, p_auth_mac, p_token_hash, p_token_hint, p_generation, p_principal, NULL, p_scope, p_places, p_label, p_created_by,
                timestamptz 'epoch' + p_expires * interval '1 millisecond', NULL, p_seal, p_passkey);
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, public.log_object('credential', p_id::text), p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN json_build_object('number', n::text);
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.log_refuse_retired()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    IF EXISTS (SELECT 1 FROM public.checkpoint_fence f WHERE f.only_row AND substring(NEW.mac FROM 1 FOR 4) = ANY(f.retired)) THEN
        RAISE EXCEPTION 'the log moved on from the signing key this entry is under: a vault given a newer key replaced this one, and a replaced key writes nothing more (ask again)'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NEW;
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.log_rotate(p_number bigint, p_request text, p_at bigint, p_payload text, p_mac bytea, p_from bytea)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    IF p_payload::jsonb ->> 'op' IS DISTINCT FROM 'rotate' OR p_payload::jsonb ->> 'at' IS DISTINCT FROM p_number::text
       OR octet_length(p_from) <> 4 OR octet_length(p_mac) <> 16 OR substring(p_mac FROM 1 FOR 4) = p_from THEN
        RAISE EXCEPTION 'not a rotation: %', p_payload USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The number this transaction's log_rotate_number took, its locks still held (taking them again is a no-op).
    PERFORM pg_advisory_xact_lock(1668244070, 1);
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    IF p_number IS DISTINCT FROM currval('public.log_number') OR EXISTS (SELECT 1 FROM public.checkpoint_fence f WHERE f.only_row AND p_from = ANY(f.retired)) THEN
        RAISE EXCEPTION 'not the rotation this transaction numbered' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
    VALUES (p_number, p_at, p_request, public.log_object('log', 'key'), 'system:vault', p_payload, NULL, p_mac);
    UPDATE public.checkpoint_fence SET retired = array_append(retired, p_from) WHERE only_row;
    -- No fence row (a damaged or partial restore): no key retired, so the whole rotation fails, closed.
    IF NOT FOUND THEN RAISE EXCEPTION 'the log''s fence row is gone' USING ERRCODE = 'object_not_in_prerequisite_state'; END IF;
    RETURN p_number;
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.log_rotate_number(p_from bytea)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    IF octet_length(p_from) <> 4 THEN RAISE EXCEPTION 'a key''s tag is 4 bytes' USING ERRCODE = 'invalid_parameter_value'; END IF;
    PERFORM pg_advisory_xact_lock(1668244070, 1);
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    IF EXISTS (SELECT 1 FROM public.checkpoint_fence f WHERE f.only_row AND p_from = ANY(f.retired)) THEN RETURN NULL; END IF;
    RETURN nextval('public.log_number');
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.prune_bulk(p_limit integer)
 RETURNS integer
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET lock_timeout TO '3s'
AS $function$
    WITH bound AS (
        SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint - w.window_ms - least(60000, w.window_ms / 10) - public.deadline_max() - 3600000 AS before
          FROM (
              SELECT (x.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS window_ms FROM public.log_changes x
               WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
          ) w
         WHERE w.window_ms IS NOT NULL
    ),
    pruned AS (
        DELETE FROM public.bulk_cap
         WHERE last < (SELECT before FROM bound)
           AND ctid IN (SELECT ctid FROM public.bulk_cap WHERE last < (SELECT before FROM bound) LIMIT p_limit FOR UPDATE SKIP LOCKED)
        RETURNING 1
    )
    SELECT count(*)::integer FROM pruned;
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.prune_consumed_tokens(at_most integer)
 RETURNS integer
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
    WITH pruned AS (
        DELETE FROM public.spent_id_tokens
         WHERE hash IN (SELECT hash FROM public.spent_id_tokens WHERE consumed_at < now() - interval '2 hours' LIMIT at_most)
        RETURNING 1
    )
    SELECT count(*)::integer FROM pruned;
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.sign_in(p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea, p_binding uuid, p_principal text, p_generation integer, p_binding_profile text, p_binding_scope text, p_binding_policy text, p_binding_issuer text, p_binding_jwks_uri text, p_binding_claims text, p_binding_seal bytea, p_spent bytea, p_valid_until bigint, p_frozen boolean, p_rate integer, p_window bigint, p_longest bigint, p_id uuid, p_kind text, p_auth_mac bytea, p_token_hash bytea, p_token_hint text, p_label text, p_created_by text, p_scope text, p_places text, p_expires bigint, p_not_after bigint, p_jkt text, p_app_key text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET lock_timeout TO '1s'
AS $function$
DECLARE
    n bigint;
    held record;
    now_ms bigint;
    since timestamptz;
    target uuid := public.log_object('credential', p_id::text);
BEGIN
    IF p_created_by IS DISTINCT FROM 'binding:' || p_binding::text OR p_kind NOT IN ('service', 'workload') THEN
        RAISE EXCEPTION 'a sign-in makes a credential of its binding''s, a service''s or a workload''s' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A lock not had within `lock_timeout` raises `lock_not_available`, which the vault answers as busy: no subtransaction to catch it here.
    -- The account's row, locked, then held to its newest change's seal in a statement of its own, which reads what committed
    -- while it waited: a recheck under the lock sees the row's new version beside the snapshot's older changes, and would
    -- refuse an account a grant just changed. A row put back is none; 0.14's has neither seal nor change (before the cutover).
    SELECT m.seal INTO held FROM public.principals m
     WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation
       FOR SHARE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    IF held.seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('principal', p_principal) ORDER BY c.number DESC LIMIT 1) THEN
        RETURN json_build_object('state', 'unbound');
    END IF;
    -- The binding as the vault checked its seal (BindingSealed): its every column its object takes, and that seal; then, in
    -- a statement of its own once locked, that seal its object's newest change's. A row put back after its end, or edited
    -- around the vault, is none.
    PERFORM 1 FROM public.service_bindings b
     WHERE b.id = p_binding AND b.principal = p_principal AND b.generation = p_generation AND b.revoked_at IS NULL AND b.profile = p_binding_profile
       AND b.scope IS NOT DISTINCT FROM p_binding_scope AND b.policy IS NOT DISTINCT FROM p_binding_policy
       AND b.issuer = p_binding_issuer AND b.jwks_uri = p_binding_jwks_uri AND b.claims = p_binding_claims AND b.seal = p_binding_seal
       FOR UPDATE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    IF p_binding_seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('binding', p_binding::text) ORDER BY c.number DESC LIMIT 1) THEN
        RETURN json_build_object('state', 'unbound');
    END IF;
    -- The app's key, not one it rotated from (audit_log_subject_idx).
    IF EXISTS (SELECT 1 FROM public.audit_log a WHERE a.author = 'app' AND a.subject_principal = p_app_key AND a.action IN ('key.reseal', 'key.rotate')) THEN
        RETURN json_build_object('state', 'retired');
    END IF;
    -- A freeze of the whole instance, the account or the binding: its newest freeze or lift (audit_log_freeze_idx).
    IF p_frozen AND EXISTS (
        SELECT 1 FROM unnest(ARRAY['instance', p_principal, 'binding:' || p_binding::text]) t(target)
         WHERE (SELECT a.action FROM public.audit_log a
                 WHERE a.author = 'app' AND a.action IN ('workload.freeze', 'workload.unfreeze') AND a.decision = 'allow'
                   AND (a.metadata::jsonb ->> 'target') = t.target
                 ORDER BY a.seq DESC LIMIT 1) = 'workload.freeze'
    ) THEN
        RETURN json_build_object('state', 'frozen');
    END IF;
    -- Its rate, under the binding's row (credentials_issued_by_idx: the last window's, never the history). Its start a
    -- value, not `clock_timestamp()`, which is volatile: compared with that, the index bounds nothing, and the window's
    -- count would read the binding's every credential.
    since := clock_timestamp() - p_window * interval '1 millisecond';
    IF (SELECT count(*) FROM (
            SELECT 1 FROM public.credentials c
             WHERE c.principal = p_principal AND c.created_by = p_created_by AND c.created_at > since
             LIMIT p_rate
        ) z) >= p_rate THEN
        RETURN json_build_object('state', 'busy');
    END IF;
    now_ms := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF p_valid_until <= now_ms OR p_expires <= now_ms OR p_expires > now_ms + p_longest + 60000 OR (p_not_after IS NOT NULL AND (p_not_after <= now_ms OR p_expires > p_not_after)) THEN
        RETURN json_build_object('state', 'expired');
    END IF;
    -- The token spent (SpentChecked): the primary key decides between two runs presenting it at once.
    IF p_spent IS NOT NULL THEN
        INSERT INTO public.spent_id_tokens (hash) VALUES (p_spent) ON CONFLICT DO NOTHING;
        IF NOT FOUND THEN RETURN json_build_object('state', 'replayed'); END IF;
    END IF;
    INSERT INTO public.credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, identity_id, scope, places, label, created_by,
                                    expires_at, revoked_at, jkt, not_after, seal)
        VALUES (p_id, p_kind, p_auth_mac, p_token_hash, p_token_hint, p_generation, p_principal, NULL, p_scope, p_places, p_label, p_created_by,
                timestamptz 'epoch' + p_expires * interval '1 millisecond', NULL, p_jkt,
                CASE WHEN p_not_after IS NULL THEN NULL ELSE timestamptz 'epoch' + p_not_after * interval '1 millisecond' END, p_seal);
    UPDATE public.service_bindings SET last_used_at = clock_timestamp() WHERE id = p_binding;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN json_build_object('number', n::text);
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.use_credential(p_credential uuid, p_secret uuid, p_request bigint, p_at bigint, p_purpose smallint, p_place uuid, p_mac bytea, p_deadline bigint, p_cover bigint DEFAULT NULL::bigint, p_cover_at bigint DEFAULT NULL::bigint, p_cover_request bigint DEFAULT NULL::bigint, p_known bigint DEFAULT NULL::bigint, p_known_mac bytea DEFAULT NULL::bytea, p_cap_count integer DEFAULT NULL::integer, p_cap_window bigint DEFAULT NULL::bigint, p_token_hash bytea DEFAULT NULL::bytea, p_project text DEFAULT NULL::text, p_environment text DEFAULT NULL::text, p_key text DEFAULT NULL::text, p_decided boolean DEFAULT false, p_handle boolean DEFAULT false, p_unless text[] DEFAULT NULL::text[], p_signin boolean DEFAULT NULL::boolean, p_issuers text[] DEFAULT NULL::text[], p_roles jsonb DEFAULT NULL::jsonb, p_way smallint DEFAULT 0, p_principal text DEFAULT NULL::text, p_forks boolean DEFAULT false, p_route text DEFAULT NULL::text, p_gate boolean DEFAULT false)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
AS $function$
DECLARE
    r public.use_row;
    -- The principal's lock held: exclusive (`locked`), to enter its key in the cap's set; shared (`moving`), to move it on.
    locked boolean := false;
    moving boolean := false;
    probe boolean := p_known IS NULL OR p_cap_count IS NULL OR p_cap_window IS NULL;
    -- A use through a place, or of a key with no value of its own (a reference), reads every input; the others, most
    -- uses, the plain shape: no place, no source, none of their joins.
    whole boolean := p_place IS NOT NULL;
    -- The cached forms' refresh and period, from the cap the isolate passes; the probing forms work theirs out from the cap they read.
    c_refresh bigint := greatest(1, least(60000, p_cap_window / 10));
    c_period bigint := p_at - ((p_at % c_refresh) + c_refresh) % c_refresh;
    -- Whether this session has yet to plan the four statements (T131), and the form the warm-up is at.
    dry boolean := current_setting('coffre.use_planned', true) IS DISTINCT FROM '0073';
    form integer := 0;
    first_probe boolean;
    first_whole boolean;
    -- The period this call writes, if it writes the cap's row, and the lock that elects the one use that moves it.
    b_refresh bigint;
    b_period bigint;
    b_lock bigint;
    b_round integer := 0;
    -- What the call reads by: the ids passed, or, for a named call, those its names name now (D153), read once under
    -- the fence; whether they are the ids passed (`v_right`), and what the names name if not a live place (`v_named`).
    v_credential uuid := p_credential;
    v_secret uuid := p_secret;
    v_place uuid := p_place;
    v_right boolean := true;
    v_named text;
    v_accepted boolean;
    v_np uuid;
    v_np_project uuid;
    v_places text;
    v_bound uuid;
    v_live boolean;
    v_project text;
    v_environment text;
    resolved boolean := p_token_hash IS NULL;
    -- Whether a named call's caller stands at the place its names name, for its purpose (`use_stands`, W268): only then
    -- does it read the key.
    v_stands boolean;
    -- The caller's principal, which `dev@me` names the personal config of (T165).
    v_principal text;
    -- `dev@me` named, and her personal config of dev found: the place is it, and the gate weighs dev (T165).
    v_personal boolean := false;
    -- The place and the environments it inherits from, nearest first (T165): a fork's, or a personal config's.
    v_layers uuid[];
    -- The place's chain cut (a parent archived or deleted, or a chain that loops or runs past 3): it reads nothing (T165).
    v_cut boolean := false;
    -- The environment that holds the key named: the place, or one it inherits it from.
    v_holder uuid;
    -- The place's parent: none but a fork's, or a personal config's (dev).
    v_np_parent uuid;
    -- A named call's, or a route use's (T186, `p_route`; a workload's gate in `use_route` among them): its use of a key
    -- the place does not hold, or of a plain value, writes no entry and takes no lock, the vault deciding it on what was read.
    v_quiet boolean := p_token_hash IS NOT NULL OR p_route IS NOT NULL;
    -- A route's named call (T205; docs/design/proxy-ui.md, section 4): a handle's, which names the route (`p_route`) and
    -- no key. After the caller's standing, under the same fence, it reads the route's item through the place's chain, its
    -- editor's principal, and resolves the one key the item names by that name, as a code route's named call resolves the
    -- key the request names; the isolate's map's ids only let it make the use when they are that key's now. One call, the
    -- route's levels and editor answered beside the key's row (`route`), for the vault to check and decide.
    v_routed boolean := p_route IS NOT NULL AND p_token_hash IS NOT NULL;
    -- The key the call resolves by name: the request's, or the one its route's item names.
    v_key text := p_key;
    -- The route read (`v_read`): its item serving and naming one key (`v_whole`), what the call answers of it (`v_route`), and the
    -- newest change of its inputs `use_credential` does not otherwise read, which a cover must be past (`v_inputs`).
    v_read boolean := false;
    v_whole boolean := false;
    v_route json;
    v_inputs bigint := 0;
    v_made_for boolean;
    v_serving jsonb;
    v_item jsonb;
    v_digests bytea;
    v_seal bytea;
    v_row boolean;
    v_number bigint;
    v_newest bytea;
    v_change json;
    level_env json;
    v_env_number bigint;
    levels json[] := '{}';
    v_editor text;
    editor json;
    names text[] := '{}';
BEGIN
    -- The way in (T147): a credential, 0; an MCP connection, 1; a Cloudflare binding, 2; each by its id; or, behind
    -- Cloudflare Access, the account, 3, a person's or a service token's, whose object's key the entry names. Its kind is in the entry, the purpose's
    -- bits above 512, under its MAC; and only a credential's token is named.
    IF p_way IS NULL OR p_way NOT IN (0, 1, 2, 3) OR p_purpose / 512 <> p_way OR (p_way = 3) <> (p_principal IS NOT NULL)
       OR (p_way <> 0 AND p_token_hash IS NOT NULL)
       OR (p_way = 3 AND (NOT (p_principal LIKE 'user:%' OR p_principal LIKE 'token:%') OR p_credential IS DISTINCT FROM public.log_object('principal', p_principal))) THEN
        RAISE EXCEPTION 'a use names its way in: a credential, a connection or a binding by id, or an account behind Access by its key' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A route use's is by ids, the route's name a credential's (`CREDENTIAL_NAME`): `use_route` makes it.
    -- A route use's light gate (`p_gate`, T200) is a handle's named call of no key: `use_route` makes it.
    IF p_gate IS NULL OR (p_gate AND (p_token_hash IS NULL OR p_key IS NOT NULL OR p_credential IS NOT NULL OR p_secret IS NOT NULL)) THEN
        RAISE EXCEPTION 'a light gate is a handle''s named call of no key' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A route's named call (T205) is a handle's, of no key it names itself, at a place whose forks it serves.
    IF p_route IS NOT NULL AND ((p_token_hash IS NOT NULL AND (p_key IS NOT NULL OR p_gate OR NOT p_forks)) OR p_route !~ '^[a-z][a-z0-9-]{0,31}$') THEN
        RAISE EXCEPTION 'a route use is by ids, or a handle''s named call of its route, and names its route as a credential is named' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_deadline IS NULL OR p_deadline > p_at + public.deadline_max() THEN r.state := 'late'; RETURN CASE WHEN v_routed THEN json_build_object('row', to_json(r), 'route', v_route) ELSE to_json(r) END; END IF;
    -- Its Worker's clock ahead by over a minute (0022 says why): checked here at no cost, and again in the statement.
    IF p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN r.state := 'ahead'; RETURN CASE WHEN v_routed THEN json_build_object('row', to_json(r), 'route', v_route) ELSE to_json(r) END; END IF;
    IF dry THEN
        -- Each form first runs dry, outside the fence, so that its planning's cold work (the catalog, the statistics, the
        -- indexes: tens of ms on a new connection) is done before this call holds the fence (T131). Under it, a call plans
        -- warm, about 2 ms, until the plan cache settles on a plan, by the session's sixth call of a form.
        first_probe := probe;
        first_whole := whole;
        probe := true;
        whole := false;
        -- Planned for no key, the nil id, which none has (T207 r2). Until the plan cache settles, each statement is
        -- planned for the call's own values, and planning for them reads pages by them: dry runs planned for the key the
        -- isolate passed, before anything decided the caller may know of it, read 16 more blocks of the key's tables
        -- for a key held than for one never made (use.matrix.ts, a named call of one standing nowhere). The call
        -- binds a key where it reads it: a use by id, or a named one for a caller who stands.
        v_secret := '00000000-0000-0000-0000-000000000000';
    ELSE
        PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    END IF;
    LOOP
        IF NOT dry AND NOT resolved THEN
            -- What the request names, by its names, under the fence, which no change moves (as `use_resolve` reads it):
            -- the credential of its token's hash; the place of its slugs, or a handle's one place; its key there by name.
            -- Each by an index, whatever plan the cache settles on: a handle's place by its id, a
            -- named one by its slugs, never one plan for both, which no index serves (review r1 of D153). The dry run
            -- skips this block: these statements, the gate's among them, are planned on a session's first named call,
            -- under the fence, which hangs on nothing a request names.
            -- The credential first, held to what the app's config accepts (`p_signin`, `p_issuers`; review r6 and r7 of
            -- D153; Probing.tla, AcceptedFirst): the deployment signs in through coffre's own sign-in, and a browser
            -- session's identity names a provider it configures, as the app's own check has it (`#liveCredential`). One it
            -- would refuse is answered as a token no credential has, `unknown`, here: no place, no key, no lock read or
            -- taken, whatever the request names.
            SELECT c.id, c.places, c.principal,
                   coalesce(p_signin, false) AND (c.kind <> 'browser' OR (x.provider || ':' || x.issuer_hash) = ANY (coalesce(p_issuers, '{}')))
              INTO v_credential, v_places, v_principal, v_accepted
              FROM public.credentials c LEFT JOIN public.identities x ON x.id = c.identity_id
             WHERE c.token_hash = p_token_hash;
            IF v_credential IS NULL OR NOT coalesce(v_accepted, false) THEN r.state := 'unknown'; RETURN CASE WHEN v_routed THEN json_build_object('row', to_json(r), 'route', v_route) ELSE to_json(r) END; END IF;
            IF p_handle THEN
                -- Unchecked yet, so parsed without raising, each step in turn (a CASE's order, which AND does not promise).
                v_bound := CASE WHEN NOT coalesce(pg_input_is_valid(v_places, 'json'), false) THEN NULL
                                WHEN json_typeof(v_places::json) IS DISTINCT FROM 'array' OR json_array_length(v_places::json) <> 1 THEN NULL
                                WHEN json_typeof(v_places::json -> 0) IS DISTINCT FROM 'object' THEN NULL
                                WHEN coalesce(v_places::json -> 0 ->> 'personal', 'false') <> 'false' THEN NULL
                                WHEN NOT coalesce(pg_input_is_valid(v_places::json -> 0 ->> 'environmentId', 'uuid'), false) THEN NULL
                                ELSE (v_places::json -> 0 ->> 'environmentId')::uuid END;
                -- A fork's place too, with forks served (`p_forks`, T165); never a personal config's (above).
                SELECT e.id, e.project_id, q.slug, e.slug, e.archived_at IS NULL AND q.archived_at IS NULL AND e.owner IS NULL AND (e.parent_id IS NULL OR p_forks), e.parent_id
                  INTO v_np, v_np_project, v_project, v_environment, v_live, v_np_parent
                  FROM public.environments e JOIN public.projects q ON q.id = e.project_id
                 WHERE e.id = v_bound AND e.slug NOT LIKE '%~%' AND q.slug NOT LIKE '%~%';
            ELSIF p_forks AND right(p_environment, 3) = '@me' THEN
                -- `dev@me` (T165; `resolveRead`): dev, an environment of its own or a fork, never a personal config; then the
                -- caller's personal config of it, by its parent and owner (the unique index's own predicate), which is the
                -- place; or, while they have none, dev itself, read as dev (`fallback`). Archived, either is none.
                SELECT e.id, e.project_id, q.slug, e.slug, e.archived_at IS NULL AND q.archived_at IS NULL AND e.owner IS NULL, e.parent_id
                  INTO v_np, v_np_project, v_project, v_environment, v_live, v_np_parent
                  FROM public.projects q JOIN public.environments e ON e.project_id = q.id AND e.slug = left(p_environment, -3)
                 WHERE q.slug = p_project AND q.slug NOT LIKE '%~%' AND e.slug NOT LIKE '%~%';
                IF v_np IS NOT NULL AND v_live THEN
                    SELECT e.id, e.archived_at IS NULL INTO v_bound, v_live
                      FROM public.environments e WHERE e.parent_id = v_np AND e.owner = v_principal AND strpos(e.slug, '~') = 0;
                    IF v_bound IS NOT NULL THEN
                        v_np_parent := v_np;
                        v_np := v_bound;
                        v_personal := true;
                    ELSE
                        v_live := true;
                    END IF;
                END IF;
                -- The names the request gave, `dev@me`, whichever place they name now.
                v_environment := p_environment;
            ELSE
                SELECT e.id, e.project_id, q.slug, e.slug, e.archived_at IS NULL AND q.archived_at IS NULL AND e.owner IS NULL AND (e.parent_id IS NULL OR p_forks), e.parent_id
                  INTO v_np, v_np_project, v_project, v_environment, v_live, v_np_parent
                  FROM public.projects q JOIN public.environments e ON e.project_id = q.id AND e.slug = p_environment
                 WHERE q.slug = p_project AND q.slug NOT LIKE '%~%' AND e.slug NOT LIKE '%~%';
            END IF;
            -- A handle's place the stable URL does not mean, by the slugs read here: the app's, as a place that is none.
            v_named := CASE WHEN v_np IS NULL OR NOT v_live OR (p_handle AND (v_project || '/' || v_environment) = ANY (coalesce(p_unless, '{}'))) THEN 'nowhere' END;
            -- A route's named call is made at the reading of the URL the isolate's map picked (section 6), `p_unless` naming
            -- the URL's other reading: the place reading, where the URL has a stable one too (its route), only for a handle
            -- made for that place, by the place the slugs name now, as `use_route` picks it; the stable one only where the
            -- handle's one place serves and is no place the URL names. Else nothing of the place or the route is read
            -- (`reread`), and the vault asks `use_route`, which picks the reading itself, under the fence.
            IF v_routed THEN
                -- Unchecked yet, so parsed without raising, each step in turn (a CASE's order, which AND does not promise).
                v_made_for := CASE WHEN p_handle OR v_np IS NULL OR v_personal OR right(p_environment, 3) = '@me' THEN false
                                   WHEN NOT coalesce(pg_input_is_valid(v_places, 'jsonb'), false) THEN false
                                   WHEN jsonb_typeof(v_places::jsonb) IS DISTINCT FROM 'array' THEN false
                                   ELSE EXISTS (SELECT 1 FROM jsonb_array_elements(v_places::jsonb) x
                                                 WHERE jsonb_typeof(x) = 'object' AND x ->> 'environmentId' = v_np::text
                                                   AND coalesce(x ->> 'personal', 'false') <> 'true') END;
                IF (p_handle AND v_named IS NOT NULL) OR (NOT p_handle AND cardinality(coalesce(p_unless, '{}')) > 0 AND NOT v_made_for) THEN
                    v_named := 'reread';
                END IF;
            END IF;
            -- The caller's standing at the place, for the request's purpose, from rows no key decides (W268; Probing.tla,
            -- StandingFirst): its key's name is read only for one who stands there. Without the roles coffre ships, which
            -- every named call of the vault's passes, it stands: never refused here where the vault's rule allows.
            -- At a personal config, its owner's standing there, as the vault's rule weighs it with dev (`personalRefusal`, R8;
            -- Probing.tla, GateWeighsParent): theirs while they read or use dev, whatever they ask.
            v_stands := CASE WHEN v_named IS NOT NULL THEN false WHEN p_roles IS NULL THEN true
                             WHEN v_personal THEN public.use_stands_personal(v_credential, v_np, p_at, p_roles)
                             ELSE public.use_stands(v_credential, v_np, p_purpose, p_at, p_roles) END;
            -- What the place inherits from, for one who stands there (T165; `parentsOf`, `readableValues`): the place, then
            -- each parent, nearest first, by the parent's index, from rows no key decides. A parent archived, deleted (its
            -- slug a tombstone) or not there, or a chain that loops or runs past 3 (`MAX_PARENTS`) cuts it: the place reads
            -- nothing, as the app's read refuses it whole, decided on the place alone (Probing.tla, CutByPlace).
            v_layers := ARRAY[v_np];
            IF v_stands AND p_forks AND v_np_parent IS NOT NULL THEN
                WITH RECURSIVE chain (id, parent, cut, depth, seen) AS (
                    SELECT e.id, e.parent_id, false, 0, ARRAY[e.id] FROM public.environments e WHERE e.id = v_np
                    UNION ALL
                    SELECT chain.parent, p.parent_id, p.id IS NULL OR p.archived_at IS NOT NULL OR p.slug LIKE '%~%' OR chain.parent = ANY (chain.seen) OR chain.depth >= 3,
                           chain.depth + 1, chain.seen || chain.parent
                      FROM chain LEFT JOIN public.environments p ON p.id = chain.parent
                     WHERE chain.parent IS NOT NULL AND NOT chain.cut
                )
                SELECT array_agg(chain.id ORDER BY chain.depth), coalesce(bool_or(chain.cut), false) INTO v_layers, v_cut FROM chain;
                v_layers := coalesce(v_layers, ARRAY[v_np]);
            END IF;
            -- The route (T205), for one who stands at the place, its chain whole (Routing.tla, StandingFirst): each level,
            -- nearest first, its definitions through the first whose row holds the route's item, and every level's
            -- environment, its row and seal and its object's newest change, which the vault checks the chain by, link by
            -- link (`use_route`'s reads, reviews r1 and r2 of #464); the item's editor's principal; and the one key the item
            -- names, resolved by that name below as a code route's named call resolves its own (KeyByItem). An item of
            -- another number of keys, or none, resolves no key: the call reads on as one of no key at the place, its rows
            -- the vault's to decide the caller on, and the vault asks `use_route`.
            IF v_routed AND v_named IS NULL AND v_stands AND NOT v_cut AND NOT v_personal THEN
                FOR l IN 1 .. cardinality(v_layers) LOOP
                    v_item := NULL; v_digests := NULL; v_seal := NULL; v_row := NULL; v_number := NULL; v_newest := NULL; v_change := NULL;
                    IF v_serving IS NULL THEN
                        SELECT p.items -> p_route, p.digests, p.seal, p.environment_id IS NOT NULL,
                               lp.number, lp.seal, CASE WHEN lp.number IS NOT NULL THEN json_build_array(lp.at, lp.request_id, lp.actor, lp.payload, lp.mac) END,
                               CASE WHEN e.id IS NOT NULL THEN json_build_object('project', e.project_id, 'slug', e.slug, 'owner', e.owner, 'parent', e.parent_id, 'protected', e.protected,
                                                 'archived', e.archived_at IS NOT NULL, 'project_archived', q.archived_at IS NOT NULL, 'seal', e.seal, 'last', le.seal,
                                                 'change', CASE WHEN le.number IS NOT NULL THEN json_build_array(le.at, le.request_id, le.actor, le.payload, le.mac) END) END,
                               le.number
                          INTO v_item, v_digests, v_seal, v_row, v_number, v_newest, v_change, level_env, v_env_number
                          FROM (SELECT v_layers[l] AS id) lv
                          LEFT JOIN public.proxy_definitions p ON p.environment_id = lv.id
                          LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = public.log_object('proxy', lv.id::text) ORDER BY x.number DESC LIMIT 1) lp ON true
                          LEFT JOIN public.environments e ON e.id = lv.id
                          LEFT JOIN public.projects q ON q.id = e.project_id
                          LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = public.log_object('environment', e.id::text) ORDER BY x.number DESC LIMIT 1) le ON e.id IS NOT NULL;
                        v_inputs := greatest(v_inputs, coalesce(v_number, 0));
                    ELSE
                        SELECT json_build_object('project', e.project_id, 'slug', e.slug, 'owner', e.owner, 'parent', e.parent_id, 'protected', e.protected,
                                                 'archived', e.archived_at IS NOT NULL, 'project_archived', q.archived_at IS NOT NULL, 'seal', e.seal, 'last', le.seal,
                                                 'change', CASE WHEN le.number IS NOT NULL THEN json_build_array(le.at, le.request_id, le.actor, le.payload, le.mac) END),
                               le.number
                          INTO level_env, v_env_number
                          FROM public.environments e LEFT JOIN public.projects q ON q.id = e.project_id
                          LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = public.log_object('environment', e.id::text) ORDER BY x.number DESC LIMIT 1) le ON true
                         WHERE e.id = v_layers[l];
                    END IF;
                    v_inputs := greatest(v_inputs, coalesce(v_env_number, 0));
                    levels := levels || json_build_object('environment', v_layers[l], 'row', coalesce(v_row, false), 'item', v_item, 'digests', v_digests, 'seal', v_seal,
                                                          'newest', v_newest, 'number', v_number::text, 'change', v_change, 'env', level_env);
                    IF v_item IS NOT NULL THEN
                        v_serving := v_item;
                    END IF;
                END LOOP;
                IF v_serving IS NOT NULL THEN
                    -- Its editor's principal, as a use reads its caller's: their row and grants, and their object's newest change.
                    v_editor := CASE WHEN jsonb_typeof(v_serving) = 'object' AND jsonb_typeof(v_serving -> 'savedBy') = 'string' THEN v_serving ->> 'savedBy' END;
                    IF v_editor IS NOT NULL THEN
                        SELECT json_build_object(
                                   'principal', v_editor, 'status', m.status, 'owner', m.owner, 'role', m.role, 'scope', m.scope, 'generation', m.generation, 'seal', m.seal,
                                   'g_project', gr.g_project, 'g_environment', gr.g_environment, 'g_slug', gr.g_slug, 'g_role', gr.g_role, 'g_expires', gr.g_expires,
                                   'last', lm.seal, 'number', lm.number::text, 'old', lm.payload::jsonb ->> 'old',
                                   'change', CASE WHEN lm.number IS NOT NULL THEN json_build_array(lm.at, lm.request_id, lm.actor, lm.payload, lm.mac) END,
                                   'access', (SELECT a.seq::text FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v_editor AND a.decision = 'allow'
                                                AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke')
                                              ORDER BY a.seq DESC LIMIT 1)),
                               lm.number
                          INTO editor, v_number
                          FROM (SELECT 1) one
                          LEFT JOIN public.principals m ON m.principal = v_editor
                          LEFT JOIN LATERAL (
                              SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                                     array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at::text) AS g_expires
                                FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                               WHERE g.principal = v_editor
                          ) gr ON m.status IS NOT NULL
                          LEFT JOIN LATERAL (
                              SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = public.log_object('principal', v_editor) ORDER BY x.number DESC LIMIT 1
                          ) lm ON true;
                        v_inputs := greatest(v_inputs, coalesce(v_number, 0));
                    END IF;
                    names := CASE WHEN jsonb_typeof(v_serving) = 'object' AND jsonb_typeof(v_serving -> 'keys') = 'array'
                                  THEN ARRAY(SELECT k FROM jsonb_array_elements_text(v_serving -> 'keys') WITH ORDINALITY t (k, i) ORDER BY i) ELSE '{}'::text[] END;
                    v_key := CASE WHEN cardinality(names) = 1 THEN names[1] END;
                    v_whole := v_key IS NOT NULL;
                END IF;
                -- A cover rides only past every change of the route's own inputs, which the statement below does not read.
                IF p_cover IS NOT NULL AND p_cover <= v_inputs THEN
                    p_cover := NULL;
                END IF;
                v_read := true;
            END IF;
            IF v_key IS NOT NULL AND v_stands AND NOT v_cut THEN
                IF cardinality(v_layers) = 1 THEN
                    SELECT x.id, x.environment_id INTO v_secret, v_holder FROM public.secrets x
                     WHERE x.project_id = v_np_project AND x.environment_id = v_np AND x.key = v_key AND x.archived_at IS NULL LIMIT 1;
                ELSE
                    -- The nearest layer that settles the key (`resolveValues`): holds it live, or removed it (a dismissal not
                    -- restored), but the last, whose dismissals remove nothing. Held there, it is that key; removed, none.
                    SELECT x.id, l.id INTO v_secret, v_holder
                      FROM unnest(v_layers) WITH ORDINALITY l (id, depth)
                      LEFT JOIN public.secrets x ON x.project_id = v_np_project AND x.environment_id = l.id AND x.key = v_key AND x.archived_at IS NULL
                     WHERE x.id IS NOT NULL
                        OR (l.depth < cardinality(v_layers)
                            AND EXISTS (SELECT 1 FROM public.dismissed_keys d WHERE d.environment_id = l.id AND d.key = v_key AND d.restored_at IS NULL))
                     ORDER BY l.depth LIMIT 1;
                END IF;
            ELSE
                v_secret := NULL;
            END IF;
            -- A key named is read by its id; one the place does not hold, through the place (the whole form, e1); one it
            -- inherits, by its id through the place, as a fork's read is.
            v_place := CASE WHEN v_secret IS NULL OR v_holder IS DISTINCT FROM v_np THEN v_np END;
            -- A route's: and the route read whole, one key named and resolved by that name (KeyByItem).
            v_right := coalesce(v_credential = p_credential, false) AND v_secret IS NOT DISTINCT FROM p_secret AND v_place IS NOT DISTINCT FROM p_place
                AND (NOT v_routed OR v_whole);
            IF v_read THEN
                v_route := json_build_object('place', v_np, 'project', v_np_project, 'levels', array_to_json(levels), 'editor', editor, 'keys', to_json(names),
                                             'made', v_right, 'keyed', v_key IS NOT NULL);
            END IF;
            IF NOT v_stands OR v_cut THEN
                -- No standing, or no live place, or a chain cut: answered on the place alone, as for a key it does not hold, probing,
                -- whatever the isolate passed: no cover, no seals (NoKeyBeforeStanding). Nothing is written or locked,
                -- as for any key the place does not hold.
                p_cover := NULL;
                probe := true;
            END IF;
            whole := v_place IS NOT NULL;
            resolved := true;
            -- A route use's light gate (T200): a caller who stands at a live place, its chain whole, is answered here, by
            -- its names and the app's rows of the place, nothing more read. The statement goes on to make the route's keys'
            -- uses, whose rows, read under the same fence, are the ones the vault decides the caller on; it asks the
            -- whole gate (this call without `p_gate`) where it makes none. One who stands nowhere, or at a place cut, reads
            -- on as any named call of no key: the vault decides them on that row.
            IF p_gate AND v_stands AND NOT v_cut THEN
                r.state := 'stood';
                r.n_credential := v_credential;
                r.n_place := v_np;
                r.n_project := v_project;
                r.n_environment := v_environment;
                r.n_standing := true;
                r.n_cut := false;
                -- The app's rows of the request, as the whole form answers them for a named call of no key at the place.
                r.app := json_build_object(
                    'now', CURRENT_TIMESTAMP, 'credential', (SELECT to_json(c) FROM public.credentials c WHERE c.id = v_credential),
                    'identity', (SELECT to_json(x) FROM public.credentials c JOIN public.identities x ON x.id = c.identity_id WHERE c.id = v_credential),
                    'policy', (SELECT a.seq::text FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1),
                    'project', (SELECT to_json(q) FROM public.projects q WHERE q.id = v_np_project),
                    'environment', (SELECT to_json(e) FROM public.environments e WHERE e.id = v_np),
                    'parent', CASE WHEN v_np_parent IS NOT NULL THEN (SELECT pe.slug FROM public.environments pe WHERE pe.id = v_np_parent) END,
                    'held', NULL::json, 'secrets', '[]'::json);
                RETURN CASE WHEN v_routed THEN json_build_object('row', to_json(r), 'route', v_route) ELSE to_json(r) END;
            END IF;
        END IF;
        IF probe AND NOT whole THEN
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, f.retired, (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS cap_count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS cap_window,
                    lpol.number AS lpol_number, lpol.seal AS p_last, CASE WHEN lpol.number IS NOT NULL THEN json_build_array(lpol.at, lpol.request_id, lpol.actor, lpol.payload, lpol.mac) END AS p_change,
                    w.principal AS p, c.kind AS c_kind, w.scope AS c_scope, w.revoked_at IS NOT NULL AS c_revoked,
                    floor(extract(epoch FROM w.expires_at) * 1000)::bigint AS c_expires, w.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal, w.generation AS c_generation, m.generation AS m_generation,
                    w.row AS w_row,
                    -- What the request named, for the names it checks, and the rows the app checks, when it names them (0044).
                    c.token_hash AS c_token_hash,
                    CASE WHEN p_token_hash IS NOT NULL THEN to_json(c) END AS c_row, CASE WHEN p_token_hash IS NOT NULL THEN to_json(s) END AS s_row,
                    CASE WHEN p_token_hash IS NOT NULL AND s.current_version_id IS NOT NULL THEN to_json(sv) END AS sv_row,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, NULL::uuid AS s_source, NULL::uuid AS s_reference, s.seal AS s_seal,
                    NULL::uuid AS x_project, NULL::uuid AS x_environment, NULL::uuid AS x_version, NULL::uuid AS x_source, NULL::uuid AS x_reference, NULL::bytea AS x_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain, sv.plaintext AS v_plaintext,
                    NULL::uuid AS e1_id, NULL::uuid AS e1_project, NULL::text AS e1_slug, NULL::text AS e1_owner, NULL::uuid AS e1_parent, NULL::boolean AS e1_protected, NULL::boolean AS e1_archived, NULL::boolean AS e1_project_archived, NULL::bytea AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e2.project_id) AS e2_project_archived, e2.seal AS e2_seal,
                    NULL::uuid AS e3_id, NULL::uuid AS e3_project, NULL::text AS e3_slug, NULL::text AS e3_owner, NULL::uuid AS e3_parent, NULL::boolean AS e3_protected, NULL::boolean AS e3_archived, NULL::boolean AS e3_project_archived, NULL::bytea AS e3_seal,
                    CASE WHEN e2.owner IS NOT NULL THEN e2.parent_id END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e4.project_id) AS e4_project_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last,
                    -- Each input's object key, computed once: a key in a probe's own condition is computed again for every row it reads (0022, decision 3).
                    public.log_object(w.kind, v_credential::text) AS k_credential,
                    public.log_object('principal', w.principal) AS k_member,
                    public.log_object('secret', v_secret::text) AS k_secret,
                    public.log_object('environment', s.environment_id::text) AS k_e2,
                    public.log_object('environment', (CASE WHEN e2.owner IS NOT NULL THEN e2.parent_id END)::text) AS k_e4
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN LATERAL (SELECT y.at_floor, y.retired FROM public.checkpoint_fence y WHERE y.only_row LIMIT 1) f ON true
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  -- The cap as the policy's newest change says it (CapSealed): every policy change logs the whole policy as its `value`.
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
                  ) lpol ON true
                  -- The way in (T147), one of these by its id; or, behind Access, none: the account alone, whose row is all the
                  -- use weighs of it. The way rides the join key: the others' is null, which no index scan descends for. A
                  -- `p_way = 1` beside the key is no one-time filter of an outer join's inner side, and its probe ran (review r2).
                  LEFT JOIN public.credentials c ON c.id = CASE WHEN p_way = 0 THEN v_credential END
                  LEFT JOIN public.mcp_connections k ON k.id = CASE WHEN p_way = 1 THEN v_credential END
                  LEFT JOIN public.service_bindings wb ON wb.id = CASE WHEN p_way = 2 THEN v_credential END
                  CROSS JOIN LATERAL (
                      SELECT CASE p_way WHEN 0 THEN 'credential' WHEN 1 THEN 'connection' WHEN 2 THEN 'binding' END AS kind,
                             CASE p_way WHEN 0 THEN c.principal WHEN 1 THEN k.principal WHEN 2 THEN wb.principal WHEN 3 THEN p_principal END AS principal,
                             CASE p_way WHEN 0 THEN c.scope WHEN 2 THEN wb.scope END AS scope,
                             CASE p_way WHEN 0 THEN c.revoked_at WHEN 1 THEN k.revoked_at WHEN 2 THEN wb.revoked_at END AS revoked_at,
                             CASE p_way WHEN 0 THEN least(c.expires_at, c.not_after) WHEN 1 THEN k.expires_at END AS expires_at,
                             CASE p_way WHEN 0 THEN c.seal WHEN 1 THEN k.seal WHEN 2 THEN wb.seal END AS seal,
                             CASE p_way WHEN 0 THEN c.generation WHEN 1 THEN k.generation WHEN 2 THEN wb.generation END AS generation,
                             -- A binding's object is its whole row (objects.ts, bindingObject), its seal checked over it.
                             CASE WHEN p_way = 2 AND wb.id IS NOT NULL THEN to_json(wb) END AS row
                  ) w
                  LEFT JOIN public.principals m ON m.principal = w.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = v_secret AND s.archived_at IS NULL
                  -- The key's own version, its own environment, and that environment's parent when it is a personal config.
                  LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e4 ON e4.id = e2.parent_id AND e2.owner IS NOT NULL
                  LEFT JOIN public.bulk_cap b ON b.principal = w.principal AND b.secret = v_secret
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, cap.refresh, cap.period,
                    CASE WHEN i.s_project IS NOT NULL AND i.s_version IS NULL THEN 'whole'
                         -- What no key decides comes first (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416): the
                         -- floor, the deadline, the clock, the cap's config; then what the names decide, which the vault
                         -- answers on the caller's standing first.
                         WHEN substring(p_mac FROM 1 FOR 4) = ANY(i.retired) THEN 'superseded'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         -- What the names name, read by them: no credential of that token, no live place of those names.
                         WHEN v_named IS NOT NULL THEN v_named
                         -- The ids the vault passed are not the ones the names name now (D153): the names' rows are read,
                         -- and nothing is written or locked.
                         WHEN NOT v_right THEN 'moved'
                         WHEN p_token_hash IS NOT NULL AND NOT v_routed AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                           OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut) THEN 'archived'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT (v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND NOT (v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND i.bulk_last < cap.period THEN 'share' END AS state,
                    greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, l2.number, l4.number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, (lm.payload::jsonb ->> 'old')::bigint AS m_old, lr.seal AS r_last, ls.seal AS s_last, NULL::bytea AS x_last,
                    NULL::bytea AS e1_last, l2.seal AS e2_last, NULL::bytea AS e3_last, l4.seal AS e4_last,
                    -- What each newest change's MAC covers but its object and seal, and the MAC: the vault checks it before it holds a row to that seal (T190).
                    json_build_object('c', CASE WHEN lc.number IS NOT NULL THEN json_build_array(lc.at, lc.request_id, lc.actor, lc.payload, lc.mac) END, 'm', CASE WHEN lm.number IS NOT NULL THEN json_build_array(lm.at, lm.request_id, lm.actor, lm.payload, lm.mac) END, 'r', CASE WHEN lr.number IS NOT NULL THEN json_build_array(lr.at, lr.request_id, lr.actor, lr.payload, lr.mac) END, 'p', i.p_change, 's', CASE WHEN ls.number IS NOT NULL THEN json_build_array(ls.at, ls.request_id, ls.actor, ls.payload, ls.mac) END,
                        'e2', CASE WHEN l2.number IS NOT NULL THEN json_build_array(l2.at, l2.request_id, l2.actor, l2.payload, l2.mac) END, 'e4', CASE WHEN l4.number IS NOT NULL THEN json_build_array(l4.at, l4.request_id, l4.actor, l4.payload, l4.mac) END) AS changes,
                    coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.bulk_cap o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - i.cap_window - cap.refresh - public.deadline_max() - 60000
                             LIMIT i.cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= cap.period AND p_cover > coalesce(greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, l2.number, l4.number), 0)
                        AND public.use_covered(p_cover_at, p_cover_request, p_cover, p_credential, p_secret, p_purpose, p_place, p_route), false) AS is_covered
                  FROM i
                  CROSS JOIN LATERAL (SELECT greatest(1, least(60000, i.cap_window / 10)) AS refresh) r0
                  CROSS JOIN LATERAL (SELECT r0.refresh, p_at - ((p_at % r0.refresh) + r0.refresh) % r0.refresh AS period) cap
                  -- Each input's newest change: one probe each (log_changes_object_idx), and its row, for the columns its MAC
                  -- covers (T190); the principal's payload names the 0.14 entry it accounts for.
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_credential ORDER BY x.number DESC LIMIT 1) lc ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_member ORDER BY x.number DESC LIMIT 1) lm ON i.k_member IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = public.log_object('roles', 'instance') ORDER BY x.number DESC LIMIT 1) lr ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_secret ORDER BY x.number DESC LIMIT 1) ls ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_e2 ORDER BY x.number DESC LIMIT 1) l2 ON i.k_e2 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_e4 ORDER BY x.number DESC LIMIT 1) l4 ON i.k_e4 IS NOT NULL
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place, route)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place, p_route
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (v_quiet AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, v.inputs, true,
                v.p, v.c_kind, v.c_scope, v.c_revoked, v.c_expires, v.c_seal, v.c_last,
                v.m_status, v.m_owner, v.m_role, v.m_scope, v.m_seal, v.m_last, v.m_old,
                (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v.p AND a.decision = 'allow'
                    AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
                gr.g_project, gr.g_environment, gr.g_slug, gr.g_role, gr.g_expires,
                v.r_value, v.r_seal, v.r_last,
                v.p_value, v.p_seal, v.p_last, v.cap_count, v.cap_window,
                v.s_project, v.s_environment, v.s_version, v.s_source, v.s_seal, v.s_last,
                v.x_project, v.x_environment, v.x_version, v.x_source, v.x_seal, v.x_last,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                v.e1_id, v.e1_project, v.e1_slug, v.e1_owner, v.e1_parent, v.e1_protected, v.e1_archived, v.e1_seal, v.e1_last,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, v.e2_last,
                v.e3_id, v.e3_project, v.e3_slug, v.e3_owner, v.e3_parent, v.e3_protected, v.e3_archived, v.e3_seal, v.e3_last,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, v.e4_last,
                v.is_in, v.n_others, v.v_plaintext, v.e1_project_archived, v.e2_project_archived, v.e3_project_archived, v.e4_project_archived, v.s_reference, v.x_reference, v.c_generation, v.m_generation, v.c_token_hash,
                CASE WHEN p_token_hash IS NOT NULL THEN json_build_object(
                    'now', CURRENT_TIMESTAMP, 'credential', v.c_row, 'identity', (SELECT to_json(x) FROM public.identities x WHERE x.id = (v.c_row ->> 'identity_id')::uuid),
                    'policy', (SELECT a.seq::text FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1),
                    'project', (SELECT to_json(q) FROM public.projects q WHERE q.id = coalesce(v.e1_project, v.e2_project)),
                    'environment', (SELECT to_json(e) FROM public.environments e WHERE e.id = coalesce(v.e1_id, v.e2_id)),
                    'parent', CASE WHEN v_np_parent IS NOT NULL THEN (SELECT pe.slug FROM public.environments pe WHERE pe.id = v_np_parent) END,
                    'held', CASE WHEN v.e1_id IS NOT NULL AND v.e2_id IS NOT NULL THEN json_build_object('id', v.e2_id, 'slug', v.e2_slug) END,
                    'secrets', CASE WHEN v.s_row IS NULL THEN '[]'::json ELSE json_build_array(json_build_object('secret', v.s_row, 'version', v.sv_row)) END) END,
                -- A named call's (`n_*`), set below; a binding's row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::boolean, v.w_row, NULL::boolean, v.changes
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSIF probe THEN
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, f.retired, (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS cap_count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS cap_window,
                    lpol.number AS lpol_number, lpol.seal AS p_last, CASE WHEN lpol.number IS NOT NULL THEN json_build_array(lpol.at, lpol.request_id, lpol.actor, lpol.payload, lpol.mac) END AS p_change,
                    w.principal AS p, c.kind AS c_kind, w.scope AS c_scope, w.revoked_at IS NOT NULL AS c_revoked,
                    floor(extract(epoch FROM w.expires_at) * 1000)::bigint AS c_expires, w.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal, w.generation AS c_generation, m.generation AS m_generation,
                    w.row AS w_row,
                    -- What the request named, for the names it checks, and the rows the app checks, when it names them (0044).
                    c.token_hash AS c_token_hash,
                    CASE WHEN p_token_hash IS NOT NULL THEN to_json(c) END AS c_row, CASE WHEN p_token_hash IS NOT NULL THEN to_json(s) END AS s_row,
                    CASE WHEN p_token_hash IS NOT NULL AND s.current_version_id IS NOT NULL THEN to_json(sv) END AS sv_row,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, ref.source_secret_id AS s_source, ref.reference_id AS s_reference, s.seal AS s_seal,
                    src.project_id AS x_project, src.environment_id AS x_environment, src.current_version_id AS x_version, xref.source_secret_id AS x_source, xref.reference_id AS x_reference, src.seal AS x_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain, sv.plaintext AS v_plaintext,
                    ids.e1 AS e1_id, e1.project_id AS e1_project, e1.slug AS e1_slug, e1.owner AS e1_owner, e1.parent_id AS e1_parent, e1.protected AS e1_protected, e1.archived_at IS NOT NULL AS e1_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e1.project_id) AS e1_project_archived, e1.seal AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e2.project_id) AS e2_project_archived, e2.seal AS e2_seal,
                    ids.e3 AS e3_id, e3.project_id AS e3_project, e3.slug AS e3_slug, e3.owner AS e3_owner, e3.parent_id AS e3_parent, e3.protected AS e3_protected, e3.archived_at IS NOT NULL AS e3_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e3.project_id) AS e3_project_archived, e3.seal AS e3_seal,
                    CASE WHEN ve.owner IS NOT NULL THEN ve.parent END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e4.project_id) AS e4_project_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last,
                    -- Each input's object key, computed once: a key in a probe's own condition is computed again for every row it reads (0022, decision 3).
                    public.log_object(w.kind, v_credential::text) AS k_credential,
                    public.log_object('principal', w.principal) AS k_member,
                    public.log_object('secret', v_secret::text) AS k_secret,
                    public.log_object('secret', ref.source_secret_id::text) AS k_source,
                    public.log_object('environment', ids.e1::text) AS k_e1,
                    public.log_object('environment', s.environment_id::text) AS k_e2,
                    public.log_object('environment', ids.e3::text) AS k_e3,
                    public.log_object('environment', (CASE WHEN ve.owner IS NOT NULL THEN ve.parent END)::text) AS k_e4
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN LATERAL (SELECT y.at_floor, y.retired FROM public.checkpoint_fence y WHERE y.only_row LIMIT 1) f ON true
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  -- The cap as the policy's newest change says it (CapSealed): every policy change logs the whole policy as its `value`.
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
                  ) lpol ON true
                  -- The way in (T147), one of these by its id; or, behind Access, none: the account alone, whose row is all the
                  -- use weighs of it. The way rides the join key: the others' is null, which no index scan descends for. A
                  -- `p_way = 1` beside the key is no one-time filter of an outer join's inner side, and its probe ran (review r2).
                  LEFT JOIN public.credentials c ON c.id = CASE WHEN p_way = 0 THEN v_credential END
                  LEFT JOIN public.mcp_connections k ON k.id = CASE WHEN p_way = 1 THEN v_credential END
                  LEFT JOIN public.service_bindings wb ON wb.id = CASE WHEN p_way = 2 THEN v_credential END
                  CROSS JOIN LATERAL (
                      SELECT CASE p_way WHEN 0 THEN 'credential' WHEN 1 THEN 'connection' WHEN 2 THEN 'binding' END AS kind,
                             CASE p_way WHEN 0 THEN c.principal WHEN 1 THEN k.principal WHEN 2 THEN wb.principal WHEN 3 THEN p_principal END AS principal,
                             CASE p_way WHEN 0 THEN c.scope WHEN 2 THEN wb.scope END AS scope,
                             CASE p_way WHEN 0 THEN c.revoked_at WHEN 1 THEN k.revoked_at WHEN 2 THEN wb.revoked_at END AS revoked_at,
                             CASE p_way WHEN 0 THEN least(c.expires_at, c.not_after) WHEN 1 THEN k.expires_at END AS expires_at,
                             CASE p_way WHEN 0 THEN c.seal WHEN 1 THEN k.seal WHEN 2 THEN wb.seal END AS seal,
                             CASE p_way WHEN 0 THEN c.generation WHEN 1 THEN k.generation WHEN 2 THEN wb.generation END AS generation,
                             -- A binding's object is its whole row (objects.ts, bindingObject), its seal checked over it.
                             CASE WHEN p_way = 2 AND wb.id IS NOT NULL THEN to_json(wb) END AS row
                  ) w
                  LEFT JOIN public.principals m ON m.principal = w.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = v_secret AND s.archived_at IS NULL
                  -- A key with no version of its own is a reference while its newest reference row names a source and has not ended (`ended_at`): an ended one's holder reads as no value, no source (`ended`).
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.secret_id = s.id AND y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.secret_id = s.id AND y.ended_at IS NULL THEN y.id END AS reference_id
                        FROM public.secret_references y WHERE y.secret_id <= s.id ORDER BY y.secret_id DESC, y.created_seq DESC LIMIT 1
                  ) ref ON s.current_version_id IS NULL
                  LEFT JOIN public.secrets src ON src.id = ref.source_secret_id AND src.archived_at IS NULL
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.secret_id = src.id AND y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.secret_id = src.id AND y.ended_at IS NULL THEN y.id END AS reference_id
                        FROM public.secret_references y WHERE y.secret_id <= src.id ORDER BY y.secret_id DESC, y.created_seq DESC LIMIT 1
                  ) xref ON src.current_version_id IS NULL
                  -- The value's version: the key's own, or its source's.
                  LEFT JOIN public.secret_versions sv ON sv.id = CASE WHEN ref.source_secret_id IS NULL THEN s.current_version_id ELSE src.current_version_id END
                  -- The environments `useEnvironments` names, each by the id the rows name, whether or not its row is there: e1 the
                  -- place read through, e2 the key's own, e3 its value's (a reference's source's) where that is another, and e4
                  -- the parent of its value's when that is a personal config.
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN v_place IS DISTINCT FROM s.environment_id THEN v_place END AS e1,
                             CASE WHEN src.environment_id IS DISTINCT FROM s.environment_id THEN src.environment_id END AS e3
                  ) ids ON true
                  LEFT JOIN public.environments e1 ON e1.id = ids.e1
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e3 ON e3.id = ids.e3
                  -- The value's environment's row: the key's own, unless it is a reference, whose source is elsewhere or gone.
                  LEFT JOIN LATERAL (
                      -- A named call's key the place does not hold: the place's, a personal config's parent, which its standing
                      -- there weighs (T165, `standingParents`). A use by ids reads as before.
                      SELECT CASE WHEN s.id IS NULL AND p_token_hash IS NOT NULL THEN e1.owner
                                  WHEN ref.source_secret_id IS NULL OR (src.id IS NOT NULL AND ids.e3 IS NULL) THEN e2.owner ELSE e3.owner END AS owner,
                             CASE WHEN s.id IS NULL AND p_token_hash IS NOT NULL THEN e1.parent_id
                                  WHEN ref.source_secret_id IS NULL OR (src.id IS NOT NULL AND ids.e3 IS NULL) THEN e2.parent_id ELSE e3.parent_id END AS parent
                  ) ve ON true
                  LEFT JOIN public.environments e4 ON e4.id = ve.parent AND ve.owner IS NOT NULL
                  LEFT JOIN public.bulk_cap b ON b.principal = w.principal AND b.secret = v_secret
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, cap.refresh, cap.period,
                    -- What no key decides comes first (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416): the
                    -- floor, the deadline, the clock, the cap's config; then what the names decide, which the vault
                    -- answers on the caller's standing first.
                    CASE WHEN substring(p_mac FROM 1 FOR 4) = ANY(i.retired) THEN 'superseded'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         -- What the names name, read by them: no credential of that token, no live place of those names.
                         WHEN v_named IS NOT NULL THEN v_named
                         -- The ids the vault passed are not the ones the names name now (D153): the names' rows are read,
                         -- and nothing is written or locked.
                         WHEN NOT v_right THEN 'moved'
                         WHEN p_token_hash IS NOT NULL AND NOT v_routed AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                           OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut) THEN 'archived'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT (v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND NOT (v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND i.bulk_last < cap.period THEN 'share' END AS state,
                    greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, lx.number, l1.number, l2.number, l3.number, l4.number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, (lm.payload::jsonb ->> 'old')::bigint AS m_old, lr.seal AS r_last, ls.seal AS s_last, lx.seal AS x_last,
                    l1.seal AS e1_last, l2.seal AS e2_last, l3.seal AS e3_last, l4.seal AS e4_last,
                    -- What each newest change's MAC covers but its object and seal, and the MAC: the vault checks it before it holds a row to that seal (T190).
                    json_build_object('c', CASE WHEN lc.number IS NOT NULL THEN json_build_array(lc.at, lc.request_id, lc.actor, lc.payload, lc.mac) END, 'm', CASE WHEN lm.number IS NOT NULL THEN json_build_array(lm.at, lm.request_id, lm.actor, lm.payload, lm.mac) END, 'r', CASE WHEN lr.number IS NOT NULL THEN json_build_array(lr.at, lr.request_id, lr.actor, lr.payload, lr.mac) END, 'p', i.p_change, 's', CASE WHEN ls.number IS NOT NULL THEN json_build_array(ls.at, ls.request_id, ls.actor, ls.payload, ls.mac) END, 'x', CASE WHEN lx.number IS NOT NULL THEN json_build_array(lx.at, lx.request_id, lx.actor, lx.payload, lx.mac) END,
                        'e1', CASE WHEN l1.number IS NOT NULL THEN json_build_array(l1.at, l1.request_id, l1.actor, l1.payload, l1.mac) END, 'e2', CASE WHEN l2.number IS NOT NULL THEN json_build_array(l2.at, l2.request_id, l2.actor, l2.payload, l2.mac) END, 'e3', CASE WHEN l3.number IS NOT NULL THEN json_build_array(l3.at, l3.request_id, l3.actor, l3.payload, l3.mac) END, 'e4', CASE WHEN l4.number IS NOT NULL THEN json_build_array(l4.at, l4.request_id, l4.actor, l4.payload, l4.mac) END) AS changes,
                    coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.bulk_cap o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - i.cap_window - cap.refresh - public.deadline_max() - 60000
                             LIMIT i.cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= cap.period AND p_cover > coalesce(greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, lx.number, l1.number, l2.number, l3.number, l4.number), 0)
                        AND public.use_covered(p_cover_at, p_cover_request, p_cover, p_credential, p_secret, p_purpose, p_place, p_route), false) AS is_covered
                  FROM i
                  CROSS JOIN LATERAL (SELECT greatest(1, least(60000, i.cap_window / 10)) AS refresh) r0
                  CROSS JOIN LATERAL (SELECT r0.refresh, p_at - ((p_at % r0.refresh) + r0.refresh) % r0.refresh AS period) cap
                  -- Each input's newest change: one probe each (log_changes_object_idx), and its row, for the columns its MAC
                  -- covers (T190); the principal's payload names the 0.14 entry it accounts for.
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_credential ORDER BY x.number DESC LIMIT 1) lc ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_member ORDER BY x.number DESC LIMIT 1) lm ON i.k_member IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = public.log_object('roles', 'instance') ORDER BY x.number DESC LIMIT 1) lr ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_secret ORDER BY x.number DESC LIMIT 1) ls ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_source ORDER BY x.number DESC LIMIT 1) lx ON i.k_source IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_e1 ORDER BY x.number DESC LIMIT 1) l1 ON i.k_e1 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_e2 ORDER BY x.number DESC LIMIT 1) l2 ON i.k_e2 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_e3 ORDER BY x.number DESC LIMIT 1) l3 ON i.k_e3 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.at, x.request_id, x.actor, x.payload, x.mac FROM public.log_changes x WHERE x.object = i.k_e4 ORDER BY x.number DESC LIMIT 1) l4 ON i.k_e4 IS NOT NULL
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place, route)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place, p_route
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (v_quiet AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, v.inputs, true,
                v.p, v.c_kind, v.c_scope, v.c_revoked, v.c_expires, v.c_seal, v.c_last,
                v.m_status, v.m_owner, v.m_role, v.m_scope, v.m_seal, v.m_last, v.m_old,
                (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v.p AND a.decision = 'allow'
                    AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
                gr.g_project, gr.g_environment, gr.g_slug, gr.g_role, gr.g_expires,
                v.r_value, v.r_seal, v.r_last,
                v.p_value, v.p_seal, v.p_last, v.cap_count, v.cap_window,
                v.s_project, v.s_environment, v.s_version, v.s_source, v.s_seal, v.s_last,
                v.x_project, v.x_environment, v.x_version, v.x_source, v.x_seal, v.x_last,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                v.e1_id, v.e1_project, v.e1_slug, v.e1_owner, v.e1_parent, v.e1_protected, v.e1_archived, v.e1_seal, v.e1_last,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, v.e2_last,
                v.e3_id, v.e3_project, v.e3_slug, v.e3_owner, v.e3_parent, v.e3_protected, v.e3_archived, v.e3_seal, v.e3_last,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, v.e4_last,
                v.is_in, v.n_others, v.v_plaintext, v.e1_project_archived, v.e2_project_archived, v.e3_project_archived, v.e4_project_archived, v.s_reference, v.x_reference, v.c_generation, v.m_generation, v.c_token_hash,
                CASE WHEN p_token_hash IS NOT NULL THEN json_build_object(
                    'now', CURRENT_TIMESTAMP, 'credential', v.c_row, 'identity', (SELECT to_json(x) FROM public.identities x WHERE x.id = (v.c_row ->> 'identity_id')::uuid),
                    'policy', (SELECT a.seq::text FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1),
                    'project', (SELECT to_json(q) FROM public.projects q WHERE q.id = coalesce(v.e1_project, v.e2_project)),
                    'environment', (SELECT to_json(e) FROM public.environments e WHERE e.id = coalesce(v.e1_id, v.e2_id)),
                    'parent', CASE WHEN v_np_parent IS NOT NULL THEN (SELECT pe.slug FROM public.environments pe WHERE pe.id = v_np_parent) END,
                    'held', CASE WHEN v.e1_id IS NOT NULL AND v.e2_id IS NOT NULL THEN json_build_object('id', v.e2_id, 'slug', v.e2_slug) END,
                    'secrets', CASE WHEN v.s_row IS NULL THEN '[]'::json ELSE json_build_array(json_build_object('secret', v.s_row, 'version', v.sv_row)) END) END,
                -- A named call's (`n_*`), set below; a binding's row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::boolean, v.w_row, NULL::boolean, v.changes
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSIF NOT whole THEN
            -- The isolate's seals, and its cap, read at the change it names: no probe, only whether a change came since
            -- (then nothing is written: 'reprobe').
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, f.retired,
                    w.principal AS p, c.kind AS c_kind, w.scope AS c_scope, w.revoked_at IS NOT NULL AS c_revoked,
                    floor(extract(epoch FROM w.expires_at) * 1000)::bigint AS c_expires, w.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal, w.generation AS c_generation, m.generation AS m_generation,
                    w.row AS w_row,
                    -- What the request named, for the names it checks, and the rows the app checks, when it names them (0044).
                    c.token_hash AS c_token_hash,
                    CASE WHEN p_token_hash IS NOT NULL THEN to_json(c) END AS c_row, CASE WHEN p_token_hash IS NOT NULL THEN to_json(s) END AS s_row,
                    CASE WHEN p_token_hash IS NOT NULL AND s.current_version_id IS NOT NULL THEN to_json(sv) END AS sv_row,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, NULL::uuid AS s_source, NULL::uuid AS s_reference, s.seal AS s_seal,
                    NULL::uuid AS x_project, NULL::uuid AS x_environment, NULL::uuid AS x_version, NULL::uuid AS x_source, NULL::uuid AS x_reference, NULL::bytea AS x_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain, sv.plaintext AS v_plaintext,
                    NULL::uuid AS e1_id, NULL::uuid AS e1_project, NULL::text AS e1_slug, NULL::text AS e1_owner, NULL::uuid AS e1_parent, NULL::boolean AS e1_protected, NULL::boolean AS e1_archived, NULL::boolean AS e1_project_archived, NULL::bytea AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e2.project_id) AS e2_project_archived, e2.seal AS e2_seal,
                    NULL::uuid AS e3_id, NULL::uuid AS e3_project, NULL::text AS e3_slug, NULL::text AS e3_owner, NULL::uuid AS e3_parent, NULL::boolean AS e3_protected, NULL::boolean AS e3_archived, NULL::boolean AS e3_project_archived, NULL::bytea AS e3_seal,
                    CASE WHEN e2.owner IS NOT NULL THEN e2.parent_id END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e4.project_id) AS e4_project_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN LATERAL (SELECT y.at_floor, y.retired FROM public.checkpoint_fence y WHERE y.only_row LIMIT 1) f ON true
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  -- The way in (T147), one of these by its id; or, behind Access, none: the account alone, whose row is all the
                  -- use weighs of it. The way rides the join key: the others' is null, which no index scan descends for. A
                  -- `p_way = 1` beside the key is no one-time filter of an outer join's inner side, and its probe ran (review r2).
                  LEFT JOIN public.credentials c ON c.id = CASE WHEN p_way = 0 THEN v_credential END
                  LEFT JOIN public.mcp_connections k ON k.id = CASE WHEN p_way = 1 THEN v_credential END
                  LEFT JOIN public.service_bindings wb ON wb.id = CASE WHEN p_way = 2 THEN v_credential END
                  CROSS JOIN LATERAL (
                      SELECT CASE p_way WHEN 0 THEN 'credential' WHEN 1 THEN 'connection' WHEN 2 THEN 'binding' END AS kind,
                             CASE p_way WHEN 0 THEN c.principal WHEN 1 THEN k.principal WHEN 2 THEN wb.principal WHEN 3 THEN p_principal END AS principal,
                             CASE p_way WHEN 0 THEN c.scope WHEN 2 THEN wb.scope END AS scope,
                             CASE p_way WHEN 0 THEN c.revoked_at WHEN 1 THEN k.revoked_at WHEN 2 THEN wb.revoked_at END AS revoked_at,
                             CASE p_way WHEN 0 THEN least(c.expires_at, c.not_after) WHEN 1 THEN k.expires_at END AS expires_at,
                             CASE p_way WHEN 0 THEN c.seal WHEN 1 THEN k.seal WHEN 2 THEN wb.seal END AS seal,
                             CASE p_way WHEN 0 THEN c.generation WHEN 1 THEN k.generation WHEN 2 THEN wb.generation END AS generation,
                             -- A binding's object is its whole row (objects.ts, bindingObject), its seal checked over it.
                             CASE WHEN p_way = 2 AND wb.id IS NOT NULL THEN to_json(wb) END AS row
                  ) w
                  LEFT JOIN public.principals m ON m.principal = w.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = v_secret AND s.archived_at IS NULL
                  -- The key's own version, its own environment, and that environment's parent when it is a personal config.
                  LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e4 ON e4.id = e2.parent_id AND e2.owner IS NOT NULL
                  LEFT JOIN public.bulk_cap b ON b.principal = w.principal AND b.secret = v_secret
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, c_refresh AS refresh, c_period AS period,
                    CASE WHEN NOT i.cached THEN 'reprobe'
                         WHEN i.s_project IS NOT NULL AND i.s_version IS NULL THEN 'whole'
                         -- What no key decides comes first (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416): the
                         -- floor, the deadline, the clock, the cap's config; then what the names decide, which the vault
                         -- answers on the caller's standing first.
                         WHEN substring(p_mac FROM 1 FOR 4) = ANY(i.retired) THEN 'superseded'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         -- What the names name, read by them: no credential of that token, no live place of those names.
                         WHEN v_named IS NOT NULL THEN v_named
                         -- The ids the vault passed are not the ones the names name now (D153): the names' rows are read,
                         -- and nothing is written or locked.
                         WHEN NOT v_right THEN 'moved'
                         WHEN p_token_hash IS NOT NULL AND NOT v_routed AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                           OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut) THEN 'archived'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT (v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND NOT (v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND i.bulk_last < c_period THEN 'share' END AS state,
                    coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.bulk_cap o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - p_cap_window - c_refresh - public.deadline_max() - 60000
                             LIMIT p_cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= c_period
                        AND public.use_covered(p_cover_at, p_cover_request, p_cover, p_credential, p_secret, p_purpose, p_place, p_route), false) AS is_covered
                  FROM i
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place, route)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place, p_route
                  -- The isolate held its cover to the cached seals' numbers when it read them.
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (v_quiet AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, NULL::bigint, false,
                v.p, v.c_kind, v.c_scope, v.c_revoked, v.c_expires, v.c_seal, NULL::bytea,
                v.m_status, v.m_owner, v.m_role, v.m_scope, v.m_seal, NULL::bytea, NULL::bigint,
                (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v.p AND a.decision = 'allow'
                    AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
                gr.g_project, gr.g_environment, gr.g_slug, gr.g_role, gr.g_expires,
                v.r_value, v.r_seal, NULL::bytea,
                v.p_value, v.p_seal, NULL::bytea, p_cap_count, p_cap_window,
                v.s_project, v.s_environment, v.s_version, v.s_source, v.s_seal, NULL::bytea,
                v.x_project, v.x_environment, v.x_version, v.x_source, v.x_seal, NULL::bytea,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                v.e1_id, v.e1_project, v.e1_slug, v.e1_owner, v.e1_parent, v.e1_protected, v.e1_archived, v.e1_seal, NULL::bytea,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, NULL::bytea,
                v.e3_id, v.e3_project, v.e3_slug, v.e3_owner, v.e3_parent, v.e3_protected, v.e3_archived, v.e3_seal, NULL::bytea,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, NULL::bytea,
                v.is_in, v.n_others, v.v_plaintext, v.e1_project_archived, v.e2_project_archived, v.e3_project_archived, v.e4_project_archived, v.s_reference, v.x_reference, v.c_generation, v.m_generation, v.c_token_hash,
                CASE WHEN p_token_hash IS NOT NULL THEN json_build_object(
                    'now', CURRENT_TIMESTAMP, 'credential', v.c_row, 'identity', (SELECT to_json(x) FROM public.identities x WHERE x.id = (v.c_row ->> 'identity_id')::uuid),
                    'policy', (SELECT a.seq::text FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1),
                    'project', (SELECT to_json(q) FROM public.projects q WHERE q.id = coalesce(v.e1_project, v.e2_project)),
                    'environment', (SELECT to_json(e) FROM public.environments e WHERE e.id = coalesce(v.e1_id, v.e2_id)),
                    'parent', CASE WHEN v_np_parent IS NOT NULL THEN (SELECT pe.slug FROM public.environments pe WHERE pe.id = v_np_parent) END,
                    'held', CASE WHEN v.e1_id IS NOT NULL AND v.e2_id IS NOT NULL THEN json_build_object('id', v.e2_id, 'slug', v.e2_slug) END,
                    'secrets', CASE WHEN v.s_row IS NULL THEN '[]'::json ELSE json_build_array(json_build_object('secret', v.s_row, 'version', v.sv_row)) END) END,
                -- A named call's (`n_*`), set below; a binding's row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::boolean, v.w_row, NULL::boolean, NULL::json
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSE
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, f.retired,
                    w.principal AS p, c.kind AS c_kind, w.scope AS c_scope, w.revoked_at IS NOT NULL AS c_revoked,
                    floor(extract(epoch FROM w.expires_at) * 1000)::bigint AS c_expires, w.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal, w.generation AS c_generation, m.generation AS m_generation,
                    w.row AS w_row,
                    -- What the request named, for the names it checks, and the rows the app checks, when it names them (0044).
                    c.token_hash AS c_token_hash,
                    CASE WHEN p_token_hash IS NOT NULL THEN to_json(c) END AS c_row, CASE WHEN p_token_hash IS NOT NULL THEN to_json(s) END AS s_row,
                    CASE WHEN p_token_hash IS NOT NULL AND s.current_version_id IS NOT NULL THEN to_json(sv) END AS sv_row,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, ref.source_secret_id AS s_source, ref.reference_id AS s_reference, s.seal AS s_seal,
                    src.project_id AS x_project, src.environment_id AS x_environment, src.current_version_id AS x_version, xref.source_secret_id AS x_source, xref.reference_id AS x_reference, src.seal AS x_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain, sv.plaintext AS v_plaintext,
                    ids.e1 AS e1_id, e1.project_id AS e1_project, e1.slug AS e1_slug, e1.owner AS e1_owner, e1.parent_id AS e1_parent, e1.protected AS e1_protected, e1.archived_at IS NOT NULL AS e1_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e1.project_id) AS e1_project_archived, e1.seal AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e2.project_id) AS e2_project_archived, e2.seal AS e2_seal,
                    ids.e3 AS e3_id, e3.project_id AS e3_project, e3.slug AS e3_slug, e3.owner AS e3_owner, e3.parent_id AS e3_parent, e3.protected AS e3_protected, e3.archived_at IS NOT NULL AS e3_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e3.project_id) AS e3_project_archived, e3.seal AS e3_seal,
                    CASE WHEN ve.owner IS NOT NULL THEN ve.parent END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e4.project_id) AS e4_project_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN LATERAL (SELECT y.at_floor, y.retired FROM public.checkpoint_fence y WHERE y.only_row LIMIT 1) f ON true
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  -- The way in (T147), one of these by its id; or, behind Access, none: the account alone, whose row is all the
                  -- use weighs of it. The way rides the join key: the others' is null, which no index scan descends for. A
                  -- `p_way = 1` beside the key is no one-time filter of an outer join's inner side, and its probe ran (review r2).
                  LEFT JOIN public.credentials c ON c.id = CASE WHEN p_way = 0 THEN v_credential END
                  LEFT JOIN public.mcp_connections k ON k.id = CASE WHEN p_way = 1 THEN v_credential END
                  LEFT JOIN public.service_bindings wb ON wb.id = CASE WHEN p_way = 2 THEN v_credential END
                  CROSS JOIN LATERAL (
                      SELECT CASE p_way WHEN 0 THEN 'credential' WHEN 1 THEN 'connection' WHEN 2 THEN 'binding' END AS kind,
                             CASE p_way WHEN 0 THEN c.principal WHEN 1 THEN k.principal WHEN 2 THEN wb.principal WHEN 3 THEN p_principal END AS principal,
                             CASE p_way WHEN 0 THEN c.scope WHEN 2 THEN wb.scope END AS scope,
                             CASE p_way WHEN 0 THEN c.revoked_at WHEN 1 THEN k.revoked_at WHEN 2 THEN wb.revoked_at END AS revoked_at,
                             CASE p_way WHEN 0 THEN least(c.expires_at, c.not_after) WHEN 1 THEN k.expires_at END AS expires_at,
                             CASE p_way WHEN 0 THEN c.seal WHEN 1 THEN k.seal WHEN 2 THEN wb.seal END AS seal,
                             CASE p_way WHEN 0 THEN c.generation WHEN 1 THEN k.generation WHEN 2 THEN wb.generation END AS generation,
                             -- A binding's object is its whole row (objects.ts, bindingObject), its seal checked over it.
                             CASE WHEN p_way = 2 AND wb.id IS NOT NULL THEN to_json(wb) END AS row
                  ) w
                  LEFT JOIN public.principals m ON m.principal = w.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = v_secret AND s.archived_at IS NULL
                  -- A key with no version of its own is a reference while its newest reference row names a source and has not ended (`ended_at`): an ended one's holder reads as no value, no source (`ended`).
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.secret_id = s.id AND y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.secret_id = s.id AND y.ended_at IS NULL THEN y.id END AS reference_id
                        FROM public.secret_references y WHERE y.secret_id <= s.id ORDER BY y.secret_id DESC, y.created_seq DESC LIMIT 1
                  ) ref ON s.current_version_id IS NULL
                  LEFT JOIN public.secrets src ON src.id = ref.source_secret_id AND src.archived_at IS NULL
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.secret_id = src.id AND y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.secret_id = src.id AND y.ended_at IS NULL THEN y.id END AS reference_id
                        FROM public.secret_references y WHERE y.secret_id <= src.id ORDER BY y.secret_id DESC, y.created_seq DESC LIMIT 1
                  ) xref ON src.current_version_id IS NULL
                  -- The value's version: the key's own, or its source's.
                  LEFT JOIN public.secret_versions sv ON sv.id = CASE WHEN ref.source_secret_id IS NULL THEN s.current_version_id ELSE src.current_version_id END
                  -- The environments `useEnvironments` names, each by the id the rows name, whether or not its row is there: e1 the
                  -- place read through, e2 the key's own, e3 its value's (a reference's source's) where that is another, and e4
                  -- the parent of its value's when that is a personal config.
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN v_place IS DISTINCT FROM s.environment_id THEN v_place END AS e1,
                             CASE WHEN src.environment_id IS DISTINCT FROM s.environment_id THEN src.environment_id END AS e3
                  ) ids ON true
                  LEFT JOIN public.environments e1 ON e1.id = ids.e1
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e3 ON e3.id = ids.e3
                  -- The value's environment's row: the key's own, unless it is a reference, whose source is elsewhere or gone.
                  LEFT JOIN LATERAL (
                      -- A named call's key the place does not hold: the place's, a personal config's parent, which its standing
                      -- there weighs (T165, `standingParents`). A use by ids reads as before.
                      SELECT CASE WHEN s.id IS NULL AND p_token_hash IS NOT NULL THEN e1.owner
                                  WHEN ref.source_secret_id IS NULL OR (src.id IS NOT NULL AND ids.e3 IS NULL) THEN e2.owner ELSE e3.owner END AS owner,
                             CASE WHEN s.id IS NULL AND p_token_hash IS NOT NULL THEN e1.parent_id
                                  WHEN ref.source_secret_id IS NULL OR (src.id IS NOT NULL AND ids.e3 IS NULL) THEN e2.parent_id ELSE e3.parent_id END AS parent
                  ) ve ON true
                  LEFT JOIN public.environments e4 ON e4.id = ve.parent AND ve.owner IS NOT NULL
                  LEFT JOIN public.bulk_cap b ON b.principal = w.principal AND b.secret = v_secret
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, c_refresh AS refresh, c_period AS period,
                    CASE WHEN NOT i.cached THEN 'reprobe'
                         -- What no key decides comes first (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416): the
                         -- floor, the deadline, the clock, the cap's config; then what the names decide, which the vault
                         -- answers on the caller's standing first.
                         WHEN substring(p_mac FROM 1 FOR 4) = ANY(i.retired) THEN 'superseded'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         -- What the names name, read by them: no credential of that token, no live place of those names.
                         WHEN v_named IS NOT NULL THEN v_named
                         -- The ids the vault passed are not the ones the names name now (D153): the names' rows are read,
                         -- and nothing is written or locked.
                         WHEN NOT v_right THEN 'moved'
                         WHEN p_token_hash IS NOT NULL AND NOT v_routed AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                           OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut) THEN 'archived'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT (v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND NOT (v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND i.bulk_last < c_period THEN 'share' END AS state,
                    coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.bulk_cap o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - p_cap_window - c_refresh - public.deadline_max() - 60000
                             LIMIT p_cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= c_period
                        AND public.use_covered(p_cover_at, p_cover_request, p_cover, p_credential, p_secret, p_purpose, p_place, p_route), false) AS is_covered
                  FROM i
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place, route)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place, p_route
                  -- The isolate held its cover to the cached seals' numbers when it read them.
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (v_quiet AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, NULL::bigint, false,
                v.p, v.c_kind, v.c_scope, v.c_revoked, v.c_expires, v.c_seal, NULL::bytea,
                v.m_status, v.m_owner, v.m_role, v.m_scope, v.m_seal, NULL::bytea, NULL::bigint,
                (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v.p AND a.decision = 'allow'
                    AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
                gr.g_project, gr.g_environment, gr.g_slug, gr.g_role, gr.g_expires,
                v.r_value, v.r_seal, NULL::bytea,
                v.p_value, v.p_seal, NULL::bytea, p_cap_count, p_cap_window,
                v.s_project, v.s_environment, v.s_version, v.s_source, v.s_seal, NULL::bytea,
                v.x_project, v.x_environment, v.x_version, v.x_source, v.x_seal, NULL::bytea,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                v.e1_id, v.e1_project, v.e1_slug, v.e1_owner, v.e1_parent, v.e1_protected, v.e1_archived, v.e1_seal, NULL::bytea,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, NULL::bytea,
                v.e3_id, v.e3_project, v.e3_slug, v.e3_owner, v.e3_parent, v.e3_protected, v.e3_archived, v.e3_seal, NULL::bytea,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, NULL::bytea,
                v.is_in, v.n_others, v.v_plaintext, v.e1_project_archived, v.e2_project_archived, v.e3_project_archived, v.e4_project_archived, v.s_reference, v.x_reference, v.c_generation, v.m_generation, v.c_token_hash,
                CASE WHEN p_token_hash IS NOT NULL THEN json_build_object(
                    'now', CURRENT_TIMESTAMP, 'credential', v.c_row, 'identity', (SELECT to_json(x) FROM public.identities x WHERE x.id = (v.c_row ->> 'identity_id')::uuid),
                    'policy', (SELECT a.seq::text FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1),
                    'project', (SELECT to_json(q) FROM public.projects q WHERE q.id = coalesce(v.e1_project, v.e2_project)),
                    'environment', (SELECT to_json(e) FROM public.environments e WHERE e.id = coalesce(v.e1_id, v.e2_id)),
                    'parent', CASE WHEN v_np_parent IS NOT NULL THEN (SELECT pe.slug FROM public.environments pe WHERE pe.id = v_np_parent) END,
                    'held', CASE WHEN v.e1_id IS NOT NULL AND v.e2_id IS NOT NULL THEN json_build_object('id', v.e2_id, 'slug', v.e2_slug) END,
                    'secrets', CASE WHEN v.s_row IS NULL THEN '[]'::json ELSE json_build_array(json_build_object('secret', v.s_row, 'version', v.sv_row)) END) END,
                -- A named call's (`n_*`), set below; a binding's row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::boolean, v.w_row, NULL::boolean, NULL::json
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        END IF;
        IF dry THEN
            -- The forms in turn: probing plain, probing whole, cached plain, cached whole; then the call itself, under the fence.
            form := form + 1;
            IF form < 4 THEN
                probe := form < 2;
                whole := form % 2 = 1;
                CONTINUE;
            END IF;
            PERFORM set_config('coffre.use_planned', '0073', false);
            dry := false;
            probe := first_probe;
            whole := first_whole;
            v_secret := p_secret;
            PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
            CONTINUE;
        END IF;
        -- A named call answered `moved` or `archived` is decided by the vault before anything else is done (T158, D153):
        -- it is read again probing, so that every row's newest seal is there to check, in this call.
        IF r.state IN ('moved', 'archived') AND p_token_hash IS NOT NULL AND NOT probe THEN
            probe := true;
            CONTINUE;
        END IF;
        -- A use the statement took writes its entry or rides its cover, never neither: but a named one, or a route use's, of
        -- a key the place does not hold, or of a plain value, which writes none.
        IF r.state IS NULL AND r.number IS NULL AND r.covered IS NULL AND NOT (v_quiet AND (r.s_project IS NULL OR coalesce(r.v_plain, false))) THEN
            RAISE EXCEPTION 'a use wrote no entry and rode no cover' USING ERRCODE = 'XX000';
        END IF;
        IF r.state = 'reprobe' THEN probe := true; CONTINUE; END IF;
        IF r.state = 'whole' THEN whole := true; CONTINUE; END IF;
        -- A use whose key would take its principal's lock (to enter the cap's set, or move on in it), named or by ids,
        -- takes it only in the vault's call after it decided the use on the rows of this one (`p_decided`; T158, D153;
        -- formal/Probing.tla, DecideBeforeLock, DecideEachLock; HotPathOne, NoLockWithoutStanding). Otherwise the call ends
        -- here, nothing locked or written, and answers the rows it read (`decide`): the vault refuses a use it may not make
        -- on them, the same as for a key never made, and makes one it may, in a second call.
        IF r.state IN ('lock', 'share') AND NOT p_decided AND NOT locked AND NOT moving THEN
            r.state := 'decide';
            EXIT;
        END IF;
        EXIT WHEN r.state IS DISTINCT FROM 'lock' AND r.state IS DISTINCT FROM 'share';
        -- Its key's bulk row is missing or out of the set: this use may enter it, so it takes its principal's lock exclusive
        -- and reads again. Or the row is in the set, from an earlier period: this use may move it on, so it takes the lock
        -- shared, beside the principal's other uses that move a key on, and reads again.
        -- Holding it shared, a key never leaves the set (SharedStaysInSet) unless a row was put back under it: then the
        -- call ends, refused as late, rather than ask for the lock exclusive while it holds it shared (two such would
        -- deadlock).
        IF r.state = 'lock' AND moving THEN
            RAISE EXCEPTION 'its key left the cap''s set under the principal''s lock: a row put back' USING ERRCODE = '57014';
        END IF;
        IF r.state = 'lock' THEN
            PERFORM pg_advisory_xact_lock(1668244066, hashtext(r.c_principal));
            locked := true;
        ELSE
            PERFORM pg_advisory_xact_lock_shared(1668244066, hashtext(r.c_principal));
            moving := true;
        END IF;
    END LOOP;
    -- The cap's row, written only by a call that took the principal's lock, in a statement of its own after the one that
    -- read, in the same transaction, under the same locks: the uses that read their key fresh, nearly all, run no write.
    -- A key in the set moves on to this use's period, only ever up. A key entering the set, under the lock exclusive, is
    -- made or moved on from a window past. Every request counts, whatever the Worker then decides but the cap (HotPathOneStaleBulk).
    IF r.state IS NULL AND (locked OR moving) THEN
        b_refresh := greatest(1, least(60000, r.cap_window / 10));
        b_period := p_at - ((p_at % b_refresh) + b_refresh) % b_refresh;
        IF r.in_set THEN
            -- One use moves the key to this period: the one that takes a lock of the key and period's own without waiting.
            -- The others take it shared, which waits only for that one's end, never for each other, and read the row again,
            -- locking none: moved, they leave it. An UPDATE that waits on a row another is moving, then finds it moved,
            -- keeps the row locked to its own commit, and queues the next. If the one moving it rolled back, the others
            -- elect another the same way, on the lock's next round.
            LOOP
                b_lock := hashtextextended(r.c_principal || '/' || p_secret::text || '/' || b_period::text || '/' || b_round::text, 1668244066);
                IF pg_try_advisory_xact_lock(b_lock) THEN
                    UPDATE public.bulk_cap SET last = b_period WHERE principal = r.c_principal AND secret = p_secret AND last < b_period;
                    EXIT;
                END IF;
                PERFORM pg_advisory_xact_lock_shared(b_lock);
                EXIT WHEN NOT EXISTS (SELECT 1 FROM public.bulk_cap WHERE principal = r.c_principal AND secret = p_secret AND last < b_period);
                b_round := b_round + 1;
            END LOOP;
        ELSIF r.others < r.cap_count THEN
            INSERT INTO public.bulk_cap (principal, secret, last) VALUES (r.c_principal, p_secret, b_period)
                ON CONFLICT ON CONSTRAINT bulk_cap_pkey DO UPDATE SET last = greatest(bulk_cap.last, EXCLUDED.last);
        END IF;
    END IF;
    -- The deadline holds in Postgres to the end: a call that ran past it rolls back and writes nothing. The hot login's lock_timeout and statement_timeout bound the waits.
    IF r.state IS NULL AND (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN
        RAISE EXCEPTION 'past its deadline' USING ERRCODE = '57014';
    END IF;
    -- What a named call's names name: the ids the vault makes the use by once it has decided, and the place's slugs.
    IF p_token_hash IS NOT NULL THEN
        r.n_credential := v_credential;
        r.n_secret := v_secret;
        r.n_place := v_np;
        r.n_project := v_project;
        r.n_environment := v_environment;
        r.n_standing := v_stands;
        r.n_cut := v_cut;
    END IF;
    RETURN CASE WHEN v_routed THEN json_build_object('row', to_json(r), 'route', v_route) ELSE to_json(r) END;
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.use_route(p_token_hash bytea, p_project text, p_environment text, p_named text, p_stable text, p_reading smallint, p_signin boolean, p_issuers text[], p_roles jsonb, p_credential uuid, p_way smallint, p_principal text, p_place uuid, p_at bigint, p_purpose smallint, p_deadline bigint, p_read_mac bytea, p_secrets uuid[], p_places uuid[], p_requests bigint[], p_macs bytea[], p_covers bigint[], p_cover_ats bigint[], p_cover_requests bigint[], p_decided boolean[], p_offset integer, p_limit integer, p_lock text, p_use boolean, p_light boolean DEFAULT false)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
AS $function$
DECLARE
    v_handle boolean := p_token_hash IS NOT NULL;
    -- 1: the place reading; 2: the stable reading (a workload's, `proxyItem`'s at a handle's own place).
    v_reading smallint;
    v_route text;
    v_places text;
    v_candidate uuid;
    v_made_for boolean := false;
    v_attempt integer := 0;
    v_gated smallint;
    made_for json;
    gate json;
    v_credential uuid;
    v_np uuid;
    v_project uuid;
    v_owner text;
    v_layers uuid[];
    v_cut boolean;
    levels json[] := '{}';
    v_item jsonb;
    v_digests bytea;
    v_seal bytea;
    v_row boolean;
    v_number bigint;
    v_newest bytea;
    v_change json;
    level_env json;
    v_env_number bigint;
    -- The newest change of the route's inputs this statement reads and `use_credential` does not: a cover must be past it.
    v_inputs bigint := 0;
    v_serving jsonb;
    v_editor text;
    editor json;
    names text[] := '{}';
    v_n integer := 0;
    v_ids uuid[];
    v_holders uuid[];
    v_resolved json[];
    v_right boolean;
    answers json[] := '{}';
    -- The vault's ask (T200): the gate light, its caller's rows read by the keys' uses this statement makes with its ids.
    v_light boolean := coalesce(p_light, false) AND p_token_hash IS NOT NULL AND p_use AND p_secrets IS NOT NULL;
    -- What the statement ends on, short of the route's keys: a personal config, or a chain cut.
    v_personal boolean := false;
    v_chain_cut boolean := false;
    -- A handle's gate that found it standing nowhere there, or at a place cut: the route is not read.
    v_unstood boolean := false;
    -- Whether this session planned the reading's statements, on its first call, before the fence (T200).
    v_planned boolean := current_setting('coffre.route_planned', true) IS NOT DISTINCT FROM '0073';
    -- The gate's answer, parsed once (T200): each `->>` of a json value parses its text whole again.
    g jsonb;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_offset IS NULL OR p_offset < 0 OR p_read_mac IS NULL OR p_purpose IS NULL OR p_use IS NULL
       OR (v_handle AND (p_place IS NOT NULL OR coalesce(p_way, 0) <> 0 OR p_principal IS NOT NULL))
       OR (NOT v_handle AND (p_credential IS NULL OR p_place IS NULL OR p_way IS NULL OR p_project IS NOT NULL OR p_named IS NOT NULL))
       OR (p_use AND p_stable IS NULL AND p_named IS NULL)
       OR (p_named IS NOT NULL AND (p_project IS NULL OR p_environment IS NULL))
       OR (p_secrets IS NOT NULL AND (NOT p_use OR p_credential IS NULL OR cardinality(p_secrets) = 0 OR cardinality(p_secrets) > p_limit
           OR cardinality(p_places) IS DISTINCT FROM cardinality(p_secrets) OR cardinality(p_requests) IS DISTINCT FROM cardinality(p_secrets)
           OR cardinality(p_macs) IS DISTINCT FROM cardinality(p_secrets) OR cardinality(p_covers) IS DISTINCT FROM cardinality(p_secrets)
           OR cardinality(p_cover_ats) IS DISTINCT FROM cardinality(p_secrets) OR cardinality(p_cover_requests) IS DISTINCT FROM cardinality(p_secrets)
           OR cardinality(p_decided) IS DISTINCT FROM cardinality(p_secrets)))
       OR (p_lock IS NOT NULL AND p_secrets IS NULL)
       OR p_light IS NULL OR (p_light AND (NOT v_handle OR NOT p_use OR p_secrets IS NULL)) THEN
        RAISE EXCEPTION 'a route use names its caller (a handle''s token, or a workload''s way in at its place), its route, and its keys'' ids a key in each of its lists, at most its limit' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The reading: the place reading for an environment the handle was made for, else the stable one (section 6). Picked
    -- before the fence, which the gate takes, so that its plans are made before the call holds it; then picked again under
    -- it, and the gate asked again by the new one if a rename moved it in between (review r2 of #464): the gate decides by
    -- the reading the rows it reads under the fence pick. A session whose first call planned them picks once, under the
    -- fence, taken first (T200): the pick the second round would make, with no first to make it again.
    IF v_planned AND v_handle AND p_named IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
        v_attempt := 1;
    END IF;
    LOOP
        v_attempt := v_attempt + 1;
        IF v_handle AND p_named IS NOT NULL THEN
            SELECT c.places INTO v_places FROM public.credentials c WHERE c.token_hash = p_token_hash;
            SELECT e.id INTO v_candidate FROM public.projects q JOIN public.environments e ON e.project_id = q.id
                AND e.slug = CASE WHEN right(p_environment, 3) = '@me' THEN left(p_environment, -3) ELSE p_environment END
             WHERE q.slug = p_project AND q.slug NOT LIKE '%~%' AND e.slug NOT LIKE '%~%';
            -- Unchecked yet, so parsed without raising, each step in turn (a CASE's order, which AND does not promise).
            v_made_for := CASE WHEN v_candidate IS NULL OR NOT coalesce(pg_input_is_valid(v_places, 'jsonb'), false) THEN false
                               WHEN jsonb_typeof(v_places::jsonb) IS DISTINCT FROM 'array' THEN false
                               ELSE EXISTS (SELECT 1 FROM jsonb_array_elements(v_places::jsonb) x
                                             WHERE jsonb_typeof(x) = 'object' AND x ->> 'environmentId' = v_candidate::text
                                               AND (coalesce(x ->> 'personal', 'false') = 'true') = (right(p_environment, 3) = '@me')) END;
        END IF;
        v_reading := CASE WHEN p_use THEN (CASE WHEN v_handle AND p_named IS NOT NULL AND (v_made_for OR p_stable IS NULL) THEN 1 ELSE 2 END)
                          ELSE (CASE WHEN p_project IS NOT NULL THEN 1 ELSE 2 END) END;
        v_route := CASE WHEN v_reading = 1 THEN p_named ELSE p_stable END;
        EXIT WHEN NOT v_handle OR (v_attempt = 2 AND v_reading = v_gated);
        -- The gate: the caller's standing at the place, by the reading's names, from rows no key decides. It takes the fence.
        -- Light, when the vault asks (T200): one who stands is answered by their names alone, and the keys' uses below
        -- read their rows; the whole gate, below too, where none is made.
        gate := public.use_credential(
            NULL::uuid, NULL::uuid, 0::bigint, p_at, p_purpose, NULL::uuid, p_read_mac, p_deadline,
            NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint,
            p_token_hash, CASE WHEN v_reading = 1 THEN p_project END, CASE WHEN v_reading = 1 THEN p_environment END, NULL::text,
            false, v_reading = 2,
            CASE WHEN v_reading = 2 AND p_project IS NOT NULL THEN ARRAY[p_project || '/' || p_environment] ELSE '{}'::text[] END,
            p_signin, p_issuers, p_roles,
            0::smallint, NULL::text, true, NULL::text, v_light
        );
        v_gated := v_reading;
        EXIT WHEN p_named IS NULL OR v_attempt = 2;
        -- Held already, unless the gate refused before it took it: held now, for the reading picked again.
        PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    END LOOP;
    IF NOT v_planned AND v_handle AND p_named IS NOT NULL THEN
        PERFORM set_config('coffre.route_planned', '0073', false);
    END IF;
    IF v_handle THEN
        g := gate::jsonb;
        IF coalesce(g ->> 'state', '') NOT IN ('moved', 'stood') OR (g ->> 'n_standing') IS DISTINCT FROM 'true' OR (g ->> 'n_cut') IS DISTINCT FROM 'false' THEN
            v_unstood := true;
        ELSE
            v_np := (g ->> 'n_place')::uuid;
            v_credential := (g ->> 'n_credential')::uuid;
        END IF;
    ELSE
        -- A workload's: its use of no key at the place, by ids, quiet: the vault decides its standing on the row.
        gate := public.use_credential(
            p_credential, NULL::uuid, 0::bigint, p_at, p_purpose, p_place, p_read_mac, p_deadline,
            NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint,
            NULL::bytea, NULL::text, NULL::text, NULL::text,
            false, false, NULL::text[], NULL::boolean, NULL::text[], NULL::jsonb,
            -- Its route, or, for every item (`proxyItem` with no name), one it names only to be quiet: no entry is written.
            p_way, p_principal, false, coalesce(v_route, 'every')
        );
        IF (gate ->> 'state') IS NOT NULL THEN
            RETURN json_build_object('gate', gate, 'reading', v_reading, 'route', v_route, 'stood', false);
        END IF;
        v_np := p_place;
        v_credential := p_credential;
    END IF;
    <<route>>
    BEGIN
        EXIT route WHEN v_unstood;
        -- The place itself (C2b4): a place reading of no route (`''`, a name no item has) taken, for the plan, compute or
        -- code's credential under the place. The reading and the gate are the answer: no definition is read.
        EXIT route WHEN v_reading = 1 AND v_route = '';
        SELECT e.project_id, e.owner INTO v_project, v_owner FROM public.environments e WHERE e.id = v_np;
        -- A personal config serves no UI route (decision 7): its owner's values are no editor's to route.
        IF v_owner IS NOT NULL OR (v_handle AND v_reading = 1 AND right(p_environment, 3) = '@me') THEN
            v_personal := true;
            EXIT route;
        END IF;
        WITH RECURSIVE chain (id, parent, cut, depth, seen) AS (
            SELECT e.id, e.parent_id, false, 0, ARRAY[e.id] FROM public.environments e WHERE e.id = v_np
            UNION ALL
            SELECT chain.parent, p.parent_id, p.id IS NULL OR p.archived_at IS NOT NULL OR p.slug LIKE '%~%' OR chain.parent = ANY (chain.seen) OR chain.depth >= 3,
                   chain.depth + 1, chain.seen || chain.parent
              FROM chain LEFT JOIN public.environments p ON p.id = chain.parent
             WHERE chain.parent IS NOT NULL AND NOT chain.cut
        )
        SELECT array_agg(chain.id ORDER BY chain.depth), coalesce(bool_or(chain.cut), false) INTO v_layers, v_cut FROM chain;
        IF v_cut OR v_layers IS NULL THEN
            v_chain_cut := true;
            EXIT route;
        END IF;
        -- Each level, nearest first: its definitions through the first whose row holds the route's item (every level's, for
        -- every item), and every level's environment, which the keys resolve through whatever level serves (review r2).
        FOR l IN 1 .. cardinality(v_layers) LOOP
            v_item := NULL; v_digests := NULL; v_seal := NULL; v_row := NULL; v_number := NULL; v_newest := NULL; v_change := NULL;
            -- The level's environment, its row and seal and its object's newest change: the chain read from `parent_id` is
            -- the vault's to check link by link, as the rows say it, before any level's item serves (a parent re-pointed
            -- around the log would graft another environment's definitions onto this one's keys). Through the level that
            -- serves, its definitions and their object's newest change too, in the same statement (T200), each read by the
            -- level's id whether or not its environment's row is there.
            IF v_serving IS NULL THEN
                SELECT CASE WHEN v_route IS NULL THEN p.items ELSE p.items -> v_route END, p.digests, p.seal, p.environment_id IS NOT NULL,
                       lp.number, lp.seal, CASE WHEN lp.number IS NOT NULL THEN json_build_array(lp.at, lp.request_id, lp.actor, lp.payload, lp.mac) END,
                       CASE WHEN e.id IS NOT NULL THEN json_build_object('project', e.project_id, 'slug', e.slug, 'owner', e.owner, 'parent', e.parent_id, 'protected', e.protected,
                                         'archived', e.archived_at IS NOT NULL, 'project_archived', q.archived_at IS NOT NULL, 'seal', e.seal, 'last', le.seal,
                                         'change', CASE WHEN le.number IS NOT NULL THEN json_build_array(le.at, le.request_id, le.actor, le.payload, le.mac) END) END,
                       le.number
                  INTO v_item, v_digests, v_seal, v_row, v_number, v_newest, v_change, level_env, v_env_number
                  FROM (SELECT v_layers[l] AS id) lv
                  LEFT JOIN public.proxy_definitions p ON p.environment_id = lv.id
                  LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = public.log_object('proxy', lv.id::text) ORDER BY x.number DESC LIMIT 1) lp ON true
                  LEFT JOIN public.environments e ON e.id = lv.id
                  LEFT JOIN public.projects q ON q.id = e.project_id
                  LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = public.log_object('environment', e.id::text) ORDER BY x.number DESC LIMIT 1) le ON e.id IS NOT NULL;
                v_inputs := greatest(v_inputs, coalesce(v_number, 0));
            ELSE
                SELECT json_build_object('project', e.project_id, 'slug', e.slug, 'owner', e.owner, 'parent', e.parent_id, 'protected', e.protected,
                                         'archived', e.archived_at IS NOT NULL, 'project_archived', q.archived_at IS NOT NULL, 'seal', e.seal, 'last', le.seal,
                                         'change', CASE WHEN le.number IS NOT NULL THEN json_build_array(le.at, le.request_id, le.actor, le.payload, le.mac) END),
                       le.number
                  INTO level_env, v_env_number
                  FROM public.environments e LEFT JOIN public.projects q ON q.id = e.project_id
                  LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = public.log_object('environment', e.id::text) ORDER BY x.number DESC LIMIT 1) le ON true
                 WHERE e.id = v_layers[l];
            END IF;
            v_inputs := greatest(v_inputs, coalesce(v_env_number, 0));
            levels := levels || json_build_object('environment', v_layers[l], 'row', coalesce(v_row, false), 'item', v_item, 'digests', v_digests, 'seal', v_seal,
                                                  'newest', v_newest, 'number', v_number::text, 'change', v_change, 'env', level_env);
            IF v_route IS NOT NULL AND v_item IS NOT NULL THEN
                v_serving := v_item;
            END IF;
        END LOOP;
        IF v_serving IS NOT NULL THEN
            -- Its editor's principal, as a use reads its caller's: their row and grants, and their object's newest change.
            v_editor := CASE WHEN jsonb_typeof(v_serving) = 'object' AND jsonb_typeof(v_serving -> 'savedBy') = 'string' THEN v_serving ->> 'savedBy' END;
            IF v_editor IS NOT NULL THEN
                SELECT json_build_object(
                           'principal', v_editor, 'status', m.status, 'owner', m.owner, 'role', m.role, 'scope', m.scope, 'generation', m.generation, 'seal', m.seal,
                           'g_project', gr.g_project, 'g_environment', gr.g_environment, 'g_slug', gr.g_slug, 'g_role', gr.g_role, 'g_expires', gr.g_expires,
                           'last', lm.seal, 'number', lm.number::text, 'old', lm.payload::jsonb ->> 'old',
                           'change', CASE WHEN lm.number IS NOT NULL THEN json_build_array(lm.at, lm.request_id, lm.actor, lm.payload, lm.mac) END,
                           'access', (SELECT a.seq::text FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v_editor AND a.decision = 'allow'
                                        AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke')
                                      ORDER BY a.seq DESC LIMIT 1)),
                       lm.number
                  INTO editor, v_number
                  FROM (SELECT 1) one
                  LEFT JOIN public.principals m ON m.principal = v_editor
                  LEFT JOIN LATERAL (
                      SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                             array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at::text) AS g_expires
                        FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                       WHERE g.principal = v_editor
                  ) gr ON m.status IS NOT NULL
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = public.log_object('principal', v_editor) ORDER BY x.number DESC LIMIT 1
                  ) lm ON true;
                v_inputs := greatest(v_inputs, coalesce(v_number, 0));
            END IF;
            -- The keys its save stored, each resolved by name through the chain (0051), with the app's rows of it.
            names := CASE WHEN jsonb_typeof(v_serving) = 'object' AND jsonb_typeof(v_serving -> 'keys') = 'array'
                          THEN ARRAY(SELECT k FROM jsonb_array_elements_text(v_serving -> 'keys') WITH ORDINALITY t (k, i) ORDER BY i) ELSE '{}'::text[] END;
            WITH q AS (SELECT q.key, q.k FROM unnest((SELECT names)) WITH ORDINALITY q (key, k)),
            held AS (
                SELECT q.k, h.id, h.holder FROM q LEFT JOIN LATERAL (
                    SELECT x.id, l.id AS holder
                      FROM unnest((SELECT v_layers)) WITH ORDINALITY l (id, depth)
                      LEFT JOIN public.secrets x ON x.project_id = v_project AND x.environment_id = l.id AND x.key = q.key AND x.archived_at IS NULL
                     WHERE x.id IS NOT NULL
                        OR (l.depth < cardinality(v_layers)
                            AND EXISTS (SELECT 1 FROM public.dismissed_keys d WHERE d.environment_id = l.id AND d.key = q.key AND d.restored_at IS NULL))
                     ORDER BY l.depth LIMIT 1
                ) h ON true
            )
            SELECT array_agg(held.id ORDER BY held.k), array_agg(held.holder ORDER BY held.k),
                   array_agg(json_build_object('id', held.id, 'sensitive', sv.sensitive, 'secret', to_json(s), 'version', to_json(sv),
                                               'held', CASE WHEN held.id IS NOT NULL AND held.holder IS DISTINCT FROM v_np THEN json_build_object('environmentId', held.holder, 'slug', e.slug) END)
                             ORDER BY held.k)
              INTO v_ids, v_holders, v_resolved
              FROM held
              LEFT JOIN public.secrets s ON s.id = held.id
              LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
              LEFT JOIN public.environments e ON e.id = held.holder AND held.holder IS DISTINCT FROM v_np;
            v_n := greatest(0, least(cardinality(names) - p_offset, p_limit));
            -- The vault's ids, for these keys, are their names' now, at the reading it picked: each key's use, by them.
            v_right := coalesce(p_use AND p_secrets IS NOT NULL AND cardinality(p_secrets) = v_n AND v_n > 0 AND p_reading IS NOT DISTINCT FROM v_reading
                                AND p_credential = v_credential, false);
            FOR k IN 1 .. v_n LOOP
                EXIT WHEN NOT v_right;
                v_right := p_secrets[k] IS NOT DISTINCT FROM v_ids[p_offset + k]
                    AND p_places[k] IS NOT DISTINCT FROM (CASE WHEN v_ids[p_offset + k] IS NULL OR v_holders[p_offset + k] IS DISTINCT FROM v_np THEN v_np END);
            END LOOP;
            IF v_right THEN
                -- A second round's keys take the principal's lock, exclusive, before any (StrongestFirst); the fence is held.
                IF p_lock IS NOT NULL THEN PERFORM pg_advisory_xact_lock(1668244066, hashtext(p_lock)); END IF;
                FOR k IN 1 .. v_n LOOP
                    -- A key with no request: one a second round does not make again (its use made in the first), only checked.
                    IF p_requests[k] IS NULL THEN
                        answers := array_append(answers, NULL::json);
                        CONTINUE;
                    END IF;
                    answers := answers || public.use_credential(
                        v_credential, p_secrets[k], p_requests[k], p_at, p_purpose, p_places[k], p_macs[k], p_deadline,
                        CASE WHEN p_covers[k] > v_inputs THEN p_covers[k] END, p_cover_ats[k], p_cover_requests[k], NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint,
                        NULL::bytea, NULL::text, NULL::text, NULL::text,
                        coalesce(p_decided[k], false), false, NULL::text[], NULL::boolean, NULL::text[], NULL::jsonb,
                        coalesce(p_way, 0::smallint), p_principal, false, v_route
                    );
                END LOOP;
            END IF;
        END IF;
    END route;
    -- A light gate whose statement made no use (a personal config, a chain cut, no item, or ids that are not the names'
    -- now): the whole gate, under the fence still held, its rows the vault's to decide the caller on, as without it.
    IF (g ->> 'state') = 'stood' AND NOT coalesce(v_right, false) THEN
        gate := public.use_credential(
            NULL::uuid, NULL::uuid, 0::bigint, p_at, p_purpose, NULL::uuid, p_read_mac, p_deadline,
            NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint,
            p_token_hash, CASE WHEN v_reading = 1 THEN p_project END, CASE WHEN v_reading = 1 THEN p_environment END, NULL::text,
            false, v_reading = 2,
            CASE WHEN v_reading = 2 AND p_project IS NOT NULL THEN ARRAY[p_project || '/' || p_environment] ELSE '{}'::text[] END,
            p_signin, p_issuers, p_roles,
            0::smallint, NULL::text, true, NULL::text, false
        );
    END IF;
    -- The handle's places by path, as named now, for the vault's map to pick the next reading by (`made_for`): on an
    -- answer that makes no use, the only one whose reading the map may have picked wrong (T200: a use made by the map's
    -- ids was made at the reading it picked, which this statement's rows pick too).
    IF v_handle AND p_named IS NOT NULL AND NOT coalesce(v_right, false) THEN
        made_for := CASE WHEN coalesce(pg_input_is_valid(v_places, 'jsonb'), false) AND jsonb_typeof(v_places::jsonb) = 'array' THEN (
            SELECT coalesce(json_agg(p.path) FILTER (WHERE p.path IS NOT NULL), '[]'::json)
              FROM (
                  -- Each place by its environment's key, its id read as a uuid where it is one: a subquery per place, one
                  -- index probe each, which no plan joins (a join, planned for any values, hashed every environment: 114
                  -- buffers at 10k; review r1 of #464).
                  SELECT (SELECT q.slug || '/' || e.slug || CASE WHEN coalesce(x ->> 'personal', 'false') = 'true' THEN '@me' ELSE '' END
                            FROM public.environments e JOIN public.projects q ON q.id = e.project_id
                           WHERE e.id = CASE WHEN jsonb_typeof(x) = 'object' AND coalesce(pg_input_is_valid(x ->> 'environmentId', 'uuid'), false)
                                             THEN (x ->> 'environmentId')::uuid END
                             AND e.slug NOT LIKE '%~%' AND q.slug NOT LIKE '%~%') AS path
                    FROM jsonb_array_elements(v_places::jsonb) x
              ) p) ELSE '[]'::json END;
    END IF;
    IF v_unstood THEN
        RETURN json_build_object('gate', gate, 'reading', v_reading, 'route', v_route, 'made_for', made_for, 'stood', false);
    END IF;
    IF v_personal THEN
        RETURN json_build_object('gate', gate, 'reading', v_reading, 'route', v_route, 'made_for', made_for, 'stood', true, 'place', v_np, 'personal', true);
    END IF;
    IF v_chain_cut THEN
        RETURN json_build_object('gate', gate, 'reading', v_reading, 'route', v_route, 'made_for', made_for, 'stood', true, 'place', v_np, 'cut', true);
    END IF;
    RETURN json_build_object(
        'gate', gate, 'reading', v_reading, 'route', v_route, 'made_for', made_for, 'stood', true, 'place', v_np, 'project', v_project,
        'levels', array_to_json(levels), 'editor', editor, 'keys', to_json(names), 'resolved', array_to_json(coalesce(v_resolved, '{}')),
        'made', coalesce(v_right, false), 'rows', array_to_json(answers)
    );
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.use_stands(p_credential uuid, p_place uuid, p_purpose smallint, p_at bigint, p_roles jsonb)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE PARALLEL SAFE
AS $function$
BEGIN
    RETURN coalesce((
        SELECT k.live AND (k.c_scope IS NULL OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements(k.c_scope) g
                     WHERE g.value ->> 'projectId' = k.e_project::text AND (g.value ->> 'environmentId' IS NULL OR g.value ->> 'environmentId' = k.e_id::text)
                       AND coalesce(CASE WHEN g.value ? 'permissions' THEN g.value -> 'permissions' -> CASE WHEN k.guarded THEN 'protected' ELSE 'normal' END
                                         ELSE p_roles -> 'roles' -> (g.value ->> 'role') -> CASE WHEN k.guarded THEN 'protected' ELSE 'permissions' END END @> k.wanted, false)))
           AND ((public.use_admits(k.m_scope -> 'projects', k.e_project::text) AND public.use_admits(k.m_scope -> 'environments', k.e_slug)
                 AND coalesce(coalesce(k.r_value -> 'instanceRoles' -> k.role, p_roles -> 'instanceRoles' -> k.role) -> CASE WHEN k.guarded THEN 'protected' ELSE 'permissions' END @> k.wanted, false))
             OR EXISTS (
                    SELECT 1 FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                     WHERE g.principal = k.principal AND (g.expires_at IS NULL OR g.expires_at > p_at)
                       AND coalesce(g.project_id, ge.project_id) = k.e_project AND (g.environment_id IS NULL OR g.environment_id = k.e_id)
                       AND coalesce(coalesce(k.r_value -> 'roles' -> g.role, p_roles -> 'roles' -> g.role) -> CASE WHEN k.guarded THEN 'protected' ELSE 'permissions' END @> k.wanted, false)))
          FROM (
              -- Each row by its key alone, what ends the credential weighed here: a condition on `revoked_at` would
              -- let a generic plan take the live credentials' partial index and read them all (R48).
              SELECT c.revoked_at IS NULL AND m.status = 'active' AND m.generation = c.generation
                       AND coalesce(p_at < floor(extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint, true) AS live,
                     c.principal, e.id AS e_id, e.project_id AS e_project, e.slug AS e_slug,
                     c.principal LIKE 'user:%' AND coalesce(e.protected, false) AS guarded,
                     to_jsonb(CASE WHEN p_purpose % 256 = 4 THEN 'secret.use' ELSE 'secret.read' END) AS wanted,
                     -- A scope that is no list stands as none: the rule reads it as nothing, and refuses.
                     CASE WHEN c.scope IS NOT NULL AND pg_input_is_valid(c.scope, 'jsonb') AND jsonb_typeof(c.scope::jsonb) = 'array' THEN c.scope::jsonb END AS c_scope,
                     CASE WHEN r.value IS NOT NULL AND pg_input_is_valid(r.value, 'jsonb') THEN r.value::jsonb END AS r_value,
                     -- `storedRole` (@coffre/db/grants) for a person: their role, and its scope; one that does not parse, everywhere.
                     sr.role,
                     CASE WHEN sr.role = 'member' OR m.scope IS NULL OR NOT pg_input_is_valid(m.scope, 'jsonb') THEN '{"projects": "all", "environments": "all"}'::jsonb
                          ELSE m.scope::jsonb END AS m_scope
                FROM public.credentials c
                JOIN public.principals m ON m.principal = c.principal
                JOIN public.environments e ON e.id = p_place
                LEFT JOIN public.log_config r ON r.name = 'roles'
                CROSS JOIN LATERAL (
                    SELECT CASE WHEN c.principal NOT LIKE 'user:%' THEN 'member'
                                WHEN m.role IS NULL THEN CASE WHEN m.owner THEN 'admin' ELSE 'member' END
                                WHEN p_roles -> 'instanceRoles' ? m.role THEN m.role
                                ELSE 'member' END AS role
                ) sr
               WHERE c.id = p_credential
          ) k
    ), false);
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.write_inputs(p_token_hash bytea, p_project text, p_environment text, p_keys text[])
 RETURNS text
 LANGUAGE plpgsql
 STABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
 SET "TimeZone" TO 'UTC'
AS $function$
DECLARE
    v jsonb;
BEGIN
    SELECT jsonb_build_object(
        'credential', CASE WHEN c.id IS NOT NULL THEN jsonb_build_object(
            'row', to_jsonb(c) - 'last_used_at' - 'last_used_ip',
            'expires', floor(extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint,
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('credential', c.id::text) ORDER BY x.number DESC LIMIT 1)) END,
        'identity', to_jsonb(i) - 'last_sign_in_at',
        'principal', CASE WHEN c.id IS NOT NULL THEN jsonb_build_object(
            'row', to_jsonb(m),
            -- Every grant, lapsed ones too, an environment's with its project, in one order.
            'grants', (SELECT coalesce(jsonb_agg(to_jsonb(g) || jsonb_build_object('resolved_project', coalesce(g.project_id, ge.project_id))
                                 ORDER BY g.project_id, g.environment_id, g.environment_slug, g.role, g.expires_at), '[]'::jsonb)
                         FROM public.grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id WHERE g.principal = c.principal),
            -- 0.14's newest access entry about the principal (UsesSeeOldWrites), as a use reads it.
            'access', (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = c.principal AND a.decision = 'allow'
                AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('principal', c.principal) ORDER BY x.number DESC LIMIT 1)) END,
        'roles', jsonb_build_object('value', cfg.r_value, 'seal', cfg.r_seal,
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('roles', 'instance') ORDER BY x.number DESC LIMIT 1)),
        'policy', jsonb_build_object('value', cfg.p_value, 'seal', cfg.p_seal,
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1)),
        'policy14', (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1),
        'project', to_jsonb(p),
        'environment', CASE WHEN e.id IS NOT NULL THEN jsonb_build_object(
            'row', to_jsonb(e),
            'newest', (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('environment', e.id::text) ORDER BY x.number DESC LIMIT 1)) END,
        -- Each key named, in the order asked, by its name in the place: its row (archived or not) and its current
        -- version, or none; and its object's newest change. A probe each, by the key's index (LIMIT 1: a lateral the
        -- planner keeps a probe, as `app_read`'s).
        'secrets', (SELECT coalesce(jsonb_agg(jsonb_build_object(
                'key', k.key,
                'row', to_jsonb(s),
                'version', CASE WHEN sv.id IS NOT NULL THEN jsonb_build_object(
                    'id', sv.id, 'version', sv.version, 'sensitive', sv.sensitive, 'kek_provider', sv.kek_provider, 'kek_id', sv.kek_id, 'kek_version', sv.kek_version,
                    'wrapped_dek', encode(sv.wrapped_dek, 'hex'),
                    -- A plain value by its digest, as its object holds it (`plainDigest`), in hex (Postgres's base64 breaks
                    -- its lines): its text stays out of the read.
                    'digest', CASE WHEN sv.plaintext IS NOT NULL THEN encode(sha256(convert_to(sv.plaintext, 'UTF8')), 'hex') END) END,
                'newest', CASE WHEN s.id IS NOT NULL THEN (SELECT to_jsonb(x) FROM public.log_changes x WHERE x.object = public.log_object('secret', s.id::text) ORDER BY x.number DESC LIMIT 1) END
            ) ORDER BY k.ord), '[]'::jsonb)
              FROM unnest(p_keys) WITH ORDINALITY k (key, ord)
              LEFT JOIN LATERAL (
                  SELECT * FROM public.secrets x WHERE x.project_id = e.project_id AND x.environment_id = e.id AND x.key = k.key LIMIT 1
              ) s ON e.id IS NOT NULL
              LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id)
    ) INTO v
      FROM (SELECT 1) one
      LEFT JOIN public.credentials c ON c.token_hash = p_token_hash
      LEFT JOIN public.identities i ON i.id = c.identity_id
      LEFT JOIN public.principals m ON m.principal = c.principal
      LEFT JOIN LATERAL (
          SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                 max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
            FROM public.log_config g
      ) cfg ON true
      -- Standing slugs only, as `app_read` resolves them: a tombstone's is no place.
      LEFT JOIN public.projects p ON p.slug = p_project AND p.slug NOT LIKE '%~%'
      LEFT JOIN public.environments e ON e.project_id = p.id AND e.slug = p_environment AND e.slug NOT LIKE '%~%';
    RETURN v::text;
END
$function$;
