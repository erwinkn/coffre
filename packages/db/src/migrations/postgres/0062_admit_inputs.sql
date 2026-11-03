-- 0.16, T179 PR 5: a member add in three round trips (docs/design/two-trips.md, "A member add", "As built: PR 5"; formal/Writing.tla, the add; formal/WriteLocks.tla, AddLocks). Additive (AGENTS.md, "expand, then contract"): three functions, and `change_input_strict` holding a change that names its read to the hold of that read, as 0061 holds `app_change_strict`'s. Only this release's code calls any of them.
--
-- - `admit_inputs`, the read: everything the vault's decision about a first add weighs, in one snapshot (STABLE), as one canonical text (`jsonb` rendered), as `write_inputs` reads a key write's: the credential of the token's hash and its identity (every column but their last use), the caller's member row, its grants and its newest 0.14 access entry, the roles and the policy, the newest 0.14 policy change; the member asked for, by its principal: its row (none, for a first add), its grants, its newest 0.14 access entry; and the scope's projects by slug, in the order asked. Each object with its newest change in `log_changes`, whole, which the vault holds to its MAC (T190) and to its seal (StaleFirst), and whose number the hold compares (ReadByNumber). No clock: the hold must read the same bytes. Owned by the owner and granted to no login: its two callers below run it as the owner.
-- - `admit_read`, the vault's first statement: the read, and the app's rows of the caller as `app_read` reads them (the credential, its identity and the newest policy change, no place). No lock: nothing is numbered, and the write holds the read again under the fence (formal/Writing.tla, ARead).
-- - `admit_hold`, the vault's, in the write's transaction, after the members' rows and 0.14's head (`lockMembers`, then the head, as every decision takes them): the issue lock shared and the fence exclusive, as `change_input` and 0.14's `member.add` trigger take them; then, in a statement of its own after the locks, the read again, and `coffre_moved` (CF001) unless its SHA-256 is the one the vault decided on (ReadHeld). Holding, it marks its transaction with that digest, as `hold_inputs` does, which `change_input_strict` then requires of a change that names one.
CREATE FUNCTION admit_inputs(p_token_hash bytea, p_principal text, p_scope text[]) RETURNS text
    LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp SET bytea_output = 'hex' SET "TimeZone" = 'UTC' SET jit = off AS $$
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
                         FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id WHERE g.principal = c.principal),
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
                         FROM public.vault_grants g WHERE g.principal = p_principal),
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
      LEFT JOIN public.vault_members m ON m.principal = c.principal
      LEFT JOIN public.vault_members sm ON sm.principal = p_principal
      LEFT JOIN LATERAL (
          SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                 max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
            FROM public.log_config g
      ) cfg ON true;
    RETURN v::text;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION admit_inputs(bytea, text, text[]) FROM PUBLIC;
--> statement-breakpoint
CREATE FUNCTION admit_read(p_at bigint, p_token_hash bytea, p_principal text, p_scope text[]) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET bytea_output = 'hex' SET jit = off AS $$
DECLARE
    v_inputs text;
    v_app text;
BEGIN
    IF p_token_hash IS NULL OR p_principal IS NULL THEN
        RAISE EXCEPTION 'an add names its token and the member it adds' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- Its Worker's clock ahead by over a minute (0022 says why): nothing read.
    IF p_at IS NULL OR p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN RETURN json_build_object('state', 'ahead'); END IF;
    -- One statement, one snapshot: the read and the app's rows of the same moment.
    SELECT public.admit_inputs(p_token_hash, p_principal, p_scope),
           (public.app_read(p_token_hash, NULL, NULL, NULL)::jsonb || jsonb_build_object('now', CURRENT_TIMESTAMP))::text
      INTO v_inputs, v_app;
    RETURN json_build_object('state', 'read', 'inputs', v_inputs, 'digest', encode(sha256(convert_to(v_inputs, 'UTF8')), 'hex'), 'app', v_app);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION admit_read(bigint, bytea, text, text[]) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION admit_read(bigint, bytea, text, text[]) TO coffre_vault;
--> statement-breakpoint
CREATE FUNCTION admit_hold(p_token_hash bytea, p_principal text, p_scope text[], p_expected bytea) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
BEGIN
    -- As `change_input` and 0.14's `member.add` trigger take them: the issue lock shared, then the fence exclusive
    -- (IssueBeforeFence), after the members' rows and 0.14's head, which the add's transaction took first (MembersFirst).
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    -- The read again, in a statement after the locks (HoldAfterFence): every change committed before them is in it.
    IF p_expected IS NULL OR sha256(convert_to(public.admit_inputs(p_token_hash, p_principal, p_scope), 'UTF8')) IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'coffre_moved: what the add was decided on changed since the vault read it' USING ERRCODE = 'CF001';
    END IF;
    PERFORM set_config('coffre.write_inputs', encode(p_expected, 'hex'), true);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION admit_hold(bytea, text, text[], bytea) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION admit_hold(bytea, text, text[], bytea) TO coffre_vault;
--> statement-breakpoint
-- `change_input_strict` as 0052 made it, but a change whose payload names the read it was decided on (`inputs`, the
-- read's SHA-256 in hex) goes only in a transaction that held that read (`admit_hold`), as 0061 holds the app's: a code
-- path that forgot the hold fails every add, in the suites.
CREATE OR REPLACE FUNCTION change_input_strict(
    p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_value text, p_seal_from bytea, p_seal bytea, p_mac bytea
) RETURNS bigint
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    n bigint;
    inputs text := CASE WHEN p_payload IS NOT NULL THEN p_payload::jsonb ->> 'inputs' END;
BEGIN
    IF inputs IS NOT NULL AND inputs IS DISTINCT FROM current_setting('coffre.write_inputs', true) THEN
        RAISE EXCEPTION 'the % change % names a read its transaction did not hold', p_kind, p_id USING ERRCODE = 'invalid_parameter_value';
    END IF;
    n := public.change_input(p_kind, p_id, p_request, p_at, p_actor, p_payload, p_value, p_seal_from, p_seal, p_mac);
    IF n IS NULL THEN
        RAISE EXCEPTION 'coffre_moved: the % object % moved since it was read', p_kind, p_id USING ERRCODE = 'CF001';
    END IF;
    RETURN n;
END
$$;
