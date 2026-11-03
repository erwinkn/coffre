-- 0.16, T179 PR 3: a key write in five round trips (docs/design/two-trips.md, "A key write", "The read and its hold"; formal/Writing.tla). Additive (AGENTS.md, "expand, then contract"): three functions, and `app_change_strict` holding a change that names its read to the hold of that read. Only this release's code calls any of them.
--
-- - `write_inputs`, the read: everything the vault's decision about a key write weighs, in one snapshot (STABLE), as one canonical text (`jsonb` rendered): the credential of the token's hash and its identity (every column but their last use, which a use moves and no decision weighs), the principal's member row, its grants and its newest 0.14 access entry, the roles and the policy, the place by its slugs, each key by its name there with its current version, the newest 0.14 policy change; and each object's newest change in `log_changes`, whole, which the vault holds to its MAC (T190) and to its seal (StaleFirst), and whose number the hold compares (ReadByNumber). No clock: the hold must read the same bytes. `bytea_output` and `TimeZone` pinned, so that its text is the same whichever login, and whichever session, asks. Owned by the owner and granted to no login: its two callers below run it as the owner.
-- - `write_request`, the vault's one statement: the fence shared, then, in a statement of its own after the lock (so its snapshot sees every change committed before it was held), the read, the app's rows of the request as `app_read` reads them, and the request's number, from `log_number` (RequestUnderFence: no change is numbered between the read and the number). Answers the read with its SHA-256, which the vault's changes carry as `inputs`.
-- - `hold_inputs`, the app's: the issue lock shared and the fence exclusive, as `app_change` takes them; then, in a statement of its own after the locks, the read again, and `coffre_moved` (CF001) unless its SHA-256 is the one the vault decided on (ReadHeld). Holding, it marks its transaction with that digest, which `app_change_strict` then requires of a change that names one.
CREATE FUNCTION write_inputs(p_token_hash bytea, p_project text, p_environment text, p_keys text[]) RETURNS text
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
            -- Every grant, lapsed ones too, an environment's with its project, in one order.
            'grants', (SELECT coalesce(jsonb_agg(to_jsonb(g) || jsonb_build_object('resolved_project', coalesce(g.project_id, ge.project_id))
                                 ORDER BY g.project_id, g.environment_id, g.environment_slug, g.role, g.expires_at), '[]'::jsonb)
                         FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id WHERE g.principal = c.principal),
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
      LEFT JOIN public.vault_members m ON m.principal = c.principal
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
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION write_inputs(bytea, text, text, text[]) FROM PUBLIC;
--> statement-breakpoint
CREATE FUNCTION write_request(p_at bigint, p_token_hash bytea, p_project text, p_environment text, p_keys text[]) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET bytea_output = 'hex' SET jit = off AS $$
DECLARE
    v_inputs text;
    v_app text;
    v_number bigint;
BEGIN
    IF p_token_hash IS NULL OR p_project IS NULL OR p_environment IS NULL OR p_keys IS NULL OR cardinality(p_keys) = 0 THEN
        RAISE EXCEPTION 'a write names its token, its place and its keys' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- Its Worker's clock ahead by over a minute (0022 says why): nothing read.
    IF p_at IS NULL OR p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN RETURN json_build_object('state', 'ahead'); END IF;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    -- A statement of its own, after the lock: its snapshot is taken now, and sees every change committed before the
    -- fence was held; none is numbered until this one's transaction ends.
    SELECT public.write_inputs(p_token_hash, p_project, p_environment, p_keys),
           (public.app_read(p_token_hash, p_project, p_environment, p_keys)::jsonb || jsonb_build_object('now', CURRENT_TIMESTAMP))::text,
           nextval('public.log_number')
      INTO v_inputs, v_app, v_number;
    RETURN json_build_object('state', 'read', 'number', v_number::text, 'inputs', v_inputs,
        'digest', encode(sha256(convert_to(v_inputs, 'UTF8')), 'hex'), 'app', v_app);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION write_request(bigint, bytea, text, text, text[]) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION write_request(bigint, bytea, text, text, text[]) TO coffre_vault;
--> statement-breakpoint
CREATE FUNCTION hold_inputs(p_token_hash bytea, p_project text, p_environment text, p_keys text[], p_expected bytea) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
BEGIN
    -- As `app_change` takes them: the issue lock shared, then the fence exclusive (IssueBeforeFence), after 0.14's head,
    -- which the app's transaction took first.
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    -- The read again, in a statement after the locks (HoldAfterFence): every change committed before them is in it.
    IF p_expected IS NULL OR sha256(convert_to(public.write_inputs(p_token_hash, p_project, p_environment, p_keys), 'UTF8')) IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'coffre_moved: what the write was decided on changed since the vault read it' USING ERRCODE = 'CF001';
    END IF;
    PERFORM set_config('coffre.write_inputs', encode(p_expected, 'hex'), true);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION hold_inputs(bytea, text, text, text[], bytea) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION hold_inputs(bytea, text, text, text[], bytea) TO coffre_app;
--> statement-breakpoint
-- `app_change_strict` as 0052 made it, but a change whose payload names the read it was decided on (`inputs`, the
-- read's SHA-256 in hex) goes only in a transaction that held that read (`hold_inputs`): a code path that forgot the hold
-- fails every write, in the suites. It guards against coffre's own code: an app login that skips it is a database writer
-- (R64), and what it cannot do is make a change the vault did not decide, whose MAC the checkpointer checks.
CREATE OR REPLACE FUNCTION app_change_strict(
    p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_seal_from bytea, p_seal bytea, p_mac bytea, p_restores bytea
) RETURNS bigint
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    n bigint;
    inputs text := CASE WHEN p_payload IS NOT NULL THEN p_payload::jsonb ->> 'inputs' END;
BEGIN
    IF inputs IS NOT NULL AND inputs IS DISTINCT FROM current_setting('coffre.write_inputs', true) THEN
        RAISE EXCEPTION 'the % change % names a read its transaction did not hold', p_kind, p_id USING ERRCODE = 'invalid_parameter_value';
    END IF;
    n := public.app_change(p_kind, p_id, p_request, p_at, p_actor, p_payload, p_seal_from, p_seal, p_mac, p_restores);
    IF n IS NULL THEN
        RAISE EXCEPTION 'coffre_moved: the % object % moved since it was read', p_kind, p_id USING ERRCODE = 'CF001';
    END IF;
    RETURN n;
END
$$;
