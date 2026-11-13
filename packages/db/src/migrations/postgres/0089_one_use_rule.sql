-- 0.16.0, T274 (V2a; state-rows.md, section 3, "Two use statements, one rule"): `use_credential` held its statement four
-- times, probing or from the isolate's seals, plain or through a place or a reference, its rule in each, and went from
-- one form to another in a loop (`reprobe`, `whole`). Now it holds two statements and the rule once. The full statement
-- is the use's definition: it reads what the four read, by the same keys, and answers every call alone; the seal probes
-- ride a key that is null when the isolate's seals are still the log's (no index scan descends for a null), a
-- reference's rows a condition on the key's own row, and the place read through an id that is null for a use by ids of
-- a key the place holds. The lean statement, the old cached plain form, is a fast path in front of it for the common
-- use, and answers what the full one would or hands off (`whole`); it exists only because Postgres sets up every node
-- of a plan on each run, read or not, and the full plan costs a lean use about 130 us more of it. The rule is
-- `use_refused` then `use_lock`, SQL functions the planner inlines into both. Same locks, in the same order, and the
-- same re-checks: the fence shared before the statements, the principal's lock only after the vault decided, the bulk
-- write in a statement of its own. The route's read (its levels, its item's editor, the keys it names), which a route's
-- named call and `use_route` each held a copy of, is one function both call, `use_route_read`. No login may call any
-- of the three helpers.
-- The warm-up's mark moves on (`coffre.use_planned`), so a session plans both statements before it holds the fence.
-- A route's read (T205; T200), as both `use_route` and a route's named call in `use_credential` make it, written once:
-- each level of the place's chain (`p_layers`, nearest first), its environment's row, seal and newest change, and,
-- through the first level whose definitions hold the route's item, those definitions and their newest change; that
-- item's editor's principal, as a use reads its caller's; the keys the item names; and the newest change of these
-- inputs, which a cover must be past (`inputs`). A null route reads every item, and none serves.
CREATE OR REPLACE FUNCTION public.use_route_read(p_layers uuid[], p_route text, OUT levels json, OUT serving jsonb, OUT editor json, OUT names text[], OUT inputs bigint)
 LANGUAGE plpgsql
AS $function$
DECLARE
    v_levels json[] := '{}';
    v_item jsonb;
    v_digests bytea;
    v_seal bytea;
    v_row boolean;
    v_number bigint;
    v_newest bytea;
    v_change json;
    level_env json;
    v_env_number bigint;
    v_editor text;
BEGIN
    inputs := 0;
    names := '{}';
    -- Each level, nearest first: its definitions through the first whose row holds the route's item (every level's, for
    -- every item), and every level's environment, which the keys resolve through whatever level serves (review r2).
    FOR l IN 1 .. cardinality(p_layers) LOOP
        v_item := NULL; v_digests := NULL; v_seal := NULL; v_row := NULL; v_number := NULL; v_newest := NULL; v_change := NULL;
        -- The level's environment, its row and seal and its object's newest change: the chain read from `parent_id` is
        -- the vault's to check link by link, as the rows say it, before any level's item serves (a parent re-pointed
        -- around the log would graft another environment's definitions onto this one's keys). Through the level that
        -- serves, its definitions and their object's newest change too, in the same statement (T200), each read by the
        -- level's id whether or not its environment's row is there.
        IF serving IS NULL THEN
            SELECT CASE WHEN p_route IS NULL THEN p.items ELSE p.items -> p_route END, p.digests, p.seal, p.environment_id IS NOT NULL,
                   lp.number, lp.seal, CASE WHEN lp.number IS NOT NULL THEN json_build_array(lp.at, lp.request_id, lp.actor, lp.payload, lp.mac) END,
                   CASE WHEN e.id IS NOT NULL THEN json_build_object('project', e.project_id, 'slug', e.slug, 'owner', e.owner, 'parent', e.parent_id, 'protected', e.protected,
                                     'archived', e.archived_at IS NOT NULL, 'project_archived', q.archived_at IS NOT NULL, 'seal', e.seal, 'last', le.seal,
                                     'change', CASE WHEN le.number IS NOT NULL THEN json_build_array(le.at, le.request_id, le.actor, le.payload, le.mac) END) END,
                   le.number
              INTO v_item, v_digests, v_seal, v_row, v_number, v_newest, v_change, level_env, v_env_number
              FROM (SELECT p_layers[l] AS id) lv
              LEFT JOIN public.proxy_definitions p ON p.environment_id = lv.id
              LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = ANY(ARRAY[public.log_object('proxy', lv.id::text)::uuid]) ORDER BY x.object DESC, x.number DESC LIMIT 1) lp ON true
              LEFT JOIN public.environments e ON e.id = lv.id
              LEFT JOIN public.projects q ON q.id = e.project_id
              LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = ANY(ARRAY[public.log_object('environment', e.id::text)::uuid]) ORDER BY x.object DESC, x.number DESC LIMIT 1) le ON e.id IS NOT NULL;
            inputs := greatest(inputs, coalesce(v_number, 0));
        ELSE
            SELECT json_build_object('project', e.project_id, 'slug', e.slug, 'owner', e.owner, 'parent', e.parent_id, 'protected', e.protected,
                                     'archived', e.archived_at IS NOT NULL, 'project_archived', q.archived_at IS NOT NULL, 'seal', e.seal, 'last', le.seal,
                                     'change', CASE WHEN le.number IS NOT NULL THEN json_build_array(le.at, le.request_id, le.actor, le.payload, le.mac) END),
                   le.number
              INTO level_env, v_env_number
              FROM public.environments e LEFT JOIN public.projects q ON q.id = e.project_id
              LEFT JOIN LATERAL (SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = ANY(ARRAY[public.log_object('environment', e.id::text)::uuid]) ORDER BY x.object DESC, x.number DESC LIMIT 1) le ON true
             WHERE e.id = p_layers[l];
        END IF;
        inputs := greatest(inputs, coalesce(v_env_number, 0));
        v_levels := v_levels || json_build_object('environment', p_layers[l], 'row', coalesce(v_row, false), 'item', v_item, 'digests', v_digests, 'seal', v_seal,
                                              'newest', v_newest, 'number', v_number::text, 'change', v_change, 'env', level_env);
        IF p_route IS NOT NULL AND v_item IS NOT NULL THEN
            serving := v_item;
        END IF;
    END LOOP;
    IF serving IS NOT NULL THEN
        -- Its editor's principal, as a use reads its caller's: their row and grants, and their object's newest change.
        v_editor := CASE WHEN jsonb_typeof(serving) = 'object' AND jsonb_typeof(serving -> 'savedBy') = 'string' THEN serving ->> 'savedBy' END;
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
                  SELECT x.number, x.at, x.request_id, x.actor, x.payload, x.seal, x.mac FROM public.log_changes x WHERE x.object = ANY(ARRAY[public.log_object('principal', v_editor)::uuid]) ORDER BY x.object DESC, x.number DESC LIMIT 1
              ) lm ON true;
            inputs := greatest(inputs, coalesce(v_number, 0));
        END IF;
        -- The keys its save stored, in order.
        names := CASE WHEN jsonb_typeof(serving) = 'object' AND jsonb_typeof(serving -> 'keys') = 'array'
                      THEN ARRAY(SELECT k FROM jsonb_array_elements_text(serving -> 'keys') WITH ORDINALITY t (k, i) ORDER BY i) ELSE '{}'::text[] END;
    END IF;
    levels := array_to_json(v_levels);
END
$function$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.use_route_read(uuid[], text) FROM PUBLIC;
--> statement-breakpoint
-- The use's rule (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416), written once for both of `use_credential`'s
-- statements, each of which calls it on the rows it read, as `coalesce(use_refused(...), use_lock(...))`: two rules, in
-- order. Refused: what no key decides comes first, a MAC by a retired key, the floor, the deadline, the clock, the cap's
-- config; then what the names decide, which the vault answers on the caller's standing first (`p_named`: no credential
-- of that token, no live place of those names), the ids the vault passed not the ones the names name now (`p_right`,
-- D153), and a named call's environment read through archived or its chain cut (`p_archived`). Then the lock: the
-- principal's, to enter its key in the cap's set (`lock`), or to move it on (`share`), unless the use writes no entry
-- (`p_silent`: a quiet use of no key or of a plain value). Null from both: the use is made. Plain SQL expressions, so
-- that the planner inlines them into each statement: no call at run time (not SECURITY DEFINER, no SET, no subquery,
-- each argument used more than once a column or a parameter, and `use_refused` VOLATILE, as `clock_timestamp` is).
-- No login may call either.
CREATE OR REPLACE FUNCTION public.use_refused(p_mac bytea, p_retired bytea[], p_floor bigint, p_at bigint, p_deadline bigint,
                                   p_configured boolean, p_named text, p_right boolean, p_archived boolean)
 RETURNS text
 LANGUAGE sql
AS $function$
SELECT CASE WHEN substring(p_mac FROM 1 FOR 4) = ANY(p_retired) THEN 'superseded'
            WHEN p_floor IS NULL OR p_at < p_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
            WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
            WHEN NOT p_configured THEN 'unconfigured'
            WHEN p_named IS NOT NULL THEN p_named
            WHEN NOT p_right THEN 'moved'
            WHEN p_archived THEN 'archived' END
$function$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.use_refused(bytea, bytea[], bigint, bigint, bigint, boolean, text, boolean, boolean) FROM PUBLIC;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.use_lock(p_principal text, p_locked boolean, p_moving boolean, p_silent boolean, p_in boolean, p_behind boolean)
 RETURNS text
 LANGUAGE sql
AS $function$
SELECT CASE WHEN p_principal IS NOT NULL AND NOT p_locked AND NOT p_silent AND NOT p_in THEN 'lock'
            WHEN p_principal IS NOT NULL AND NOT p_locked AND NOT p_moving AND NOT p_silent AND p_behind THEN 'share' END
$function$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.use_lock(text, boolean, boolean, boolean, boolean, boolean) FROM PUBLIC;
--> statement-breakpoint
-- No argument has a default, here and in every use function a runtime login calls: 0.15.0's call of 27 resolves to
-- none, and no 0.16 function answers it (#569, section 6). Made again, since a replace cannot drop a default.
DROP FUNCTION IF EXISTS public.use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint, bytea, text, text, text, boolean, boolean, text[], boolean, text[], jsonb, smallint, text, boolean, text, boolean, text);
--> statement-breakpoint
CREATE FUNCTION public.use_credential(p_credential uuid, p_secret uuid, p_request bigint, p_at bigint, p_purpose smallint, p_place uuid, p_mac bytea, p_deadline bigint, p_cover bigint, p_cover_at bigint, p_cover_request bigint, p_known bigint, p_known_mac bytea, p_cap_count integer, p_cap_window bigint, p_token_hash bytea, p_project text, p_environment text, p_key text, p_decided boolean, p_handle boolean, p_unless text[], p_signin boolean, p_issuers text[], p_roles jsonb, p_way smallint, p_principal text, p_forks boolean, p_route text, p_gate boolean, p_passkeys text)
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
    -- Whether the statement reads each input's newest change whatever the isolate's seals say: it passed none, or no cap.
    probe boolean := p_known IS NULL OR p_cap_count IS NULL OR p_cap_window IS NULL;
    -- The lean statement's refresh, from the cap the isolate passes; the full one works its own out from the cap it reads.
    c_refresh bigint := greatest(1, least(60000, p_cap_window / 10));
    -- Whether the call is the full statement's: it reads a place through (`p_place`), or is a named call, whose names and
    -- rows the app checks the lean statement reads none of (a named call always probes besides), or the lean statement
    -- handed it off.
    whole boolean := p_place IS NOT NULL OR p_token_hash IS NOT NULL;
    -- Whether this session has yet to plan the two statements (T131), and which the warm-up is at.
    dry boolean := current_setting('coffre.use_planned', true) IS DISTINCT FROM '0086';
    form integer := 0;
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
    -- What stands behind a person's credential (T216; docs/design/passkeys.md, sections 6.2 and 6.4), read with it under
    -- the fence and answered in the app's rows: its kind, generation and the passkey it names; that passkey's row, and
    -- whether its person holds a live passkey at its generation (2), has rows but none live at it (1), or none ever
    -- (null), as the app's own statement reads them (`heldSql`); and whether that passkey is live and theirs.
    v_kind text;
    v_generation integer;
    v_passkey_id uuid;
    v_passkey json;
    v_passkey_held smallint;
    v_backed boolean;
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
    -- The route read (`v_read`): its levels, its item's editor and the keys the item names (`use_route_read`), its item
    -- naming one key (`v_whole`), what the call answers of it (`v_route`), and the newest change of its inputs
    -- `use_credential` does not otherwise read, which a cover must be past (`v_inputs`).
    v_read boolean := false;
    v_whole boolean := false;
    v_route json;
    v_inputs bigint := 0;
    v_made_for boolean;
    v_levels json := '[]';
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
    -- What the app's config says of passkeys (T216): one of its three policies, or none (an app before T216, which runs
    -- the check itself before the call).
    IF p_passkeys IS NOT NULL AND p_passkeys NOT IN ('off', 'optional', 'required') THEN
        RAISE EXCEPTION 'a named call''s passkey policy is off, optional or required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_deadline IS NULL OR p_deadline > p_at + public.deadline_max() THEN r.state := 'late'; RETURN CASE WHEN v_routed THEN json_build_object('row', to_json(r), 'route', v_route) ELSE to_json(r) END; END IF;
    -- Its Worker's clock ahead by over a minute (0022 says why): checked here at no cost, and again in the statement.
    IF p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN r.state := 'ahead'; RETURN CASE WHEN v_routed THEN json_build_object('row', to_json(r), 'route', v_route) ELSE to_json(r) END; END IF;
    IF dry THEN
        -- The statement first runs dry, outside the fence, so that its planning's cold work (the catalog, the statistics,
        -- the indexes: tens of ms on a new connection) is done before this call holds the fence (T131).
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
            SELECT c.id, c.places, c.principal, c.kind, c.generation, c.passkey_id,
                   coalesce(p_signin, false) AND (c.kind <> 'browser' OR (x.provider || ':' || x.issuer_hash) = ANY (coalesce(p_issuers, '{}')))
              INTO v_credential, v_places, v_principal, v_kind, v_generation, v_passkey_id, v_accepted
              FROM public.credentials c LEFT JOIN public.identities x ON x.id = c.identity_id
             WHERE c.token_hash = p_token_hash;
            -- Then the passkey behind a person's session or token, with passkeys not `off` (`p_passkeys`; T216;
            -- passkeys.md, section 6.2, `passkeyStands`), as the app's own check has it: one that names a passkey is
            -- taken while that passkey is live, its person's at the credential's generation; one that names none, under
            -- `optional`, while its person holds no live passkey, never under `required`. Refused, it is `unknown` too,
            -- before anything else is read. Two probes of the passkeys' indexes and one by id, which nothing a request
            -- names moves; never for a handle, a service's token or a workload's, which the check exempts (R44). The
            -- MACs are the app's, which it checks on the rows answered (`app`), so that it reads none itself (a row a
            -- database writer forged is accepted here and refused there, 401, D154).
            IF v_credential IS NOT NULL AND coalesce(v_accepted, false) AND v_kind IN ('browser', 'cli', 'personal') AND p_passkeys IN ('optional', 'required') THEN
                SELECT to_json(k), coalesce(k.removed_at IS NULL AND k.principal = v_principal AND k.generation = v_generation, false),
                       CASE WHEN EXISTS (SELECT 1 FROM public.passkeys h WHERE h.principal = v_principal AND h.generation = v_generation AND h.removed_at IS NULL) THEN 2
                            WHEN EXISTS (SELECT 1 FROM public.passkeys h WHERE h.principal = v_principal) THEN 1 END
                  INTO v_passkey, v_backed, v_passkey_held
                  FROM (SELECT 1) one LEFT JOIN public.passkeys k ON k.id = v_passkey_id;
                v_accepted := CASE WHEN v_passkey_id IS NOT NULL THEN v_backed ELSE p_passkeys = 'optional' AND v_passkey_held IS DISTINCT FROM 2 END;
            END IF;
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
            -- The route (T205), for one who stands at the place, its chain whole (Routing.tla, StandingFirst): its levels, its
            -- item's editor and the keys the item names, read as `use_route` reads them (`use_route_read`). The one key the
            -- item names is resolved by that name below, as a code route's named call resolves its own (KeyByItem). An item
            -- of another number of keys, or none, resolves no key: the call reads on as one of no key at the place, its rows
            -- the vault's to decide the caller on, and the vault asks `use_route`.
            IF v_routed AND v_named IS NULL AND v_stands AND NOT v_cut AND NOT v_personal THEN
                SELECT x.levels, x.editor, x.names, x.inputs INTO v_levels, editor, names, v_inputs
                  FROM public.use_route_read(v_layers, p_route) x;
                v_key := CASE WHEN cardinality(names) = 1 THEN names[1] END;
                v_whole := v_key IS NOT NULL;
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
            -- A key named is read by its id; one the place does not hold, through the place (e1); one it inherits, by its
            -- id through the place, as a fork's read is.
            v_place := CASE WHEN v_secret IS NULL OR v_holder IS DISTINCT FROM v_np THEN v_np END;
            -- A route's: and the route read whole, one key named and resolved by that name (KeyByItem).
            v_right := coalesce(v_credential = p_credential, false) AND v_secret IS NOT DISTINCT FROM p_secret AND v_place IS NOT DISTINCT FROM p_place
                AND (NOT v_routed OR v_whole);
            IF v_read THEN
                v_route := json_build_object('place', v_np, 'project', v_np_project, 'levels', v_levels, 'editor', editor, 'keys', to_json(names),
                                             'made', v_right, 'keyed', v_key IS NOT NULL);
            END IF;
            IF NOT v_stands OR v_cut THEN
                -- No standing, or no live place, or a chain cut: answered on the place alone, as for a key it does not hold, probing,
                -- whatever the isolate passed: no cover, no seals (NoKeyBeforeStanding). Nothing is written or locked,
                -- as for any key the place does not hold.
                p_cover := NULL;
                probe := true;
            END IF;
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
                -- The app's rows of the request, as the statement answers them for a named call of no key at the place.
                r.app := json_build_object(
                    'now', CURRENT_TIMESTAMP, 'passkey', v_passkey, 'passkey_held', v_passkey_held, 'credential', (SELECT to_json(c) FROM public.credentials c WHERE c.id = v_credential),
                    'identity', (SELECT to_json(x) FROM public.credentials c JOIN public.identities x ON x.id = c.identity_id WHERE c.id = v_credential),
                    'policy', (SELECT a.seq::text FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1),
                    'project', (SELECT to_json(q) FROM public.projects q WHERE q.id = v_np_project),
                    'environment', (SELECT to_json(e) FROM public.environments e WHERE e.id = v_np),
                    'parent', CASE WHEN v_np_parent IS NOT NULL THEN (SELECT pe.slug FROM public.environments pe WHERE pe.id = v_np_parent) END,
                    'held', NULL::json, 'secrets', '[]'::json);
                RETURN CASE WHEN v_routed THEN json_build_object('row', to_json(r), 'route', v_route) ELSE to_json(r) END;
            END IF;
        END IF;
        -- Two statements, one rule (T274, V2a). The full statement is the use's definition: every row the decision weighs,
        -- each by its key, then the entry; it answers every call alone. The lean one is a fast path in front of it, for the
        -- common use: no place read through, a key with a version of its own, the isolate's seals still the log's. It reads
        -- a subset of the full one's rows by the same keys and must answer what the full one would, or hand off (`whole`),
        -- writing and locking nothing; the full one then runs, as the old forms' handoff did. Both decide by one rule,
        -- `use_refused` then `use_lock`, which the planner inlines into each. Two, not one: Postgres sets up every node of a plan on each run,
        -- run or not, and the full plan's probes and reference chain cost a lean use about 130 us of executor start-up.
        IF (dry AND form = 0) OR (NOT dry AND NOT probe AND NOT whole) THEN
            -- The isolate's seals, and its cap, read at the change it names: no probe, only whether a change came since.
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, f.retired,
                    w.principal AS p, c.kind AS c_kind, w.scope AS c_scope, w.revoked_at IS NOT NULL AS c_revoked,
                    floor(extract(epoch FROM w.expires_at) * 1000)::bigint AS c_expires, w.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal, w.generation AS c_generation, m.generation AS m_generation,
                    w.row AS w_row,
                    c.token_hash AS c_token_hash,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, s.seal AS s_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain, sv.plaintext AS v_plaintext,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e2.project_id) AS e2_project_archived, e2.seal AS e2_seal,
                    CASE WHEN e2.owner IS NOT NULL THEN e2.parent_id END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e4.project_id) AS e4_project_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN LATERAL (SELECT y.at_floor, y.retired FROM public.checkpoint_fence y WHERE y.only_row LIMIT 1) f ON true
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             (SELECT json_build_object('kind', 'policy', 'bulk', json_build_object('count', p.bulk_count, 'windowMs', p.bulk_window_ms))::text FROM public.policy p) AS p_value,
                             (SELECT p.seal FROM public.policy p) AS p_seal
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
                SELECT i.*, c_refresh AS refresh, cap.period,
                    -- A key with no version of its own, or a change since the isolate's seals: the full statement's.
                    CASE WHEN NOT i.cached OR (i.s_project IS NOT NULL AND i.s_version IS NULL) THEN 'whole'
                         ELSE coalesce(public.use_refused(p_mac, i.retired, i.at_floor, p_at, p_deadline, true, v_named, v_right, false),
                                       public.use_lock(i.p, locked, moving, v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false)),
                                                       coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false), i.bulk_last < cap.period)) END AS state,
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
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= cap.period
                        AND public.use_covered(p_cover_at, p_cover_request, p_cover, p_credential, p_secret, p_purpose, p_place, p_route), false) AS is_covered
                  FROM i
                  CROSS JOIN LATERAL (SELECT public.bulk_period(i.p, v_secret, p_at, c_refresh) AS period) cap
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place, route, phased)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place, p_route, true
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
                v.s_project, v.s_environment, v.s_version, NULL::uuid, v.s_seal, NULL::bytea,
                -- The slots it reads nothing of, e1, e3 and the source, as the full statement answers them for no row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid, NULL::bytea, NULL::bytea,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::uuid, NULL::boolean, false, NULL::bytea, NULL::bytea,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, NULL::bytea,
                NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::uuid, NULL::boolean, false, NULL::bytea, NULL::bytea,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, NULL::bytea,
                v.is_in, v.n_others, v.v_plaintext, NULL::boolean, v.e2_project_archived, NULL::boolean, v.e4_project_archived, NULL::uuid, NULL::uuid, v.c_generation, v.m_generation, v.c_token_hash,
                -- No app rows: they are a named call's, which never runs here. A named call's (`n_*`), set below; a binding's row.
                NULL::json,
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
            -- The use's one statement (V2a; state-rows.md, section 3): every row the decision weighs, each by its key, then
            -- the entry. It reads each input's newest change (`seeks`: the probe) unless the isolate's seals are still the
            -- log's: it named the log's newest change it knew (`p_known`), and that is still the newest. A key's reference
            -- and its source, and the place read through, are read only where the key has no version of its own or the place
            -- is another than the key's (`whole`): each row by an id the rows before it give, none where they give none.
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, sk.seeks, f.at_floor, f.retired,
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
                    ids.e1 AS e1_id, e1.project_id AS e1_project, e1.slug AS e1_slug, e1.owner AS e1_owner, e1.parent_id AS e1_parent, e1.protected AS e1_protected, e1.archived_at IS NOT NULL AS e1_archived, CASE WHEN e1.id IS NOT NULL THEN (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e1.project_id) END AS e1_project_archived, e1.seal AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, CASE WHEN e2.id IS NOT NULL THEN (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e2.project_id) END AS e2_project_archived, e2.seal AS e2_seal,
                    ids.e3 AS e3_id, e3.project_id AS e3_project, e3.slug AS e3_slug, e3.owner AS e3_owner, e3.parent_id AS e3_parent, e3.protected AS e3_protected, e3.archived_at IS NOT NULL AS e3_archived, CASE WHEN e3.id IS NOT NULL THEN (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e3.project_id) END AS e3_project_archived, e3.seal AS e3_seal,
                    CASE WHEN ve.owner IS NOT NULL THEN ve.parent END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, CASE WHEN e4.id IS NOT NULL THEN (SELECT q.archived_at IS NOT NULL FROM public.projects q WHERE q.id = e4.project_id) END AS e4_project_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last,
                    -- Each input's object key, computed once (a key in a probe's own condition is computed again for every row
                    -- it reads: 0022, decision 3), in the order of the probe's slots below: the way in, the principal, the
                    -- roles, the policy, the key, its source, then e1 to e4. No row, no key, and no probe: no index scan
                    -- descends for a null. None at all while the isolate's seals are still the log's.
                    CASE WHEN sk.seeks THEN ARRAY[public.log_object(w.kind, v_credential::text), public.log_object('principal', w.principal), public.log_object('roles', 'instance'),
                          public.log_object('policy', 'instance'), public.log_object('secret', v_secret::text), public.log_object('secret', ref.source_secret_id::text),
                          public.log_object('environment', ids.e1::text), public.log_object('environment', s.environment_id::text), public.log_object('environment', ids.e3::text),
                          public.log_object('environment', (CASE WHEN ve.owner IS NOT NULL THEN ve.parent END)::text)] END AS objects
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  CROSS JOIN LATERAL (SELECT probe OR NOT coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS seeks) sk
                  LEFT JOIN LATERAL (SELECT y.at_floor, y.retired FROM public.checkpoint_fence y WHERE y.only_row LIMIT 1) f ON true
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             (SELECT json_build_object('kind', 'policy', 'bulk', json_build_object('count', p.bulk_count, 'windowMs', p.bulk_window_ms))::text FROM public.policy p) AS p_value,
                             (SELECT p.seal FROM public.policy p) AS p_seal
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
                  -- A key with no version of its own is a reference while its newest reference row names a source and has not
                  -- ended (`ended_at`): an ended one's holder reads as no value, no source (`ended`). A key with a version reads
                  -- no reference: the condition is the subquery's, on the outer row alone, so it is checked before the scan.
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.secret_id = s.id AND y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.secret_id = s.id AND y.ended_at IS NULL THEN y.id END AS reference_id
                        FROM public.secret_references y WHERE s.current_version_id IS NULL AND y.secret_id <= s.id ORDER BY y.secret_id DESC, y.created_seq DESC LIMIT 1
                  ) ref ON true
                  LEFT JOIN public.secrets src ON src.id = ref.source_secret_id AND src.archived_at IS NULL
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.secret_id = src.id AND y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.secret_id = src.id AND y.ended_at IS NULL THEN y.id END AS reference_id
                        FROM public.secret_references y WHERE src.current_version_id IS NULL AND y.secret_id <= src.id ORDER BY y.secret_id DESC, y.created_seq DESC LIMIT 1
                  ) xref ON true
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
                SELECT i.*, cp.cap_count, cp.cap_window, cap.refresh, cap.period, pr.inputs, pr.changes,
                    coalesce(public.use_refused(p_mac, i.retired, i.at_floor, p_at, p_deadline, cp.cap_count IS NOT NULL AND cp.cap_window IS NOT NULL, v_named, v_right,
                                         p_token_hash IS NOT NULL AND NOT v_routed
                                           AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                                             OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut)),
                             public.use_lock(i.p, locked, moving, v_quiet AND (i.s_project IS NULL OR coalesce(i.v_plain, false)),
                                             coalesce(i.bulk_last > p_at - cp.cap_window - cap.refresh, false), i.bulk_last < cap.period)) AS state,
                    pr.c_last, pr.m_last, (pr.m_payload::jsonb ->> 'old')::bigint AS m_old, pr.r_last, pr.p_last, pr.s_last, pr.x_last, pr.e1_last, pr.e2_last, pr.e3_last, pr.e4_last,
                    coalesce(i.bulk_last > p_at - cp.cap_window - cap.refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - cp.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.bulk_cap o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - cp.cap_window - cap.refresh - public.deadline_max() - 60000
                             LIMIT cp.cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing
                    -- (CoverFresh), nor, probing, on one any input of has changed since. The isolate held a cover to the
                    -- seals it keeps when it read them.
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= cap.period AND p_cover > coalesce(pr.inputs, 0)
                        AND public.use_covered(p_cover_at, p_cover_request, p_cover, p_credential, p_secret, p_purpose, p_place, p_route), false) AS is_covered
                  FROM i
                  -- Each input's newest change, probed: one probe of log_changes_object_idx a slot, and the change's row, for the
                  -- columns its MAC covers (T190; the principal's payload names the 0.14 entry it accounts for), which the
                  -- vault checks before it holds a row to the seal recorded there. None while the isolate's seals are still the
                  -- log's: the condition is the subquery's, on `i` alone, so it is checked before any probe. A slot with no object
                  -- (no source, no place read through) is no row of the probe's, which it would find nothing for.
                  LEFT JOIN LATERAL (
                      SELECT max(ch.number) AS inputs,
                             json_object_agg(u.slot, json_build_array(ch.at, ch.request_id, ch.actor, ch.payload, ch.mac)) FILTER (WHERE ch.number IS NOT NULL) AS changes,
                             (array_agg(ch.seal) FILTER (WHERE u.n = 1))[1] AS c_last, (array_agg(ch.seal) FILTER (WHERE u.n = 2))[1] AS m_last,
                             (array_agg(ch.seal) FILTER (WHERE u.n = 3))[1] AS r_last, (array_agg(ch.seal) FILTER (WHERE u.n = 4))[1] AS p_last,
                             (array_agg(ch.seal) FILTER (WHERE u.n = 5))[1] AS s_last, (array_agg(ch.seal) FILTER (WHERE u.n = 6))[1] AS x_last,
                             (array_agg(ch.seal) FILTER (WHERE u.n = 7))[1] AS e1_last, (array_agg(ch.seal) FILTER (WHERE u.n = 8))[1] AS e2_last,
                             (array_agg(ch.seal) FILTER (WHERE u.n = 9))[1] AS e3_last, (array_agg(ch.seal) FILTER (WHERE u.n = 10))[1] AS e4_last,
                             (array_agg(ch.payload) FILTER (WHERE u.n = 2))[1] AS m_payload, (array_agg(ch.payload) FILTER (WHERE u.n = 4))[1] AS p_payload
                        FROM unnest(ARRAY['c', 'm', 'r', 'p', 's', 'x', 'e1', 'e2', 'e3', 'e4'], i.objects) WITH ORDINALITY u (slot, object, n)
                        LEFT JOIN LATERAL (
                            SELECT y.number, y.seal, y.at, y.request_id, y.actor, y.payload, y.mac FROM public.log_changes y
                             WHERE y.object = ANY(ARRAY[u.object::uuid]) ORDER BY y.object DESC, y.number DESC LIMIT 1
                        ) ch ON true
                       WHERE i.seeks AND u.object IS NOT NULL
                  ) pr ON true
                  -- The cap: the isolate's, read from the policy's newest change at the change it names, or that change's as
                  -- probed now (CapSealed, CapFromPolicy): every policy change logs the whole policy as its `value`.
                  CROSS JOIN LATERAL (
                      SELECT CASE WHEN i.seeks THEN (pr.p_payload::jsonb #>> '{value,bulk,count}')::integer ELSE p_cap_count END AS cap_count,
                             CASE WHEN i.seeks THEN (pr.p_payload::jsonb #>> '{value,bulk,windowMs}')::bigint ELSE p_cap_window END AS cap_window
                  ) cp
                  CROSS JOIN LATERAL (SELECT greatest(1, least(60000, cp.cap_window / 10)) AS refresh) r0
                  CROSS JOIN LATERAL (SELECT r0.refresh, public.bulk_period(i.p, v_secret, p_at, r0.refresh) AS period) cap
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place, route, phased)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place, p_route, true
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (v_quiet AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, v.inputs, v.seeks,
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
                    'now', CURRENT_TIMESTAMP, 'passkey', v_passkey, 'passkey_held', v_passkey_held, 'credential', v.c_row, 'identity', (SELECT to_json(x) FROM public.identities x WHERE x.id = (v.c_row ->> 'identity_id')::uuid),
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
        END IF;
        IF dry THEN
            -- The lean statement, then the full one; then the call itself, under the fence.
            form := form + 1;
            IF form < 2 THEN
                CONTINUE;
            END IF;
            PERFORM set_config('coffre.use_planned', '0086', false);
            dry := false;
            v_secret := p_secret;
            PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
            CONTINUE;
        END IF;
        -- A named call answered `moved` or `archived` is decided by the vault before anything else is done (T158, D153):
        -- it is read again probing, so that every row's newest seal is there to check, in this call.
        IF r.state IN ('moved', 'archived') AND p_token_hash IS NOT NULL AND NOT r.probed THEN
            probe := true;
            CONTINUE;
        END IF;
        -- Handed off by the lean statement: the full one reads it again, and every later read of the call is the full one's.
        IF r.state = 'whole' THEN
            whole := true;
            CONTINUE;
        END IF;
        -- Once it has probed, each later read of the call probes too.
        probe := probe OR r.probed;
        -- A use the statement took writes its entry or rides its cover, never neither: but a named one, or a route use's, of
        -- a key the place does not hold, or of a plain value, which writes none.
        IF r.state IS NULL AND r.number IS NULL AND r.covered IS NULL AND NOT (v_quiet AND (r.s_project IS NULL OR coalesce(r.v_plain, false))) THEN
            RAISE EXCEPTION 'a use wrote no entry and rode no cover' USING ERRCODE = 'XX000';
        END IF;
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
        b_period := public.bulk_period(r.c_principal, p_secret, p_at, b_refresh);
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
REVOKE ALL ON FUNCTION public.use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint, bytea, text, text, text, boolean, boolean, text[], boolean, text[], jsonb, smallint, text, boolean, text, boolean, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint, bytea, text, text, text, boolean, boolean, text[], boolean, text[], jsonb, smallint, text, boolean, text, boolean, text) TO coffre_vault;
--> statement-breakpoint
-- As 0057 says of the use's other helpers: `use_credential` runs as its owner, which may not be the login that made this.
DO $$
DECLARE
    v_owner name := (SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname = 'use_credential' AND pronamespace = 'public'::regnamespace);
BEGIN
    IF NOT has_function_privilege(v_owner, 'public.use_route_read(uuid[], text)'::regprocedure, 'EXECUTE') THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.use_route_read(uuid[], text) TO %I', v_owner);
    END IF;
    -- The planner inlines `use_refused` and `use_lock` only where the statement's owner may call them.
    IF NOT has_function_privilege(v_owner, 'public.use_refused(bytea, bytea[], bigint, bigint, bigint, boolean, text, boolean, boolean)'::regprocedure, 'EXECUTE') THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.use_refused(bytea, bytea[], bigint, bigint, bigint, boolean, text, boolean, boolean) TO %I', v_owner);
    END IF;
    IF NOT has_function_privilege(v_owner, 'public.use_lock(text, boolean, boolean, boolean, boolean, boolean)'::regprocedure, 'EXECUTE') THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION public.use_lock(text, boolean, boolean, boolean, boolean, boolean) TO %I', v_owner);
    END IF;
END
$$;
--> statement-breakpoint
-- `use_route` with no default either, each of its calls of `use_credential` naming every argument.
DROP FUNCTION IF EXISTS public.use_route(bytea, text, text, text, text, smallint, boolean, text[], jsonb, uuid, smallint, text, uuid, bigint, smallint, bigint, bytea, uuid[], uuid[], bigint[], bytea[], bigint[], bigint[], bigint[], boolean[], integer, integer, text, boolean, boolean, text);
--> statement-breakpoint
CREATE FUNCTION public.use_route(p_token_hash bytea, p_project text, p_environment text, p_named text, p_stable text, p_reading smallint, p_signin boolean, p_issuers text[], p_roles jsonb, p_credential uuid, p_way smallint, p_principal text, p_place uuid, p_at bigint, p_purpose smallint, p_deadline bigint, p_read_mac bytea, p_secrets uuid[], p_places uuid[], p_requests bigint[], p_macs bytea[], p_covers bigint[], p_cover_ats bigint[], p_cover_requests bigint[], p_decided boolean[], p_offset integer, p_limit integer, p_lock text, p_use boolean, p_light boolean, p_passkeys text)
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
    v_levels json := '[]';
    -- The newest change of the route's inputs this statement reads and `use_credential` does not: a cover must be past it.
    v_inputs bigint := 0;
    v_serving jsonb;
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
    v_planned boolean := current_setting('coffre.route_planned', true) IS NOT DISTINCT FROM '0082';
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
            0::smallint, NULL::text, true, NULL::text, v_light, p_passkeys => p_passkeys
        );
        v_gated := v_reading;
        EXIT WHEN p_named IS NULL OR v_attempt = 2;
        -- Held already, unless the gate refused before it took it: held now, for the reading picked again.
        PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    END LOOP;
    IF NOT v_planned AND v_handle AND p_named IS NOT NULL THEN
        PERFORM set_config('coffre.route_planned', '0082', false);
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
            p_way, p_principal, false, coalesce(v_route, 'every'), false, NULL::text
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
        -- Each level, nearest first, its item's editor and the keys it names (`use_route_read`).
        SELECT x.levels, x.serving, x.editor, x.names, x.inputs INTO v_levels, v_serving, editor, names, v_inputs
          FROM public.use_route_read(v_layers, v_route) x;
        IF v_serving IS NOT NULL THEN
            -- The keys its save stored, each resolved by name through the chain (0051), with the app's rows of it.
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
                        coalesce(p_way, 0::smallint), p_principal, false, v_route, false, NULL::text
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
            0::smallint, NULL::text, true, NULL::text, false, p_passkeys => p_passkeys
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
        'levels', v_levels, 'editor', editor, 'keys', to_json(names), 'resolved', array_to_json(coalesce(v_resolved, '{}')),
        'made', coalesce(v_right, false), 'rows', array_to_json(answers)
    );
END
$function$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.use_route(bytea, text, text, text, text, smallint, boolean, text[], jsonb, uuid, smallint, text, uuid, bigint, smallint, bigint, bytea, uuid[], uuid[], bigint[], bytea[], bigint[], bigint[], bigint[], boolean[], integer, integer, text, boolean, boolean, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.use_route(bytea, text, text, text, text, smallint, boolean, text[], jsonb, uuid, smallint, text, uuid, bigint, smallint, bigint, bytea, uuid[], uuid[], bigint[], bytea[], bigint[], bigint[], bigint[], boolean[], integer, integer, text, boolean, boolean, text) TO coffre_vault;
--> statement-breakpoint
-- `use_named_batch` as 0073 made it, but with no default, each of its calls of `use_credential` naming every argument.
DROP FUNCTION IF EXISTS public.use_named_batch(bytea, text, text, boolean, text[], boolean, text[], jsonb, bigint, smallint, bigint, bytea, text[], uuid[], uuid[], uuid[], bigint[], bytea[], bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], smallint, text, integer, text);
--> statement-breakpoint
CREATE FUNCTION public.use_named_batch(p_token_hash bytea, p_project text, p_environment text, p_handle boolean, p_unless text[], p_signin boolean, p_issuers text[], p_roles jsonb, p_at bigint, p_purpose smallint, p_deadline bigint, p_read_mac bytea, p_keys text[], p_credentials uuid[], p_secrets uuid[], p_places uuid[], p_requests bigint[], p_macs bytea[], p_covers bigint[], p_cover_ats bigint[], p_cover_requests bigint[], p_knowns bigint[], p_known_macs bytea[], p_cap_counts integer[], p_cap_windows bigint[], p_way smallint, p_principal text, p_limit integer, p_passkeys text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
AS $function$
DECLARE
    n integer := coalesce(cardinality(p_keys), 0);
    gate json;
    names text[];
    answers json[] := '{}';
    by_ids boolean[] := '{}';
    v_by boolean;
    v_id uuid;
    v_holder uuid;
    v_rows json;
    aheads json[] := '{}';
    v_np uuid;
    v_project uuid;
    v_layers uuid[];
    v_cut boolean;
    v_ids uuid[];
    v_holders uuid[];
    v_sealed json[];
BEGIN
    IF p_token_hash IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_read_mac IS NULL
       OR (p_keys IS NULL AND (p_credentials IS NOT NULL OR p_secrets IS NOT NULL OR p_places IS NOT NULL OR p_requests IS NOT NULL OR p_macs IS NOT NULL
                               OR p_covers IS NOT NULL OR p_cover_ats IS NOT NULL OR p_cover_requests IS NOT NULL
                               OR p_knowns IS NOT NULL OR p_known_macs IS NOT NULL OR p_cap_counts IS NOT NULL OR p_cap_windows IS NOT NULL))
       OR (p_keys IS NOT NULL AND (n = 0 OR n > p_limit
           OR cardinality(p_credentials) IS DISTINCT FROM n OR cardinality(p_secrets) IS DISTINCT FROM n OR cardinality(p_places) IS DISTINCT FROM n
           OR cardinality(p_requests) IS DISTINCT FROM n OR cardinality(p_macs) IS DISTINCT FROM n
           OR cardinality(p_covers) IS DISTINCT FROM n OR cardinality(p_cover_ats) IS DISTINCT FROM n OR cardinality(p_cover_requests) IS DISTINCT FROM n
           OR cardinality(p_knowns) IS DISTINCT FROM n OR cardinality(p_known_macs) IS DISTINCT FROM n
           OR cardinality(p_cap_counts) IS DISTINCT FROM n OR cardinality(p_cap_windows) IS DISTINCT FROM n
           OR (SELECT count(DISTINCT k) FROM unnest(p_keys) k) <> n OR array_position(p_keys, NULL) IS NOT NULL)) THEN
        RAISE EXCEPTION 'a named batch names its token, and each key once, with one entry a key in each of its lists, at most its limit; or no key, for every one the place holds' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The gate: the caller's standing at the place, by the request's names, from rows no key decides (0051's named call
    -- with no key, read by names alone: it writes and locks nothing). It takes the fence, shared, held to the commit.
    -- It holds the credential to the passkey check too (`p_passkeys`, T216), once: a change to the person's passkeys
    -- that leaves no passkey behind the credential revokes it (passkeys.md, section 6.1), a change that waits for this
    -- fence, so what the gate found stands for each key's named call below, which reads the credential again under it.
    gate := public.use_credential(
        NULL::uuid, NULL::uuid, 0::bigint, p_at, p_purpose, NULL::uuid, p_read_mac, p_deadline,
        NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint,
        p_token_hash, p_project, p_environment, NULL::text,
        false, p_handle, p_unless, p_signin, p_issuers, p_roles,
        0::smallint, NULL::text, true, NULL::text, false, p_passkeys
    );
    -- Anything but a place she stands at, its chain whole, by names read in full: answered on the gate's row alone.
    IF (gate ->> 'state') IS DISTINCT FROM 'moved' OR (gate ->> 'n_standing') IS DISTINCT FROM 'true' OR (gate ->> 'n_cut') IS DISTINCT FROM 'false' THEN
        RETURN json_build_object('gate', gate, 'keys', NULL, 'rows', '[]'::json, 'by_ids', '[]'::json, 'aheads', '[]'::json);
    END IF;
    -- The place, then what it inherits from, nearest first (0051's chain, which the gate found whole).
    v_np := (gate ->> 'n_place')::uuid;
    SELECT e.project_id INTO v_project FROM public.environments e WHERE e.id = v_np;
    WITH RECURSIVE chain (id, parent, cut, depth, seen) AS (
        SELECT e.id, e.parent_id, false, 0, ARRAY[e.id] FROM public.environments e WHERE e.id = v_np
        UNION ALL
        SELECT chain.parent, p.parent_id, p.id IS NULL OR p.archived_at IS NOT NULL OR p.slug LIKE '%~%' OR chain.parent = ANY (chain.seen) OR chain.depth >= 3,
               chain.depth + 1, chain.seen || chain.parent
          FROM chain LEFT JOIN public.environments p ON p.id = chain.parent
         WHERE chain.parent IS NOT NULL AND NOT chain.cut
    )
    SELECT array_agg(chain.id ORDER BY chain.depth), coalesce(bool_or(chain.cut), false) INTO v_layers, v_cut FROM chain;
    -- Cut since the gate read it, around the log (the fence holds every change back): nothing read, and no names listed
    -- either, so that the vault cannot take it for a place she stands at that holds no key (review r1 of T165 PR 2).
    IF v_cut OR v_layers IS NULL THEN
        RETURN json_build_object('gate', gate, 'keys', NULL, 'rows', '[]'::json, 'by_ids', '[]'::json, 'aheads', '[]'::json);
    END IF;
    IF p_keys IS NULL THEN
        -- Every key the place holds, as `resolveValues` lists them: a key held live in a layer is the place's unless a
        -- nearer layer but the last removed it (a dismissal not restored). By name, sorted, as the app lists them.
        WITH l AS (SELECT l.id, l.depth FROM unnest((SELECT v_layers)) WITH ORDINALITY l (id, depth)),
        live AS (
            SELECT x.key, min(l.depth) AS depth FROM l JOIN public.secrets x ON x.project_id = v_project AND x.environment_id = l.id AND x.archived_at IS NULL
             GROUP BY x.key
        ),
        removed AS (
            SELECT d.key, min(l.depth) AS depth FROM l JOIN public.dismissed_keys d ON d.environment_id = l.id AND d.restored_at IS NULL
             WHERE l.depth < cardinality(v_layers) GROUP BY d.key
        )
        SELECT coalesce(array_agg(live.key ORDER BY live.key COLLATE "C"), '{}') INTO names
          FROM live LEFT JOIN removed ON removed.key = live.key
         WHERE removed.depth IS NULL OR live.depth <= removed.depth;
    ELSE
        names := p_keys;
    END IF;
    -- Each key, in order. Its name first, as 0051 resolves it: the nearest layer that holds it live, or but the last that
    -- removed it. A key with a sealed value of its own is then a use by ids: made here when the vault passed its ids and
    -- they are the name's now (the gate's credential; a key it inherits, through the place, 0051), else left to the
    -- vault's batch by ids, which decides it next (its row null here, its ids in its `aheads`): a key's named call costs
    -- its place, standing and chain read again, five times a use by ids (T165, PR 2's CI: 1,001 keys took 2.3 s, the
    -- use's deadline 3). A use by ids logs its request whatever it finds; a plain value, a reference or a key the place
    -- does not hold is no use's, and its named call decides it here, writing nothing (`useMany` never passed one either).
    -- Its rows, for the app, which then reads nothing itself (`NamedKey.app`).
    -- Every key's name resolved at once, in one statement, in the statement's order, with the rows of each sealed one.
    WITH q AS (SELECT q.key, q.k FROM unnest((SELECT names[1:p_limit])) WITH ORDINALITY q (key, k)),
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
           array_agg(CASE WHEN sv.id IS NOT NULL THEN json_build_object('id', s.id, 'sensitive', sv.sensitive, 'secret', to_json(s), 'version', to_json(sv),
                                     'held', CASE WHEN held.holder IS DISTINCT FROM v_np THEN json_build_object('environmentId', held.holder, 'slug', e.slug) END) END
                     ORDER BY held.k)
      INTO v_ids, v_holders, v_sealed
      FROM held
      LEFT JOIN public.secrets s ON s.id = held.id
      LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id AND sv.plaintext IS NULL
      LEFT JOIN public.environments e ON e.id = held.holder AND held.holder IS DISTINCT FROM v_np;
    FOR k IN 1 .. least(coalesce(cardinality(names), 0), p_limit) LOOP
        v_id := v_ids[k];
        v_holder := v_holders[k];
        v_rows := v_sealed[k];
        v_by := v_rows IS NOT NULL AND p_keys IS NOT NULL AND p_credentials[k] IS NOT NULL
            AND p_credentials[k] = (gate ->> 'n_credential')::uuid AND p_secrets[k] = v_id
            AND p_places[k] IS NOT DISTINCT FROM (CASE WHEN v_holder IS DISTINCT FROM v_np THEN v_np END);
        IF v_by THEN
            answers := answers || public.use_credential(
                p_credentials[k], p_secrets[k], p_requests[k], p_at, p_purpose, p_places[k], p_macs[k], p_deadline,
                p_covers[k], p_cover_ats[k], p_cover_requests[k], p_knowns[k], p_known_macs[k], p_cap_counts[k], p_cap_windows[k],
                NULL::bytea, NULL::text, NULL::text, NULL::text,
                false, false, NULL::text[], NULL::boolean, NULL::text[], NULL::jsonb,
                p_way, p_principal, false, NULL::text, false, NULL::text
            );
        ELSIF v_rows IS NOT NULL THEN
            answers := array_append(answers, NULL::json);
        ELSE
            answers := answers || public.use_credential(
                NULL::uuid, NULL::uuid, 0::bigint, p_at, p_purpose, NULL::uuid, p_read_mac, p_deadline,
                NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint,
                p_token_hash, p_project, p_environment, names[k],
                false, p_handle, p_unless, p_signin, p_issuers, p_roles,
                0::smallint, NULL::text, true, NULL::text, false, NULL::text
            );
        END IF;
        by_ids := by_ids || v_by;
        aheads := array_append(aheads, v_rows);
    END LOOP;
    RETURN json_build_object('gate', gate, 'keys', CASE WHEN p_keys IS NULL THEN to_json(names) END, 'rows', array_to_json(answers), 'by_ids', array_to_json(by_ids), 'aheads', array_to_json(aheads));
END
$function$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.use_named_batch(bytea, text, text, boolean, text[], boolean, text[], jsonb, bigint, smallint, bigint, bytea, text[], uuid[], uuid[], uuid[], bigint[], bytea[], bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], smallint, text, integer, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.use_named_batch(bytea, text, text, boolean, text[], boolean, text[], jsonb, bigint, smallint, bigint, bytea, text[], uuid[], uuid[], uuid[], bigint[], bytea[], bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], smallint, text, integer, text) TO coffre_vault;
--> statement-breakpoint
-- 0048's `use_batch`, by its new name: its arguments are 0.15.0's, so its old name would answer 0.15.0's call. Its
-- call of `use_credential` names every argument. 19 arguments, over the 10 a function may take (AGENTS.md), only because
-- they are `use_credential`'s, a list each; V2a renames them and adds none, and the use's redesign (`simple-use.md`) cuts both.
DROP FUNCTION IF EXISTS public.use_batch(uuid, uuid[], bigint[], bigint, smallint, uuid[], bytea[], bigint, bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], boolean[], smallint, text, text);
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.use_id_batch(p_credential uuid, p_secrets uuid[], p_requests bigint[], p_at bigint, p_purpose smallint, p_places uuid[], p_macs bytea[], p_deadline bigint, p_covers bigint[], p_cover_ats bigint[], p_cover_requests bigint[], p_knowns bigint[], p_known_macs bytea[], p_cap_counts integer[], p_cap_windows bigint[], p_decided boolean[], p_way smallint, p_principal text, p_lock text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
AS $function$
DECLARE
    n integer := coalesce(cardinality(p_secrets), 0);
    answers json[] := '{}';
BEGIN
    IF n = 0
       OR cardinality(p_requests) IS DISTINCT FROM n OR cardinality(p_places) IS DISTINCT FROM n OR cardinality(p_macs) IS DISTINCT FROM n
       OR cardinality(p_covers) IS DISTINCT FROM n OR cardinality(p_cover_ats) IS DISTINCT FROM n OR cardinality(p_cover_requests) IS DISTINCT FROM n
       OR cardinality(p_knowns) IS DISTINCT FROM n OR cardinality(p_known_macs) IS DISTINCT FROM n
       OR cardinality(p_cap_counts) IS DISTINCT FROM n OR cardinality(p_cap_windows) IS DISTINCT FROM n OR cardinality(p_decided) IS DISTINCT FROM n THEN
        RAISE EXCEPTION 'a batch names a key at least, and each of its lists one entry a key' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_lock IS NOT NULL THEN
        -- The fence first, as every use takes it, then the principal's lock, exclusive, before any key (StrongestFirst).
        PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
        PERFORM pg_advisory_xact_lock(1668244066, hashtext(p_lock));
    END IF;
    FOR k IN 1 .. n LOOP
        answers := answers || public.use_credential(
            p_credential, p_secrets[k], p_requests[k], p_at, p_purpose, p_places[k], p_macs[k], p_deadline,
            p_covers[k], p_cover_ats[k], p_cover_requests[k], p_knowns[k], p_known_macs[k], p_cap_counts[k], p_cap_windows[k],
            NULL, NULL, NULL, NULL,
            coalesce(p_decided[k], false),
            false, NULL, NULL, NULL, NULL,
            p_way, p_principal, false, NULL::text, false, NULL::text
        );
    END LOOP;
    RETURN array_to_json(answers);
END
$function$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.use_id_batch(uuid, uuid[], bigint[], bigint, smallint, uuid[], bytea[], bigint, bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], boolean[], smallint, text, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.use_id_batch(uuid, uuid[], bigint[], bigint, smallint, uuid[], bytea[], bigint, bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], boolean[], smallint, text, text) TO coffre_vault;
