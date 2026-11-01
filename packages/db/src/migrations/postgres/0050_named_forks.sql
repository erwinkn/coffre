-- 0.15's use by name serves forks and personal configs too (T165, B2; docs/design/0.15-plan.md, "As built: T165"; formal/Probing.tla, Where, ForksByName, GateWeighsParent, ParentInDecision, CutByPlace). Before, a named call whose place was a fork or a personal config answered `nowhere`, and the app's own path read it (`access`, its own reads, a use by ids), whose work hangs on the key: a `no` there cost one call or two, by the key's shape (D153). Now, with `p_forks` (which this release's vault passes, and 0.15.0's does not: its calls read as before), the named call reads such a place itself, in its one statement:
-- - A fork's path, `market/dev-ada`, names the fork, as an environment's path names it; a handle's one place may be a fork too. A personal config's own slug stays none (`nowhere`): only `dev@me` names it.
-- - `dev@me` names dev, an environment of its own or a fork, then the caller's personal config of it, by its parent and owner (`resolveRead`): that config is the place; while they have none, dev is, read as dev. Archived, either is none.
-- - The gate decides the caller's standing at the place first, from rows no key decides, as before (W268): at a personal config, as the vault's rule weighs it, its owner's while they read or use dev (`use_stands_personal`; `personalRefusal`).
-- - Then, for one who stands, what the place inherits from, nearest first, from rows no key decides: a parent archived, deleted, not there, or a chain that loops or runs past 3 cuts it, and the place reads nothing, as the app's read refuses it whole (`n_cut`, answered `archived`, nothing of the key read).
-- - Then the key, by its name, in the nearest layer that settles it (`resolveValues`): one that holds it live, or one but the last that removed it (a dismissal not restored). Held at the place, it is used by its id, as before; inherited, by its id through the place, as a fork's read uses it (e1, the whole form), and the vault decides it on the caller's standing where it is held too (`decideChecked`); removed, or held nowhere, it is a key the place does not hold.
-- - A named call's key the place does not hold reads the place's parent when the place is a personal config (e4), which the standing there weighs.
-- - The app's rows name the place's parent's slug (`parent`), as `app_read` names a fork's.
-- Additive: the previous release's calls pass no `p_forks`, and the statement reads what 0046's did for them.
ALTER TYPE use_row ADD ATTRIBUTE n_cut boolean;
--> statement-breakpoint
-- Whether a credential's scope, if it has one, holds `p_wanted` at the place, as `withinCredential` (@coffre/core/access) asks: `use_stands`' first test alone, on the rows as read (a scope that is no list stands, as there: the vault's rule, which reads it as nothing, refuses after).
CREATE FUNCTION use_scope_holds(p_credential uuid, p_place uuid, p_wanted text, p_roles jsonb) RETURNS boolean
    LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
BEGIN
    RETURN coalesce((
        SELECT k.c_scope IS NULL OR EXISTS (
                   SELECT 1 FROM jsonb_array_elements(k.c_scope) g
                    WHERE g.value ->> 'projectId' = k.e_project::text AND (g.value ->> 'environmentId' IS NULL OR g.value ->> 'environmentId' = k.e_id::text)
                      AND coalesce(CASE WHEN g.value ? 'permissions' THEN g.value -> 'permissions' -> CASE WHEN k.guarded THEN 'protected' ELSE 'normal' END
                                        ELSE p_roles -> 'roles' -> (g.value ->> 'role') -> CASE WHEN k.guarded THEN 'protected' ELSE 'permissions' END END @> to_jsonb(p_wanted), false))
          FROM (
              SELECT e.id AS e_id, e.project_id AS e_project, c.principal LIKE 'user:%' AND coalesce(e.protected, false) AS guarded,
                     CASE WHEN c.scope IS NOT NULL AND pg_input_is_valid(c.scope, 'jsonb') AND jsonb_typeof(c.scope::jsonb) = 'array' THEN c.scope::jsonb END AS c_scope
                FROM public.credentials c JOIN public.environments e ON e.id = p_place
               WHERE c.id = p_credential
          ) k
    ), false);
END
$$;
--> statement-breakpoint
-- Whether the caller of a named use stands at a personal config, `p_place` (T165): `namedStanding` there, its rows as read, which the vault's rule weighs with dev (`personalRefusal`, decide.ts; the app's `can`): the credential's principal is its owner, neither it nor dev deleted, and they read or use dev (`allows`, `use_stands` at dev for either), their credential's scope holding use there (`withinCredential`, `personalCap`), whatever they ask: an owner reads what they wrote while they use dev. A key dev holds, which the config inherits, is decided at dev after, for what they ask (`decideChecked`).
CREATE FUNCTION use_stands_personal(p_credential uuid, p_place uuid, p_at bigint, p_roles jsonb) RETURNS boolean
    LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
DECLARE
    v_parent uuid;
    v_owns boolean;
BEGIN
    SELECT e.parent_id, c.principal = e.owner AND e.slug NOT LIKE '%~%' AND d.slug NOT LIKE '%~%'
      INTO v_parent, v_owns
      FROM public.credentials c JOIN public.environments e ON e.id = p_place JOIN public.environments d ON d.id = e.parent_id
     WHERE c.id = p_credential;
    IF NOT coalesce(v_owns, false) THEN RETURN false; END IF;
    RETURN public.use_stands(p_credential, v_parent, 4::smallint, p_at, p_roles)
        OR (public.use_stands(p_credential, v_parent, 1::smallint, p_at, p_roles) AND public.use_scope_holds(p_credential, v_parent, 'secret.use', p_roles));
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION use_scope_holds(uuid, uuid, text, jsonb) FROM PUBLIC;
--> statement-breakpoint
REVOKE ALL ON FUNCTION use_stands_personal(uuid, uuid, bigint, jsonb) FROM PUBLIC;
--> statement-breakpoint
DROP FUNCTION use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint, bytea, text, text, text, boolean, boolean, text[], boolean, text[], jsonb, smallint, text);
--> statement-breakpoint
-- `use_credential` as 0046 made it (its comments, and those it names, say how), but for forks and personal configs by name (`p_forks`, above), its row's `n_cut`, the app's rows' `parent`, and its warm-up's mark (`coffre.use_planned`). `use_batch` (0048) calls it as before: its calls pass no `p_forks`, a use by ids, which reads as 0046's.
CREATE FUNCTION use_credential(
    p_credential uuid, p_secret uuid, p_request bigint, p_at bigint, p_purpose smallint, p_place uuid, p_mac bytea, p_deadline bigint,
    p_cover bigint DEFAULT NULL, p_cover_at bigint DEFAULT NULL, p_cover_request bigint DEFAULT NULL, p_known bigint DEFAULT NULL, p_known_mac bytea DEFAULT NULL,
    p_cap_count integer DEFAULT NULL, p_cap_window bigint DEFAULT NULL,
    p_token_hash bytea DEFAULT NULL, p_project text DEFAULT NULL, p_environment text DEFAULT NULL, p_key text DEFAULT NULL,
    p_decided boolean DEFAULT false,
    p_handle boolean DEFAULT false,
    p_unless text[] DEFAULT NULL,
    p_signin boolean DEFAULT NULL,
    p_issuers text[] DEFAULT NULL,
    p_roles jsonb DEFAULT NULL,
    p_way smallint DEFAULT 0,
    p_principal text DEFAULT NULL,
    p_forks boolean DEFAULT false
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET bytea_output = 'hex' SET jit = off AS $$
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
    dry boolean := current_setting('coffre.use_planned', true) IS DISTINCT FROM '0050';
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
BEGIN
    -- The way in (T147): a credential, 0; an MCP connection, 1; a Cloudflare binding, 2; each by its id; or, behind
    -- Cloudflare Access, the account, 3, a person's or a service token's, whose object's key the entry names. Its kind is in the entry, the purpose's
    -- bits above 512, under its MAC; and only a credential's token is named.
    IF p_way IS NULL OR p_way NOT IN (0, 1, 2, 3) OR p_purpose / 512 <> p_way OR (p_way = 3) <> (p_principal IS NOT NULL)
       OR (p_way <> 0 AND p_token_hash IS NOT NULL)
       OR (p_way = 3 AND (NOT (p_principal LIKE 'user:%' OR p_principal LIKE 'token:%') OR p_credential IS DISTINCT FROM public.log_object('principal', p_principal))) THEN
        RAISE EXCEPTION 'a use names its way in: a credential, a connection or a binding by id, or an account behind Access by its key' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_deadline IS NULL OR p_deadline > p_at + public.deadline_max() THEN r.state := 'late'; RETURN to_json(r); END IF;
    -- Its Worker's clock ahead by over a minute (0022 says why): checked here at no cost, and again in the statement.
    IF p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN r.state := 'ahead'; RETURN to_json(r); END IF;
    IF dry THEN
        -- Each form first runs dry, outside the fence, so that its plan is made before this call holds the fence.
        first_probe := probe;
        first_whole := whole;
        probe := true;
        whole := false;
    ELSE
        PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    END IF;
    LOOP
        IF NOT dry AND NOT resolved THEN
            -- What the request names, by its names, under the fence, which no change moves (as `use_resolve` reads it):
            -- the credential of its token's hash; the place of its slugs, or a handle's one place; its key there by name.
            -- Each by an index, its plan generic (the hot login's `force_generic_plan`): a handle's place by its id, a
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
            IF v_credential IS NULL OR NOT coalesce(v_accepted, false) THEN r.state := 'unknown'; RETURN to_json(r); END IF;
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
            IF p_key IS NOT NULL AND v_stands AND NOT v_cut THEN
                IF cardinality(v_layers) = 1 THEN
                    SELECT x.id, x.environment_id INTO v_secret, v_holder FROM public.secrets x
                     WHERE x.project_id = v_np_project AND x.environment_id = v_np AND x.key = p_key AND x.archived_at IS NULL LIMIT 1;
                ELSE
                    -- The nearest layer that settles the key (`resolveValues`): holds it live, or removed it (a dismissal not
                    -- restored), but the last, whose dismissals remove nothing. Held there, it is that key; removed, none.
                    SELECT x.id, l.id INTO v_secret, v_holder
                      FROM unnest(v_layers) WITH ORDINALITY l (id, depth)
                      LEFT JOIN public.secrets x ON x.project_id = v_np_project AND x.environment_id = l.id AND x.key = p_key AND x.archived_at IS NULL
                     WHERE x.id IS NOT NULL
                        OR (l.depth < cardinality(v_layers)
                            AND EXISTS (SELECT 1 FROM public.dismissed_keys d WHERE d.environment_id = l.id AND d.key = p_key AND d.restored_at IS NULL))
                     ORDER BY l.depth LIMIT 1;
                END IF;
            ELSE
                v_secret := NULL;
            END IF;
            -- A key named is read by its id; one the place does not hold, through the place (the whole form, e1); one it
            -- inherits, by its id through the place, as a fork's read is.
            v_place := CASE WHEN v_secret IS NULL OR v_holder IS DISTINCT FROM v_np THEN v_np END;
            v_right := coalesce(v_credential = p_credential, false) AND v_secret IS NOT DISTINCT FROM p_secret AND v_place IS NOT DISTINCT FROM p_place;
            IF NOT v_stands OR v_cut THEN
                -- No standing, or no live place, or a chain cut: answered on the place alone, as for a key it does not hold, probing,
                -- whatever the isolate passed: no cover, no seals (NoKeyBeforeStanding). Nothing is written or locked,
                -- as for any key the place does not hold.
                p_cover := NULL;
                probe := true;
            END IF;
            whole := v_place IS NOT NULL;
            resolved := true;
        END IF;
        IF probe AND NOT whole THEN
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS cap_count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS cap_window,
                    lpol.number AS lpol_number, lpol.seal AS p_last,
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
                  LEFT JOIN public.log_fence f ON f.only_row
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  -- The cap as the policy's newest change says it (CapSealed): every policy change logs the whole policy as its `value`.
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
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
                  LEFT JOIN public.vault_members m ON m.principal = w.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = v_secret AND s.archived_at IS NULL
                  -- The key's own version, its own environment, and that environment's parent when it is a personal config.
                  LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e4 ON e4.id = e2.parent_id AND e2.owner IS NOT NULL
                  LEFT JOIN public.log_bulk b ON b.principal = w.principal AND b.secret = v_secret
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, cap.refresh, cap.period,
                    CASE WHEN i.s_project IS NOT NULL AND i.s_version IS NULL THEN 'whole'
                         -- What no key decides comes first (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416): the
                         -- floor, the deadline, the clock, the cap's config; then what the names decide, which the vault
                         -- answers on the caller's standing first.
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         -- What the names name, read by them: no credential of that token, no live place of those names.
                         WHEN v_named IS NOT NULL THEN v_named
                         -- The ids the vault passed are not the ones the names name now (D153): the names' rows are read,
                         -- and nothing is written or locked.
                         WHEN NOT v_right THEN 'moved'
                         WHEN p_token_hash IS NOT NULL AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                           OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut) THEN 'archived'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT (p_token_hash IS NOT NULL AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND NOT (p_token_hash IS NOT NULL AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND i.bulk_last < cap.period THEN 'share' END AS state,
                    greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, l2.number, l4.number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, (lm.payload::jsonb ->> 'old')::bigint AS m_old, lr.seal AS r_last, ls.seal AS s_last, NULL::bytea AS x_last,
                    NULL::bytea AS e1_last, l2.seal AS e2_last, NULL::bytea AS e3_last, l4.seal AS e4_last,
                    coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - i.cap_window - cap.refresh - public.deadline_max() - 60000
                             LIMIT i.cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= cap.period AND p_cover > coalesce(greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, l2.number, l4.number), 0)
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover
                            AND u.credential = p_credential AND u.secret = p_secret AND u.purpose = p_purpose AND u.place IS NOT DISTINCT FROM p_place), false) AS is_covered
                  FROM i
                  CROSS JOIN LATERAL (SELECT greatest(1, least(60000, i.cap_window / 10)) AS refresh) r0
                  CROSS JOIN LATERAL (SELECT r0.refresh, p_at - ((p_at % r0.refresh) + r0.refresh) % r0.refresh AS period) cap
                  -- Each input's newest change: one index-only probe each (log_changes_object_idx holds the seal), the principal's
                  -- with its payload, which names the 0.14 entry it accounts for.
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_credential ORDER BY x.number DESC LIMIT 1) lc ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = i.k_member ORDER BY x.number DESC LIMIT 1) lm ON i.k_member IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = public.log_object('roles', 'instance') ORDER BY x.number DESC LIMIT 1) lr ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_secret ORDER BY x.number DESC LIMIT 1) ls ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e2 ORDER BY x.number DESC LIMIT 1) l2 ON i.k_e2 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e4 ORDER BY x.number DESC LIMIT 1) l4 ON i.k_e4 IS NOT NULL
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (p_token_hash IS NOT NULL AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
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
                    'secrets', CASE WHEN v.s_row IS NULL THEN '[]'::json ELSE json_build_array(json_build_object('secret', v.s_row, 'version', v.sv_row)) END) END,
                -- A named call's (`n_*`), set below; a binding's row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::boolean, v.w_row, NULL::boolean
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSIF probe THEN
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS cap_count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS cap_window,
                    lpol.number AS lpol_number, lpol.seal AS p_last,
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
                  LEFT JOIN public.log_fence f ON f.only_row
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  -- The cap as the policy's newest change says it (CapSealed): every policy change logs the whole policy as its `value`.
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
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
                  LEFT JOIN public.vault_members m ON m.principal = w.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = v_secret AND s.archived_at IS NULL
                  -- A key with no version of its own is a reference while its newest reference row names a source and has not ended (`ended_at`): an ended one's holder reads as no value, no source (`ended`).
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.ended_at IS NULL THEN y.id END AS reference_id FROM public.secret_references y WHERE y.secret_id = s.id ORDER BY y.created_seq DESC LIMIT 1
                  ) ref ON s.current_version_id IS NULL
                  LEFT JOIN public.secrets src ON src.id = ref.source_secret_id AND src.archived_at IS NULL
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.ended_at IS NULL THEN y.id END AS reference_id FROM public.secret_references y WHERE y.secret_id = src.id ORDER BY y.created_seq DESC LIMIT 1
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
                  LEFT JOIN public.log_bulk b ON b.principal = w.principal AND b.secret = v_secret
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, cap.refresh, cap.period,
                    -- What no key decides comes first (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416): the
                    -- floor, the deadline, the clock, the cap's config; then what the names decide, which the vault
                    -- answers on the caller's standing first.
                    CASE WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         -- What the names name, read by them: no credential of that token, no live place of those names.
                         WHEN v_named IS NOT NULL THEN v_named
                         -- The ids the vault passed are not the ones the names name now (D153): the names' rows are read,
                         -- and nothing is written or locked.
                         WHEN NOT v_right THEN 'moved'
                         WHEN p_token_hash IS NOT NULL AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                           OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut) THEN 'archived'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT (p_token_hash IS NOT NULL AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND NOT (p_token_hash IS NOT NULL AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND i.bulk_last < cap.period THEN 'share' END AS state,
                    greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, lx.number, l1.number, l2.number, l3.number, l4.number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, (lm.payload::jsonb ->> 'old')::bigint AS m_old, lr.seal AS r_last, ls.seal AS s_last, lx.seal AS x_last,
                    l1.seal AS e1_last, l2.seal AS e2_last, l3.seal AS e3_last, l4.seal AS e4_last,
                    coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - i.cap_window - cap.refresh - public.deadline_max() - 60000
                             LIMIT i.cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= cap.period AND p_cover > coalesce(greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, lx.number, l1.number, l2.number, l3.number, l4.number), 0)
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover
                            AND u.credential = p_credential AND u.secret = p_secret AND u.purpose = p_purpose AND u.place IS NOT DISTINCT FROM p_place), false) AS is_covered
                  FROM i
                  CROSS JOIN LATERAL (SELECT greatest(1, least(60000, i.cap_window / 10)) AS refresh) r0
                  CROSS JOIN LATERAL (SELECT r0.refresh, p_at - ((p_at % r0.refresh) + r0.refresh) % r0.refresh AS period) cap
                  -- Each input's newest change: one index-only probe each (log_changes_object_idx holds the seal), the principal's
                  -- with its payload, which names the 0.14 entry it accounts for.
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_credential ORDER BY x.number DESC LIMIT 1) lc ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = i.k_member ORDER BY x.number DESC LIMIT 1) lm ON i.k_member IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = public.log_object('roles', 'instance') ORDER BY x.number DESC LIMIT 1) lr ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_secret ORDER BY x.number DESC LIMIT 1) ls ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_source ORDER BY x.number DESC LIMIT 1) lx ON i.k_source IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e1 ORDER BY x.number DESC LIMIT 1) l1 ON i.k_e1 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e2 ORDER BY x.number DESC LIMIT 1) l2 ON i.k_e2 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e3 ORDER BY x.number DESC LIMIT 1) l3 ON i.k_e3 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e4 ORDER BY x.number DESC LIMIT 1) l4 ON i.k_e4 IS NOT NULL
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (p_token_hash IS NOT NULL AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
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
                    'secrets', CASE WHEN v.s_row IS NULL THEN '[]'::json ELSE json_build_array(json_build_object('secret', v.s_row, 'version', v.sv_row)) END) END,
                -- A named call's (`n_*`), set below; a binding's row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::boolean, v.w_row, NULL::boolean
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSIF NOT whole THEN
            -- The isolate's seals, and its cap, read at the change it names: no probe, only whether a change came since
            -- (then nothing is written: 'reprobe').
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor,
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
                  LEFT JOIN public.log_fence f ON f.only_row
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
                  LEFT JOIN public.vault_members m ON m.principal = w.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = v_secret AND s.archived_at IS NULL
                  -- The key's own version, its own environment, and that environment's parent when it is a personal config.
                  LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e4 ON e4.id = e2.parent_id AND e2.owner IS NOT NULL
                  LEFT JOIN public.log_bulk b ON b.principal = w.principal AND b.secret = v_secret
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, c_refresh AS refresh, c_period AS period,
                    CASE WHEN NOT i.cached THEN 'reprobe'
                         WHEN i.s_project IS NOT NULL AND i.s_version IS NULL THEN 'whole'
                         -- What no key decides comes first (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416): the
                         -- floor, the deadline, the clock, the cap's config; then what the names decide, which the vault
                         -- answers on the caller's standing first.
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         -- What the names name, read by them: no credential of that token, no live place of those names.
                         WHEN v_named IS NOT NULL THEN v_named
                         -- The ids the vault passed are not the ones the names name now (D153): the names' rows are read,
                         -- and nothing is written or locked.
                         WHEN NOT v_right THEN 'moved'
                         WHEN p_token_hash IS NOT NULL AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                           OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut) THEN 'archived'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT (p_token_hash IS NOT NULL AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND NOT (p_token_hash IS NOT NULL AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND i.bulk_last < c_period THEN 'share' END AS state,
                    coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - p_cap_window - c_refresh - public.deadline_max() - 60000
                             LIMIT p_cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= c_period
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover
                            AND u.credential = p_credential AND u.secret = p_secret AND u.purpose = p_purpose AND u.place IS NOT DISTINCT FROM p_place), false) AS is_covered
                  FROM i
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  -- The isolate held its cover to the cached seals' numbers when it read them.
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (p_token_hash IS NOT NULL AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
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
                    'secrets', CASE WHEN v.s_row IS NULL THEN '[]'::json ELSE json_build_array(json_build_object('secret', v.s_row, 'version', v.sv_row)) END) END,
                -- A named call's (`n_*`), set below; a binding's row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::boolean, v.w_row, NULL::boolean
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSE
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor,
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
                  LEFT JOIN public.log_fence f ON f.only_row
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
                  LEFT JOIN public.vault_members m ON m.principal = w.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = v_secret AND s.archived_at IS NULL
                  -- A key with no version of its own is a reference while its newest reference row names a source and has not ended (`ended_at`): an ended one's holder reads as no value, no source (`ended`).
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.ended_at IS NULL THEN y.id END AS reference_id FROM public.secret_references y WHERE y.secret_id = s.id ORDER BY y.created_seq DESC LIMIT 1
                  ) ref ON s.current_version_id IS NULL
                  LEFT JOIN public.secrets src ON src.id = ref.source_secret_id AND src.archived_at IS NULL
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN y.ended_at IS NULL THEN y.source_secret_id END AS source_secret_id, CASE WHEN y.ended_at IS NULL THEN y.id END AS reference_id FROM public.secret_references y WHERE y.secret_id = src.id ORDER BY y.created_seq DESC LIMIT 1
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
                  LEFT JOIN public.log_bulk b ON b.principal = w.principal AND b.secret = v_secret
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, c_refresh AS refresh, c_period AS period,
                    CASE WHEN NOT i.cached THEN 'reprobe'
                         -- What no key decides comes first (T158; Probing.tla, AdmissionBeforeKey; review d3 of #416): the
                         -- floor, the deadline, the clock, the cap's config; then what the names decide, which the vault
                         -- answers on the caller's standing first.
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         -- What the names name, read by them: no credential of that token, no live place of those names.
                         WHEN v_named IS NOT NULL THEN v_named
                         -- The ids the vault passed are not the ones the names name now (D153): the names' rows are read,
                         -- and nothing is written or locked.
                         WHEN NOT v_right THEN 'moved'
                         WHEN p_token_hash IS NOT NULL AND (coalesce(i.e1_archived, false) OR coalesce(i.e2_archived, false) OR coalesce(i.e3_archived, false)
                           OR coalesce(i.e1_project_archived, false) OR coalesce(i.e2_project_archived, false) OR coalesce(i.e3_project_archived, false) OR v_cut) THEN 'archived'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT (p_token_hash IS NOT NULL AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND NOT (p_token_hash IS NOT NULL AND (i.s_project IS NULL OR coalesce(i.v_plain, false))) AND i.bulk_last < c_period THEN 'share' END AS state,
                    coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> v_secret AND o.last > p_at - p_cap_window - c_refresh - public.deadline_max() - 60000
                             LIMIT p_cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= c_period
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover
                            AND u.credential = p_credential AND u.secret = p_secret AND u.purpose = p_purpose AND u.place IS NOT DISTINCT FROM p_place), false) AS is_covered
                  FROM i
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  -- The isolate held its cover to the cached seals' numbers when it read them.
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered AND NOT (p_token_hash IS NOT NULL AND (v.s_project IS NULL OR coalesce(v.v_plain, false)))
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
                    'secrets', CASE WHEN v.s_row IS NULL THEN '[]'::json ELSE json_build_array(json_build_object('secret', v.s_row, 'version', v.sv_row)) END) END,
                -- A named call's (`n_*`), set below; a binding's row.
                NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::boolean, v.w_row, NULL::boolean
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
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
            PERFORM set_config('coffre.use_planned', '0050', false);
            dry := false;
            probe := first_probe;
            whole := first_whole;
            PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
            CONTINUE;
        END IF;
        -- A named call answered `moved` or `archived` is decided by the vault before anything else is done (T158, D153):
        -- it is read again probing, so that every row's newest seal is there to check, in this call.
        IF r.state IN ('moved', 'archived') AND p_token_hash IS NOT NULL AND NOT probe THEN
            probe := true;
            CONTINUE;
        END IF;
        -- A use the statement took writes its entry or rides its cover, never neither: but a named one of a key the place
        -- does not hold, or of a plain value, which writes none.
        IF r.state IS NULL AND r.number IS NULL AND r.covered IS NULL AND NOT (p_token_hash IS NOT NULL AND (r.s_project IS NULL OR coalesce(r.v_plain, false))) THEN
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
                    UPDATE public.log_bulk SET last = b_period WHERE principal = r.c_principal AND secret = p_secret AND last < b_period;
                    EXIT;
                END IF;
                PERFORM pg_advisory_xact_lock_shared(b_lock);
                EXIT WHEN NOT EXISTS (SELECT 1 FROM public.log_bulk WHERE principal = r.c_principal AND secret = p_secret AND last < b_period);
                b_round := b_round + 1;
            END LOOP;
        ELSIF r.others < r.cap_count THEN
            INSERT INTO public.log_bulk (principal, secret, last) VALUES (r.c_principal, p_secret, b_period)
                ON CONFLICT ON CONSTRAINT log_bulk_pkey DO UPDATE SET last = greatest(log_bulk.last, EXCLUDED.last);
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
    RETURN to_json(r);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint, bytea, text, text, text, boolean, boolean, text[], boolean, text[], jsonb, smallint, text, boolean) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint, bytea, text, text, text, boolean, boolean, text[], boolean, text[], jsonb, smallint, text, boolean) TO coffre_vault;
