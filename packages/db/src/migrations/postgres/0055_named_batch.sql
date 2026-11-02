-- T165 (B2, PR 2): a request's several keys by name, the vault's one call (docs/design/0.15-plan.md, "As built: T165, PR 2"; formal/ProbingMany.tla). Before, a request of several keys (`coffre export`, `--keys A,B`, the proxy's keys of a credential) read the place and its keys through the app (`app_read`, or a fork's layers), decided the caller's standing there (`need`), then made its uses by ids (`use_batch`): a refusal's work hung on the keys the place holds. Now its first statement is this one:
-- - The gate first: `use_credential` with no key, by the request's names, which decides the caller's standing at the place from rows no key decides and walks its chain (0051), writing and locking nothing. No standing, a chain cut, a token no credential has, a place that is none: answered on that row alone, nothing of any key read (GateBeforeKeys, CutByPlace).
-- - Then, for one who stands: the keys, the request's names, or, `p_keys` null, every key the place holds, listed through its layers as the app's read lists them (`resolveValues`: the nearest layer that holds a key live settles it, unless a nearer one but the last removed it).
-- - Each key, in the order asked: a key with a sealed value of its own, by the ids the isolate maps it to, when the vault passes them and they are the names' now (the gate's credential and place, the key's name resolved through the place's layers here, as 0051 resolves it), its use by ids, as `use_batch` (0048) makes it: the isolate's seals let it skip what it knows (the cached form), and a key whose row of the cap's is fresh is used at once. One who stands at the place knows its key names (R6), so what the isolate kept of them may shape the work, as it does for a use by ids. A sealed key of its own without them (no ids, or ids out of date): no call here, its row null, its ids and rows in `aheads`, for the vault's batch by ids to decide (`use_batch`'s first round): a named call per key reads its place, standing and chain again, five times the work of a use by ids. Otherwise (a plain value, a reference, a key the place does not hold), a lone named call by its name alone (`use_credential`, 0051), which writes and locks nothing and answers its rows. The vault decides every key before any takes a lock or enters the cap's set (DecideAllFirst) and makes the rest by ids, in `use_batch`.
-- - At most `p_limit` keys a statement: a place of more is read in statements of that many, each by its names (`p_keys`), the first answering every name it listed.
-- Its answer is one JSON object: the gate's row (`gate`), the names listed (`keys`, when `p_keys` is null), each key's `use_credential` row (`rows`, null for a key left to the batch by ids), in order, whether each was its use by ids (`by_ids`), and, for each with a sealed value of its own, its id, whether that value is sensitive, and the app's rows of it (`aheads`: its row, its version's, and where it is held, for a key the place inherits). Any raise rolls the whole statement back: nothing of it is written.
CREATE FUNCTION use_named_batch(
    p_token_hash bytea, p_project text, p_environment text, p_handle boolean, p_unless text[], p_signin boolean, p_issuers text[], p_roles jsonb,
    p_at bigint, p_purpose smallint, p_deadline bigint, p_read_mac bytea,
    p_keys text[], p_credentials uuid[], p_secrets uuid[], p_places uuid[], p_requests bigint[], p_macs bytea[],
    p_covers bigint[], p_cover_ats bigint[], p_cover_requests bigint[],
    p_knowns bigint[], p_known_macs bytea[], p_cap_counts integer[], p_cap_windows bigint[], p_way smallint, p_principal text,
    p_limit integer
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET bytea_output = 'hex' SET jit = off AS $$
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
    gate := public.use_credential(
        NULL::uuid, NULL::uuid, 0::bigint, p_at, p_purpose, NULL::uuid, p_read_mac, p_deadline,
        NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint,
        p_token_hash, p_project, p_environment, NULL::text,
        false, p_handle, p_unless, p_signin, p_issuers, p_roles,
        0::smallint, NULL::text, true
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
        WITH l AS (SELECT l.id, l.depth FROM unnest(v_layers) WITH ORDINALITY l (id, depth)),
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
    WITH q AS (SELECT q.key, q.k FROM unnest(names[1:p_limit]) WITH ORDINALITY q (key, k)),
    held AS (
        SELECT q.k, h.id, h.holder FROM q LEFT JOIN LATERAL (
            SELECT x.id, l.id AS holder
              FROM unnest(v_layers) WITH ORDINALITY l (id, depth)
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
                p_way, p_principal
            );
        ELSIF v_rows IS NOT NULL THEN
            answers := array_append(answers, NULL::json);
        ELSE
            answers := answers || public.use_credential(
                NULL::uuid, NULL::uuid, 0::bigint, p_at, p_purpose, NULL::uuid, p_read_mac, p_deadline,
                NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bytea, NULL::integer, NULL::bigint,
                p_token_hash, p_project, p_environment, names[k],
                false, p_handle, p_unless, p_signin, p_issuers, p_roles,
                0::smallint, NULL::text, true
            );
        END IF;
        by_ids := by_ids || v_by;
        aheads := array_append(aheads, v_rows);
    END LOOP;
    RETURN json_build_object('gate', gate, 'keys', CASE WHEN p_keys IS NULL THEN to_json(names) END, 'rows', array_to_json(answers), 'by_ids', array_to_json(by_ids), 'aheads', array_to_json(aheads));
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION use_named_batch(bytea, text, text, boolean, text[], boolean, text[], jsonb, bigint, smallint, bigint, bytea, text[], uuid[], uuid[], uuid[], bigint[], bytea[], bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], smallint, text, integer) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION use_named_batch(bytea, text, text, boolean, text[], boolean, text[], jsonb, bigint, smallint, bigint, bytea, text[], uuid[], uuid[], uuid[], bigint[], bytea[], bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], smallint, text, integer) TO coffre_vault;
