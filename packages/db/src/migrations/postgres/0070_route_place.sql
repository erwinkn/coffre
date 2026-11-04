-- 0.16, T186 PR C2b4: `use_route` as 0069 made it (T207's, T220's mark), but for the place itself (docs/design/proxy-ui.md, section 6, "URLs of one or two segments"). A handle's `/use/<a>/<b>` is the place `<a>/<b>` (the plan, compute, code's credential under it) when the handle was made for it, else route `<a>` at `/<b>`: the vault asks both readings in this one call, the place's as a place reading of no route, `p_named = ''`, which no item may be named (CREDENTIAL_NAME). Taken, the statement answers the reading and the gate and reads no definition: the route block is left before the place's chain and its levels (Sol's review r1 of #486). Additive (AGENTS.md, "expand, then contract"): the same signature, settings and answer, every other call as 0069's; 0.15.0's code never sends `''`. `CREATE OR REPLACE` keeps the function's owner and grants; its plans are its own, so the session's mark that they are made is `0070`'s (T200).
CREATE OR REPLACE FUNCTION use_route(
    p_token_hash bytea, p_project text, p_environment text, p_named text, p_stable text, p_reading smallint,
    p_signin boolean, p_issuers text[], p_roles jsonb,
    p_credential uuid, p_way smallint, p_principal text, p_place uuid,
    p_at bigint, p_purpose smallint, p_deadline bigint, p_read_mac bytea,
    p_secrets uuid[], p_places uuid[], p_requests bigint[], p_macs bytea[],
    p_covers bigint[], p_cover_ats bigint[], p_cover_requests bigint[], p_decided boolean[],
    p_offset integer, p_limit integer, p_lock text, p_use boolean, p_light boolean DEFAULT false
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET bytea_output = 'hex' AS $$
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
    v_planned boolean := current_setting('coffre.route_planned', true) IS NOT DISTINCT FROM '0070';
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
        PERFORM set_config('coffre.route_planned', '0070', false);
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
                  LEFT JOIN public.vault_members m ON m.principal = v_editor
                  LEFT JOIN LATERAL (
                      SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                             array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at::text) AS g_expires
                        FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
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
$$;
