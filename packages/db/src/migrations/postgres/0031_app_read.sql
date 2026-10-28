-- The app's reads before a use, in one call (T135; docs/design/0.15-plan.md, "As built: T135"): a request's credential, the newest policy change, the place it reads and its keys' rows, each what the app's own statements read (`credentialRow`, `resolvePath`, `environmentSecrets` in packages/server/src/db/queries.ts), as one JSON value. A function, so that each backend plans its statements once: planned anew for every request, the app's three statements cost 2.35 ms of Postgres CPU a request on a 2 vCPU Postgres, their plans most of it; this, 0.5 ms (measured, ibid.). One snapshot (STABLE): the place and the keys are read with the credential. It decides nothing: the app checks each row as it checks its own statements' (the MAC, what is live, what is inherited). Only 0.15's switch calls it: 0.14's code serves on it as before.
--
-- Planned once per backend (`force_generic_plan`), as the hot login's statements are: the plpgsql default plans each call again while a custom plan looks cheaper, which here was every call. Every read is a probe of a unique key, or an environment's keys by their index: `enable_seqscan = off` keeps a generic plan from reading a small table whole, whose pages grow with every row the instance gains (R48; proxy-use-cost.test.ts). `jit = off`, as the hot path's `use_credential` has it: a generic plan's estimate, a disabled scan's above all, can pass `jit_above_cost`, and compiling it costs a hundred times the read.
--
-- Each part is asked for or not: `p_token_hash` the credential (null: none); `p_project` and `p_environment` the place, by slugs, standing ones only (null: none); `p_keys` its keys, those it names, each once (null: every one). A personal config (`dev@me`), a key's own path and a tombstone are the app's own statements' to read; so are a fork's keys, and none is read for a token that names no credential. `bytea_output` pinned: the app reads each bytea as `\x`-hex.
CREATE FUNCTION app_read(p_token_hash bytea, p_project text, p_environment text, p_keys text[]) RETURNS text
    LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp SET plan_cache_mode = force_generic_plan SET enable_seqscan = off SET jit = off SET bytea_output = 'hex' AS $$
DECLARE
    v_credential json;
    v_identity json;
    v_policy text;
    v_project json;
    v_environment json;
    v_parent text;
    v_project_id uuid;
    v_environment_id uuid;
    v_parent_id uuid;
    v_live boolean;
    v_rows json;
BEGIN
    SELECT to_json(c), to_json(i), pol.seq::text, to_json(p), to_json(e), par.slug, p.id, e.id, e.parent_id, p.archived_at IS NULL AND e.archived_at IS NULL
      INTO v_credential, v_identity, v_policy, v_project, v_environment, v_parent, v_project_id, v_environment_id, v_parent_id, v_live
      FROM (SELECT 1) one
      LEFT JOIN public.credentials c ON c.token_hash = p_token_hash
      LEFT JOIN public.identities i ON i.id = c.identity_id
      -- The newest policy change (`newestSeqQuery`), read with the credential, as `credentialRow` reads it.
      LEFT JOIN LATERAL (
          SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1
      ) pol ON p_token_hash IS NOT NULL
      LEFT JOIN public.projects p ON p.slug = p_project AND p.slug NOT LIKE '%~%'
      LEFT JOIN public.environments e ON e.project_id = p.id AND e.slug = p_environment AND e.slug NOT LIKE '%~%'
      LEFT JOIN public.environments par ON par.id = e.parent_id;
    -- Its keys as `environmentSecrets` reads them, each its row and its current version, in key order: none of an
    -- archived project's or environment's. The named ones (distinct: the app's to say) one probe each, by the key's
    -- index and the version's; two statements, as one plan serves only one shape. Not read (null) for a token that
    -- names no credential, which is refused on that alone, so that an unknown one costs its probe and no more; nor of
    -- a fork, whose layers the app reads together, in one snapshot (`readableValues`).
    IF v_environment_id IS NOT NULL AND v_live AND (p_token_hash IS NULL OR v_credential IS NOT NULL) AND v_parent_id IS NULL THEN
        IF p_keys IS NULL THEN
            SELECT json_agg(json_build_object('secret', to_json(s), 'version', to_json(v)) ORDER BY s.key) INTO v_rows
              FROM public.secrets s LEFT JOIN public.secret_versions v ON v.id = s.current_version_id
             WHERE s.project_id = v_project_id AND s.environment_id = v_environment_id;
        ELSE
            SELECT json_agg(json_build_object('secret', to_json(s), 'version', to_json(v)) ORDER BY s.key) INTO v_rows
              FROM unnest(p_keys) k (key)
              -- LIMIT 1, a key being unique in its environment, keeps the lateral a probe by `k.key`: flattened, the planner
              -- estimates an environment's keys as one row, of so many environments, and reads them all to join (review r4).
              CROSS JOIN LATERAL (
                  SELECT * FROM public.secrets x WHERE x.project_id = v_project_id AND x.environment_id = v_environment_id AND x.key = k.key LIMIT 1
              ) s
              LEFT JOIN LATERAL (SELECT * FROM public.secret_versions y WHERE y.id = s.current_version_id) v ON true;
        END IF;
    END IF;
    RETURN json_build_object(
        'credential', v_credential, 'identity', v_identity, 'policy', v_policy,
        'project', v_project, 'environment', v_environment, 'parent', v_parent,
        'secrets', CASE WHEN v_environment_id IS NULL OR (p_token_hash IS NOT NULL AND v_credential IS NULL) OR v_parent_id IS NOT NULL THEN NULL
                        WHEN v_live THEN coalesce(v_rows, '[]') ELSE '[]' END
    )::text;
END;
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app_read(bytea, text, text, text[]) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app_read(bytea, text, text, text[]) TO coffre_app;
