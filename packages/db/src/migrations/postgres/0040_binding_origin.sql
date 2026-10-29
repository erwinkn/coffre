-- The instance a binding was made on (T149, PR 3b; docs/design/credential-lifecycle.md, section 4b): its public URL when the vault sealed it, the audience its runs' tokens name, which its object's seal covers. Kept in its row, `origin`, so that the app names it as sealed whatever the instance's URL is now: a binding made on another URL is still the vault's to end, with what it issued, and signs nobody in through tokens for this one. Null on a binding made before this column (PR 3a's, unreleased; 0.14's, which the log never held), which the app names on its public URL. It adds a nullable column, which the previous release never reads, and redefines `change_bindings` to write it: only 0.15's vault calls it, and that vault is unreleased, as 0037 redefined 0034's `sign_in`.
ALTER TABLE "service_bindings" ADD COLUMN "origin" text;
--> statement-breakpoint
DROP FUNCTION change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid, integer, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[]);
--> statement-breakpoint
CREATE FUNCTION change_bindings(
    p_at bigint, p_actor text,
    p_make boolean, p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint,
    p_via uuid, p_via_seal bytea, p_via_end bigint, p_connection uuid, p_connection_generation integer,
    p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text, p_max integer,
    p_live uuid[], p_read_keys uuid[], p_read_names text[],
    p_id uuid, p_auth_mac bytea, p_profile text, p_issuer text, p_jwks_uri text, p_jwks text, p_claims text, p_scope text, p_policy text, p_origin text,
    p_label text, p_created_by text, p_created_at bigint, p_seal bytea,
    p_ends uuid[], p_end_mac_from bytea[], p_end_seal_from bytea[], p_end_auth_mac bytea[], p_end_seal bytea[],
    p_creds uuid[], p_cred_binding uuid[], p_cred_mac_from bytea[], p_cred_seal_from bytea[], p_cred_auth_mac bytea[], p_cred_seal bytea[],
    p_revoked_at bigint, p_revoked_by text,
    p_change_request text[], p_change_object uuid[], p_change_payload text[], p_change_seal bytea[], p_change_mac bytea[]
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off SET lock_timeout = '1s' AS $$
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
        PERFORM 1 FROM public.vault_members m WHERE m.principal = p_principal FOR NO KEY UPDATE;
        PERFORM 1 FROM public.vault_members m WHERE m.principal = p_actor FOR SHARE;
        IF NOT EXISTS (SELECT 1 FROM public.vault_members m WHERE m.principal = p_actor AND m.status = 'active' AND m.generation = p_actor_generation AND m.access_seq = p_actor_seq)
           OR NOT EXISTS (SELECT 1 FROM public.vault_members m WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation AND m.access_seq = p_principal_seq) THEN
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
$$;

--> statement-breakpoint
REVOKE ALL ON FUNCTION change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid, integer, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[]) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid, integer, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[]) TO coffre_vault;
