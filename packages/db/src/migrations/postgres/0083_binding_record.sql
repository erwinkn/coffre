-- 0.17, T253 (docs/design/oidc.md, section 9.3): a binding records claims of its sign-ins' tokens beyond the run's, by name, `service_bindings.record`: canonical JSON, the names sorted, null for none. It is part of the binding, immutable, under the app's MAC (its tuple kind `recorded_…`) and the vault's seal (its object's `record`, present only when set, so every binding sealed before seals as it did).
-- Additive (AGENTS.md, "expand, then contract"): a nullable column the previous release never reads, and `change_bindings` an overload one argument longer, `p_record`, which writes it. 0.16's signature, which the previous release's vault calls, becomes the same change with none, one body, as 0079 made 0.15's; 0.15's still calls 0.16's. And `cutover_bindings_recorded`, 0041's `cutover_bindings` with the column, which this release's vault reads a 0.14 instance's bindings through when it cuts its log over; 0041's stays for the previous release's.
-- `sign_in` is untouched: it holds a binding's row to the columns its sealed object decides a sign-in on, and `record` decides nothing; the vault takes the names from the sealed object, never the row. Nor is the use statement: it reads a binding's row only for a Cloudflare call, whose binding never records (refused by the app and the vault), so its object is the same without the column.
ALTER TABLE "service_bindings" ADD COLUMN "record" text;
--> statement-breakpoint
-- `change_bindings` as 0082 made it, and the binding's `record`.
CREATE FUNCTION public.change_bindings(p_at bigint, p_actor text, p_make boolean, p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint, p_via uuid, p_via_seal bytea, p_via_end bigint, p_connection uuid, p_connection_generation integer, p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text, p_max integer, p_live uuid[], p_read_keys uuid[], p_read_names text[], p_id uuid, p_auth_mac bytea, p_profile text, p_issuer text, p_jwks_uri text, p_jwks text, p_claims text, p_scope text, p_policy text, p_origin text, p_label text, p_created_by text, p_created_at bigint, p_seal bytea, p_ends uuid[], p_end_mac_from bytea[], p_end_seal_from bytea[], p_end_auth_mac bytea[], p_end_seal bytea[], p_creds uuid[], p_cred_binding uuid[], p_cred_mac_from bytea[], p_cred_seal_from bytea[], p_cred_auth_mac bytea[], p_cred_seal bytea[], p_revoked_at bigint, p_revoked_by text, p_change_request text[], p_change_object uuid[], p_change_payload text[], p_change_seal bytea[], p_change_mac bytea[], p_sweep boolean, p_record text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET lock_timeout TO '500ms'
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
    -- A sweep makes nothing and ends no binding: it closes them and revokes the credentials named, a change for each.
    -- Of a replacement, it names the binding to make, held to its maker's rows and the account's as the make is (all of
    -- `p_make`'s checks below), so it closes and revokes only on the standing the make will have (review r4 of #520);
    -- the make itself is the end's.
    IF p_sweep AND (cardinality(p_ends) = 0 OR EXISTS (SELECT 1 FROM unnest(p_end_seal) AS s WHERE s IS NOT NULL)) THEN
        RAISE EXCEPTION 'a sweep closes bindings and revokes their credentials, making and ending none' USING ERRCODE = 'invalid_parameter_value';
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
               OR p_via_seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = ANY(ARRAY[public.log_object('credential', p_via::text)::uuid]) ORDER BY c.object DESC, c.number DESC LIMIT 1) THEN
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
    -- never left live; but a sweep's, which ends no binding (Unbinding.tla: EndComplete is the end's).
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
       <> cardinality(p_creds) THEN
        RETURN json_build_object('state', 'moved');
    END IF;
    -- A statement of its own, so that a sweep never runs it: a binding's other live credentials are the next call's.
    IF NOT p_sweep AND EXISTS (SELECT 1 FROM unnest(p_ends) AS e(id) JOIN public.credentials c
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
        -- Counted among the open ones: a binding a removal closed is on its way out, and a replacement's sweep makes the new
        -- one while the old one, closed, still waits for its end, which would hold a service at the cap a slot short
        -- (review r10). The live set above still names every row not revoked.
        IF (SELECT count(*) FROM public.service_bindings b WHERE b.principal = p_principal AND b.generation = p_generation
                AND b.revoked_at IS NULL AND b.closed_at IS NULL AND NOT (b.id = ANY(p_ends))) >= p_max THEN
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
    -- A sweep that only closes revokes nothing: no fence.
    IF (NOT p_sweep AND cardinality(p_ends) > 0) OR cardinality(p_creds) > 0 THEN PERFORM pg_advisory_xact_lock(1668244070, 0); END IF;
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
                WHERE e.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = ANY(ARRAY[public.log_object('binding', e.id::text)::uuid]) ORDER BY l.object DESC, l.number DESC LIMIT 1))
       OR EXISTS (SELECT 1 FROM unnest(p_creds, p_cred_seal_from) AS x(id, seal)
                WHERE x.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = ANY(ARRAY[public.log_object('credential', x.id::text)::uuid]) ORDER BY l.object DESC, l.number DESC LIMIT 1)) THEN
        RETURN json_build_object('state', 'stale');
    END IF;
    -- A replacement's sweep makes its binding as it closes those it replaces (reviews r8, r9 of #520; Unbinding.tla's
    -- MakesAtClose): stopped after it, what is left is their removal, never a closed binding with nothing in its place.
    IF p_make THEN
        -- Again, now that no lock is left to wait for: a make of the same id that committed meanwhile, its row deleted since,
        -- is seen; one not yet committed holds the id's key, which this insert then waits for and fails on (review r4).
        IF EXISTS (SELECT 1 FROM public.log_changes l WHERE l.object = public.log_object('binding', p_id::text)) THEN
            RETURN json_build_object('state', 'stale');
        END IF;
        INSERT INTO public.service_bindings (id, auth_mac, principal, generation, profile, issuer, jwks_uri, jwks, claims, scope, policy, record, origin, label, created_by, created_at, seal)
            VALUES (p_id, p_auth_mac, p_principal, p_generation, p_profile, p_issuer, p_jwks_uri, p_jwks, p_claims, p_scope, p_policy, p_record, p_origin, p_label, p_created_by,
                    timestamptz 'epoch' + p_created_at * interval '1 millisecond', p_seal);
    END IF;
    IF p_sweep THEN
        -- Closed (Unbinding.tla's close): `sign_in` drops a closed row from its WHERE, so no sign-in commits through it once
        -- this does, and the removal's next read is its last but for what it revokes. Neither the row's MAC nor its seal
        -- covers `closed_at`: a writer who clears it lets sign-ins on, which the end then finds (`moved`), never leaves live.
        -- By whom, the first close standing: the scheduled run names them when it goes on with the removal (`continues`).
        UPDATE public.service_bindings b SET closed_at = coalesce(b.closed_at, now_ts), closed_by = coalesce(b.closed_by, p_actor) WHERE b.id = ANY(p_ends);
    ELSE
        UPDATE public.service_bindings b SET revoked_at = ended, revoked_by = p_revoked_by, auth_mac = e.mac, seal = e.seal
          FROM unnest(p_ends, p_end_auth_mac, p_end_seal) AS e(id, mac, seal) WHERE b.id = e.id;
    END IF;
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
REVOKE ALL ON FUNCTION public.change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid, integer, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[], boolean, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid, integer, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[], boolean, text) TO coffre_vault;
--> statement-breakpoint
-- 0.16's signature, which the previous release's vault calls: the same change, with no recorded claims, one body (above).
CREATE OR REPLACE FUNCTION public.change_bindings(p_at bigint, p_actor text, p_make boolean, p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint, p_via uuid, p_via_seal bytea, p_via_end bigint, p_connection uuid, p_connection_generation integer, p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text, p_max integer, p_live uuid[], p_read_keys uuid[], p_read_names text[], p_id uuid, p_auth_mac bytea, p_profile text, p_issuer text, p_jwks_uri text, p_jwks text, p_claims text, p_scope text, p_policy text, p_origin text, p_label text, p_created_by text, p_created_at bigint, p_seal bytea, p_ends uuid[], p_end_mac_from bytea[], p_end_seal_from bytea[], p_end_auth_mac bytea[], p_end_seal bytea[], p_creds uuid[], p_cred_binding uuid[], p_cred_mac_from bytea[], p_cred_seal_from bytea[], p_cred_auth_mac bytea[], p_cred_seal bytea[], p_revoked_at bigint, p_revoked_by text, p_change_request text[], p_change_object uuid[], p_change_payload text[], p_change_seal bytea[], p_change_mac bytea[], p_sweep boolean)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET lock_timeout TO '500ms'
AS $function$
BEGIN
    RETURN public.change_bindings(p_at, p_actor, p_make, p_principal, p_generation, p_principal_seq, p_actor_generation, p_actor_seq, p_via, p_via_seal, p_via_end, p_connection, p_connection_generation, p_policy_seq, p_protected, p_slugs, p_app_key, p_max, p_live, p_read_keys, p_read_names, p_id, p_auth_mac, p_profile, p_issuer, p_jwks_uri, p_jwks, p_claims, p_scope, p_policy, p_origin, p_label, p_created_by, p_created_at, p_seal, p_ends, p_end_mac_from, p_end_seal_from, p_end_auth_mac, p_end_seal, p_creds, p_cred_binding, p_cred_mac_from, p_cred_seal_from, p_cred_auth_mac, p_cred_seal, p_revoked_at, p_revoked_by, p_change_request, p_change_object, p_change_payload, p_change_seal, p_change_mac, p_sweep, NULL::text);
END
$function$;
--> statement-breakpoint
-- `cutover_bindings` as 0041 made it, and the binding's `record`: a binding this release makes before the cutover, under 0.14's log, carries it under the app's MAC, so the vault seals it with the rest. 0041's stays for the previous release's vault.
CREATE FUNCTION cutover_bindings_recorded(p_ids uuid[]) RETURNS TABLE (
    id uuid, principal text, generation integer, profile text, issuer text, origin text, jwks_uri text, claims text, scope text, policy text, record text, revoked boolean, seal bytea, logged boolean
)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT b.id, b.principal, b.generation, b.profile, b.issuer, b.origin, b.jwks_uri, b.claims, b.scope, b.policy, b.record, b.revoked_at IS NOT NULL, b.seal,
           EXISTS (SELECT 1 FROM public.log_changes l WHERE l.object = public.log_object('binding', b.id::text))
      FROM public.service_bindings b WHERE b.id = ANY (p_ids)
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION cutover_bindings_recorded(uuid[]) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION cutover_bindings_recorded(uuid[]) TO coffre_vault;
