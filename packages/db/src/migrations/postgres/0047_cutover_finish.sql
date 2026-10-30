-- 0.15's cutover from 0.14, finished (docs/design/0.15-plan.md, "As built: PR 9b"; formal/Migration015.tla). It adds a column 0.14 never writes, a trigger, and replaces three functions only 0.15's vault calls.
--
-- Once the cutover is there, 0.14's code writes nothing (OldWritesRefused, OldWritesBeforeAnchor). An isolate of 0.14 may still serve after 0.15 cut over: its uses go on, its writes would leave rows no change of 0.15's seals, `stale` to every use (the plan's "late 0.14 write"). Each entry a writer under 0.15's log appends carries `log015`, which no MAC covers and 0.14 never sets; the trigger refuses an allowed entry without it, but a read's, a use's or the log's own (`audit.*`: its beats, checkpoints, findings and the losses an Owner accepts; the alarms), once the cutover's change is in `log_changes`. The append fails, and with it the transaction that wrote its rows: the old isolate answers an error, and its client asks again of 0.15. Every 0.14 append holds 0.14's head, which the cutover holds to its commit, so an append either commits before the cutover or sees it. Sign-ins are refused too (`sign_in`, `token.exchange`, `device.approve`): a credential 0.14 makes after the cutover is one 0.15 never sealed. Before the cutover it costs a 0.14 write one probe of `log_changes_object_idx`; a 0.15 entry passes it by its WHEN. An owner who drops the trigger lets a late write land, its object `stale`; a row put back over it is still refused by the use's probe of 0.14's newest access entry (UsesSeeOldWrites).
ALTER TABLE "audit_log" ADD COLUMN "log015" boolean;
--> statement-breakpoint
CREATE FUNCTION log_refuse_old_write() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = public.log_object('log', 'cutover')) THEN
        RAISE EXCEPTION '0.15''s log is cut over from 0.14: 0.14''s % is refused, as every write of 0.14''s after it (an isolate of the earlier release still serving: ask again)', NEW.action
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NEW;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION log_refuse_old_write() FROM PUBLIC;
--> statement-breakpoint
CREATE TRIGGER audit_log_refuse_old BEFORE INSERT ON audit_log FOR EACH ROW
    WHEN (NEW.decision = 'allow' AND NEW.log015 IS NULL AND NEW.action NOT LIKE 'audit.%' AND NEW.action NOT IN (
        'credential.use', 'token.use', 'secret.read', 'secret.use', 'secret.list', 'secret.history', 'secret.version', 'missing.list', 'personal.list',
        'roles.list', 'roles.preview', 'mcp.read', 'mcp.view', 'key.check', 'key.intent', 'workload.alert', 'vault.tampered'
    ))
    EXECUTE FUNCTION log_refuse_old_write();
--> statement-breakpoint
-- A revoke as 0034 made it (its comment says how), but for 0.14's head, taken first (EntryLessHead, Migration015EntryLess): it writes no 0.14 entry, and 0.14's use of the credential, on an isolate still serving, checks its row under the head, then commits. Without the head, the revoke commits and answers between the two, and that use goes on. So: 0.14's head, the row, the fence, as the app's writes take them (AppHeadFirst). Until 0.16 removes 0.14's path.
CREATE OR REPLACE FUNCTION revoke_credential(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal_from bytea, p_seal bytea,
    p_id uuid, p_mac_from bytea, p_auth_mac bytea, p_revoked_at bigint, p_revoked_by text,
    p_policy boolean, p_policy_seq bigint, p_protected uuid[], p_slugs text[]
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off SET lock_timeout = '1s' AS $$
DECLARE
    n bigint;
    target uuid := public.log_object('credential', p_id::text);
BEGIN
    IF p_seal_from IS NULL OR p_seal IS NULL THEN
        RAISE EXCEPTION 'the vault revokes a credential the log holds, from its seal' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE;
    PERFORM 1 FROM public.credentials c
     WHERE c.id = p_id AND c.revoked_at IS NULL AND c.auth_mac = p_mac_from AND c.seal IS NOT DISTINCT FROM p_seal_from
       FOR UPDATE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'moved'); END IF;
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    -- ChangeChecksSeal: a row the log sealed once, put back since, is not its newest change's.
    IF p_seal_from IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = target ORDER BY c.number DESC LIMIT 1) THEN
        RETURN json_build_object('state', 'stale');
    END IF;
    IF p_policy AND (
        (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.action = 'policy.change' AND a.decision = 'allow' ORDER BY a.seq DESC LIMIT 1)
            IS DISTINCT FROM p_policy_seq
        -- Each protected environment's slug as it stands, none once it or its project is deleted (a tombstone), as `policyNow` reads them.
        OR EXISTS (
            SELECT 1 FROM unnest(p_protected, p_slugs) AS p(id, slug)
             WHERE (SELECT e.slug FROM public.environments e JOIN public.projects q ON q.id = e.project_id
                     WHERE e.id = p.id AND strpos(e.slug, '~') = 0 AND strpos(q.slug, '~') = 0) IS DISTINCT FROM p.slug
        )
    ) THEN
        RETURN json_build_object('state', 'policy');
    END IF;
    UPDATE public.credentials
       SET revoked_at = timestamptz 'epoch' + p_revoked_at * interval '1 millisecond', revoked_by = p_revoked_by, auth_mac = p_auth_mac, seal = p_seal
     WHERE id = p_id;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN json_build_object('number', n::text);
END
$$;
--> statement-breakpoint
-- A change of bindings as 0040 made it (its comment says how), but for 0.14's head when it ends any, for the revokes it writes with no 0.14 entry, as `revoke_credential` above: after the members' rows (0.14's vault takes a member's row before the head) and before any row of the app's (the credential it came in on, the bindings, their credentials), as 0.14's app takes the head before its rows. A bind that ends nothing takes none.
CREATE OR REPLACE FUNCTION change_bindings(
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
        -- 0.14's head, when it ends any, after the members' rows and before any row of the app's (row, head, issue lock, fence).
        IF cardinality(p_ends) > 0 THEN PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE; END IF;
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
$$;
--> statement-breakpoint
-- A binding's genesis as 0041 made it, but for its scope, held to the object too (PR 9a's review, P3): a row whose scope moved past the cutover's read, under its locks, is not sealed (`moved`: the cutover reads again), rather than sealed to an object every use of it then refuses. A scope is canonical JSON in its object and any JSON in its row: compared as jsonb. One the vault cannot read as a scope is no binding's of 0.14 (`planCutover`), never sealed.
CREATE OR REPLACE FUNCTION seal_binding(p_id uuid, p_request text, p_at bigint, p_actor text, p_payload text, p_seal bytea, p_mac bytea) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    op jsonb := p_payload::jsonb;
    target uuid := public.log_object('binding', p_id::text);
    n bigint;
    done integer;
BEGIN
    IF op ->> 'op' IS DISTINCT FROM 'genesis' OR op #>> '{ref,kind}' IS DISTINCT FROM 'binding' OR op #>> '{ref,id}' IS DISTINCT FROM p_id::text
       OR op #>> '{value,kind}' IS DISTINCT FROM 'binding' OR op #>> '{value,id}' IS DISTINCT FROM p_id::text OR op #>> '{value,origin}' IS NULL OR p_seal IS NULL THEN
        RAISE EXCEPTION 'not a binding''s genesis: %', p_payload USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE;
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request;
    IF FOUND THEN
        IF NOT EXISTS (SELECT 1 FROM public.log_changes c WHERE c.request_id = p_request AND c.object = target AND c.payload = p_payload AND c.seal = p_seal) THEN
            RAISE EXCEPTION 'request % names another change', p_request USING ERRCODE = 'unique_violation';
        END IF;
        RETURN n;
    END IF;
    IF EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = public.log_object('log', 'cutover')) THEN
        RAISE EXCEPTION 'the log is cut over from 0.14 already: a binding is the vault''s to make' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = target) THEN
        RETURN NULL;
    END IF;
    UPDATE public.service_bindings b SET seal = p_seal, origin = op #>> '{value,origin}'
     WHERE b.id = p_id AND b.seal IS NULL AND b.revoked_at IS NULL AND b.origin IS NULL
       AND b.principal = op #>> '{value,principal}' AND b.generation = (op #>> '{value,generation}')::integer
       AND b.profile = op #>> '{value,profile}' AND b.issuer = op #>> '{value,issuer}' AND b.jwks_uri = op #>> '{value,jwksUri}'
       AND b.claims = op #>> '{value,claims}' AND b.policy IS NOT DISTINCT FROM op #>> '{value,policy}'
       AND (CASE WHEN b.scope IS NULL THEN 'null'::jsonb WHEN pg_input_is_valid(b.scope, 'jsonb') THEN b.scope::jsonb END) = op #> '{value,scope}';
    GET DIAGNOSTICS done = ROW_COUNT;
    IF done = 0 THEN RETURN NULL; END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN n;
END
$$;
