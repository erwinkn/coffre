-- A service's trust bindings are the vault's to make and end (T149, PR 3a; D148; docs/design/credential-lifecycle.md, section 4; formal/Lifecycle.tla's BindingSealed). A binding was the app's row, vouched for by its MAC alone, so the app's code, turned hostile, could write one that trusts its own key and sign in through it: it holds APP_KEY. Now the vault weighs who makes one, as it weighs a service token's issue, and seals it as a change of the log (`change_bindings`). A sign-in takes only a binding whose seal is the vault's and its object's newest change's: `sign_in` again, given the binding's every column and its seal. This drops 0034's `sign_in`, which only 0.15's vault calls, and that vault is unreleased; it adds a function only that vault calls.
--> statement-breakpoint
-- A sign-in as in 0034, through a binding held to the columns and seal the vault checked (BindingSealed), and that seal held to its object's newest change. A binding's end is that change, so 0.14's tombstone (`token.unbind`) is no longer read. Locks as in 0034.
DROP FUNCTION sign_in(text, bigint, text, text, bytea, bytea, uuid, text, integer, text, text, text, bytea, bigint, boolean, integer, bigint, bigint, uuid, text, bytea, bytea, text, text, text, text, text, bigint, bigint, text, text);
--> statement-breakpoint
CREATE FUNCTION sign_in(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea,
    p_binding uuid, p_principal text, p_generation integer, p_binding_profile text, p_binding_scope text, p_binding_policy text,
    p_binding_issuer text, p_binding_jwks_uri text, p_binding_claims text, p_binding_seal bytea,
    p_spent bytea, p_valid_until bigint, p_frozen boolean, p_rate integer, p_window bigint, p_longest bigint,
    p_id uuid, p_kind text, p_auth_mac bytea, p_token_hash bytea, p_token_hint text, p_label text, p_created_by text,
    p_scope text, p_places text, p_expires bigint, p_not_after bigint, p_jkt text, p_app_key text
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off SET lock_timeout = '1s' AS $$
DECLARE
    n bigint;
    held record;
    now_ms bigint;
    since timestamptz;
    target uuid := public.log_object('credential', p_id::text);
BEGIN
    IF p_created_by IS DISTINCT FROM 'binding:' || p_binding::text OR p_kind NOT IN ('service', 'workload') THEN
        RAISE EXCEPTION 'a sign-in makes a credential of its binding''s, a service''s or a workload''s' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A lock not had within `lock_timeout` raises `lock_not_available`, which the vault answers as busy: no subtransaction to catch it here.
    -- The account's row, locked, then held to its newest change's seal in a statement of its own, which reads what committed
    -- while it waited: a recheck under the lock sees the row's new version beside the snapshot's older changes, and would
    -- refuse an account a grant just changed. A row put back is none; 0.14's has neither seal nor change (before the cutover).
    SELECT m.seal INTO held FROM public.vault_members m
     WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation
       FOR SHARE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    IF held.seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('principal', p_principal) ORDER BY c.number DESC LIMIT 1) THEN
        RETURN json_build_object('state', 'unbound');
    END IF;
    -- The binding as the vault checked its seal (BindingSealed): its every column its object takes, and that seal; then, in
    -- a statement of its own once locked, that seal its object's newest change's. A row put back after its end, or edited
    -- around the vault, is none.
    PERFORM 1 FROM public.service_bindings b
     WHERE b.id = p_binding AND b.principal = p_principal AND b.generation = p_generation AND b.revoked_at IS NULL AND b.profile = p_binding_profile
       AND b.scope IS NOT DISTINCT FROM p_binding_scope AND b.policy IS NOT DISTINCT FROM p_binding_policy
       AND b.issuer = p_binding_issuer AND b.jwks_uri = p_binding_jwks_uri AND b.claims = p_binding_claims AND b.seal = p_binding_seal
       FOR UPDATE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    IF p_binding_seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('binding', p_binding::text) ORDER BY c.number DESC LIMIT 1) THEN
        RETURN json_build_object('state', 'unbound');
    END IF;
    -- The app's key, not one it rotated from (audit_log_subject_idx).
    IF EXISTS (SELECT 1 FROM public.audit_log a WHERE a.author = 'app' AND a.subject_principal = p_app_key AND a.action IN ('key.reseal', 'key.rotate')) THEN
        RETURN json_build_object('state', 'retired');
    END IF;
    -- A freeze of the whole instance, the account or the binding: its newest freeze or lift (audit_log_freeze_idx).
    IF p_frozen AND EXISTS (
        SELECT 1 FROM unnest(ARRAY['instance', p_principal, 'binding:' || p_binding::text]) t(target)
         WHERE (SELECT a.action FROM public.audit_log a
                 WHERE a.author = 'app' AND a.action IN ('workload.freeze', 'workload.unfreeze') AND a.decision = 'allow'
                   AND (a.metadata::jsonb ->> 'target') = t.target
                 ORDER BY a.seq DESC LIMIT 1) = 'workload.freeze'
    ) THEN
        RETURN json_build_object('state', 'frozen');
    END IF;
    -- Its rate, under the binding's row (credentials_issued_by_idx: the last window's, never the history). Its start a
    -- value, not `clock_timestamp()`, which is volatile: compared with that, the index bounds nothing, and the window's
    -- count would read the binding's every credential.
    since := clock_timestamp() - p_window * interval '1 millisecond';
    IF (SELECT count(*) FROM (
            SELECT 1 FROM public.credentials c
             WHERE c.principal = p_principal AND c.created_by = p_created_by AND c.created_at > since
             LIMIT p_rate
        ) z) >= p_rate THEN
        RETURN json_build_object('state', 'busy');
    END IF;
    now_ms := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF p_valid_until <= now_ms OR p_expires <= now_ms OR p_expires > now_ms + p_longest + 60000 OR (p_not_after IS NOT NULL AND (p_not_after <= now_ms OR p_expires > p_not_after)) THEN
        RETURN json_build_object('state', 'expired');
    END IF;
    -- The token spent (SpentChecked): the primary key decides between two runs presenting it at once.
    IF p_spent IS NOT NULL THEN
        INSERT INTO public.consumed_tokens (hash) VALUES (p_spent) ON CONFLICT DO NOTHING;
        IF NOT FOUND THEN RETURN json_build_object('state', 'replayed'); END IF;
    END IF;
    INSERT INTO public.credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, identity_id, scope, places, label, created_by,
                                    expires_at, revoked_at, jkt, not_after, seal)
        VALUES (p_id, p_kind, p_auth_mac, p_token_hash, p_token_hint, p_generation, p_principal, NULL, p_scope, p_places, p_label, p_created_by,
                timestamptz 'epoch' + p_expires * interval '1 millisecond', NULL, p_jkt,
                CASE WHEN p_not_after IS NULL THEN NULL ELSE timestamptz 'epoch' + p_not_after * interval '1 millisecond' END, p_seal);
    UPDATE public.service_bindings SET last_used_at = clock_timestamp() WHERE id = p_binding;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN json_build_object('number', n::text);
END
$$;
--> statement-breakpoint
-- A change of service `p_principal`'s bindings, as the vault decided it. It does either or both of these:
-- - Makes a binding (`p_make`: its row, `p_id` to `p_seal`), weighed on its maker `p_actor` at `p_actor_seq`, the account at `p_principal_seq` (their `access_seq`), the credential `p_via` at its seal and end, and the policy at `p_policy_seq` with its slugs.
-- - Ends bindings (`p_ends`, moving each from the MAC and seal read to `p_end_auth_mac` and `p_end_seal`), and with them every live credential each issued (`p_creds`, likewise).
-- Each object's change is in `p_change_*`, in order.
-- Its answer, JSON: `{"number": "<n>"}`, the last change's number, or `{"state": …}` with nothing written:
-- - `moved`: a member, a binding or a credential is not as read, or a live credential that a binding it ends issued is not named (asked again);
-- - `ended`: the credential it came in on is not as read, or past its end;
-- - `policy`: the policy moved since, or one of its environments' slugs;
-- - `retired`: the app signed the rows under a key it rotated from;
-- - `stale`: a row it ends is not its object's newest change's (one put back);
-- - `full`: the account holds `p_max` live bindings, besides those it ends.
-- Locks, in the order every writer takes them:
-- 1. the account's row, its update lock (two binds take turns over its count), then the maker's, shared (IssuerLocked);
-- 2. the credential it came in on, shared;
-- 3. the bindings it ends and their credentials, exclusive (BindingLocked: a sign-in through one waits, or is seen); the keys a binding it makes reads, shared;
-- 4. the issue lock, shared (IssuePolicyHeld, IssueOffFence);
-- 5. when it ends any, the fence, exclusive (RevokeTakesFence), after the issue lock (PolicyIssueFirst).
-- No 0.14 head and no 0.14 entry: its changes record it (D147).
CREATE FUNCTION change_bindings(
    p_at bigint, p_actor text,
    p_make boolean, p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint,
    p_via uuid, p_via_seal bytea, p_via_end bigint,
    p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text, p_max integer,
    p_live uuid[], p_read_keys uuid[], p_read_names text[],
    p_id uuid, p_auth_mac bytea, p_profile text, p_issuer text, p_jwks_uri text, p_jwks text, p_claims text, p_scope text, p_policy text,
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
       OR cardinality(p_change_request) <> (CASE WHEN p_make THEN 1 ELSE 0 END) + cardinality(p_ends) + (SELECT count(*) FROM unnest(p_cred_seal) AS s WHERE s IS NOT NULL) THEN
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
    END IF;
    -- The bindings it ends, then the credentials they issued: each row locked, by id, then held to its MAC and seal as
    -- read. Every live credential they issued must be named, so one that a sign-in made meanwhile is read again (`moved`),
    -- never left live.
    PERFORM 1 FROM public.service_bindings b WHERE b.id = ANY(p_ends) ORDER BY b.id FOR UPDATE;
    IF (SELECT count(*) FROM unnest(p_ends, p_end_mac_from, p_end_seal_from) AS e(id, mac, seal)
          JOIN public.service_bindings b ON b.id = e.id AND b.principal = p_principal AND b.revoked_at IS NULL AND b.auth_mac = e.mac AND b.seal = e.seal)
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
        -- The keys its policy reads, by the names they were asked by: held, and still those names (a rename meanwhile names another).
        PERFORM 1 FROM public.secrets x WHERE x.id = ANY(p_read_keys) ORDER BY x.id FOR SHARE;
        IF (SELECT count(*) FROM unnest(p_read_keys, p_read_names) AS r(id, name) JOIN public.secrets x ON x.id = r.id AND x.key = r.name) <> cardinality(p_read_keys) THEN
            RETURN json_build_object('state', 'moved');
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
    -- ChangeChecksSeal: each row it ends is its object's newest change's; one put back is stale.
    IF EXISTS (SELECT 1 FROM unnest(p_ends, p_end_seal_from) AS e(id, seal)
                WHERE e.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = public.log_object('binding', e.id::text) ORDER BY l.number DESC LIMIT 1))
       OR EXISTS (SELECT 1 FROM unnest(p_creds, p_cred_seal_from) AS x(id, seal)
                WHERE x.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = public.log_object('credential', x.id::text) ORDER BY l.number DESC LIMIT 1)) THEN
        RETURN json_build_object('state', 'stale');
    END IF;
    IF p_make THEN
        INSERT INTO public.service_bindings (id, auth_mac, principal, generation, profile, issuer, jwks_uri, jwks, claims, scope, policy, label, created_by, created_at, seal)
            VALUES (p_id, p_auth_mac, p_principal, p_generation, p_profile, p_issuer, p_jwks_uri, p_jwks, p_claims, p_scope, p_policy, p_label, p_created_by,
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
    RETURN json_build_object('number', n::text);
END
$$;

--> statement-breakpoint
REVOKE ALL ON FUNCTION sign_in(text, bigint, text, text, bytea, bytea, uuid, text, integer, text, text, text, text, text, text, bytea, bytea, bigint, boolean, integer, bigint, bigint, uuid, text, bytea, bytea, text, text, text, text, text, bigint, bigint, text, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION sign_in(text, bigint, text, text, bytea, bytea, uuid, text, integer, text, text, text, text, text, text, bytea, bytea, bigint, boolean, integer, bigint, bigint, uuid, text, bytea, bytea, text, text, text, text, text, bigint, bigint, text, text) TO coffre_vault;
--> statement-breakpoint
REVOKE ALL ON FUNCTION change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[]) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[]) TO coffre_vault;
