-- 0.16.0, W331 (D177): one binding's sign-ins run together, and none is counted. `sign_in` held the binding's row FOR UPDATE to its commit and counted the binding's credentials of the last minute under it, refusing the 61st (`busy`); every sign-in also wrote the row's `last_used_at`. So one binding's sign-ins took turns, each waiter holding its connection (50 at once: 1,412 a second, 35 ms each, on the compose Postgres). Now a sign-in takes the row FOR KEY SHARE, which every other sign-in shares and only an unbind's FOR UPDATE (`change_bindings`) waits for, or is waited for by: removing a binding still ends every credential it issued (formal/Lifecycle.tla: BindingLocked, UnbindExclusive, SweepAfterLock; EndedBindingEndsCredentials). No count: an ID token buys one credential (`spent_id_tokens`), and the per-address limit at the door is the bound (`perSource`). And `last_used_at` is written only when a minute old, by whichever sign-in gets the row's update lock first, which FOR KEY SHARE shares: one that finds another stamping it skips (SKIP LOCKED) rather than wait (TouchSkipsLocked; SignInsRunTogether).
-- FOR KEY SHARE, not FOR SHARE: the stamp's UPDATE takes FOR NO KEY UPDATE, which FOR SHARE excludes. Under FOR SHARE, a sign-in arriving while another stamps the row would wait for that one's commit; and the stamp, skipped whenever another sign-in shares the row, would go unwritten as long as sign-ins overlap, which under load is always (review r1 of #520). FOR KEY SHARE waits only for FOR UPDATE, which `change_bindings` takes on every binding it ends; the other writers of a binding's row take FOR NO KEY UPDATE and change nothing a 0.15 sign-in weighs: `seal_binding` gives a binding its first seal, before the cutover (a sign-in names a seal, and the row's must be it); `app_change` moves only a row's seal, which then is no binding change's; 0.14's untrust and scope seal run under 0.14's head, with a vault that does not sign in (`about().credentials` and `binds` come together), or on a scope no sign-in names (unsealed).
-- Additive (AGENTS.md, "expand, then contract"): both overloads keep their signatures and answers (0.15.0's, which the previous release's vault calls, and 0075's, T192, which this release's does), `busy` now only a lock not had within `lock_timeout`. `p_rate` and `p_window` are taken and unread, so the previous release's vault, which passes them, signs in unchanged; a later release drops them.
-- A binding's removal in batches (review r3 of #520; formal/Unbinding.tla). With no count, a binding's live credentials can outgrow one vault message (Node's 8 MiB, about 15,000 of them), and `change_bindings`, which names them all, failed, the binding left live. So a removal first closes the binding, a sweep under its row's FOR UPDATE that sets `closed_at`, which `sign_in` reads (a closed binding signs nobody in, `unbound`), and revokes a batch of its credentials, each a change; then sweeps again while more than a batch is left; then ends it as before, every live credential named. `change_bindings` takes that as `p_sweep`, an overload of its own (0.15.0's signature calls it with none, one body); `closed_at` is a nullable column the previous release never reads.
--> statement-breakpoint
ALTER TABLE "service_bindings" ADD COLUMN "closed_at" timestamp with time zone;
--> statement-breakpoint
ALTER TABLE "service_bindings" ADD COLUMN "closed_by" text;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.sign_in(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea,
    p_binding uuid, p_principal text, p_generation integer, p_binding_profile text, p_binding_scope text, p_binding_policy text,
    p_binding_issuer text, p_binding_jwks_uri text, p_binding_claims text, p_binding_seal bytea,
    p_spent bytea, p_valid_until bigint, p_frozen boolean, p_rate integer, p_window bigint, p_longest bigint,
    p_id uuid, p_kind text, p_auth_mac bytea, p_token_hash bytea, p_token_hint text, p_label text, p_created_by text,
    p_scope text, p_places text, p_expires bigint, p_not_after bigint, p_jkt text, p_app_key text
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '1s' AS $$
DECLARE
    n bigint;
    held record;
    now_ms bigint;
    -- A value, not `clock_timestamp()` in a predicate: volatile there, it is read again for every row.
    stamped timestamptz := clock_timestamp();
    target uuid := public.log_object('credential', p_id::text);
BEGIN
    IF p_created_by IS DISTINCT FROM 'binding:' || p_binding::text OR p_kind NOT IN ('service', 'workload') THEN
        RAISE EXCEPTION 'a sign-in makes a credential of its binding''s, a service''s or a workload''s' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A lock not had within `lock_timeout` raises `lock_not_available`, which the vault answers as busy: no subtransaction to catch it here.
    -- The account's row, locked, then held to its newest change's seal in a statement of its own, which reads what committed
    -- while it waited: a recheck under the lock sees the row's new version beside the snapshot's older changes, and would
    -- refuse an account a grant just changed. A row put back is none; 0.14's has neither seal nor change (before the cutover).
    SELECT m.seal INTO held FROM public.principals m
     WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation
       FOR SHARE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    IF held.seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('principal', p_principal) ORDER BY c.number DESC LIMIT 1) THEN
        RETURN json_build_object('state', 'unbound');
    END IF;
    -- The binding as the vault checked its seal (BindingSealed): its every column its object takes, and that seal; then, in
    -- a statement of its own once locked, that seal its object's newest change's. A row put back after its end, or edited
    -- around the vault, is none. FOR KEY SHARE: every sign-in through it shares the row; an unbind's FOR UPDATE waits for
    -- them all, and they for it, so a credential this commits is one the unbind's sweep finds, or the unbind is seen.
    PERFORM 1 FROM public.service_bindings b
     WHERE b.id = p_binding AND b.principal = p_principal AND b.generation = p_generation AND b.revoked_at IS NULL AND b.profile = p_binding_profile
       AND b.scope IS NOT DISTINCT FROM p_binding_scope AND b.policy IS NOT DISTINCT FROM p_binding_policy
       AND b.issuer = p_binding_issuer AND b.jwks_uri = p_binding_jwks_uri AND b.claims = p_binding_claims AND b.seal = p_binding_seal
       -- Closed by a removal under way (`change_bindings`' sweep): no row, no lock, `unbound` (Unbinding.tla, SignInChecksClosed).
       AND b.closed_at IS NULL
       FOR KEY SHARE;
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
    now_ms := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF p_valid_until <= now_ms OR p_expires <= now_ms OR p_expires > now_ms + p_longest + 60000 OR (p_not_after IS NOT NULL AND (p_not_after <= now_ms OR p_expires > p_not_after)) THEN
        RETURN json_build_object('state', 'expired');
    END IF;
    -- The token spent (SpentChecked): the primary key decides between two runs presenting it at once.
    IF p_spent IS NOT NULL THEN
        INSERT INTO public.spent_id_tokens (hash) VALUES (p_spent) ON CONFLICT DO NOTHING;
        IF NOT FOUND THEN RETURN json_build_object('state', 'replayed'); END IF;
    END IF;
    INSERT INTO public.credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, identity_id, scope, places, label, created_by,
                                    expires_at, revoked_at, jkt, not_after, seal)
        VALUES (p_id, p_kind, p_auth_mac, p_token_hash, p_token_hint, p_generation, p_principal, NULL, p_scope, p_places, p_label, p_created_by,
                timestamptz 'epoch' + p_expires * interval '1 millisecond', NULL, p_jkt,
                CASE WHEN p_not_after IS NULL THEN NULL ELSE timestamptz 'epoch' + p_not_after * interval '1 millisecond' END, p_seal);
    -- Its last use, when a minute old (TouchSkipsLocked): the row's update lock, which the sign-ins' FOR KEY SHARE shares,
    -- had at once or skipped, as another sign-in is stamping it. A minute: Erwin's (D177); what an owner reads of it,
    -- `coffre trust`'s list and the bindings page, shows the minute.
    UPDATE public.service_bindings b SET last_used_at = stamped
     WHERE b.id = (SELECT s.id FROM public.service_bindings s
                    WHERE s.id = p_binding AND (s.last_used_at IS NULL OR s.last_used_at < stamped - interval '1 minute')
                      FOR NO KEY UPDATE SKIP LOCKED);
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN json_build_object('number', n::text);
END
$$;
--> statement-breakpoint
-- 0075's overload (T192: the account and the binding pinned to the changes the vault checked), which this release's
-- vault calls: the same, the binding's row shared, no count, the stamp when a minute old, a closed binding refused. Its
-- `p_rate` and `p_window` are taken and unread.
CREATE OR REPLACE FUNCTION public.sign_in(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea,
    p_binding uuid, p_principal text, p_generation integer, p_binding_profile text, p_binding_scope text, p_binding_policy text,
    p_binding_issuer text, p_binding_jwks_uri text, p_binding_claims text, p_binding_seal bytea,
    p_spent bytea, p_valid_until bigint, p_frozen boolean, p_rate integer, p_window bigint, p_longest bigint,
    p_id uuid, p_kind text, p_auth_mac bytea, p_token_hash bytea, p_token_hint text, p_label text, p_created_by text,
    p_scope text, p_places text, p_expires bigint, p_not_after bigint, p_jkt text, p_app_key text,
    p_member_number bigint, p_member_at bigint, p_member_request text, p_member_actor text, p_member_payload text, p_member_seal bytea, p_member_mac bytea,
    p_binding_number bigint, p_binding_at bigint, p_binding_request text, p_binding_actor text, p_binding_payload text, p_binding_mac bytea
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '1s' AS $$
DECLARE
    n bigint;
    held record;
    newest record;
    now_ms bigint;
    stamped timestamptz := clock_timestamp();
    target uuid := public.log_object('credential', p_id::text);
BEGIN
    IF p_created_by IS DISTINCT FROM 'binding:' || p_binding::text OR p_kind NOT IN ('service', 'workload') THEN
        RAISE EXCEPTION 'a sign-in makes a credential of its binding''s, a service''s or a workload''s' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A lock not had within `lock_timeout` raises `lock_not_available`, which the vault answers as busy: no subtransaction to catch it here.
    -- The account's row, locked, then its newest change, in a statement of its own, which reads what committed while it
    -- waited: a recheck under the lock sees the row's new version beside the snapshot's older changes. That change must be
    -- the one whose MAC the vault checked (ChangePinsChecked), whole (ChangePinsWhole): its number, every column its MAC
    -- covers, and the MAC. Its seal alone would not do, a column a writer may edit in place, number kept, once the check is
    -- done; nor its number and seal, which an old, authentic change of the account shares with its removal once a writer
    -- sets the removal's seal to the old one's: no MAC covers a number, and the app chooses what it hands back. Whole, the
    -- row is one whose MAC holds, as if the vault had read it here. Another is `moved`, for the vault to read it again.
    -- Then the row held to that seal: a row put back is none.
    SELECT m.seal INTO held FROM public.principals m
     WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation
       FOR SHARE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    SELECT c.number, c.at, c.request_id, c.actor, c.payload, c.seal, c.mac INTO newest
      FROM public.log_changes c WHERE c.object = public.log_object('principal', p_principal) ORDER BY c.number DESC LIMIT 1;
    IF (newest.number, newest.at, newest.request_id, newest.actor, newest.payload, newest.seal, newest.mac)
       IS DISTINCT FROM (p_member_number, p_member_at, p_member_request, p_member_actor, p_member_payload, p_member_seal, p_member_mac) THEN
        RETURN json_build_object('state', 'moved');
    END IF;
    IF held.seal IS DISTINCT FROM p_member_seal THEN RETURN json_build_object('state', 'unbound'); END IF;
    -- The binding as the vault checked its seal (BindingSealed): its every column its object takes, and that seal; then, in
    -- a statement of its own once locked, its object's newest change the one the vault checked, whole, of that seal
    -- (`moved` otherwise, as the account's). A row put back after its end, or edited around the vault, is none.
    PERFORM 1 FROM public.service_bindings b
     WHERE b.id = p_binding AND b.principal = p_principal AND b.generation = p_generation AND b.revoked_at IS NULL AND b.profile = p_binding_profile
       AND b.scope IS NOT DISTINCT FROM p_binding_scope AND b.policy IS NOT DISTINCT FROM p_binding_policy
       AND b.issuer = p_binding_issuer AND b.jwks_uri = p_binding_jwks_uri AND b.claims = p_binding_claims AND b.seal = p_binding_seal
       -- Closed by a removal under way (`change_bindings`' sweep): no row, no lock, `unbound` (Unbinding.tla, SignInChecksClosed).
       AND b.closed_at IS NULL
       -- FOR KEY SHARE (W331): every sign-in through it shares the row; an unbind's or a replacement's FOR UPDATE waits for
       -- them all, and they for it, so the newest change below is still the newest at this one's commit (ChangePinsChecked).
       FOR KEY SHARE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    SELECT c.number, c.at, c.request_id, c.actor, c.payload, c.seal, c.mac INTO newest
      FROM public.log_changes c WHERE c.object = public.log_object('binding', p_binding::text) ORDER BY c.number DESC LIMIT 1;
    IF (newest.number, newest.at, newest.request_id, newest.actor, newest.payload, newest.seal, newest.mac)
       IS DISTINCT FROM (p_binding_number, p_binding_at, p_binding_request, p_binding_actor, p_binding_payload, p_binding_seal, p_binding_mac) THEN
        RETURN json_build_object('state', 'moved');
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
    now_ms := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF p_valid_until <= now_ms OR p_expires <= now_ms OR p_expires > now_ms + p_longest + 60000 OR (p_not_after IS NOT NULL AND (p_not_after <= now_ms OR p_expires > p_not_after)) THEN
        RETURN json_build_object('state', 'expired');
    END IF;
    -- The token spent (SpentChecked): the primary key decides between two runs presenting it at once.
    IF p_spent IS NOT NULL THEN
        INSERT INTO public.spent_id_tokens (hash) VALUES (p_spent) ON CONFLICT DO NOTHING;
        IF NOT FOUND THEN RETURN json_build_object('state', 'replayed'); END IF;
    END IF;
    INSERT INTO public.credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, identity_id, scope, places, label, created_by,
                                    expires_at, revoked_at, jkt, not_after, seal)
        VALUES (p_id, p_kind, p_auth_mac, p_token_hash, p_token_hint, p_generation, p_principal, NULL, p_scope, p_places, p_label, p_created_by,
                timestamptz 'epoch' + p_expires * interval '1 millisecond', NULL, p_jkt,
                CASE WHEN p_not_after IS NULL THEN NULL ELSE timestamptz 'epoch' + p_not_after * interval '1 millisecond' END, p_seal);
    -- Its last use, when a minute old (TouchSkipsLocked), as 0.15.0's overload above.
    UPDATE public.service_bindings b SET last_used_at = stamped
     WHERE b.id = (SELECT s.id FROM public.service_bindings s
                    WHERE s.id = p_binding AND (s.last_used_at IS NULL OR s.last_used_at < stamped - interval '1 minute')
                      FOR NO KEY UPDATE SKIP LOCKED);
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN json_build_object('number', n::text);
END
$$;
--> statement-breakpoint
-- `change_bindings` as 0047 made it, and its sweep (above): `p_sweep`, the bindings in `p_ends` closed, not ended, the credentials named revoked, no other live one asked for. 0068 reset its `jit`, which this leaves off too.
-- Its lock waits, and 0.15.0's signature's below, are `LOCK_WAIT_MS` (500 ms, R75), as 0078_short_fence_waits set
-- them: a `CREATE OR REPLACE` takes the settings it names, so each names that one again.
CREATE FUNCTION public.change_bindings(
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
    p_change_request text[], p_change_object uuid[], p_change_payload text[], p_change_seal bytea[], p_change_mac bytea[],
    p_sweep boolean
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '500ms' AS $$
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
                WHERE e.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = public.log_object('binding', e.id::text) ORDER BY l.number DESC LIMIT 1))
       OR EXISTS (SELECT 1 FROM unnest(p_creds, p_cred_seal_from) AS x(id, seal)
                WHERE x.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = public.log_object('credential', x.id::text) ORDER BY l.number DESC LIMIT 1)) THEN
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
        INSERT INTO public.service_bindings (id, auth_mac, principal, generation, profile, issuer, jwks_uri, jwks, claims, scope, policy, origin, label, created_by, created_at, seal)
            VALUES (p_id, p_auth_mac, p_principal, p_generation, p_profile, p_issuer, p_jwks_uri, p_jwks, p_claims, p_scope, p_policy, p_origin, p_label, p_created_by,
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
$$;
--> statement-breakpoint
-- 0.15.0's signature, which the previous release's vault calls: the same change, no sweep, one body (above).
CREATE OR REPLACE FUNCTION public.change_bindings(
    p_at bigint,
    p_actor text,
    p_make boolean,
    p_principal text,
    p_generation integer,
    p_principal_seq bigint,
    p_actor_generation integer,
    p_actor_seq bigint,
    p_via uuid,
    p_via_seal bytea,
    p_via_end bigint,
    p_connection uuid,
    p_connection_generation integer,
    p_policy_seq bigint,
    p_protected uuid[],
    p_slugs text[],
    p_app_key text,
    p_max integer,
    p_live uuid[],
    p_read_keys uuid[],
    p_read_names text[],
    p_id uuid,
    p_auth_mac bytea,
    p_profile text,
    p_issuer text,
    p_jwks_uri text,
    p_jwks text,
    p_claims text,
    p_scope text,
    p_policy text,
    p_origin text,
    p_label text,
    p_created_by text,
    p_created_at bigint,
    p_seal bytea,
    p_ends uuid[],
    p_end_mac_from bytea[],
    p_end_seal_from bytea[],
    p_end_auth_mac bytea[],
    p_end_seal bytea[],
    p_creds uuid[],
    p_cred_binding uuid[],
    p_cred_mac_from bytea[],
    p_cred_seal_from bytea[],
    p_cred_auth_mac bytea[],
    p_cred_seal bytea[],
    p_revoked_at bigint,
    p_revoked_by text,
    p_change_request text[],
    p_change_object uuid[],
    p_change_payload text[],
    p_change_seal bytea[],
    p_change_mac bytea[]
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '500ms' AS $$
BEGIN
    RETURN public.change_bindings(p_at, p_actor, p_make, p_principal, p_generation, p_principal_seq, p_actor_generation, p_actor_seq, p_via, p_via_seal, p_via_end, p_connection, p_connection_generation, p_policy_seq, p_protected, p_slugs, p_app_key, p_max, p_live, p_read_keys, p_read_names, p_id, p_auth_mac, p_profile, p_issuer, p_jwks_uri, p_jwks, p_claims, p_scope, p_policy, p_origin, p_label, p_created_by, p_created_at, p_seal, p_ends, p_end_mac_from, p_end_seal_from, p_end_auth_mac, p_end_seal, p_creds, p_cred_binding, p_cred_mac_from, p_cred_seal_from, p_cred_auth_mac, p_cred_seal, p_revoked_at, p_revoked_by, p_change_request, p_change_object, p_change_payload, p_change_seal, p_change_mac, false);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION public.change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid, integer, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[], boolean) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION public.change_bindings(bigint, text, boolean, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid, integer, bigint, uuid[], text[], text, integer, uuid[], uuid[], text[], uuid, bytea, text, text, text, text, text, text, text, text, text, text, bigint, bytea, uuid[], bytea[], bytea[], bytea[], bytea[], uuid[], uuid[], bytea[], bytea[], bytea[], bytea[], bigint, text, text[], uuid[], text[], bytea[], bytea[], boolean) TO coffre_vault;
