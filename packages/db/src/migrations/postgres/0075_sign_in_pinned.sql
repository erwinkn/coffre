-- 0.16.0, T192: a sign-in through a trust binding in one vault statement again. T190 made it two: `sign_in` holds the account's row and the binding's to their objects' newest changes' seals, a column SQL cannot authenticate, so the vault read those changes first, in a statement of its own, to check their MACs. Now the app reads them in the statement it already makes, its service's bindings on the token's issuer (each binding's newest change, and the account's), every column their MAC covers; the vault checks the MACs, and this `sign_in` holds each object's newest change, under the row's lock, to the one checked, whole: its number, every column its MAC covers, and the MAC (`p_member_*`, `p_binding_*`; the binding's seal is `p_binding_seal`), answering `moved` for any other, which the vault reads itself, as T190 did, and asks again. That closes the gap T190 left open (docs/design/sealed-inputs.md): a seal column edited in place, its number kept, once the vault had checked the change's MAC, passed 0037's comparison of the row with it. formal/HotPathOne.tla's ChangePinsChecked (HotPathOneForgedGap).
-- Additive (AGENTS.md, "expand, then contract"): a new overload, thirteen arguments longer; 0037's, which the previous release's vault calls, stays as it is until a release after this one. Settings are 0037's as they stand now (0068 reset `jit`).
-- A sign-in as in 0037, its account and binding each held to the newest change the vault checked: `moved` when that change is not the newest any more.
CREATE FUNCTION sign_in(
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
    since timestamptz;
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
    SELECT m.seal INTO held FROM public.vault_members m
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
       FOR UPDATE;
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
REVOKE ALL ON FUNCTION sign_in(text, bigint, text, text, bytea, bytea, uuid, text, integer, text, text, text, text, text, text, bytea, bytea, bigint, boolean, integer, bigint, bigint, uuid, text, bytea, bytea, text, text, text, text, text, bigint, bigint, text, text, bigint, bigint, text, text, text, bytea, bytea, bigint, bigint, text, text, text, bytea) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION sign_in(text, bigint, text, text, bytea, bytea, uuid, text, integer, text, text, text, text, text, text, bytea, bytea, bigint, boolean, integer, bigint, bigint, uuid, text, bytea, bytea, text, text, text, text, text, bigint, bigint, text, text, bigint, bigint, text, text, text, bytea, bytea, bigint, bigint, text, text, text, bytea) TO coffre_vault;
