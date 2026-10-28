-- The vault makes and ends credentials itself, each in one statement (T149, D146; docs/design/credential-lifecycle.md; formal/Lifecycle.tla). A sign-in through a trust binding (a CI run's, a workload's) and a revoke were the app's transactions under 0.14's head, with `prepare` sealing whatever row the app proposed: a sign-in was 8 statements, 6 holding the head every app write waits for, and a burst of them queued there (3.5 s at p99 for 30 at once). Here each is one call of the vault's, one statement and one round trip: the vault weighs the binding, the account, the rate, the token spent and the times on the rows as they are under their locks, writes the credential and its seal, and numbers its change, inside Postgres. It only adds: two functions only 0.15's vault calls, behind the switch.
--> statement-breakpoint
-- A sign-in through binding `p_binding`, as the vault decided it from the binding's columns it names (`p_principal`, `p_generation`, `p_binding_scope`, `p_binding_policy`): it goes ahead only while they are the row's, under its lock. Its answer, JSON: `{"number": "<n>"}`, the change's number, or `{"state": …}` with nothing written:
-- - `unbound`: the account is not active at the binding's generation, or the binding has ended, has a tombstone, or is not as named;
-- - `frozen`: a manager froze the account or the binding (`p_frozen`, a workload's sign-in);
-- - `busy`: the binding made `p_rate` credentials in the last `p_window` ms (a lock not had within `lock_timeout` raises `lock_not_available`, busy too);
-- - `expired`: the proof's own times are past (`p_valid_until`), or the credential's end is past, or further than `p_longest` ms (and a minute, for the Worker's clock) from the database's clock;
-- - `replayed`: the ID token, by its signing input's hash (`p_spent`), was spent already;
-- - `retired`: the app signed the row (its `auth_mac`) under a key it has rotated from (`p_app_key`, its log key's id), which `key.rotate` or `key.reseal` names, as `appendEntries` refuses one (KeyRetired). A rotation committing while this runs leaves a row its new key refuses: dead, never live.
-- Locks, in the order every writer takes them (0026): the account's row shared (MemberLocked: its removal waits, or is seen), the binding's exclusive (BindingLocked: its rate, and an unbind, whose update takes it before its sweep), then the issue lock shared, its number under it (IssueOffFence: never the fence, so no use waits on a sign-in, R58). Nobody can name the credential before the commit hands its token out. No 0.14 head, and no 0.14 entry: the change is the record (D147).
CREATE FUNCTION sign_in(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea,
    p_binding uuid, p_principal text, p_generation integer, p_binding_scope text, p_binding_policy text,
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
    -- A retry of a sign-in that committed, by its request: its number again, if it is this one.
    SELECT c.number, c.object, c.payload, c.seal INTO held FROM public.log_changes c WHERE c.request_id = p_request;
    IF FOUND THEN
        IF held.object <> target OR held.payload <> p_payload OR held.seal IS DISTINCT FROM p_seal THEN
            RAISE EXCEPTION 'request % names another change', p_request USING ERRCODE = 'unique_violation';
        END IF;
        RETURN json_build_object('number', held.number::text);
    END IF;
    IF p_created_by IS DISTINCT FROM 'binding:' || p_binding::text OR p_kind NOT IN ('service', 'workload') THEN
        RAISE EXCEPTION 'a sign-in makes a credential of its binding''s, a service''s or a workload''s' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A lock not had within `lock_timeout` raises `lock_not_available`, which the vault answers as busy: no subtransaction to catch it here.
    -- The account's row as its newest change sealed it, or 0.14's with neither (before the cutover): a row put back is none.
    PERFORM 1 FROM public.vault_members m
     WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation
       AND m.seal IS NOT DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('principal', p_principal) ORDER BY c.number DESC LIMIT 1)
       FOR SHARE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    PERFORM 1 FROM public.service_bindings b
     WHERE b.id = p_binding AND b.principal = p_principal AND b.generation = p_generation AND b.revoked_at IS NULL
       AND b.scope IS NOT DISTINCT FROM p_binding_scope AND b.policy IS NOT DISTINCT FROM p_binding_policy
       FOR UPDATE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'unbound'); END IF;
    -- The app's key, not one it rotated from (audit_log_subject_idx).
    IF EXISTS (SELECT 1 FROM public.audit_log a WHERE a.author = 'app' AND a.subject_principal = p_app_key AND a.action IN ('key.reseal', 'key.rotate')) THEN
        RETURN json_build_object('state', 'retired');
    END IF;
    -- Its tombstone: a binding put back after its unbind is none (audit_log_unbind_idx).
    IF EXISTS (SELECT 1 FROM public.audit_log a WHERE a.author = 'app' AND a.action = 'token.unbind' AND a.decision = 'allow'
                AND (a.metadata::jsonb ->> 'bindingId') = p_binding::text) THEN
        RETURN json_build_object('state', 'unbound');
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
-- A revoke of credential `p_id`, from the row as the vault sealed its object (`p_seal_from`) and as the app signed it (`p_mac_from`), to revoked, with the app's MAC over the revoked row (`p_mac`) and the vault's seal over its object (`p_seal`). Only a row the log holds: one 0.14 made, with no seal, the app revokes as 0.14 does, with its entry. Its answer, JSON: `{"number": "<n>"}`, or `{"state": …}` with nothing written:
-- - `moved`: the row is not as named, or revoked already;
-- - `stale`: its seal is not its object's newest change's (ChangeChecksSeal), a row put back;
-- - `policy`: the caller's right to revoke it was weighed on a policy (`p_policy_seq`, the newest `policy.change` then, and the slugs of the environments it protected, `p_protected`, `p_slugs`) that has changed since (RevokePolicyHeld), as `policyStill` refuses under 0.14's head. Read once the fence is held: every policy change and rename takes it before it commits (0.14's entry, through `audit_log_fence`; 0.15's, through its change), so one that commits before is seen, and one after waits.
-- Locks: the row's, then the fence exclusive (RevokeTakesFence), held only for the statement's work: a use in flight is numbered before, one after reads the row revoked. It issues nothing, and takes no issue lock.
CREATE FUNCTION revoke_credential(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal_from bytea, p_seal bytea,
    p_id uuid, p_mac_from bytea, p_auth_mac bytea, p_revoked_at bigint, p_revoked_by text,
    p_policy boolean, p_policy_seq bigint, p_protected uuid[], p_slugs text[]
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off SET lock_timeout = '1s' AS $$
DECLARE
    n bigint;
    held record;
    target uuid := public.log_object('credential', p_id::text);
BEGIN
    SELECT c.number, c.object, c.payload, c.seal INTO held FROM public.log_changes c WHERE c.request_id = p_request;
    IF FOUND THEN
        IF held.object <> target OR held.payload <> p_payload OR held.seal IS DISTINCT FROM p_seal THEN
            RAISE EXCEPTION 'request % names another change', p_request USING ERRCODE = 'unique_violation';
        END IF;
        RETURN json_build_object('number', held.number::text);
    END IF;
    IF p_seal_from IS NULL OR p_seal IS NULL THEN
        RAISE EXCEPTION 'the vault revokes a credential the log holds, from its seal' USING ERRCODE = 'invalid_parameter_value';
    END IF;
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
REVOKE ALL ON FUNCTION sign_in(text, bigint, text, text, bytea, bytea, uuid, text, integer, text, text, bytea, bigint, boolean, integer, bigint, bigint, uuid, text, bytea, bytea, text, text, text, text, text, bigint, bigint, text, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION sign_in(text, bigint, text, text, bytea, bytea, uuid, text, integer, text, text, bytea, bigint, boolean, integer, bigint, bigint, uuid, text, bytea, bytea, text, text, text, text, text, bigint, bigint, text, text) TO coffre_vault;
--> statement-breakpoint
REVOKE ALL ON FUNCTION revoke_credential(text, bigint, text, text, bytea, bytea, bytea, uuid, bytea, bytea, bigint, text, boolean, bigint, uuid[], text[]) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION revoke_credential(text, bigint, text, text, bytea, bytea, bytea, uuid, bytea, bytea, bigint, text, boolean, bigint, uuid[], text[]) TO coffre_vault;
