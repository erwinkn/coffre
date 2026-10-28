-- The vault issues tokens itself (T149, PR 2; docs/design/credential-lifecycle.md; formal/Lifecycle.tla's issue): a service account's token, a person's personal token, a handle. They were the app's transactions under 0.14's head, `prepare` sealing whatever row the app proposed, so the vault weighed no right of the issuer's. Now the vault reads the issuer, the account and the credential the request came in on, and decides with `@coffre/core/access`'s rules whether the issuer may give the scope (R15, R32); this statement then writes the token only while what it read is still so, under those rows' locks (IssuerLocked, IssuerCAS). Nothing is held between the read and this statement. It only adds: two functions only 0.15's vault calls, behind the switch.
--> statement-breakpoint
-- A token issued by `p_actor`, on credential `p_via` (null for none), to `p_principal` at generation `p_generation`, as the vault decided it on the members' rows at `p_actor_seq` and `p_principal_seq` (their `access_seq`: every change of what a member holds moves it), the credential at its seal `p_via_seal`, and the policy at `p_policy_seq` with the slugs of the environments it protected (`p_protected`, `p_slugs`). Its answer, JSON: `{"number": "<n>"}`, or `{"state": …}` with nothing written:
-- - `moved`: a member is not active as read, at its generation, or its access moved since (asked again);
-- - `ended`: the credential it came in on is revoked, past its end, another's, or not its object's newest change's;
-- - `policy`: the policy moved since (as `policyStill`);
-- - `retired`: the app signed the row under a key it rotated from (as `sign_in`);
-- - `expired`: the token's end is past.
-- Locks, in the order every writer takes them (0026): the members' rows shared, by principal as `lockMembers` takes them (a demotion or a removal waits for the issue, or the issue sees it), then the credential's row shared (a revoke of it waits, or the issue sees it), each compared in a statement of its own once had (a recheck under the lock would mix the new row with the snapshot's older changes), then the issue lock shared, its number under it (IssueOffFence: never the fence, so no use waits on an issue, R58). The policy is read without the fence: a change that commits while this runs leaves a token its use holds to its account's rights as they are then, the policy's included, never to more. No 0.14 head, no 0.14 entry: the change records the issue (D147).
CREATE FUNCTION issue_token(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea,
    p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint,
    p_via uuid, p_via_seal bytea,
    p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text,
    p_id uuid, p_kind text, p_auth_mac bytea, p_token_hash bytea, p_token_hint text, p_label text, p_created_by text,
    p_scope text, p_places text, p_expires bigint
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off SET lock_timeout = '1s' AS $$
DECLARE
    n bigint;
BEGIN
    IF p_kind NOT IN ('service', 'personal', 'handle') OR (p_kind = 'service') = (p_principal = p_actor) THEN
        RAISE EXCEPTION 'the vault issues a service account a token, or a person one of their own' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- IssuerLocked: the members' rows, then the credential's, shared; a lock not had within `lock_timeout` raises `lock_not_available`, busy.
    PERFORM 1 FROM public.vault_members m WHERE m.principal IN (p_actor, p_principal) ORDER BY m.principal FOR SHARE;
    -- IssuerCAS, once the locks are had.
    IF NOT EXISTS (SELECT 1 FROM public.vault_members m WHERE m.principal = p_actor AND m.status = 'active' AND m.generation = p_actor_generation AND m.access_seq = p_actor_seq)
       OR NOT EXISTS (SELECT 1 FROM public.vault_members m WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation AND m.access_seq = p_principal_seq) THEN
        RETURN json_build_object('state', 'moved');
    END IF;
    IF p_via IS NOT NULL THEN
        PERFORM 1 FROM public.credentials c WHERE c.id = p_via FOR SHARE;
        IF NOT EXISTS (SELECT 1 FROM public.credentials c
                        WHERE c.id = p_via AND c.principal = p_actor AND c.revoked_at IS NULL AND c.seal IS NOT DISTINCT FROM p_via_seal
                          AND c.expires_at > clock_timestamp() AND (c.not_after IS NULL OR c.not_after > clock_timestamp()))
           OR p_via_seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('credential', p_via::text) ORDER BY c.number DESC LIMIT 1) THEN
            RETURN json_build_object('state', 'ended');
        END IF;
    END IF;
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
    IF p_expires <= (extract(epoch FROM clock_timestamp()) * 1000)::bigint THEN
        RETURN json_build_object('state', 'expired');
    END IF;
    INSERT INTO public.credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, identity_id, scope, places, label, created_by,
                                    expires_at, revoked_at, seal)
        VALUES (p_id, p_kind, p_auth_mac, p_token_hash, p_token_hint, p_generation, p_principal, NULL, p_scope, p_places, p_label, p_created_by,
                timestamptz 'epoch' + p_expires * interval '1 millisecond', NULL, p_seal);
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, public.log_object('credential', p_id::text), p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN json_build_object('number', n::text);
END
$$;
--> statement-breakpoint
-- The credential an issue came in on, as the vault weighs it: its object's columns, its seal, and its object's newest change's seal; no row for none. The vault's login reads no credential otherwise (vault-guarantees.sql), and this answers neither its token's hash nor its MAC.
CREATE FUNCTION issuing_credential(p_id uuid) RETURNS TABLE (
    id uuid, principal text, kind text, scope text, revoked boolean, expires_at bigint, not_after bigint, generation integer, seal bytea, newest bytea
)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
    SELECT c.id, c.principal, c.kind, c.scope, c.revoked_at IS NOT NULL, floor(extract(epoch FROM c.expires_at) * 1000)::bigint,
           floor(extract(epoch FROM c.not_after) * 1000)::bigint, c.generation, c.seal,
           (SELECT l.seal FROM public.log_changes l WHERE l.object = public.log_object('credential', p_id::text) ORDER BY l.number DESC LIMIT 1)
      FROM public.credentials c WHERE c.id = p_id
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION issuing_credential(uuid) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION issuing_credential(uuid) TO coffre_vault;
--> statement-breakpoint
REVOKE ALL ON FUNCTION issue_token(text, bigint, text, text, bytea, bytea, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid[], text[], text, uuid, text, bytea, bytea, text, text, text, text, text, bigint) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION issue_token(text, bigint, text, text, bytea, bytea, text, integer, bigint, integer, bigint, uuid, bytea, bigint, uuid[], text[], text, uuid, text, bytea, bytea, text, text, text, text, text, bigint) TO coffre_vault;
