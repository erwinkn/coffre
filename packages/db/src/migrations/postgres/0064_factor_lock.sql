-- A person's factor lock in the vault's issue (0.16, T176 PR 3; docs/design/passkeys.md, sections 6.1 and 6.3; formal/Factor.tla; sqlite: `issueOnSqlite`, whose one writer is the lock). A change to a person's passkeys (PR 4: a first one added, one removed, an Owner's reset) ends credentials by revoking them, under the person's factor lock, `pg_advisory_xact_lock(1717658484, hashtext(<principal>))` ('fact'; the two-key space, apart from the fence's and the issue lock's 1668244070). Without the lock here, a removal could read the person's credentials, then wait while a handle commits from a session it is about to revoke, and miss the handle (review r12; Factor.tla's IssueTakesFactor). So `issue_token` takes it, exclusive, first: before the members' rows, which a change takes after it (FactorFirst, else the two wait on each other). Under it, the credential `via` is checked live as before, so nothing is issued from one a change ended, and nothing issued escapes the next.
-- The new overload names the passkey the issue carries (`p_passkey`, `via`'s, which the app's MAC on the row covers): `via` must name that same passkey, still live and its actor's, or the answer is `ended` with nothing written. The vault never picks it up from `via` itself: the row's MAC is the app's, made before the call, and a row naming a passkey its MAC does not cover would fail every read after.
-- The old signature, which the previous release's vault calls during a rollout, is now that overload with no passkey: it takes the lock too (else its issues would race a removal by the new release's app), and refuses to issue from a session a passkey confirmed, which it could not sign for. It keeps its arguments, its answer and its grant. Neither sets `jit` (R69); the `lock_timeout` stays, the factor lock's wait included: busy, asked again.
CREATE FUNCTION issue_token(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea,
    p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint,
    p_via uuid, p_via_seal bytea, p_via_end bigint,
    p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text,
    p_id uuid, p_kind text, p_auth_mac bytea, p_token_hash bytea, p_token_hint text, p_label text, p_created_by text,
    p_scope text, p_places text, p_expires bigint, p_passkey uuid
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '1s' AS $$
DECLARE
    n bigint;
BEGIN
    IF p_kind NOT IN ('service', 'personal', 'handle') OR (p_kind = 'service') = (p_principal = p_actor) THEN
        RAISE EXCEPTION 'the vault issues a service account a token, or a person one of their own' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_passkey IS NOT NULL AND p_via IS NULL THEN
        RAISE EXCEPTION 'a passkey is carried from the credential an issue came in on' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- FactorFirst: the issuer's factor lock, before any row's. A change to their passkeys holds it from before it reads
    -- what to end until it commits: it commits before this reads `via`, which it then finds revoked, or waits for this
    -- issue's commit and reads what it wrote.
    PERFORM pg_advisory_xact_lock(1717658484, hashtext(p_actor));
    -- IssuerLocked: the members' rows, then the credential's, shared; a lock not had within `lock_timeout` raises `lock_not_available`, busy.
    PERFORM 1 FROM public.vault_members m WHERE m.principal IN (p_actor, p_principal) ORDER BY m.principal FOR SHARE;
    -- IssuerCAS, once the locks are had.
    IF NOT EXISTS (SELECT 1 FROM public.vault_members m WHERE m.principal = p_actor AND m.status = 'active' AND m.generation = p_actor_generation AND m.access_seq = p_actor_seq)
       OR NOT EXISTS (SELECT 1 FROM public.vault_members m WHERE m.principal = p_principal AND m.status = 'active' AND m.generation = p_generation AND m.access_seq = p_principal_seq) THEN
        RETURN json_build_object('state', 'moved');
    END IF;
    IF p_via IS NOT NULL THEN
        PERFORM 1 FROM public.credentials c WHERE c.id = p_via FOR SHARE;
        -- Its end as the vault authenticated it (`p_via_end`, the earlier of its expiry and its hard end, which its seal
        -- covers): the columns still say so, and it is still ahead. A seal compares bytes, never the columns it was made of.
        -- And the passkey it names, the one this issue carries, still the actor's and not removed.
        IF NOT EXISTS (SELECT 1 FROM public.credentials c
                        WHERE c.id = p_via AND c.principal = p_actor AND c.revoked_at IS NULL AND c.seal = p_via_seal
                          AND floor(extract(epoch FROM least(c.expires_at, coalesce(c.not_after, c.expires_at))) * 1000)::bigint = p_via_end
                          AND c.passkey_id IS NOT DISTINCT FROM p_passkey)
           OR p_via_end <= (extract(epoch FROM clock_timestamp()) * 1000)::bigint
           OR p_via_seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = public.log_object('credential', p_via::text) ORDER BY c.number DESC LIMIT 1)
           OR (p_passkey IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.passkeys k WHERE k.id = p_passkey AND k.principal = p_actor AND k.removed_at IS NULL)) THEN
            RETURN json_build_object('state', 'ended');
        END IF;
    END IF;
    -- IssuePolicyHeld: the issue lock shared before the policy is compared, and the number under it. A policy change, or a
    -- write that moves a protected environment's slug, takes it exclusive before the fence (`holdIssues`): it commits
    -- before this compares, and is seen, or waits for this issue's commit.
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
    IF p_expires <= (extract(epoch FROM clock_timestamp()) * 1000)::bigint THEN
        RETURN json_build_object('state', 'expired');
    END IF;
    INSERT INTO public.credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, identity_id, scope, places, label, created_by,
                                    expires_at, revoked_at, seal, passkey_id)
        VALUES (p_id, p_kind, p_auth_mac, p_token_hash, p_token_hint, p_generation, p_principal, NULL, p_scope, p_places, p_label, p_created_by,
                timestamptz 'epoch' + p_expires * interval '1 millisecond', NULL, p_seal, p_passkey);
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, public.log_object('credential', p_id::text), p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN json_build_object('number', n::text);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION issue_token(text, bigint, text, text, bytea, bytea, text, integer, bigint, integer, bigint, uuid, bytea, bigint, bigint, uuid[], text[], text, uuid, text, bytea, bytea, text, text, text, text, text, bigint, uuid) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION issue_token(text, bigint, text, text, bytea, bytea, text, integer, bigint, integer, bigint, uuid, bytea, bigint, bigint, uuid[], text[], text, uuid, text, bytea, bytea, text, text, text, text, text, bigint, uuid) TO coffre_vault;
--> statement-breakpoint
-- The previous release's call: the overload above, carrying no passkey. Its grant stays as 0036 made it.
CREATE OR REPLACE FUNCTION issue_token(
    p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal bytea,
    p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint,
    p_via uuid, p_via_seal bytea, p_via_end bigint,
    p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text,
    p_id uuid, p_kind text, p_auth_mac bytea, p_token_hash bytea, p_token_hint text, p_label text, p_created_by text,
    p_scope text, p_places text, p_expires bigint
) RETURNS json
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '1s' AS $$
    SELECT public.issue_token(p_request, p_at, p_actor, p_payload, p_mac, p_seal, p_principal, p_generation, p_principal_seq, p_actor_generation, p_actor_seq,
                              p_via, p_via_seal, p_via_end, p_policy_seq, p_protected, p_slugs, p_app_key,
                              p_id, p_kind, p_auth_mac, p_token_hash, p_token_hint, p_label, p_created_by, p_scope, p_places, p_expires, NULL::uuid)
$$;
--> statement-breakpoint
-- The wrapper runs as its owner, which `CREATE OR REPLACE` keeps (0036's), while the overload belongs to the login that
-- made it: the same role where one owner migrates, as `coffre setup` makes it, but not where a member of the owner does
-- (a managed Postgres's admin login, say; `scripts/test-schema-owner.sh`). Its owner could then not execute the
-- overload, which PUBLIC may not, and every issue of the previous release's vault would fail during the rollout. So it
-- is granted it by name, as 0057, 0058 and 0060 grant the use functions' callers their callees.
DO $$
DECLARE
    v_legacy regprocedure := 'public.issue_token(text, bigint, text, text, bytea, bytea, text, integer, bigint, integer, bigint, uuid, bytea, bigint, bigint, uuid[], text[], text, uuid, text, bytea, bytea, text, text, text, text, text, bigint)';
    v_overload regprocedure := 'public.issue_token(text, bigint, text, text, bytea, bytea, text, integer, bigint, integer, bigint, uuid, bytea, bigint, bigint, uuid[], text[], text, uuid, text, bytea, bytea, text, text, text, text, text, bigint, uuid)';
    v_owner name := (SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = v_legacy);
BEGIN
    IF NOT has_function_privilege(v_owner, v_overload, 'EXECUTE') THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', v_overload, v_owner);
    END IF;
END
$$;
