-- 0.15's cutover from 0.14 (docs/design/0.15-plan.md, PR 9; formal/Migration015.tla): the first 0.15 vault start seals every object 0.14 left as 0.14 accepts it (`genesis`, through `change_input`), and writes the log's first `cutover` change, naming 0.14's last head. These are its writes the vault's login cannot make, and its reads of the rows only the app's login reads, each a definer function that holds itself to what a cutover does: only before the cutover's change, on rows no change of 0.15's holds. Only functions: 0.14's code serves on it as before.
--> statement-breakpoint
-- The cutover's change, once: under the fence, exclusive, which the cutover holds from before its marker's check (its locks: every member's row, 0.14's head, the issue lock, the fence; T132). It names 0.14's last head, which must be the chain's head now (`audit_chain_head`): the cutover holds it, and its own 0.14 entry, `log.cutover`, is that head. A retry by its request id finds it; any other cutover is refused.
CREATE FUNCTION log_cutover(p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    op jsonb := p_payload::jsonb;
    n bigint;
BEGIN
    IF op ->> 'op' IS DISTINCT FROM 'cutover' OR (op #>> '{anchor,seq}') !~ '^[0-9]{1,19}$' OR (op #>> '{anchor,hash}') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'not a cutover change: %', p_payload USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request AND c.object = public.log_object('log', 'cutover') AND c.payload = p_payload;
    IF n IS NOT NULL THEN RETURN n; END IF;
    IF EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = public.log_object('log', 'cutover')) THEN
        RAISE EXCEPTION 'the log is cut over from 0.14 already' USING ERRCODE = 'unique_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.audit_chain_head h
         WHERE h.only_row AND h.next_seq = (op #>> '{anchor,seq}')::bigint + 1 AND h.head_hash = decode(op #>> '{anchor,hash}', 'hex')
    ) THEN
        RAISE EXCEPTION 'a cutover names 0.14''s head as it stands' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, public.log_object('log', 'cutover'), p_actor, p_payload, NULL, p_mac)
        RETURNING number INTO n;
    RETURN n;
END
$$;
--> statement-breakpoint
-- The places 0.14 deleted, made as 0.15 leaves them (the plan's "Places 0.14 deleted", T130), before their objects' genesis: each standing environment of a project whose slug is a tombstone gets `<slug>~deleted` (`deletedWithProject`), and each key under a place deleted that is not archived is archived, its versions erased already. Only before the cutover, and only on rows no change of 0.15's holds; each one named must be such, or nothing is done.
CREATE FUNCTION cutover_places(p_at bigint, p_environments uuid[], p_secrets uuid[]) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    done integer;
BEGIN
    IF p_at IS NULL OR p_at < 0 THEN
        RAISE EXCEPTION 'the cutover writes at a time, ms since the epoch' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = public.log_object('log', 'cutover')) THEN
        RAISE EXCEPTION 'the log is cut over from 0.14 already' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE public.environments e SET slug = e.slug || '~deleted'
     WHERE e.id = ANY (p_environments) AND strpos(e.slug, '~') = 0 AND e.seal IS NULL
       AND NOT EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = public.log_object('environment', e.id::text))
       AND EXISTS (SELECT 1 FROM public.projects p WHERE p.id = e.project_id AND strpos(p.slug, '~') > 0);
    GET DIAGNOSTICS done = ROW_COUNT;
    IF done <> coalesce(cardinality(p_environments), 0) THEN
        RAISE EXCEPTION 'an environment named is no standing one of a deleted project, 0.14''s alone' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE public.secrets x SET archived_at = to_timestamp(p_at / 1000.0)
     WHERE x.id = ANY (p_secrets) AND x.archived_at IS NULL AND x.seal IS NULL
       AND NOT EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = public.log_object('secret', x.id::text))
       AND EXISTS (
           SELECT 1 FROM public.environments e JOIN public.projects p ON p.id = e.project_id
            WHERE e.id = x.environment_id AND (strpos(e.slug, '~') > 0 OR strpos(p.slug, '~') > 0)
       );
    GET DIAGNOSTICS done = ROW_COUNT;
    IF done <> coalesce(cardinality(p_secrets), 0) THEN
        RAISE EXCEPTION 'a key named is no live one under a deleted place, 0.14''s alone' USING ERRCODE = 'invalid_parameter_value';
    END IF;
END
$$;
--> statement-breakpoint
-- The credentials and bindings the app vouched for, as the cutover reads them under its locks to hold them to that: their objects' columns, their seals, and whether the log has any change of them. The vault's login reads neither table (0036's `issuing_credential` for one).
CREATE FUNCTION cutover_credentials(p_ids uuid[]) RETURNS TABLE (
    id uuid, principal text, kind text, scope text, revoked boolean, expires_at bigint, not_after bigint, generation integer, seal bytea, logged boolean
)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
    SELECT c.id, c.principal, c.kind, c.scope, c.revoked_at IS NOT NULL, floor(extract(epoch FROM c.expires_at) * 1000)::bigint,
           floor(extract(epoch FROM c.not_after) * 1000)::bigint, c.generation, c.seal,
           EXISTS (SELECT 1 FROM public.log_changes l WHERE l.object = public.log_object('credential', c.id::text))
      FROM public.credentials c WHERE c.id = ANY (p_ids)
$$;
--> statement-breakpoint
CREATE FUNCTION cutover_bindings(p_ids uuid[]) RETURNS TABLE (
    id uuid, principal text, generation integer, profile text, issuer text, origin text, jwks_uri text, claims text, scope text, policy text, revoked boolean, seal bytea, logged boolean
)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
    SELECT b.id, b.principal, b.generation, b.profile, b.issuer, b.origin, b.jwks_uri, b.claims, b.scope, b.policy, b.revoked_at IS NOT NULL, b.seal,
           EXISTS (SELECT 1 FROM public.log_changes l WHERE l.object = public.log_object('binding', b.id::text))
      FROM public.service_bindings b WHERE b.id = ANY (p_ids)
$$;
--> statement-breakpoint
-- A binding's genesis (T160): 0.14's row, which the app vouched for and the vault held to that, sealed as it is, from no seal, the object the payload's value, under the fence; and the instance it was made on, `origin` (0040), written with its seal: the deployment's public URL, as the app vouched for it. 0.14 writes no `origin`, and its MAC covers none: a row with one is no row of 0.14's, and is not sealed. Only before the cutover's change; never a binding the log holds (PR 3a's `change_bindings` makes and ends those).
CREATE FUNCTION seal_binding(p_id uuid, p_request text, p_at bigint, p_actor text, p_payload text, p_seal bytea, p_mac bytea) RETURNS bigint
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
       AND b.claims = op #>> '{value,claims}' AND b.policy IS NOT DISTINCT FROM op #>> '{value,policy}';
    GET DIAGNOSTICS done = ROW_COUNT;
    IF done = 0 THEN RETURN NULL; END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN n;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION log_cutover(text, bigint, text, text, bytea), cutover_places(bigint, uuid[], uuid[]), cutover_credentials(uuid[]), cutover_bindings(uuid[]),
    seal_binding(uuid, text, bigint, text, text, bytea, bytea) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION log_cutover(text, bigint, text, text, bytea), cutover_places(bigint, uuid[], uuid[]), cutover_credentials(uuid[]), cutover_bindings(uuid[]),
    seal_binding(uuid, text, bigint, text, text, bytea, bytea) TO coffre_vault;
