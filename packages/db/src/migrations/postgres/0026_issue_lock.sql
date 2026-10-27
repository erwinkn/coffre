-- Sign-ins never hold up a use (T123, R58; docs/design/0.15-plan.md, "Uses never wait on sign-ins"; the spec: formal/HotPathOne.tla's issues, HotPathOneIssue, and formal/Migration015.tla's, Migration015Issue). A sign-in issues a credential: one change of the log, `credential.issue`, which 0025's `app_change` made under the fence exclusive, as every change, while 0022's trigger fenced 0.14's `token.exchange` too. Each sign-in then held every use up for its last round trips, and a burst of them, serialized on 0.14's head, held them up over and over (measured: a fifth of the uses waited, 1,000 a second beside 10 sign-ins at once). Nobody can name a credential before its issue commits (its token is handed out after), and an issue changes no input any other use reads: no use can overlap it, so it needs no fence. It needs only that the checkpointer's barrier wait for it, every number handed out before the barrier being final when it closes. So an issue takes a lock of its own, the issue lock (1668244070, 1), shared, and its number under it; the barrier takes that lock exclusive, then the fence: it waits for the issues in flight without holding the fence, so no use queues behind it meanwhile (Postgres queues a shared request behind a waiting exclusive one). The order, everywhere: a member's row, 0.14's head, the issue lock, the fence. Whatever takes the fence in a transaction that may also issue takes the issue lock shared first (`app_change`, 0.14's trigger): a sign-in that revokes its account's earlier sessions fences first, then issues, and would otherwise hold the fence while it waits for the issue lock, which the barrier holds while it waits for the fence (TLC finds the cycle without). The vault's `change_input` never issues, and takes no issue lock. 0.14's code calls none of the functions; its `token.exchange`, which writes the new credential, the spent token and its binding's last use and no decision input, no longer takes the fence.
--
-- `app_change`, as 0025 made it, but for its locks: the issue lock shared, then, but for an issue of a credential its transaction wrote, the fence. The app issues only a row it inserts (`prepare` makes an issue only of no row before); an issue of a row its transaction did not write (one committed before, which a use may name; or a savepoint's) takes the fence too, as before.
CREATE OR REPLACE FUNCTION app_change(
    p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_seal_from bytea, p_seal bytea, p_mac bytea
) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    op jsonb := p_payload::jsonb;
    change text := op ->> 'op';
    target uuid := public.log_object(p_kind, p_id);
    n bigint;
    done integer;
    held bytea;
    -- An issue of a credential this very transaction wrote (its row's xmin is ours: not a savepoint's, nor a row another committed).
    -- Never null, whatever is missing (a 0.14 row's call carries no payload, so no op): else the fence.
    fresh boolean := coalesce(change = 'credential.issue' AND p_kind = 'credential'
        AND EXISTS (SELECT 1 FROM public.credentials c WHERE c.id = p_id::uuid AND c.xmin = pg_current_xact_id()::xid), false);
BEGIN
    PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE;
    -- The issue lock shared (IssueOwnLock); and, but for a fresh issue, the fence exclusive after it (IssueBeforeFence).
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    IF NOT fresh THEN PERFORM pg_advisory_xact_lock(1668244070, 0); END IF;
    held := CASE p_kind
        WHEN 'credential' THEN (SELECT c.seal FROM public.credentials c WHERE c.id = p_id::uuid)
        WHEN 'secret' THEN (SELECT x.seal FROM public.secrets x WHERE x.id = p_id::uuid)
        WHEN 'environment' THEN (SELECT e.seal FROM public.environments e WHERE e.id = p_id::uuid)
    END;
    IF p_request IS NULL THEN
        IF held IS NOT NULL OR EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = target) THEN
            RAISE EXCEPTION 'the % object''s row is not its newest change''s: stale', p_kind USING ERRCODE = 'data_corrupted';
        END IF;
        RETURN 0;
    END IF;
    SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request;
    IF FOUND THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.log_changes c
             WHERE c.request_id = p_request AND c.object = target AND c.payload = p_payload AND c.seal IS NOT DISTINCT FROM p_seal
        ) THEN
            RAISE EXCEPTION 'request % names another change', p_request USING ERRCODE = 'unique_violation';
        END IF;
        RETURN n;
    END IF;
    IF NOT ((p_kind = 'credential' AND change IN ('credential.issue', 'credential.revoke', 'credential.renew', 'credential.scope'))
        OR (p_kind = 'secret' AND change IN ('secret.write', 'secret.delete'))
        OR (p_kind = 'environment' AND change IN ('environment.create', 'environment.rename', 'environment.archive', 'environment.delete'))) THEN
        RAISE EXCEPTION 'the app makes no change % to a %', coalesce(change, 'without an op'), p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF op -> 'ref' ->> 'kind' IS DISTINCT FROM p_kind OR op -> 'ref' ->> 'id' IS DISTINCT FROM p_id THEN
        RAISE EXCEPTION 'a change names the object it is to: %, %', p_kind, p_id USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- ChangeChecksSeal.
    IF held IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = target ORDER BY c.number DESC LIMIT 1) THEN
        RAISE EXCEPTION 'the % object''s row is not its newest change''s: stale', p_kind USING ERRCODE = 'data_corrupted';
    END IF;
    -- ChangeCAS.
    CASE p_kind
        WHEN 'credential' THEN
            UPDATE public.credentials SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'secret' THEN
            UPDATE public.secrets SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'environment' THEN
            UPDATE public.environments SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
    END CASE;
    GET DIAGNOSTICS done = ROW_COUNT;
    IF done = 0 THEN RETURN NULL; END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN n;
END
$$;
--> statement-breakpoint
-- 0.14's trigger (0022, OldWritesFence): the issue lock shared, then the fence, as `app_change` takes them; and `token.exchange`, a sign-in, among the entries it lets by.
CREATE OR REPLACE FUNCTION log_fence_old_write() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1668244070, 1);
    PERFORM pg_catalog.pg_advisory_xact_lock(1668244070, 0);
    RETURN NULL;
END
$$;
--> statement-breakpoint
CREATE OR REPLACE TRIGGER audit_log_fence AFTER INSERT ON audit_log FOR EACH ROW
    WHEN (NEW.decision = 'allow' AND NEW.action NOT IN (
        'credential.use', 'token.use', 'secret.read', 'secret.use', 'secret.list', 'secret.history', 'secret.version', 'missing.list', 'personal.list',
        'roles.list', 'roles.preview', 'mcp.read', 'mcp.view', 'audit.read',
        'sign_in', 'token.exchange', 'device.approve', 'device.deny',
        'audit.heartbeat', 'audit.checkpoint', 'audit.finding', 'audit.finding_cleared', 'key.check', 'key.intent', 'workload.alert', 'vault.tampered'
    ))
    EXECUTE FUNCTION log_fence_old_write();
--> statement-breakpoint
-- The barrier (0022): the issue lock exclusive, which waits for every issue in flight and holds no use up, then the fence.
CREATE OR REPLACE FUNCTION close_one() RETURNS TABLE (upto bigint, at_floor bigint, floor_found bigint)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    found_floor bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(1668244070, 1);
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    SELECT f.at_floor INTO found_floor FROM public.log_fence f WHERE f.only_row;
    UPDATE public.log_fence f SET at_floor = greatest(f.at_floor, (extract(epoch FROM clock_timestamp()) * 1000)::bigint - public.deadline_max()) WHERE f.only_row;
    RETURN QUERY SELECT pg_sequence_last_value('public.log_number'), f.at_floor, found_floor FROM public.log_fence f WHERE f.only_row;
END
$$;
