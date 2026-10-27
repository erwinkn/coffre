-- 0.15's change path (docs/design/0.15-plan.md, PR 4a; the spec: formal/HotPathOne.tla's change actions, formal/Migration015.tla's lock order): `change_input` takes every change the vault makes to the inputs it decides on, not only the cutover's `genesis`. It replaces 0022's, which nothing called (log-015.md), with one more argument, `p_value`: the object as the change leaves it, which the vault made with `applyOp` and sealed, written into the rows this function keeps (an environment's, the roles' and the policy's), which the vault's login cannot write. It only replaces a function nothing calls: 0.14's code serves on it as before.
DROP FUNCTION change_input(text, text, text, bigint, text, text, bytea, bytea, bytea);
--> statement-breakpoint
-- A change (hot-path-one.md, "A change"): the fence exclusive, so that no use overlaps it; a retry finds its entry and answers its number (a request id names one change: another under it is refused); a row that is not its object's newest change's is refused, as a use refuses it (ChangeChecksSeal: else a row put back from before a change, validly sealed once, would be sealed again under the next change, and serve what the log says was taken away); the object's row moves only from the seal the vault read (ChangeCAS: of two changes to one object, the second finds another seal and does nothing: null); then its entry, numbered now (ChangeNumberUnderLock). Every lock is the transaction's, let go at its commit (LockToCommit). It answers the number, which a change waits to see sealed before it answers (R51, CommitBeforeAnswer).
--
-- What each kind's change writes:
-- - principal: its seal. A member's row and grants are the vault's own tables, which 0.14's decision writes in the same transaction, its MAC and entry with them, until 0.16 (the plan's dual fencing); the vault reads them back and holds them to the object it seals before it calls this.
-- - environment: its slug, protection and archiving from `p_value` (`environment.rename`, `environment.protect`, `environment.archive`), and its seal; what never changes (its project, parent and owner) and whether it was deleted must be the row's, or nothing is done. A genesis with no value seals the row as it is.
-- - roles, policy: the one row each, `log_config`, its value `p_value` (a genesis: the payload's `value`).
-- - credential, secret: genesis only, the row sealed as it is: the app writes them, and their changes come with its writes (plan PR 4b).
CREATE FUNCTION change_input(
    p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_value text, p_seal_from bytea, p_seal bytea, p_mac bytea
) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    op jsonb := p_payload::jsonb;
    v jsonb := p_value::jsonb;
    change text := op ->> 'op';
    target uuid := public.log_object(p_kind, p_id);
    n bigint;
    done integer;
    member text;
    held bytea;
    newest bytea;
    config jsonb;
BEGIN
    -- Its locks in the order 0.14's writers take theirs, so that none waits on the other in a circle until 0.16 (row,
    -- head, fence: Migration015.tla's RowFirst, ChangeHeadFirst): the member's queue (MEMBER_QUEUE, 0x636f666d) and row
    -- first, a principal's own or a credential's (0.14's vault locks them before the head, lockMembers; a change made
    -- inside a 0.14 decision holds them already), then 0.14's head (its app takes it before its rows), then the fence
    -- (0.14's appends take it after the head, audit_log_fence). The head held, no 0.14 write lands between this change
    -- and its entry.
    member := CASE p_kind
        WHEN 'principal' THEN p_id
        WHEN 'credential' THEN coalesce(
            (SELECT c.principal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.principal FROM public.service_bindings b WHERE b.id = p_id::uuid))
    END;
    IF member IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(1668245101, hashtext(m.principal)) FROM public.vault_members m WHERE m.principal = member FOR NO KEY UPDATE;
    END IF;
    PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE;
    -- ChangeLocks: exclusive, so that it waits for every use in flight, and every use after it waits for its commit.
    PERFORM pg_advisory_xact_lock(1668244070, 0);
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
    IF NOT (change = 'genesis'
        OR (p_kind = 'principal' AND change IN ('member.add', 'member.role', 'member.remove', 'member.restore', 'access.grant', 'access.revoke'))
        OR (p_kind = 'environment' AND change IN ('environment.protect', 'environment.rename', 'environment.archive'))
        OR (p_kind = 'roles' AND change = 'role.define')
        OR (p_kind = 'policy' AND change = 'bulk.limit')) THEN
        RAISE EXCEPTION 'this schema knows no change % to a %', coalesce(change, 'without an op'), p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The payload names its object (`ref`), so that a replay knows what each change is to: the column holds only its
    -- key. The cutover's genesis may leave it out, its value naming it.
    IF (change <> 'genesis' OR op ? 'ref') AND (op -> 'ref' ->> 'kind' IS DISTINCT FROM p_kind OR op -> 'ref' ->> 'id' IS DISTINCT FROM p_id) THEN
        RAISE EXCEPTION 'a change names the object it is to: %, %', p_kind, p_id USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A value is the object as this function writes it: an environment's, which a genesis may leave out to seal the
    -- row as it is; the roles' and the policy's, but at their genesis, whose payload holds it. The others' rows are
    -- written by whoever keeps them, and carry none.
    IF (CASE
        WHEN p_kind = 'environment' THEN change <> 'genesis' AND v IS NULL
        WHEN p_kind IN ('roles', 'policy') THEN (change = 'genesis') = (v IS NOT NULL)
        ELSE v IS NOT NULL
    END) THEN
        RAISE EXCEPTION 'a % change % carries the object it leaves exactly when this function writes it', p_kind, change USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- ChangeChecksSeal: the row's seal is its object's newest change's, or the object has neither yet (one probe, as
    -- a use makes). A row deleted outright, or a seal no change wrote, is stale too.
    held := CASE p_kind
        WHEN 'principal' THEN (SELECT m.seal FROM public.vault_members m WHERE m.principal = p_id)
        WHEN 'credential' THEN coalesce(
            (SELECT c.seal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.seal FROM public.service_bindings b WHERE b.id = p_id::uuid))
        WHEN 'environment' THEN (SELECT e.seal FROM public.environments e WHERE e.id = p_id::uuid)
        WHEN 'secret' THEN (SELECT x.seal FROM public.secrets x WHERE x.id = p_id::uuid)
        WHEN 'policy' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'policy')
        WHEN 'roles' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'roles')
    END;
    newest := (SELECT c.seal FROM public.log_changes c WHERE c.object = target ORDER BY c.number DESC LIMIT 1);
    IF held IS DISTINCT FROM newest THEN
        RAISE EXCEPTION 'the % object''s row is not its newest change''s: stale', p_kind USING ERRCODE = 'data_corrupted';
    END IF;
    -- ChangeCAS: each write moves the row only from the seal the vault read.
    CASE p_kind
        WHEN 'principal' THEN
            UPDATE public.vault_members SET seal = p_seal WHERE principal = p_id AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'credential' THEN
            -- A token's row, or a trust binding's: one kind of object, ids that never meet.
            UPDATE public.credentials SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            GET DIAGNOSTICS done = ROW_COUNT;
            IF done = 0 THEN
                UPDATE public.service_bindings SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            END IF;
        WHEN 'environment' THEN
            IF v IS NULL THEN
                UPDATE public.environments SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            ELSE
                -- A tombstone's slug holds a `~` (@coffre/core/schemas's isTombstone): an environment deleted stays so,
                -- and none is deleted here.
                UPDATE public.environments e
                   SET slug = v ->> 'slug',
                       protected = (v ->> 'protected')::boolean,
                       archived_at = CASE WHEN (v ->> 'archived')::boolean THEN coalesce(e.archived_at, to_timestamp(p_at / 1000.0)) END,
                       seal = p_seal
                 WHERE e.id = p_id::uuid AND e.seal IS NOT DISTINCT FROM p_seal_from
                   AND v ->> 'kind' = 'environment' AND v ->> 'id' = p_id
                   AND e.project_id = (v ->> 'projectId')::uuid
                   AND e.parent_id IS NOT DISTINCT FROM (v ->> 'parentId')::uuid
                   AND e.owner IS NOT DISTINCT FROM v ->> 'owner'
                   AND (strpos(e.slug, '~') > 0) = (v ->> 'deleted')::boolean
                   AND (strpos(v ->> 'slug', '~') > 0) = (v ->> 'deleted')::boolean
                   AND (NOT (v ->> 'deleted')::boolean OR e.slug = v ->> 'slug');
            END IF;
        WHEN 'secret' THEN
            UPDATE public.secrets SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'policy', 'roles' THEN
            config := CASE change WHEN 'genesis' THEN op -> 'value' ELSE v END;
            IF p_id <> 'instance' OR config IS NULL OR jsonb_typeof(config) <> 'object' OR (change = 'genesis' AND p_seal_from IS NOT NULL) THEN
                RAISE EXCEPTION 'the % object is one, made once from its value and changed from its seal', p_kind USING ERRCODE = 'invalid_parameter_value';
            END IF;
            -- Made by its first change (genesis, or the first role defined, the first cap set); moved after from its seal.
            IF p_seal_from IS NULL THEN
                INSERT INTO public.log_config (name, value, seal) VALUES (p_kind, config::text, p_seal) ON CONFLICT (name) DO NOTHING;
            ELSE
                UPDATE public.log_config SET value = config::text, seal = p_seal WHERE log_config.name = p_kind AND seal = p_seal_from;
            END IF;
        ELSE
            RAISE EXCEPTION 'no object kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END CASE;
    -- A row gone, a row whose seal is no longer the one read, an environment that is not what the value says it
    -- stays, or an object made already: nothing was done.
    GET DIAGNOSTICS done = ROW_COUNT;
    IF done = 0 THEN RETURN NULL; END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN n;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION change_input(text, text, text, bigint, text, text, text, bytea, bytea, bytea) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION change_input(text, text, text, bigint, text, text, text, bytea, bytea, bytea) TO coffre_vault;
