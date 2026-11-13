-- The change lock replaces `audit_chain_head FOR UPDATE` in the four functions that took the head to order a change. It
-- is an advisory lock, `(1668244070, 2)`, beside the fence's `(…, 0)` and the issue lock's `(…, 1)`. Every change takes
-- it, the app's and the vault's, where it took the head, and so does the old chain's checkpoint, a decision of the
-- vault's; no use, read or checkpointer's barrier does, so two changes exclude each other from there to their commit
-- and a use never waits behind one. Each body is its newest definition (0082; 0084
-- for `change_input`) with that one swap, in the order every change takes its locks: the members' rows where a function
-- locks them, the change lock, the issue lock, the fence (formal/WriteLocks.tla, ChangeLocks.cfg). `change_input` also
-- takes the issue lock shared before its fence, which the trigger on the old log's entries took for it.
CREATE OR REPLACE FUNCTION public.app_change(p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_seal_from bytea, p_seal bytea, p_mac bytea, p_restores bytea)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
    op jsonb := p_payload::jsonb;
    change text := op ->> 'op';
    target uuid := public.log_object(p_kind, p_id);
    n bigint;
    done integer;
    held bytea;
    -- An issue of a credential, or a connection made, that this very transaction wrote (its row's xmin is ours: not a
    -- savepoint's, nor a row another committed): no use can name it yet. Never null, whatever is missing (a 0.14 row's
    -- call carries no payload, so no op): else the fence.
    fresh boolean := coalesce((change = 'credential.issue' AND p_kind = 'credential'
        AND EXISTS (SELECT 1 FROM public.credentials c WHERE c.id = p_id::uuid AND c.xmin = pg_current_xact_id()::xid))
        OR (change = 'connection.make' AND p_kind = 'connection'
        AND EXISTS (SELECT 1 FROM public.mcp_connections k WHERE k.id = p_id::uuid AND k.xmin = pg_current_xact_id()::xid)), false);
BEGIN
    PERFORM pg_advisory_xact_lock(1668244070, 2);
    -- The issue lock shared (IssueOwnLock); and, but for a fresh issue, the fence exclusive after it (IssueBeforeFence).
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    IF NOT fresh THEN PERFORM pg_advisory_xact_lock(1668244070, 0); END IF;
    held := CASE p_kind
        WHEN 'credential' THEN (SELECT c.seal FROM public.credentials c WHERE c.id = p_id::uuid)
        WHEN 'connection' THEN (SELECT k.seal FROM public.mcp_connections k WHERE k.id = p_id::uuid)
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
        OR (p_kind = 'connection' AND change IN ('connection.make', 'connection.revoke'))
        OR (p_kind = 'secret' AND change IN ('secret.write', 'secret.delete'))
        OR (p_kind = 'environment' AND change IN ('environment.create', 'environment.rename', 'environment.archive', 'project.archive', 'environment.delete'))) THEN
        RAISE EXCEPTION 'the app makes no change % to a %', coalesce(change, 'without an op'), p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF op -> 'ref' ->> 'kind' IS DISTINCT FROM p_kind OR op -> 'ref' ->> 'id' IS DISTINCT FROM p_id THEN
        RAISE EXCEPTION 'a change names the object it is to: %, %', p_kind, p_id USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- ChangeChecksSeal.
    IF held IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = ANY(ARRAY[target::uuid]) ORDER BY c.object DESC, c.number DESC LIMIT 1) THEN
        RAISE EXCEPTION 'the % object''s row is not its newest change''s: stale', p_kind USING ERRCODE = 'data_corrupted';
    END IF;
    -- RestorePinned: an unarchive, a key's object made again from none, restores the one its log last sealed, still so.
    IF p_restores IS NOT NULL THEN
        IF p_kind <> 'secret' OR change <> 'secret.write' OR p_seal_from IS NOT NULL THEN
            RAISE EXCEPTION 'only a key''s object made again from none restores one' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        IF p_restores IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = ANY(ARRAY[target::uuid]) AND c.seal IS NOT NULL ORDER BY c.object DESC, c.number DESC LIMIT 1) THEN
            RAISE EXCEPTION 'the secret object an unarchive restores is not its newest sealed one: stale' USING ERRCODE = 'data_corrupted';
        END IF;
    END IF;
    -- ChangeCAS.
    CASE p_kind
        WHEN 'credential' THEN
            UPDATE public.credentials SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'connection' THEN
            UPDATE public.mcp_connections SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
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
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.change_input(p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_value text, p_seal_from bytea, p_seal bytea, p_mac bytea)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
    op jsonb := p_payload::jsonb;
    v jsonb := p_value::jsonb;
    change text := op ->> 'op';
    target uuid := public.log_object(p_kind, p_id);
    n bigint;
    done integer := 0;
    member text;
    held bytea;
    newest bytea;
    config jsonb;
    prior jsonb;
    v_scope text;
    v_was jsonb;
    v_now jsonb;
BEGIN
    -- Its locks in the order every change takes them: the member's queue (MEMBER_QUEUE, 0x636f666d) and row, a
    -- principal's own or a credential's (the vault's lockMembers takes them first), then the change lock, the issue
    -- lock shared, the fence. With the change lock held, no other change lands between what this reads and its commit.
    member := CASE p_kind
        WHEN 'principal' THEN p_id
        WHEN 'credential' THEN coalesce(
            (SELECT c.principal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.principal FROM public.service_bindings b WHERE b.id = p_id::uuid))
        WHEN 'connection' THEN (SELECT k.principal FROM public.mcp_connections k WHERE k.id = p_id::uuid)
    END;
    IF member IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(1668245101, hashtext(m.principal)) FROM public.principals m WHERE m.principal = member FOR NO KEY UPDATE;
    END IF;
    PERFORM pg_advisory_xact_lock(1668244070, 2);
    PERFORM pg_advisory_xact_lock_shared(1668244070, 1);
    -- The fence exclusive, so that it waits for every use in flight, and every use after it waits for its commit.
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
        OR (p_kind = 'secret' AND change IN ('secret.write', 'secret.delete'))
        OR (p_kind = 'roles' AND change = 'role.define')
        OR (p_kind = 'role' AND change = 'role.define')
        OR (p_kind = 'policy' AND change = 'bulk.limit')
        OR (p_kind = 'proxy' AND change IN ('proxy.save', 'proxy.code'))
        OR (p_kind = 'proxy-reserved' AND change IN ('proxy.code', 'proxy.release'))) THEN
        RAISE EXCEPTION 'this schema knows no change % to a %', coalesce(change, 'without an op'), p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The proxy's objects and the roles' rows are 0.16's, after every cutover: each is made by its first change, never a genesis.
    IF change = 'genesis' AND p_kind IN ('proxy', 'proxy-reserved', 'role') THEN
        RAISE EXCEPTION 'a % object has no genesis', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The payload names its object (`ref`), so that a replay knows what each change is to: the column holds only its
    -- key. The cutover's genesis may leave it out, its value naming it.
    IF (change <> 'genesis' OR op ? 'ref') AND (op -> 'ref' ->> 'kind' IS DISTINCT FROM p_kind OR op -> 'ref' ->> 'id' IS DISTINCT FROM p_id) THEN
        RAISE EXCEPTION 'a change names the object it is to: %, %', p_kind, p_id USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A value is the object as this function writes it: an environment's, which a genesis may leave out to seal the
    -- row as it is; a key's, the end of its reference (`secret.write`, the one change of a key the vault makes), and
    -- none at its genesis; the roles' and the policy's, but at their genesis, whose payload holds it. The others' rows
    -- are written by whoever keeps them, and carry none.
    IF (CASE
        WHEN p_kind = 'environment' THEN change <> 'genesis' AND v IS NULL
        WHEN p_kind = 'secret' THEN (change = 'secret.write') = (v IS NULL)
        WHEN p_kind IN ('roles', 'policy') THEN (change = 'genesis') = (v IS NOT NULL)
        WHEN p_kind IN ('proxy', 'proxy-reserved') THEN v IS NULL
        -- A role's, or none: one an Owner made, deleted.
        WHEN p_kind = 'role' THEN false
        ELSE v IS NOT NULL
    END) THEN
        RAISE EXCEPTION 'a % change % carries the object it leaves exactly when this function writes it', p_kind, change USING ERRCODE = 'invalid_parameter_value';
    END IF;
    newest := (SELECT c.seal FROM public.log_changes c WHERE c.object = ANY(ARRAY[target::uuid]) ORDER BY c.object DESC, c.number DESC LIMIT 1);
    -- ChangeChecksSeal: the row's seal is its object's newest change's, or the object has neither yet (one probe, as
    -- a use makes). A row deleted outright, or a seal no change wrote, is stale too. Not the proxy's (0.16): the vault
    -- writes each of its rows whole from its value, so a row a writer moved is replaced, never carried on; its change
    -- moves only from the newest change's seal (below), which the vault decided on.
    held := CASE p_kind
        WHEN 'principal' THEN (SELECT m.seal FROM public.principals m WHERE m.principal = p_id)
        WHEN 'credential' THEN coalesce(
            (SELECT c.seal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.seal FROM public.service_bindings b WHERE b.id = p_id::uuid))
        WHEN 'connection' THEN (SELECT k.seal FROM public.mcp_connections k WHERE k.id = p_id::uuid)
        WHEN 'environment' THEN (SELECT e.seal FROM public.environments e WHERE e.id = p_id::uuid)
        WHEN 'secret' THEN (SELECT x.seal FROM public.secrets x WHERE x.id = p_id::uuid)
        WHEN 'policy' THEN (SELECT p.seal FROM public.policy p WHERE p.name = 'instance')
        WHEN 'roles' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'roles')
        WHEN 'proxy' THEN newest
        WHEN 'proxy-reserved' THEN newest
        WHEN 'role' THEN newest
    END;
    IF held IS DISTINCT FROM newest THEN
        RAISE EXCEPTION 'the % object''s row is not its newest change''s: stale', p_kind USING ERRCODE = 'data_corrupted';
    END IF;
    -- ChangeCAS: each write moves the row only from the seal the vault read.
    CASE p_kind
        WHEN 'principal' THEN
            UPDATE public.principals SET seal = p_seal WHERE principal = p_id AND seal IS NOT DISTINCT FROM p_seal_from;
            GET DIAGNOSTICS done = ROW_COUNT;
        WHEN 'credential' THEN
            -- A token's row, or a trust binding's: one kind of object, ids that never meet.
            UPDATE public.credentials SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            GET DIAGNOSTICS done = ROW_COUNT;
            IF done = 0 THEN
                UPDATE public.service_bindings SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
                GET DIAGNOSTICS done = ROW_COUNT;
            END IF;
        WHEN 'connection' THEN
            -- An MCP connection's genesis, the cutover's: its row sealed as it is. The app's changes make and end the others.
            UPDATE public.mcp_connections SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            GET DIAGNOSTICS done = ROW_COUNT;
        WHEN 'environment' THEN
            IF v IS NULL THEN
                UPDATE public.environments SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
                GET DIAGNOSTICS done = ROW_COUNT;
            ELSE
                -- A deleted environment's row keeps its tombstone, `dev~deleted-…` (@coffre/core/schemas's isTombstone),
                -- and its object the slug before it (objects.ts, environmentObject): an environment deleted stays so,
                -- its slug is never written again, and none is deleted here; an object's slug holds no tombstone.
                UPDATE public.environments e
                   SET slug = CASE WHEN strpos(e.slug, '~') > 0 THEN e.slug ELSE v ->> 'slug' END,
                       protected = (v ->> 'protected')::boolean,
                       archived_at = CASE WHEN (v ->> 'archived')::boolean THEN coalesce(e.archived_at, to_timestamp(p_at / 1000.0)) END,
                       seal = p_seal
                 WHERE e.id = p_id::uuid AND e.seal IS NOT DISTINCT FROM p_seal_from
                   AND v ->> 'kind' = 'environment' AND v ->> 'id' = p_id
                   AND e.project_id = (v ->> 'projectId')::uuid
                   AND e.parent_id IS NOT DISTINCT FROM (v ->> 'parentId')::uuid
                   AND e.owner IS NOT DISTINCT FROM v ->> 'owner'
                   AND (strpos(e.slug, '~') > 0) = (v ->> 'deleted')::boolean
                   -- Its project's archival is the project's row's, which the app writes, and none once deleted (objects.ts): held,
                   -- never written here.
                   AND (v ->> 'projectArchived')::boolean = (strpos(e.slug, '~') = 0 AND EXISTS (SELECT 1 FROM public.projects p WHERE p.id = e.project_id AND p.archived_at IS NOT NULL))
                   AND strpos(v ->> 'slug', '~') = 0
                   AND (NOT (v ->> 'deleted')::boolean OR split_part(e.slug, '~', 1) = v ->> 'slug');
                GET DIAGNOSTICS done = ROW_COUNT;
            END IF;
        WHEN 'secret' THEN
            IF v IS NULL THEN
                UPDATE public.secrets SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
                GET DIAGNOSTICS done = ROW_COUNT;
            ELSE
                -- A reference's end, in the vault's decision that appends 0.14's `reference.end` (EndInRow, EndWithEntry:
                -- formal/SealedObjects.tla): the holder, a key with no version of its own, left with no source. Live, from
                -- its seal, its newest reference row ended. That row must stand: its seal, which the check above held to
                -- the newest change, says the holder reads its source; a row ended or gone under it is not the log's.
                -- Archived, from none (EndWhileArchived): the object its unarchive would restore, ended, then deleted
                -- again by the next call (`secret.delete`); its row was ended by its id (`end_reference`).
                UPDATE public.secrets x SET seal = p_seal
                 WHERE x.id = p_id::uuid AND x.seal IS NOT DISTINCT FROM p_seal_from AND (x.archived_at IS NULL) = (p_seal_from IS NOT NULL)
                   AND x.current_version_id IS NULL
                   AND v ->> 'kind' = 'secret' AND v ->> 'id' = p_id AND x.project_id = (v ->> 'projectId')::uuid AND x.environment_id = (v ->> 'environmentId')::uuid
                   AND v ->> 'version' = '' AND v ->> 'nature' = 'secret' AND v -> 'key' = 'null'::jsonb AND v -> 'digest' = 'null'::jsonb AND v -> 'source' = 'null'::jsonb
                   AND v -> 'reference' = 'null'::jsonb;
                GET DIAGNOSTICS done = ROW_COUNT;
                IF done > 0 AND p_seal_from IS NOT NULL THEN
                    UPDATE public.secret_references y SET ended_at = to_timestamp(p_at / 1000.0)
                     WHERE y.id = (SELECT CASE WHEN z.secret_id = p_id::uuid THEN z.id END FROM public.secret_references z
                                   WHERE z.secret_id <= p_id::uuid ORDER BY z.secret_id DESC, z.created_seq DESC LIMIT 1) AND y.ended_at IS NULL;
                    GET DIAGNOSTICS done = ROW_COUNT;
                    IF done = 0 THEN
                        RAISE EXCEPTION 'the secret object''s reference has no standing row: stale' USING ERRCODE = 'data_corrupted';
                    END IF;
                END IF;
            END IF;
        WHEN 'policy', 'roles' THEN
            config := CASE change WHEN 'genesis' THEN op -> 'value' ELSE v END;
            IF p_id <> 'instance' OR config IS NULL OR jsonb_typeof(config) <> 'object' OR (change = 'genesis' AND p_seal_from IS NOT NULL) THEN
                RAISE EXCEPTION 'the % object is one, made once from its value and changed from its seal', p_kind USING ERRCODE = 'invalid_parameter_value';
            END IF;
            -- Made by its first change (genesis, or the first role defined, the first cap set); moved after from its seal.
            prior := (SELECT g.value::jsonb FROM public.log_config g WHERE g.name = p_kind);
            IF p_seal_from IS NULL THEN
                INSERT INTO public.log_config (name, value, seal) VALUES (p_kind, config::text, p_seal) ON CONFLICT (name) DO NOTHING;
            ELSE
                UPDATE public.log_config SET value = config::text, seal = p_seal WHERE log_config.name = p_kind AND seal = p_seal_from;
            END IF;
            GET DIAGNOSTICS done = ROW_COUNT;
            -- NullOnOld (formal/Roles.tla): the row of each role the change moves, unsealed, as the change leaves it,
            -- unless it says that already, as 0.16's own change of the role, made just before this one, left it. A role
            -- an Owner made and deleted keeps its row, as one that ships put back does: unsealed, it is nobody's, and the
            -- vault's start deletes it (Sync*). A role no table names, or with a name no role has, is the vault's to
            -- refuse, as it always was: its row would break `roles`' checks, which would refuse the change.
            IF p_kind = 'roles' AND done > 0 THEN
                FOR v_scope, v_was, v_now IN
                    SELECT t.scope, coalesce(prior -> t.tbl, '{}'::jsonb), coalesce(config -> t.tbl, '{}'::jsonb)
                      FROM (VALUES ('project', 'roles'), ('instance', 'instanceRoles')) t (scope, tbl) LOOP
                    INSERT INTO public.roles AS r (scope, name, definition, seal)
                    SELECT v_scope, k.name, k.definition, NULL FROM jsonb_each(v_now) k (name, definition) WHERE v_was -> k.name IS DISTINCT FROM k.definition
                    ON CONFLICT ON CONSTRAINT roles_pkey DO UPDATE SET definition = EXCLUDED.definition, seal = NULL
                     WHERE r.definition IS DISTINCT FROM EXCLUDED.definition;
                    UPDATE public.roles r SET definition = NULL, seal = NULL
                     WHERE r.scope = v_scope AND r.definition IS NOT NULL AND v_was ? r.name AND NOT v_now ? r.name;
                END LOOP;
            END IF;
            -- The policy's typed row too, from the same value, sealed the same: `log_config`'s stays written
            -- while 0.15.0's code may read it. Both rows move, or the change is refused: neither is left behind the other.
            IF p_kind = 'policy' THEN
                IF done > 0 THEN
                    IF jsonb_typeof(config -> 'bulk' -> 'count') IS DISTINCT FROM 'number' OR jsonb_typeof(config -> 'bulk' -> 'windowMs') IS DISTINCT FROM 'number' THEN
                        RAISE EXCEPTION 'a policy object is its bulk cap''s count and window' USING ERRCODE = 'invalid_parameter_value';
                    END IF;
                    IF p_seal_from IS NULL THEN
                        INSERT INTO public.policy (name, bulk_count, bulk_window_ms, seal)
                            VALUES ('instance', (config -> 'bulk' ->> 'count')::bigint, (config -> 'bulk' ->> 'windowMs')::bigint, p_seal) ON CONFLICT (name) DO NOTHING;
                    ELSE
                        UPDATE public.policy SET bulk_count = (config -> 'bulk' ->> 'count')::bigint, bulk_window_ms = (config -> 'bulk' ->> 'windowMs')::bigint, seal = p_seal
                         WHERE name = 'instance' AND seal = p_seal_from;
                    END IF;
                    GET DIAGNOSTICS done = ROW_COUNT;
                    IF done = 0 THEN
                        RAISE EXCEPTION 'the policy object''s rows are not one another''s: stale' USING ERRCODE = 'data_corrupted';
                    END IF;
                END IF;
            END IF;
        WHEN 'proxy', 'proxy-reserved' THEN
            -- An environment's proxy definitions, or the instance's reserved names (0.16; docs/design/proxy-ui.md,
            -- section 2): the whole row from its value, and only from the newest change's seal (ChangeCAS on the log, not
            -- the row): one the vault did not decide on is no change of its. An environment's, its items by name and
            -- their index, which its seal covers; the reserved set's, the whole set.
            IF p_seal_from IS DISTINCT FROM newest THEN RETURN NULL; END IF;
            IF p_kind = 'proxy' THEN
                IF jsonb_typeof(v -> 'items') IS DISTINCT FROM 'object' OR jsonb_typeof(v -> 'digests') IS DISTINCT FROM 'string' THEN
                    RAISE EXCEPTION 'a proxy object is its items and their index' USING ERRCODE = 'invalid_parameter_value';
                END IF;
                INSERT INTO public.proxy_definitions AS d (environment_id, items, digests, seal)
                    VALUES (p_id::uuid, v -> 'items', decode(v ->> 'digests', 'base64'), p_seal)
                    ON CONFLICT (environment_id) DO UPDATE SET items = EXCLUDED.items, digests = EXCLUDED.digests, seal = EXCLUDED.seal;
            ELSE
                IF p_id <> 'instance' OR jsonb_typeof(v -> 'names') IS DISTINCT FROM 'array'
                    OR EXISTS (SELECT FROM jsonb_array_elements(v -> 'names') AS e WHERE jsonb_typeof(e) <> 'string') THEN
                    RAISE EXCEPTION 'the reserved names are one object, the whole set' USING ERRCODE = 'invalid_parameter_value';
                END IF;
                -- The names in the order the value lists them, which the seal covers (0084).
                INSERT INTO public.proxy_reserved AS r (id, names, seal)
                    VALUES (1, ARRAY(SELECT name FROM jsonb_array_elements_text(v -> 'names') WITH ORDINALITY AS t(name, i) ORDER BY i), p_seal)
                    ON CONFLICT (id) DO UPDATE SET names = EXCLUDED.names, seal = EXCLUDED.seal;
            END IF;
            GET DIAGNOSTICS done = ROW_COUNT;
        WHEN 'role' THEN
            -- A role's row (0.16; formal/Roles.tla): written whole from its value, and only from the newest
            -- change's seal, as the proxy's: a row 0.15.0 unsealed, or a writer moved, is replaced, never carried on. Its
            -- object, `{ kind: 'role', id, definition }`, the definition null for a role as it ships; none for a role an
            -- Owner made, deleted, which leaves no row and no seal.
            IF p_seal_from IS DISTINCT FROM newest THEN RETURN NULL; END IF;
            v_scope := split_part(p_id, '/', 1);
            IF v_scope NOT IN ('project', 'instance') OR strpos(p_id, '/') = 0
                OR (v IS NOT NULL AND (v ->> 'kind' IS DISTINCT FROM 'role' OR v ->> 'id' IS DISTINCT FROM p_id OR jsonb_typeof(v -> 'definition') NOT IN ('object', 'null')))
                OR (v IS NULL) <> (p_seal IS NULL) THEN
                RAISE EXCEPTION 'a role object is its scope and name, and its definition or none' USING ERRCODE = 'invalid_parameter_value';
            END IF;
            IF v IS NULL THEN
                DELETE FROM public.roles r WHERE r.scope = v_scope AND r.name = substr(p_id, strpos(p_id, '/') + 1);
            ELSE
                INSERT INTO public.roles AS r (scope, name, definition, seal)
                    VALUES (v_scope, substr(p_id, strpos(p_id, '/') + 1), nullif(v -> 'definition', 'null'::jsonb), p_seal)
                    ON CONFLICT ON CONSTRAINT roles_pkey DO UPDATE SET definition = EXCLUDED.definition, seal = EXCLUDED.seal;
            END IF;
            -- From the newest seal, whatever the row held: a deletion of a row already gone is a change all the same.
            done := 1;
        ELSE
            RAISE EXCEPTION 'no object kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END CASE;
    -- A row gone, a row whose seal is no longer the one read, an environment that is not what the value says it
    -- stays, or an object made already: nothing was done. Each kind's write counted its rows itself (`done`).
    IF done = 0 THEN RETURN NULL; END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN n;
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.change_bindings(p_at bigint, p_actor text, p_make boolean, p_principal text, p_generation integer, p_principal_seq bigint, p_actor_generation integer, p_actor_seq bigint, p_via uuid, p_via_seal bytea, p_via_end bigint, p_connection uuid, p_connection_generation integer, p_policy_seq bigint, p_protected uuid[], p_slugs text[], p_app_key text, p_max integer, p_live uuid[], p_read_keys uuid[], p_read_names text[], p_id uuid, p_auth_mac bytea, p_profile text, p_issuer text, p_jwks_uri text, p_jwks text, p_claims text, p_scope text, p_policy text, p_origin text, p_label text, p_created_by text, p_created_at bigint, p_seal bytea, p_ends uuid[], p_end_mac_from bytea[], p_end_seal_from bytea[], p_end_auth_mac bytea[], p_end_seal bytea[], p_creds uuid[], p_cred_binding uuid[], p_cred_mac_from bytea[], p_cred_seal_from bytea[], p_cred_auth_mac bytea[], p_cred_seal bytea[], p_revoked_at bigint, p_revoked_by text, p_change_request text[], p_change_object uuid[], p_change_payload text[], p_change_seal bytea[], p_change_mac bytea[], p_sweep boolean)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET lock_timeout TO '500ms'
AS $function$
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
        -- The change lock, when it ends any, after the members' rows and before any row of the app's (row, change lock, issue
        -- lock, fence).
        IF cardinality(p_ends) > 0 THEN PERFORM pg_advisory_xact_lock(1668244070, 2); END IF;
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
               OR p_via_seal IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = ANY(ARRAY[public.log_object('credential', p_via::text)::uuid]) ORDER BY c.object DESC, c.number DESC LIMIT 1) THEN
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
    -- An unbind alone: the change lock first, as above.
    IF NOT p_make THEN PERFORM pg_advisory_xact_lock(1668244070, 2); END IF;
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
                WHERE e.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = ANY(ARRAY[public.log_object('binding', e.id::text)::uuid]) ORDER BY l.object DESC, l.number DESC LIMIT 1))
       OR EXISTS (SELECT 1 FROM unnest(p_creds, p_cred_seal_from) AS x(id, seal)
                WHERE x.seal IS DISTINCT FROM (SELECT l.seal FROM public.log_changes l WHERE l.object = ANY(ARRAY[public.log_object('credential', x.id::text)::uuid]) ORDER BY l.object DESC, l.number DESC LIMIT 1)) THEN
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
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.revoke_credential(p_request text, p_at bigint, p_actor text, p_payload text, p_mac bytea, p_seal_from bytea, p_seal bytea, p_id uuid, p_mac_from bytea, p_auth_mac bytea, p_revoked_at bigint, p_revoked_by text, p_policy boolean, p_policy_seq bigint, p_protected uuid[], p_slugs text[])
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET lock_timeout TO '500ms'
AS $function$
DECLARE
    n bigint;
    target uuid := public.log_object('credential', p_id::text);
BEGIN
    IF p_seal_from IS NULL OR p_seal IS NULL THEN
        RAISE EXCEPTION 'the vault revokes a credential the log holds, from its seal' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(1668244070, 2);
    PERFORM 1 FROM public.credentials c
     WHERE c.id = p_id AND c.revoked_at IS NULL AND c.auth_mac = p_mac_from AND c.seal IS NOT DISTINCT FROM p_seal_from
       FOR UPDATE;
    IF NOT FOUND THEN RETURN json_build_object('state', 'moved'); END IF;
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    -- ChangeChecksSeal: a row the log sealed once, put back since, is not its newest change's.
    IF p_seal_from IS DISTINCT FROM (SELECT c.seal FROM public.log_changes c WHERE c.object = ANY(ARRAY[target::uuid]) ORDER BY c.object DESC, c.number DESC LIMIT 1) THEN
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
$function$;
