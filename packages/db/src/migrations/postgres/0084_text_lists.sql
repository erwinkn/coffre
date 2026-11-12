-- 0.16.0, T278: three lists of strings, held as JSON in a text or jsonb column, become text[] (typed columns, D199):
-- proxy_reserved.names, passkeys.transports and oauth_clients.redirect_uris. 0.16 upgrades offline from exactly 0.15.0
-- (D197), so each column changes type in place and no 0.15 code reads it after.
--
-- No seal or MAC changes. The reserved set's seal covers `{ kind: 'proxy-reserved', names }`, which the vault builds
-- from the row (packages/vault/src/store.ts, `readObject`): the same names in the same order. A client's MAC covers its
-- redirects as the JSON text the column held, which the app makes again from the list (packages/server/src/auth-rows.ts,
-- `tupleOf`). A passkey's transports are under no MAC.
--
-- ALTER ... USING takes no subquery: a function of this session's converts each value, the strings of a JSON array in
-- its order. Only a forger writes anything else: a non-string element is dropped and a non-array becomes no strings,
-- and a seal or MAC refuses what is left unless it is the set it covers.
CREATE FUNCTION pg_temp.coffre_text_list(value jsonb) RETURNS text[] LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN jsonb_typeof(value) = 'array'
        THEN ARRAY(SELECT e #>> '{}' FROM jsonb_array_elements(value) WITH ORDINALITY AS t(e, i) WHERE jsonb_typeof(e) = 'string' ORDER BY i)
        ELSE '{}' END
$$;--> statement-breakpoint
ALTER TABLE "oauth_clients" DROP CONSTRAINT "oauth_clients_redirect_uris_check";--> statement-breakpoint
ALTER TABLE "passkeys" DROP CONSTRAINT "passkeys_transports_check";--> statement-breakpoint
ALTER TABLE "proxy_reserved" DROP CONSTRAINT "proxy_reserved_names_check";--> statement-breakpoint
ALTER TABLE "oauth_clients" ALTER COLUMN "redirect_uris" SET DATA TYPE text[] USING pg_temp.coffre_text_list("redirect_uris"::jsonb);--> statement-breakpoint
ALTER TABLE "passkeys" ALTER COLUMN "transports" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "passkeys" ALTER COLUMN "transports" SET DATA TYPE text[] USING pg_temp.coffre_text_list("transports"::jsonb);--> statement-breakpoint
ALTER TABLE "passkeys" ALTER COLUMN "transports" SET DEFAULT '{}';--> statement-breakpoint
ALTER TABLE "proxy_reserved" ALTER COLUMN "names" SET DATA TYPE text[] USING pg_temp.coffre_text_list("names");--> statement-breakpoint
DROP FUNCTION pg_temp.coffre_text_list(jsonb);--> statement-breakpoint
-- change_input as 0082 left it, but for the reserved names, which it writes as text[], strings only.
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
        WHEN 'connection' THEN (SELECT k.principal FROM public.mcp_connections k WHERE k.id = p_id::uuid)
    END;
    IF member IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(1668245101, hashtext(m.principal)) FROM public.principals m WHERE m.principal = member FOR NO KEY UPDATE;
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
            -- An MCP connection's genesis, the cutover's (T147): its row sealed as it is. The app's changes make and end the others.
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
            -- The policy's typed row too (T178), from the same value, sealed the same: `log_config`'s stays written
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
            -- An environment's proxy definitions, or the instance's reserved names (0.16, T186; docs/design/proxy-ui.md,
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
                -- The names in the order the value lists them, which the seal covers (0084, T278).
                INSERT INTO public.proxy_reserved AS r (id, names, seal)
                    VALUES (1, ARRAY(SELECT name FROM jsonb_array_elements_text(v -> 'names') WITH ORDINALITY AS t(name, i) ORDER BY i), p_seal)
                    ON CONFLICT (id) DO UPDATE SET names = EXCLUDED.names, seal = EXCLUDED.seal;
            END IF;
            GET DIAGNOSTICS done = ROW_COUNT;
        WHEN 'role' THEN
            -- A role's row (0.16, T178; formal/Roles.tla): written whole from its value, and only from the newest
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
