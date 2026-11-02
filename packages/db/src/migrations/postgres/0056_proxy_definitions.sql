-- Proxy definitions written in the UI (0.16, T186; docs/design/proxy-ui.md, section 2). One row per environment holds its items, a sealed object of 0.15's log, kind `proxy`, which only the vault writes, through `change_input`: its items by name, the index of their digests (each item's name beside the SHA-256 of its canonical body, sorted by name), and the vault's seal over that index, so that a use reads its route's item and the index, never the whole environment (PR C). One row holds the names the deployment's code reserved, kind `proxy-reserved`, the whole set. The app reads neither: every read is a vault call. Additive (AGENTS.md, "expand, then contract"): two tables, their grants, and `change_input` as 0046 made it, but for these two kinds.
CREATE TABLE "proxy_definitions" (
	"environment_id" uuid PRIMARY KEY NOT NULL,
	"items" jsonb NOT NULL,
	"digests" "bytea" NOT NULL,
	"seal" "bytea" NOT NULL,
	CONSTRAINT "proxy_definitions_items_check" CHECK (jsonb_typeof("proxy_definitions"."items") = 'object'),
	CONSTRAINT "proxy_definitions_seal_check" CHECK (octet_length("proxy_definitions"."seal") = 16)
);
--> statement-breakpoint
CREATE TABLE "proxy_reserved" (
	"id" smallint PRIMARY KEY NOT NULL,
	"names" jsonb NOT NULL,
	"seal" "bytea" NOT NULL,
	CONSTRAINT "proxy_reserved_id_check" CHECK ("proxy_reserved"."id" = 1),
	CONSTRAINT "proxy_reserved_names_check" CHECK (jsonb_typeof("proxy_reserved"."names") = 'array'),
	CONSTRAINT "proxy_reserved_seal_check" CHECK (octet_length("proxy_reserved"."seal") = 16)
);
--> statement-breakpoint
ALTER TABLE "proxy_definitions" ADD CONSTRAINT "proxy_definitions_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE no action ON UPDATE no action;
--> statement-breakpoint
-- `change_input` as 0046 made it, but for the proxy's two kinds: each row written whole from its value, from the seal of its object's newest change.
CREATE OR REPLACE FUNCTION change_input(
    p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_value text, p_seal_from bytea, p_seal bytea, p_mac bytea
) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
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
        WHEN 'connection' THEN (SELECT k.principal FROM public.mcp_connections k WHERE k.id = p_id::uuid)
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
        OR (p_kind = 'secret' AND change IN ('secret.write', 'secret.delete'))
        OR (p_kind = 'roles' AND change = 'role.define')
        OR (p_kind = 'policy' AND change = 'bulk.limit')
        OR (p_kind = 'proxy' AND change IN ('proxy.save', 'proxy.code'))
        OR (p_kind = 'proxy-reserved' AND change IN ('proxy.code', 'proxy.release'))) THEN
        RAISE EXCEPTION 'this schema knows no change % to a %', coalesce(change, 'without an op'), p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The proxy's objects are 0.16's, after every cutover: each is made by its first change, never a genesis.
    IF change = 'genesis' AND p_kind IN ('proxy', 'proxy-reserved') THEN
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
        ELSE v IS NOT NULL
    END) THEN
        RAISE EXCEPTION 'a % change % carries the object it leaves exactly when this function writes it', p_kind, change USING ERRCODE = 'invalid_parameter_value';
    END IF;
    newest := (SELECT c.seal FROM public.log_changes c WHERE c.object = target ORDER BY c.number DESC LIMIT 1);
    -- ChangeChecksSeal: the row's seal is its object's newest change's, or the object has neither yet (one probe, as
    -- a use makes). A row deleted outright, or a seal no change wrote, is stale too. Not the proxy's (0.16): the vault
    -- writes each of its rows whole from its value, so a row a writer moved is replaced, never carried on; its change
    -- moves only from the newest change's seal (below), which the vault decided on.
    held := CASE p_kind
        WHEN 'principal' THEN (SELECT m.seal FROM public.vault_members m WHERE m.principal = p_id)
        WHEN 'credential' THEN coalesce(
            (SELECT c.seal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.seal FROM public.service_bindings b WHERE b.id = p_id::uuid))
        WHEN 'connection' THEN (SELECT k.seal FROM public.mcp_connections k WHERE k.id = p_id::uuid)
        WHEN 'environment' THEN (SELECT e.seal FROM public.environments e WHERE e.id = p_id::uuid)
        WHEN 'secret' THEN (SELECT x.seal FROM public.secrets x WHERE x.id = p_id::uuid)
        WHEN 'policy' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'policy')
        WHEN 'roles' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'roles')
        WHEN 'proxy' THEN newest
        WHEN 'proxy-reserved' THEN newest
    END;
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
        WHEN 'connection' THEN
            -- An MCP connection's genesis, the cutover's (T147): its row sealed as it is. The app's changes make and end the others.
            UPDATE public.mcp_connections SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'environment' THEN
            IF v IS NULL THEN
                UPDATE public.environments SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
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
            END IF;
        WHEN 'secret' THEN
            IF v IS NULL THEN
                UPDATE public.secrets SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
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
                     WHERE y.id = (SELECT z.id FROM public.secret_references z WHERE z.secret_id = p_id::uuid ORDER BY z.created_seq DESC LIMIT 1) AND y.ended_at IS NULL;
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
            IF p_seal_from IS NULL THEN
                INSERT INTO public.log_config (name, value, seal) VALUES (p_kind, config::text, p_seal) ON CONFLICT (name) DO NOTHING;
            ELSE
                UPDATE public.log_config SET value = config::text, seal = p_seal WHERE log_config.name = p_kind AND seal = p_seal_from;
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
                IF p_id <> 'instance' OR jsonb_typeof(v -> 'names') IS DISTINCT FROM 'array' THEN
                    RAISE EXCEPTION 'the reserved names are one object, the whole set' USING ERRCODE = 'invalid_parameter_value';
                END IF;
                INSERT INTO public.proxy_reserved AS r (id, names, seal) VALUES (1, v -> 'names', p_seal)
                    ON CONFLICT (id) DO UPDATE SET names = EXCLUDED.names, seal = EXCLUDED.seal;
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
-- The vault reads both and writes them through `change_input` alone (SECURITY DEFINER, the owner's); the backup reads every table. The app reads neither.
GRANT SELECT ON proxy_definitions, proxy_reserved TO coffre_vault;
--> statement-breakpoint
GRANT SELECT ON proxy_definitions, proxy_reserved TO coffre_backup;
