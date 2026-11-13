-- The two new sealed state rows, each read by key where 0.15 read the newest
-- entry of a kind in `audit_log`: `settings`, the instance's one row, for the newest `settings.change`; `log_keys`, a
-- row per key the app or the vault wrote entries under, for the newest `key.rotate`. Their objects are `settings`/
-- `instance` and `log-key`/`<key_id>` (packages/vault/src/objects.ts). Nothing writes or reads them yet: the upgrade's
-- migration fills them from the old log, unsealed, and the vault's upgrade step seals each with its object's first
-- change, a compare-and-set on the null seal. So the seal is nullable, as `roles`' is, and a row without one is
-- never what a reader accepts.
-- The settings' scope is typed: each filter its kind and its list, projects by id
-- (`uuid[]`), environments by slug (`text[]`), the list empty for `all`.
-- No secondary index: every read is by primary key.
CREATE TABLE "log_keys" (
	"holder" text NOT NULL,
	"key_id" text NOT NULL,
	"retired" boolean DEFAULT false NOT NULL,
	"seal" "bytea",
	CONSTRAINT "log_keys_pkey" PRIMARY KEY("holder","key_id"),
	CONSTRAINT "log_keys_holder_check" CHECK ("log_keys"."holder" IN ('app', 'vault')),
	CONSTRAINT "log_keys_key_id_check" CHECK ("log_keys"."key_id" ~ ('^' || "log_keys"."holder" || ':[0-9a-f]{16}$')),
	CONSTRAINT "log_keys_seal_check" CHECK ("log_keys"."seal" IS NULL OR octet_length("log_keys"."seal") = 16)
);
--> statement-breakpoint
CREATE TABLE "settings" (
	"name" text PRIMARY KEY NOT NULL,
	"service_accounts_projects" text NOT NULL,
	"service_accounts_project_ids" uuid[] DEFAULT '{}' NOT NULL,
	"service_accounts_environments" text NOT NULL,
	"service_accounts_environment_slugs" text[] DEFAULT '{}' NOT NULL,
	"seal" "bytea",
	CONSTRAINT "settings_name_check" CHECK ("settings"."name" = 'instance'),
	CONSTRAINT "settings_service_accounts_projects_check" CHECK ("settings"."service_accounts_projects" IN ('all', 'only', 'except') AND ("settings"."service_accounts_projects" <> 'all' OR cardinality("settings"."service_accounts_project_ids") = 0)),
	CONSTRAINT "settings_service_accounts_environments_check" CHECK ("settings"."service_accounts_environments" IN ('all', 'only', 'except') AND ("settings"."service_accounts_environments" <> 'all' OR cardinality("settings"."service_accounts_environment_slugs") = 0)),
	CONSTRAINT "settings_seal_check" CHECK ("settings"."seal" IS NULL OR octet_length("settings"."seal") = 16)
);
--> statement-breakpoint
-- The vault reads both, to hold them to their seals; the app reads the settings it shows (`GET /api/me`, the service
-- accounts' pages) and its own keys' state at its start, by key; the backup reads every table. No login writes either:
-- the vault's functions do.
GRANT SELECT ON settings TO coffre_app, coffre_vault, coffre_backup;--> statement-breakpoint
GRANT SELECT ON log_keys TO coffre_app, coffre_vault, coffre_backup;
--> statement-breakpoint
-- Events' rows (`Vault.note`, packages/vault/src/note.ts): what no object's change records, signed by the
-- vault and written here alone, by the vault (`note`, its own refusals, the beat's finding), or by the app for the
-- events `prepare` signed beside the request's changes (those that must commit with them): every event of the request
-- in one call, so 30 events are one statement, not 30 round trips. Each row's object is `log_object('event', id)`, its
-- request id the event's own id, no seal; the MAC is the vault's, which the checkpointer checks before it seals the
-- row, and which this cannot check: a row whose MAC does not hold stops the seal, as one through `app_change` does.
-- Under the fence shared, taken once for the call, as a use's: the numbers are taken where the checkpointer's barrier
-- orders them. It answers one number per element, in the arrays' order: a new event's, taken then, so the new ones
-- ascend in that order; a retry's, wherever it sits, the number it was written under, lower; an id twice in one call
-- is a retry of its first, and answers its number twice.
-- Locks, in this order, as a request's transaction takes them: the change lock where the head is taken today, the
-- issue lock and the fence as each change takes them (`app_change`, `app_change_strict`), then this, the transaction's
-- last statement and its last lock, never before a change: a change takes the issue lock before the fence
-- (IssueBeforeFence, formal/WriteLocks.tla), and the fence held first would close a wait cycle with the barrier. A
-- transaction of events alone takes the fence alone and commits; so does the vault's own call (`note`, the refusal
-- it decided, the beat's finding), which writes its events last, after any lock of its own.
-- The same event again answers its number: the same id, object, actor and payload (its time and MAC are each
-- signing's). Another under an id already written, or a payload that is no event's of its id, is refused, and the
-- call writes nothing. Its time is the vault's when it signed: as a prepared change's, nothing here bounds it, and the
-- checkpointer refuses an entry older than its pair by more than its freshness bound as a replay.
CREATE FUNCTION log_events(p_ids text[], p_ats bigint[], p_actors text[], p_payloads text[], p_macs bytea[]) RETURNS bigint[]
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    total integer := coalesce(cardinality(p_ids), 0);
    numbers bigint[] := '{}';
    event jsonb;
    target uuid;
    n bigint;
BEGIN
    IF total = 0 OR coalesce(cardinality(p_ats), 0) <> total OR coalesce(cardinality(p_actors), 0) <> total
        OR coalesce(cardinality(p_payloads), 0) <> total OR coalesce(cardinality(p_macs), 0) <> total THEN
        RAISE EXCEPTION 'log_events takes one array per column, all of one length, with at least one event' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    FOR i IN 1 .. total LOOP
        event := p_payloads[i]::jsonb;
        IF event ->> 'op' IS DISTINCT FROM 'event' OR event -> 'ref' ->> 'kind' IS DISTINCT FROM 'event'
            OR event -> 'ref' ->> 'id' IS DISTINCT FROM p_ids[i] THEN
            RAISE EXCEPTION 'an event''s payload is an event''s, filed under its own id' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        target := public.log_object('event', p_ids[i]);
        -- Two retries at once both find none: the second's insert waits for the first's, and takes its row once it commits.
        INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
            VALUES (nextval('public.log_number'), p_ats[i], p_ids[i], target, p_actors[i], p_payloads[i], NULL, p_macs[i])
            ON CONFLICT (request_id) DO NOTHING
            RETURNING number INTO n;
        IF n IS NULL THEN
            -- A second statement's snapshot: it sees the other writer's row only under READ COMMITTED, which every caller
            -- runs at (Postgres's default; coffre's one other level, `SNAPSHOT`'s repeatable read, is read only).
            SELECT c.number INTO n FROM public.log_changes c
                WHERE c.request_id = p_ids[i] AND c.object = target AND c.actor = p_actors[i] AND c.payload = p_payloads[i];
            IF n IS NULL THEN
                RAISE EXCEPTION 'the id % names another entry', p_ids[i] USING ERRCODE = 'unique_violation';
            END IF;
        END IF;
        numbers := numbers || n;
    END LOOP;
    RETURN numbers;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION log_events(text[], bigint[], text[], text[], bytea[]) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION log_events(text[], bigint[], text[], text[], bytea[]) TO coffre_app, coffre_vault;
