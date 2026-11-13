-- The audit projection (0.16; docs/design/state-rows.md, section 2): what the audit pages and the offboarding report will list, as rows the vault's projector derives from the logs, the only writer of these tables, one transaction a batch. Its sources: the two chains, `log_changes` and `log_uses`, in the windows the checkpointer has signed; and `audit_log`, walked backward by its hashes from an anchor, heartbeats and checkpoints left out. Nothing reads them yet, and nothing is copied here: the projector lists every log from its cursor, and `coffre audit rebuild` starts it over (`rebuild_audit`, the vault's alone, which leaves a signed record of who asked).
--> statement-breakpoint
-- One row per entry of any log. `detail` is JSON text that no SQL parses: what the API returns as an entry's `metadata`. `places` is every place it is listed at (`audit_event_places`), under its MAC, so that a place's page holds each row it reads to it. `mac` is the vault's, over every column but itself (`eventMac` in @coffre/vault).
CREATE TABLE "audit_events" (
	"at" bigint NOT NULL,
	"number" bigint NOT NULL,
	"log" smallint NOT NULL,
	"author" text NOT NULL,
	"action" text NOT NULL,
	"shown" boolean NOT NULL,
	"allowed" boolean NOT NULL,
	"code" text,
	"actor" text NOT NULL,
	"subject" text,
	"credential" uuid,
	"project" uuid,
	"environment" uuid,
	"secret" uuid,
	"version" uuid,
	"places" uuid[] NOT NULL,
	"request_id" text,
	"operation_id" uuid,
	"related" bigint,
	"source_ip" text,
	"detail" text NOT NULL,
	"mac" "bytea" NOT NULL,
	CONSTRAINT "audit_events_pkey" PRIMARY KEY("at","number","log"),
	CONSTRAINT "audit_events_log_check" CHECK ("audit_events"."log" IN (14, 15, 16)),
	CONSTRAINT "audit_events_author_check" CHECK ("audit_events"."author" IN ('app', 'vault')),
	CONSTRAINT "audit_events_mac_check" CHECK (octet_length("audit_events"."mac") = 16)
);
--> statement-breakpoint
-- The page of a project, an environment or a key: one row for each place an entry is at.
CREATE TABLE "audit_event_places" (
	"place" uuid NOT NULL,
	"at" bigint NOT NULL,
	"number" bigint NOT NULL,
	"log" smallint NOT NULL,
	CONSTRAINT "audit_event_places_pkey" PRIMARY KEY("place","at","number","log")
);
--> statement-breakpoint
-- The offboarding report: the newest time each member read or wrote each version of each key.
CREATE TABLE "audit_member_keys" (
	"principal" text NOT NULL,
	"secret" uuid NOT NULL,
	"version" uuid NOT NULL,
	"wrote" boolean NOT NULL,
	"at" bigint NOT NULL,
	"number" bigint NOT NULL,
	CONSTRAINT "audit_member_keys_pkey" PRIMARY KEY("principal","secret","version","wrote")
);
--> statement-breakpoint
-- How far the projector has gone, one row. The chains: every entry numbered at or below `through` is listed; `pair`, the signed pair at or below it; `at`, the signed time of the newest pair whose entries are all listed. `audit_log`: the entries with a seq below `old_floor`, and from `old_from` up to below `old_top`, are listed; `old_hash` is the hash the entry below `old_from` must have, where the walk goes on (section 6). `mac` covers through, pair, at, old_from and old_hash (`cursorMac` in @coffre/vault), null only at the start; old_floor and old_top are temporary, outside it, and go once `audit_log` is frozen: never sign them back in. `reads_from` is retention's (a dropped day's end): the summary keeps no read older, outside the MAC, as the summary has none.
CREATE TABLE "audit_cursor" (
	"only_row" boolean PRIMARY KEY DEFAULT true NOT NULL,
	"through" bigint NOT NULL,
	"pair" bigint NOT NULL,
	"at" bigint NOT NULL,
	"old_floor" bigint NOT NULL,
	"old_from" bigint NOT NULL,
	"old_top" bigint NOT NULL,
	"old_hash" "bytea" NOT NULL,
	"mac" "bytea",
	"reads_from" bigint DEFAULT 0 NOT NULL,
	CONSTRAINT "audit_cursor_only_row_check" CHECK ("audit_cursor"."only_row"),
	CONSTRAINT "audit_cursor_old_check" CHECK ("audit_cursor"."old_floor" <= "audit_cursor"."old_from" AND "audit_cursor"."old_from" <= "audit_cursor"."old_top"),
	CONSTRAINT "audit_cursor_old_hash_check" CHECK (octet_length("audit_cursor"."old_hash") = 32),
	CONSTRAINT "audit_cursor_mac_check" CHECK ("audit_cursor"."mac" IS NULL OR octet_length("audit_cursor"."mac") = 16)
);
--> statement-breakpoint
-- The default page, newest first, of shown events alone: the newest rows can all be hidden (a burst of sign-ins), and
-- the key read backward with a filter on `shown` would read every one of them first. And a member's page.
CREATE INDEX "audit_events_shown_idx" ON "audit_events" USING btree ("at","number","log") WHERE "audit_events"."shown";--> statement-breakpoint
CREATE INDEX "audit_events_actor_idx" ON "audit_events" USING btree ("actor","at","number","log");--> statement-breakpoint
-- The start: nothing listed of any log.
INSERT INTO "audit_cursor" ("only_row", "through", "pair", "at", "old_floor", "old_from", "old_top", "old_hash") VALUES (true, 0, 0, 0, 0, 0, 0, '\x0000000000000000000000000000000000000000000000000000000000000000');--> statement-breakpoint
-- A batch of the projector, in one statement: its rows, each event once (a row already under its key, a database
-- writer's or one listed before the cursor was put back, is replaced by the projector's, and the places that row named
-- go with it, by the table's key, so that none it no longer names is left), its places, the summary's
-- newest times (only ever later, and no read older than retention's `reads_from`), and the cursor on to `p_to`, only
-- while it still stands at `p_from`, where the batch started: whether it wrote. A projector another overtook, or a
-- rebuild reset, writes nothing. The cursor's row is the lock: the UPDATE takes it first, and retention's drop and a
-- rebuild take it first too, so a batch under way, a drop and a rebuild go one after another.
CREATE FUNCTION project_audit(p_events jsonb, p_keys jsonb, p_from jsonb, p_to jsonb) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE public.audit_cursor c
       SET through = (p_to ->> 'through')::bigint, pair = (p_to ->> 'pair')::bigint, at = (p_to ->> 'at')::bigint,
           old_floor = (p_to ->> 'oldFloor')::bigint, old_from = (p_to ->> 'oldFrom')::bigint, old_top = (p_to ->> 'oldTop')::bigint,
           old_hash = decode(p_to ->> 'oldHash', 'hex'), mac = decode(p_to ->> 'mac', 'hex')
     WHERE c.only_row AND c.through = (p_from ->> 'through')::bigint AND c.pair = (p_from ->> 'pair')::bigint AND c.at = (p_from ->> 'at')::bigint
       AND c.old_floor = (p_from ->> 'oldFloor')::bigint AND c.old_from = (p_from ->> 'oldFrom')::bigint AND c.old_top = (p_from ->> 'oldTop')::bigint
       AND c.old_hash = decode(p_from ->> 'oldHash', 'hex') AND c.mac IS NOT DISTINCT FROM decode(p_from ->> 'mac', 'hex');
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    DELETE FROM public.audit_event_places p
     USING (SELECT unnest(e.places) AS place, e.at, e.number, e.log
              FROM jsonb_array_elements(p_events) x
              JOIN public.audit_events e ON e.at = (x ->> 'at')::bigint AND e.number = (x ->> 'number')::bigint AND e.log = (x ->> 'log')::smallint) g
     WHERE p.place = g.place AND p.at = g.at AND p.number = g.number AND p.log = g.log;
    INSERT INTO public.audit_events (at, number, log, author, action, shown, allowed, code, actor, subject, credential, project, environment, secret, version,
                                     places, request_id, operation_id, related, source_ip, detail, mac)
    SELECT (x ->> 'at')::bigint, (x ->> 'number')::bigint, (x ->> 'log')::smallint, x ->> 'author', x ->> 'action', (x ->> 'shown')::boolean,
           (x ->> 'allowed')::boolean, x ->> 'code', x ->> 'actor', x ->> 'subject', (x ->> 'credential')::uuid, (x ->> 'project')::uuid,
           (x ->> 'environment')::uuid, (x ->> 'secret')::uuid, (x ->> 'version')::uuid,
           ARRAY(SELECT p::uuid FROM jsonb_array_elements_text(x -> 'places') p), x ->> 'requestId', (x ->> 'operationId')::uuid,
           (x ->> 'related')::bigint, x ->> 'sourceIp', x ->> 'detail', decode(x ->> 'mac', 'hex')
      FROM jsonb_array_elements(p_events) x
    ON CONFLICT (at, number, log) DO UPDATE SET author = excluded.author, action = excluded.action, shown = excluded.shown, allowed = excluded.allowed,
        code = excluded.code, actor = excluded.actor, subject = excluded.subject, credential = excluded.credential, project = excluded.project,
        environment = excluded.environment, secret = excluded.secret, version = excluded.version, places = excluded.places, request_id = excluded.request_id,
        operation_id = excluded.operation_id, related = excluded.related, source_ip = excluded.source_ip, detail = excluded.detail, mac = excluded.mac;
    INSERT INTO public.audit_event_places (place, at, number, log)
    SELECT p::uuid, (x ->> 'at')::bigint, (x ->> 'number')::bigint, (x ->> 'log')::smallint
      FROM jsonb_array_elements(p_events) x, jsonb_array_elements_text(x -> 'places') p
    ON CONFLICT DO NOTHING;
    INSERT INTO public.audit_member_keys (principal, secret, version, wrote, at, number)
    SELECT k ->> 'principal', (k ->> 'secret')::uuid, (k ->> 'version')::uuid, (k ->> 'wrote')::boolean, (k ->> 'at')::bigint, (k ->> 'number')::bigint
      FROM jsonb_array_elements(p_keys) k
     WHERE (k ->> 'wrote')::boolean OR (k ->> 'at')::bigint >= (SELECT c.reads_from FROM public.audit_cursor c WHERE c.only_row)
    ON CONFLICT (principal, secret, version, wrote) DO UPDATE SET at = excluded.at, number = excluded.number
     WHERE (audit_member_keys.at, audit_member_keys.number) < (excluded.at, excluded.number);
    RETURN true;
END
$$;--> statement-breakpoint
-- Retention's drop of a day of uses (retention.ts), once the projector has listed past its cut: the day's uses' rows and
-- their places, and from the summary every read older than the day's end, which `reads_from` then keeps out, under the
-- cursor's row, so that no batch under way puts one back.
CREATE FUNCTION drop_audit_day(p_day date) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    day_start bigint := (p_day - date '1970-01-01')::bigint * 86400000;
BEGIN
    UPDATE public.audit_cursor c SET reads_from = greatest(c.reads_from, day_start + 86400000) WHERE c.only_row;
    WITH gone AS (
        DELETE FROM public.audit_events e WHERE e.at >= day_start AND e.at < day_start + 86400000 AND e.log = 16 RETURNING e.places, e.at, e.number, e.log
    )
    DELETE FROM public.audit_event_places p USING (SELECT unnest(g.places) AS place, g.at, g.number, g.log FROM gone g) g
     WHERE p.place = g.place AND p.at = g.at AND p.number = g.number AND p.log = g.log;
    DELETE FROM public.audit_member_keys k WHERE NOT k.wrote AND k.at < day_start + 86400000;
END
$$;--> statement-breakpoint
-- `coffre audit rebuild` (the vault's `rebuildAudit`): the record of it, a change of the request's own object as a
-- refusal's (0067's `log_refusal`), its MAC the vault's and its actor the Owner who asked, written under the fence
-- shared; then, in the same transaction, the cursor back at the start of every log, its row taken first, and the tables
-- emptied. The projector lists everything again, the frozen log's entries and this record too. Retention's `reads_from`
-- stays. A retry under the same request id answers the number it took and resets nothing again.
CREATE FUNCTION rebuild_audit(p_at bigint, p_request text, p_actor text, p_payload text, p_mac bytea) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    target uuid := public.log_object('request', p_request);
    n bigint;
BEGIN
    -- The one payload a rebuild has, by its text: no SQL parses a payload.
    IF p_payload IS DISTINCT FROM '{"op":"audit.rebuild","ref":{"id":' || to_json(p_request)::text || ',"kind":"request"}}' THEN
        RAISE EXCEPTION 'a rebuild''s record names its op first and its own request' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request;
    IF FOUND THEN
        IF NOT EXISTS (SELECT 1 FROM public.log_changes c WHERE c.request_id = p_request AND c.object = target AND c.payload = p_payload) THEN
            RAISE EXCEPTION 'request % names another change', p_request USING ERRCODE = 'unique_violation';
        END IF;
        RETURN n;
    END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, NULL, p_mac)
        RETURNING number INTO n;
    UPDATE public.audit_cursor SET through = 0, pair = 0, at = 0, old_floor = 0, old_from = 0, old_top = 0,
        old_hash = '\x0000000000000000000000000000000000000000000000000000000000000000', mac = NULL WHERE only_row;
    TRUNCATE public.audit_events, public.audit_event_places, public.audit_member_keys;
    RETURN n;
END
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION project_audit(jsonb, jsonb, jsonb, jsonb), drop_audit_day(date), rebuild_audit(bigint, text, text, text, bytea) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION project_audit(jsonb, jsonb, jsonb, jsonb), drop_audit_day(date), rebuild_audit(bigint, text, text, text, bytea) TO coffre_vault;--> statement-breakpoint
GRANT SELECT ON audit_events, audit_event_places, audit_member_keys, audit_cursor TO coffre_vault, coffre_app, coffre_backup;
