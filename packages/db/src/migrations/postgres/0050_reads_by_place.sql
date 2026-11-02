-- A place's audit page lists its reads (T175; docs/design/0.15-plan.md, "As built: T175"). 0.15.0 listed 0.15's reads on the whole log and by member alone (D160): a page of a place read one stream for each set of places its reads were at, and those sets grew with the place's history (#434, review r5: 527 sets, an empty page from 3 to 535 buffers). Here each column of `log_reads` that names a place has its index, newest first: the key's, its environment's and its project's; the fork it was read in; through a reference, the source's three. A key's page reads two of these streams, an environment's three, a project's two, each no further than a page, however many forks, references or sources the place has had. `log_read_place_days` says which days hold a read at each place, as `log_read_days` does for members, so that a page reads those days alone (`log_reads_at`). Who may see each read is decided from the row's own columns, which its MAC covers, by the app. Additive: the previous release reads nothing here, and its projector's writes are placed by the trigger as this release's are.
CREATE TABLE "log_read_place_days" (
	"place" uuid NOT NULL,
	"day" integer NOT NULL,
	CONSTRAINT "log_read_place_days_pkey" PRIMARY KEY("place","day")
);
--> statement-breakpoint
CREATE INDEX "log_read_place_days_day_idx" ON "log_read_place_days" USING btree ("day");--> statement-breakpoint
-- Each read's places' days, whoever writes the read: the projector's `project_reads` (0.15.0's too, which runs on until
-- this release is deployed, its body already compiled when a call waits on its lock), and its upsert over a row
-- planted at a number (ReplaceOnConflict), which the update's trigger places. One statement each, the reads' places
-- distinct by day, so a run of a thousand reads writes the few days they are on.
CREATE FUNCTION log_reads_placed() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
BEGIN
    INSERT INTO public.log_read_place_days (place, day)
    SELECT DISTINCT p.id, (r.at / 86400000)::integer FROM placed r
     CROSS JOIN LATERAL (VALUES (r.secret), (r.environment), (r.project), (r.place), (r.source), (r.source_environment), (r.source_project)) p(id)
     WHERE p.id IS NOT NULL
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END
$$;--> statement-breakpoint
-- Made before the backfill: it locks `log_reads` until this migration commits, so that a write in flight commits first,
-- and the backfill reads it, and one after waits, and fires the trigger.
CREATE TRIGGER log_reads_placed_insert AFTER INSERT ON "log_reads" REFERENCING NEW TABLE AS placed FOR EACH STATEMENT EXECUTE FUNCTION log_reads_placed();--> statement-breakpoint
CREATE TRIGGER log_reads_placed_update AFTER UPDATE ON "log_reads" REFERENCING NEW TABLE AS placed FOR EACH STATEMENT EXECUTE FUNCTION log_reads_placed();--> statement-breakpoint
CREATE INDEX "log_reads_secret_idx" ON "log_reads" USING btree ("secret","at","number");--> statement-breakpoint
CREATE INDEX "log_reads_environment_idx" ON "log_reads" USING btree ("environment","at","number");--> statement-breakpoint
CREATE INDEX "log_reads_project_idx" ON "log_reads" USING btree ("project","at","number");--> statement-breakpoint
CREATE INDEX "log_reads_place_idx" ON "log_reads" USING btree ("place","at","number") WHERE "log_reads"."place" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "log_reads_source_idx" ON "log_reads" USING btree ("source","at","number") WHERE "log_reads"."source" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "log_reads_source_environment_idx" ON "log_reads" USING btree ("source_environment","at","number") WHERE "log_reads"."source_environment" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "log_reads_source_project_idx" ON "log_reads" USING btree ("source_project","at","number") WHERE "log_reads"."source_project" IS NOT NULL;--> statement-breakpoint
-- The reads 0.15.0 listed, placed: nothing is projected again.
INSERT INTO "log_read_place_days" (place, day)
SELECT DISTINCT p.id, (r.at / 86400000)::integer FROM "log_reads" r
 CROSS JOIN LATERAL (VALUES (r.secret), (r.environment), (r.project), (r.place), (r.source), (r.source_environment), (r.source_project)) p(id)
 WHERE p.id IS NOT NULL
ON CONFLICT DO NOTHING;--> statement-breakpoint
-- A day of reads dropped (0049), its places' days with its members'.
CREATE OR REPLACE FUNCTION drop_reads_day(p_day date) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off SET lock_timeout = '100ms' AS $$
DECLARE
    parent text;
    name text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = to_regclass('public.log_uses')
                  AND i.inhrelid = to_regclass('public.' || quote_ident('log_uses_' || to_char(p_day, 'YYYYMMDD')))) THEN
        RETURN 'kept';
    END IF;
    FOREACH parent IN ARRAY ARRAY['log_reads'] LOOP
        name := parent || '_' || to_char(p_day, 'YYYYMMDD');
        IF to_regclass('public.' || quote_ident(name)) IS NOT NULL THEN
            IF NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = to_regclass('public.' || quote_ident(name)) AND i.inhparent = to_regclass('public.' || parent)) THEN
                RAISE EXCEPTION '% is not a day of %', name, parent;
            END IF;
            EXECUTE format('DROP TABLE public.%I', name);
        END IF;
    END LOOP;
    DELETE FROM public.log_read_days WHERE day = p_day - date '1970-01-01';
    DELETE FROM public.log_read_place_days WHERE day = p_day - date '1970-01-01';
    RETURN 'dropped';
END
$$;--> statement-breakpoint
-- A place's reads, newest first, below a point, at most `p_take`: a key's (`secret`: its own, and through references
-- to it), an environment's (its keys', those read in it as a fork, and through references to its keys) or a project's
-- (its keys', and through references to them). Its days that hold any, newest first, each day's streams read in order
-- until the page is full, as `log_reads_by` reads a member's: each stream's index, no further than what is left of the
-- page, however many reads, forks or references the place has had. The streams of another kind are gated off before
-- they read anything (a one-time filter on `p_kind`).
CREATE FUNCTION log_reads_at(p_place uuid, p_kind text, p_at bigint, p_number bigint, p_take integer)
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp SET jit = off SET enable_sort = off SET enable_bitmapscan = off AS $$
DECLARE
    d integer;
    lo bigint;
    left_over integer := p_take;
    found_now integer;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('secret', 'environment', 'project') THEN
        RAISE EXCEPTION 'no place is of the kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR d IN SELECT k.day FROM public.log_read_place_days k WHERE k.place = p_place AND k.day <= LEAST(p_at / 86400000, 2147483647) ORDER BY k.day DESC LOOP
        lo := d::bigint * 86400000;
        RETURN QUERY SELECT u.at, u.number FROM (
            (SELECT r.at, r.number FROM public.log_reads r WHERE p_kind = 'secret' AND r.secret = p_place
                AND r.at >= lo AND r.at < lo + 86400000 AND (r.at, r.number) < (p_at, p_number) ORDER BY r.at DESC, r.number DESC LIMIT left_over)
            UNION
            (SELECT r.at, r.number FROM public.log_reads r WHERE p_kind = 'secret' AND r.source = p_place
                AND r.at >= lo AND r.at < lo + 86400000 AND (r.at, r.number) < (p_at, p_number) ORDER BY r.at DESC, r.number DESC LIMIT left_over)
            UNION
            (SELECT r.at, r.number FROM public.log_reads r WHERE p_kind = 'environment' AND r.environment = p_place
                AND r.at >= lo AND r.at < lo + 86400000 AND (r.at, r.number) < (p_at, p_number) ORDER BY r.at DESC, r.number DESC LIMIT left_over)
            UNION
            (SELECT r.at, r.number FROM public.log_reads r WHERE p_kind = 'environment' AND r.place = p_place
                AND r.at >= lo AND r.at < lo + 86400000 AND (r.at, r.number) < (p_at, p_number) ORDER BY r.at DESC, r.number DESC LIMIT left_over)
            UNION
            (SELECT r.at, r.number FROM public.log_reads r WHERE p_kind = 'environment' AND r.source_environment = p_place
                AND r.at >= lo AND r.at < lo + 86400000 AND (r.at, r.number) < (p_at, p_number) ORDER BY r.at DESC, r.number DESC LIMIT left_over)
            UNION
            (SELECT r.at, r.number FROM public.log_reads r WHERE p_kind = 'project' AND r.project = p_place
                AND r.at >= lo AND r.at < lo + 86400000 AND (r.at, r.number) < (p_at, p_number) ORDER BY r.at DESC, r.number DESC LIMIT left_over)
            UNION
            (SELECT r.at, r.number FROM public.log_reads r WHERE p_kind = 'project' AND r.source_project = p_place
                AND r.at >= lo AND r.at < lo + 86400000 AND (r.at, r.number) < (p_at, p_number) ORDER BY r.at DESC, r.number DESC LIMIT left_over)
        ) u ORDER BY u.at DESC, u.number DESC LIMIT left_over;
        GET DIAGNOSTICS found_now = ROW_COUNT;
        left_over := left_over - found_now;
        EXIT WHEN left_over <= 0;
    END LOOP;
END
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION log_reads_placed(), log_reads_at(uuid, text, bigint, bigint, integer) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION log_reads_at(uuid, text, bigint, bigint, integer) TO coffre_app;--> statement-breakpoint
GRANT SELECT ON log_read_place_days TO coffre_vault, coffre_app, coffre_backup;
