-- 0.16.0, T252 (D189): an offboarding report's reads under 0.15's log cost the same however long a member's history grows (R48), so that 0.16's 5 s `statement_timeout` on the app's login holds for it. `readsBy` probed every retained day the member read, and retention keeps every day by default. `log_read_newest` holds each member's newest read of each key and version, the key as the report names it (the source through a reference), and the report reads those alone (formal/Reads.tla, T252). Additive (AGENTS.md, "expand, then contract"): a table, a trigger that writes it, and `drop_reads_day`'s body with its signature and answers as 0050's. The previous release reads none of it, and its projector's writes reach it through the trigger as this release's do.
CREATE TABLE "log_read_newest" (
	"principal" text NOT NULL,
	"secret" uuid NOT NULL,
	"version" uuid NOT NULL,
	"at" bigint NOT NULL,
	CONSTRAINT "log_read_newest_pkey" PRIMARY KEY("principal","secret","version")
);
--> statement-breakpoint
CREATE INDEX "log_read_newest_at_idx" ON "log_read_newest" USING btree ("at");--> statement-breakpoint
-- Each written read's entry, whoever writes the read: the projector's `project_reads` (0.15's too, which runs on until
-- this release is deployed, its body already compiled when a call waits on its lock), and its upsert over a row planted
-- at a number (ReplaceOnConflict), which the update's trigger writes (NewestWithRows). One statement each, the reads
-- grouped by member, key and version, so that each entry is written once and a run of a thousand reads writes the few
-- they are of. Its time only moves up (GreatestAt): a later number's read from a clock behind leaves the newer time.
-- The projector's calls take turns under `project_reads`' lock, so two never write the same entries at once; retention's
-- `drop_reads_day` gives way within its `lock_timeout`.
CREATE FUNCTION log_reads_newest() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO public.log_read_newest (principal, secret, version, at)
    SELECT r.principal, coalesce(r.source, r.secret), r.version, max(r.at) FROM written r
     WHERE r.version IS NOT NULL
     GROUP BY r.principal, coalesce(r.source, r.secret), r.version
    ON CONFLICT (principal, secret, version) DO UPDATE SET at = excluded.at WHERE log_read_newest.at < excluded.at;
    RETURN NULL;
END
$$;--> statement-breakpoint
-- Made before the backfill: it locks `log_reads` until this migration commits, so that a write in flight commits first,
-- and the backfill reads it, and one after waits, and fires the trigger (0050's).
CREATE TRIGGER log_reads_newest_insert AFTER INSERT ON "log_reads" REFERENCING NEW TABLE AS written FOR EACH STATEMENT EXECUTE FUNCTION log_reads_newest();--> statement-breakpoint
CREATE TRIGGER log_reads_newest_update AFTER UPDATE ON "log_reads" REFERENCING NEW TABLE AS written FOR EACH STATEMENT EXECUTE FUNCTION log_reads_newest();--> statement-breakpoint
-- The reads 0.15 listed: one read of them, once, here, as the owner.
INSERT INTO "log_read_newest" (principal, secret, version, at)
SELECT r.principal, coalesce(r.source, r.secret), r.version, max(r.at) FROM "log_reads" r
 WHERE r.version IS NOT NULL
 GROUP BY r.principal, coalesce(r.source, r.secret), r.version
ON CONFLICT (principal, secret, version) DO UPDATE SET at = excluded.at WHERE log_read_newest.at < excluded.at;--> statement-breakpoint
-- A day of reads dropped (0050), with its entries of `log_read_newest` (NewestRetired), and on every call the entries
-- older than the oldest day of reads left: each read lies in a day's partition (no default one), so no entry below the
-- first holds a read the log still lists. That sweep is for what a call of 0.15's body left: one started before this
-- migration and waiting on the lock it holds on `log_reads` drops its day after the commit and leaves its entries, until
-- the next call, 'kept' included, which retention makes each run a day is due. Until then the report names reads the log
-- has retired, a day's at most, read all the same.
-- Under the projector's lock, taken first (PruneLocked): a `project_reads` in flight may make a day below the floor and
-- write a read in it (a use older than the days made ahead), which this call's snapshot does not see; read the floor
-- before it commits, and the sweep drops the entry it wrote (review r2). The lock waits up to 1 s: a projector's call
-- holds it through its chunk of a thousand reads, and chunks run back to back while it catches up, so the partition's
-- 100 ms would give up on each and no day would drop (review r5). That wait blocks no reader, only the next chunk; the
-- partition's drop, which readers queue behind, waits 100 ms again. A retention run that gives up tries again on the
-- next (55P03).
CREATE OR REPLACE FUNCTION drop_reads_day(p_day date) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '100ms' AS $$
DECLARE
    parent text;
    name text;
    kept boolean;
    oldest date;
BEGIN
    PERFORM set_config('lock_timeout', '1s', true);
    PERFORM pg_advisory_xact_lock(1668244070, 166);
    PERFORM set_config('lock_timeout', '100ms', true);
    kept := EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = to_regclass('public.log_uses')
                       AND i.inhrelid = to_regclass('public.' || quote_ident('log_uses_' || to_char(p_day, 'YYYYMMDD'))));
    IF NOT kept THEN
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
        DELETE FROM public.log_read_newest WHERE at >= (p_day - date '1970-01-01')::bigint * 86400000
                                             AND at < (p_day - date '1970-01-01' + 1)::bigint * 86400000;
    END IF;
    SELECT min(to_date(right(c.relname, 8), 'YYYYMMDD')) INTO oldest FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
     WHERE i.inhparent = 'public.log_reads'::regclass AND c.relname ~ '^log_reads_[0-9]{8}$';
    DELETE FROM public.log_read_newest WHERE at < coalesce((oldest - date '1970-01-01')::bigint * 86400000, 9223372036854775807);
    RETURN CASE WHEN kept THEN 'kept' ELSE 'dropped' END;
END
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION log_reads_newest() FROM PUBLIC;--> statement-breakpoint
GRANT SELECT ON log_read_newest TO coffre_vault, coffre_app, coffre_backup;
