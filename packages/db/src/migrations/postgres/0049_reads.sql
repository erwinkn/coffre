-- The audit pages list 0.15's reads from a sealed projection of its uses (T166; docs/design/0.15-plan.md, "As built: T166"; formal/Reads.tla). With 0.15's log a read writes no 0.14 `secret.read` entry: its use, the slim row of R53, is the record, which names neither whose read it was nor where, and whose MAC cannot cover the number the sequence gives it. So the vault's projector, apart from the checkpointer, writes a row of `log_reads` for each use a signed pair seals: its account, its key's place, the fork it was read in, through a reference the source and its place, and the version read, every one from the sealed objects at the use's number, under a MAC of the vault's over all of it, the number included. The audit pages list them on the whole log, and by member (`log_reads_principal_idx`); a key's or an environment's page lists none in 0.15 (D160). `log_reads_cursor` says how far the projector has gone; the pages say so when it is behind. Nothing of this is on a use's path. Additive: the previous release reads nothing here.
--> statement-breakpoint
CREATE TABLE "log_reads" (
	"number" bigint NOT NULL,
	"at" bigint NOT NULL,
	"credential" uuid NOT NULL,
	"purpose" smallint NOT NULL,
	"principal" text NOT NULL,
	"secret" uuid NOT NULL,
	"environment" uuid NOT NULL,
	"project" uuid NOT NULL,
	"place" uuid,
	"source" uuid,
	"source_environment" uuid,
	"source_project" uuid,
	"version" uuid,
	"mac" "bytea" NOT NULL,
	CONSTRAINT "log_reads_mac_check" CHECK (octet_length("log_reads"."mac") = 16)
) PARTITION BY RANGE ("at");
--> statement-breakpoint
CREATE TABLE "log_read_days" (
	"principal" text NOT NULL,
	"day" integer NOT NULL,
	CONSTRAINT "log_read_days_pkey" PRIMARY KEY("principal","day")
);
--> statement-breakpoint
CREATE TABLE "log_reads_cursor" (
	"only_row" boolean PRIMARY KEY DEFAULT true NOT NULL,
	"through" bigint NOT NULL,
	"pair" bigint NOT NULL,
	"at" bigint NOT NULL,
	"mac" "bytea",
	CONSTRAINT "log_reads_cursor_only_row_check" CHECK ("log_reads_cursor"."only_row"),
	CONSTRAINT "log_reads_cursor_mac_check" CHECK ("log_reads_cursor"."mac" IS NULL OR octet_length("log_reads_cursor"."mac") = 16)
);
--> statement-breakpoint
-- A use's projection once, by its time and number (a unique index of a partitioned table holds its partition key).
CREATE UNIQUE INDEX "log_reads_number_idx" ON "log_reads" USING btree ("at","number");--> statement-breakpoint
-- A member's reads, within a day: `log_read_days` says which days hold any, so that a page of theirs reads those days
-- alone, never a probe of each day since (an index of a partitioned table is each day's; review r6: a member's page
-- read 26 buffers, then 125 with 100 newer days of others' reads).
CREATE INDEX "log_reads_principal_idx" ON "log_reads" USING btree ("principal","at","number");--> statement-breakpoint
INSERT INTO "log_reads_cursor" ("only_row", "through", "pair", "at") VALUES (true, 0, 0, 0);--> statement-breakpoint
-- A day of reads, made as make_day makes one of uses, and beside it.
CREATE FUNCTION make_reads_day(p_day date) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    lo bigint := (p_day - date '1970-01-01')::bigint * 86400000;
    parent text;
    name text;
BEGIN
    FOREACH parent IN ARRAY ARRAY['log_reads'] LOOP
        name := parent || '_' || to_char(p_day, 'YYYYMMDD');
        IF to_regclass('public.' || quote_ident(name)) IS NOT NULL THEN
            IF NOT EXISTS (
                SELECT 1 FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
                 WHERE i.inhparent = to_regclass('public.' || parent) AND c.oid = to_regclass('public.' || quote_ident(name))
                   AND pg_get_expr(c.relpartbound, c.oid) = format('FOR VALUES FROM (%L) TO (%L)', lo, lo + 86400000)
            ) THEN
                RAISE EXCEPTION '% exists, and is not the % of %', name, parent, p_day;
            END IF;
            CONTINUE;
        END IF;
        BEGIN
            EXECUTE format('CREATE TABLE public.%I PARTITION OF public.%I FOR VALUES FROM (%s) TO (%s)', name, parent, lo, lo + 86400000);
            -- pg_dump reads each partition as a table of its own.
            EXECUTE format('GRANT SELECT ON public.%I TO coffre_backup', name);
        EXCEPTION WHEN duplicate_table THEN
            -- Another call made it meanwhile, and committed.
            NULL;
        END;
    END LOOP;
    RETURN to_char(p_day, 'YYYYMMDD');
END
$$;--> statement-breakpoint
-- A day of reads dropped, once its uses are gone (retention dropped their day): what is projected of them goes with them.
CREATE FUNCTION drop_reads_day(p_day date) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off SET lock_timeout = '100ms' AS $$
DECLARE
    parent text;
    name text;
BEGIN
    IF to_regclass('public.' || quote_ident('log_uses_' || to_char(p_day, 'YYYYMMDD'))) IS NOT NULL THEN
        RAISE EXCEPTION 'the uses of % are kept', p_day USING ERRCODE = 'invalid_parameter_value';
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
    RETURN 'dropped';
END
$$;--> statement-breakpoint
-- The projector's write: reads, each once (by its time and number), the projector's row put back over any other at its number (a row planted ahead would otherwise make it skip one: formal/Reads.tla, ReplaceOnConflict; two projectors write the same bytes), each member's days of them (`log_read_days`), and the cursor moved on to `p_through`, never back, with the signed pair at or below it whose floor the next read takes (`p_pair`) and its MAC (CursorMac), in one call, after the rows (IdempotentByNumber, CursorAfterRows). One projector's call at a time, the lock taken before any statement reads. None past the newest signed pair's number (ProjectSealedOnly): the projector holds the pair's signatures itself before it asks.
CREATE FUNCTION project_reads(p_reads jsonb, p_through bigint, p_pair bigint, p_at bigint, p_mac bytea) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    sealed bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(1668244070, 166);
    sealed := (SELECT max(k.upto) FROM public.log_checkpoints k);
    IF sealed IS NULL OR p_through > sealed THEN
        RAISE EXCEPTION 'reads through % are past the newest pair, %', p_through, sealed USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The cursor is the migration's one row: gone, nothing is projected, and the pages say so (review r6).
    IF NOT EXISTS (SELECT 1 FROM public.log_reads_cursor c WHERE c.only_row) THEN
        RAISE EXCEPTION 'the reads cursor is gone' USING ERRCODE = 'data_corrupted';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_reads) r WHERE (r ->> 'number')::bigint > p_through) THEN
        RAISE EXCEPTION 'a read past % is no read it projects', p_through USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO public.log_reads (number, at, credential, purpose, principal, secret, environment, project, place, source, source_environment, source_project, version, mac)
    SELECT (x ->> 'number')::bigint, (x ->> 'at')::bigint, (x ->> 'credential')::uuid, (x ->> 'purpose')::smallint, x ->> 'principal', (x ->> 'secret')::uuid,
           (x ->> 'environment')::uuid, (x ->> 'project')::uuid, (x ->> 'place')::uuid, (x ->> 'source')::uuid, (x ->> 'sourceEnvironment')::uuid,
           (x ->> 'sourceProject')::uuid, (x ->> 'version')::uuid, decode(x ->> 'mac', 'hex')
      FROM jsonb_array_elements(p_reads) x
    ON CONFLICT (at, number) DO UPDATE SET credential = excluded.credential, purpose = excluded.purpose, principal = excluded.principal, secret = excluded.secret,
        environment = excluded.environment, project = excluded.project, place = excluded.place, source = excluded.source, source_environment = excluded.source_environment,
        source_project = excluded.source_project, version = excluded.version, mac = excluded.mac;
    INSERT INTO public.log_read_days (principal, day)
    SELECT DISTINCT x ->> 'principal', ((x ->> 'at')::bigint / 86400000)::integer FROM jsonb_array_elements(p_reads) x
    ON CONFLICT DO NOTHING;
    UPDATE public.log_reads_cursor SET through = p_through, pair = p_pair, at = p_at, mac = p_mac WHERE only_row AND through < p_through;
    RETURN (SELECT c.through FROM public.log_reads_cursor c WHERE c.only_row);
END
$$;--> statement-breakpoint
-- A member's reads, newest first, below a point, at most `p_take`: their days that hold any, newest first, each day's index read in order until the page is full. However many days the log holds, a page reads its member's days and no other (review r6); weighing the empty days made ahead, the planner would otherwise read a busy member's day whole and sort it (measured, T166).
CREATE FUNCTION log_reads_by(p_principal text, p_at bigint, p_number bigint, p_take integer)
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp SET jit = off SET enable_sort = off SET enable_bitmapscan = off AS $$
DECLARE
    d integer;
    left_over integer := p_take;
    found_now integer;
BEGIN
    FOR d IN SELECT k.day FROM public.log_read_days k WHERE k.principal = p_principal AND k.day <= LEAST(p_at / 86400000, 2147483647) ORDER BY k.day DESC LOOP
        RETURN QUERY SELECT r.at, r.number FROM public.log_reads r
         WHERE r.principal = p_principal AND r.at >= d::bigint * 86400000 AND r.at < (d::bigint + 1) * 86400000 AND (r.at, r.number) < (p_at, p_number)
         ORDER BY r.at DESC, r.number DESC LIMIT left_over;
        GET DIAGNOSTICS found_now = ROW_COUNT;
        left_over := left_over - found_now;
        EXIT WHEN left_over <= 0;
    END LOOP;
END
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION make_reads_day(date), drop_reads_day(date), project_reads(jsonb, bigint, bigint, bigint, bytea),
    log_reads_by(text, bigint, bigint, integer) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION make_reads_day(date), drop_reads_day(date), project_reads(jsonb, bigint, bigint, bigint, bytea) TO coffre_vault;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION log_reads_by(text, bigint, bigint, integer) TO coffre_app;--> statement-breakpoint
GRANT SELECT ON log_reads, log_read_days, log_reads_cursor TO coffre_vault, coffre_app, coffre_backup;--> statement-breakpoint
-- The pairs' places and times, for the pages to say how far behind the projection is: public, as the notes are.
GRANT SELECT ON log_checkpoints TO coffre_app;--> statement-breakpoint
-- Today's, yesterday's and the next three days, as 0035 made the uses' (the projector makes more as it goes).
SELECT make_reads_day((now() AT TIME ZONE 'UTC')::date + d) FROM generate_series(-1, 3) AS d;
