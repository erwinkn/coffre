-- The audit pages list 0.15's reads from a sealed projection of its uses (T166; docs/design/0.15-plan.md, "As built: T166"; formal/Reads.tla). With 0.15's log a read writes no 0.14 `secret.read` entry: its use, the slim row of R53, is the record, which names neither whose read it was nor where, and whose MAC cannot cover the number the sequence gives it. So the vault's projector, apart from the checkpointer, writes a row of `log_reads` for each use a signed pair seals: its account, its key's place, the fork it was read in, through a reference the source and its place, and the version read, every one from the sealed objects at the use's number, under a MAC of the vault's over all of it, the number included. And a row of `log_read_places` for each place the use is at, with the place it is at besides (`partner`; its own for a use at one place), which the pages read by, newest first, a page at a time. `log_reads_cursor` says how far the projector has gone; the pages say so when it is behind. Nothing of this is on a use's path. Additive: the previous release reads nothing here.
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
CREATE TABLE "log_read_places" (
	"environment" uuid NOT NULL,
	"partner" uuid NOT NULL,
	"at" bigint NOT NULL,
	"number" bigint NOT NULL,
	"principal" text NOT NULL,
	"secret" uuid NOT NULL,
	"partners" uuid[] NOT NULL
) PARTITION BY RANGE ("at");
--> statement-breakpoint
CREATE TABLE "log_read_partners" (
	"environment" uuid NOT NULL,
	"partner" uuid NOT NULL,
	CONSTRAINT "log_read_partners_pkey" PRIMARY KEY("environment","partner")
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
-- A member's reads.
CREATE INDEX "log_reads_principal_idx" ON "log_reads" USING btree ("principal","at","number");--> statement-breakpoint
-- A place's reads, by the place each is at besides: a page reads those of the places it shows.
CREATE INDEX "log_read_places_place_idx" ON "log_read_places" USING btree ("environment","partner","at","number");--> statement-breakpoint
-- A member's reads at a place.
CREATE INDEX "log_read_places_member_idx" ON "log_read_places" USING btree ("principal","environment","partner","at","number");--> statement-breakpoint
-- A key's reads at a place: the key held there, or a reference's source.
CREATE INDEX "log_read_places_key_idx" ON "log_read_places" USING btree ("secret","environment","partner","at","number");--> statement-breakpoint
-- A member's reads of a key at a place.
CREATE INDEX "log_read_places_member_key_idx" ON "log_read_places" USING btree ("principal","secret","environment","partner","at","number");--> statement-breakpoint
INSERT INTO "log_reads_cursor" ("only_row", "through", "pair", "at") VALUES (true, 0, 0, 0);--> statement-breakpoint
-- A day of reads and of their places, made as make_day makes one of uses, and beside it.
CREATE FUNCTION make_reads_day(p_day date) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    lo bigint := (p_day - date '1970-01-01')::bigint * 86400000;
    parent text;
    name text;
BEGIN
    FOREACH parent IN ARRAY ARRAY['log_reads', 'log_read_places'] LOOP
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
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '100ms' AS $$
DECLARE
    parent text;
    name text;
BEGIN
    IF to_regclass('public.' || quote_ident('log_uses_' || to_char(p_day, 'YYYYMMDD'))) IS NOT NULL THEN
        RAISE EXCEPTION 'the uses of % are kept', p_day USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOREACH parent IN ARRAY ARRAY['log_reads', 'log_read_places'] LOOP
        name := parent || '_' || to_char(p_day, 'YYYYMMDD');
        IF to_regclass('public.' || quote_ident(name)) IS NOT NULL THEN
            IF NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = to_regclass('public.' || quote_ident(name)) AND i.inhparent = to_regclass('public.' || parent)) THEN
                RAISE EXCEPTION '% is not a day of %', name, parent;
            END IF;
            EXECUTE format('DROP TABLE public.%I', name);
        END IF;
    END LOOP;
    RETURN 'dropped';
END
$$;--> statement-breakpoint
-- The projector's write: reads and their places, each read once (by its time and number), the projector's row put back over any other at its number (a row planted ahead would otherwise make it skip one: formal/Reads.tla, ReplaceOnConflict; two projectors write the same bytes), and the cursor moved on to `p_through`, never back, with the signed pair at or below it whose floor the next read takes (`p_pair`) and its MAC (CursorMac), in one call, after the rows (IdempotentByNumber, CursorAfterRows). None past the newest signed pair's number (ProjectSealedOnly): the projector holds the pair's signatures itself before it asks.
CREATE FUNCTION project_reads(p_reads jsonb, p_places jsonb, p_through bigint, p_pair bigint, p_at bigint, p_mac bytea) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    sealed bigint := (SELECT max(k.upto) FROM public.log_checkpoints k);
BEGIN
    IF sealed IS NULL OR p_through > sealed THEN
        RAISE EXCEPTION 'reads through % are past the newest pair, %', p_through, sealed USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_reads) r WHERE (r ->> 'number')::bigint > p_through) THEN
        RAISE EXCEPTION 'a read past % is no read it projects', p_through USING ERRCODE = 'invalid_parameter_value';
    END IF;
    WITH r AS (
        INSERT INTO public.log_reads (number, at, credential, purpose, principal, secret, environment, project, place, source, source_environment, source_project, version, mac)
        SELECT (x ->> 'number')::bigint, (x ->> 'at')::bigint, (x ->> 'credential')::uuid, (x ->> 'purpose')::smallint, x ->> 'principal', (x ->> 'secret')::uuid,
               (x ->> 'environment')::uuid, (x ->> 'project')::uuid, (x ->> 'place')::uuid, (x ->> 'source')::uuid, (x ->> 'sourceEnvironment')::uuid,
               (x ->> 'sourceProject')::uuid, (x ->> 'version')::uuid, decode(x ->> 'mac', 'hex')
          FROM jsonb_array_elements(p_reads) x
        ON CONFLICT (at, number) DO UPDATE SET credential = excluded.credential, purpose = excluded.purpose, principal = excluded.principal, secret = excluded.secret,
            environment = excluded.environment, project = excluded.project, place = excluded.place, source = excluded.source, source_environment = excluded.source_environment,
            source_project = excluded.source_project, version = excluded.version, mac = excluded.mac
        RETURNING at, number
    ), cleared AS (
        DELETE FROM public.log_read_places p USING r WHERE p.at = r.at AND p.number = r.number RETURNING 1
    ), placed AS (
        INSERT INTO public.log_read_places (environment, partner, at, number, principal, secret, partners)
        SELECT (x ->> 'environment')::uuid, (x ->> 'partner')::uuid, (x ->> 'at')::bigint, (x ->> 'number')::bigint, x ->> 'principal', (x ->> 'secret')::uuid,
               ARRAY(SELECT jsonb_array_elements_text(x -> 'partners'))::uuid[]
          FROM jsonb_array_elements(p_places) x WHERE (SELECT count(*) FROM cleared) >= 0
        RETURNING environment, partner
    )
    INSERT INTO public.log_read_partners (environment, partner) SELECT DISTINCT environment, partner FROM placed ON CONFLICT DO NOTHING;
    UPDATE public.log_reads_cursor SET through = p_through, pair = p_pair, at = p_at, mac = p_mac WHERE only_row AND through < p_through;
    RETURN (SELECT c.through FROM public.log_reads_cursor c WHERE c.only_row);
END
$$;--> statement-breakpoint
-- A page's reads of one place (by the place each is at besides), one member's, one member's at a place, one key's at a place: each its index read newest first, below a point, at most `p_take`. Functions, so that each reads its index in order and stops: weighing the empty days made ahead, the planner would otherwise read a busy place's day whole and sort it (measured, T166). Of a use at three places, the one row kept is the one whose places besides are none of `p_except`.
CREATE FUNCTION log_reads_in(p_environment uuid, p_partner uuid, p_at bigint, p_number bigint, p_take integer, p_except uuid[])
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    SELECT p.at, p.number FROM public.log_read_places p
     WHERE p.environment = p_environment AND p.partner = p_partner AND (p.at, p.number) < (p_at, p_number)
       AND (cardinality(p.partners) <= 1 OR NOT (p.partners && p_except))
     ORDER BY p.at DESC, p.number DESC LIMIT p_take
$$;--> statement-breakpoint
CREATE FUNCTION log_reads_by_in(p_principal text, p_environment uuid, p_partner uuid, p_at bigint, p_number bigint, p_take integer, p_except uuid[])
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    SELECT p.at, p.number FROM public.log_read_places p
     WHERE p.principal = p_principal AND p.environment = p_environment AND p.partner = p_partner AND (p.at, p.number) < (p_at, p_number)
       AND (cardinality(p.partners) <= 1 OR NOT (p.partners && p_except))
     ORDER BY p.at DESC, p.number DESC LIMIT p_take
$$;--> statement-breakpoint
CREATE FUNCTION log_reads_of(p_secret uuid, p_environment uuid, p_partner uuid, p_at bigint, p_number bigint, p_take integer, p_except uuid[])
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    SELECT p.at, p.number FROM public.log_read_places p
     WHERE p.secret = p_secret AND p.environment = p_environment AND p.partner = p_partner AND (p.at, p.number) < (p_at, p_number)
       AND (cardinality(p.partners) <= 1 OR NOT (p.partners && p_except))
     ORDER BY p.at DESC, p.number DESC LIMIT p_take
$$;--> statement-breakpoint
CREATE FUNCTION log_reads_by_of(p_principal text, p_secret uuid, p_environment uuid, p_partner uuid, p_at bigint, p_number bigint, p_take integer, p_except uuid[])
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    SELECT p.at, p.number FROM public.log_read_places p
     WHERE p.principal = p_principal AND p.secret = p_secret AND p.environment = p_environment AND p.partner = p_partner AND (p.at, p.number) < (p_at, p_number)
       AND (cardinality(p.partners) <= 1 OR NOT (p.partners && p_except))
     ORDER BY p.at DESC, p.number DESC LIMIT p_take
$$;--> statement-breakpoint
CREATE FUNCTION log_reads_by(p_principal text, p_at bigint, p_number bigint, p_take integer)
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    SELECT r.at, r.number FROM public.log_reads r
     WHERE r.principal = p_principal AND (r.at, r.number) < (p_at, p_number)
     ORDER BY r.at DESC, r.number DESC LIMIT p_take
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION make_reads_day(date), drop_reads_day(date), project_reads(jsonb, jsonb, bigint, bigint, bigint, bytea),
    log_reads_in(uuid, uuid, bigint, bigint, integer, uuid[]), log_reads_by_in(text, uuid, uuid, bigint, bigint, integer, uuid[]),
    log_reads_of(uuid, uuid, uuid, bigint, bigint, integer, uuid[]), log_reads_by_of(text, uuid, uuid, uuid, bigint, bigint, integer, uuid[]),
    log_reads_by(text, bigint, bigint, integer) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION make_reads_day(date), drop_reads_day(date), project_reads(jsonb, jsonb, bigint, bigint, bigint, bytea) TO coffre_vault;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION log_reads_in(uuid, uuid, bigint, bigint, integer, uuid[]), log_reads_by_in(text, uuid, uuid, bigint, bigint, integer, uuid[]),
    log_reads_of(uuid, uuid, uuid, bigint, bigint, integer, uuid[]), log_reads_by_of(text, uuid, uuid, uuid, bigint, bigint, integer, uuid[]),
    log_reads_by(text, bigint, bigint, integer) TO coffre_app;--> statement-breakpoint
GRANT SELECT ON log_reads, log_read_places, log_read_partners, log_reads_cursor TO coffre_vault, coffre_app, coffre_backup;--> statement-breakpoint
-- The pairs' places and times, for the pages to say how far behind the projection is: public, as the notes are.
GRANT SELECT ON log_checkpoints TO coffre_app;--> statement-breakpoint
-- Today's, yesterday's and the next three days, as 0035 made the uses' (the projector makes more as it goes).
SELECT make_reads_day((now() AT TIME ZONE 'UTC')::date + d) FROM generate_series(-1, 3) AS d;
