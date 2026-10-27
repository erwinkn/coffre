-- 0.15's retention (docs/design/0.15-plan.md, PR 7; the spec: formal/Seal.tla's retention, SealRetention.cfg): the checkpointer drops a day of uses once a sealed retention change cuts the uses tree above it, and the uses tree's tiles below the cut, keeping the tile that holds it at each level. Changes are kept for good. It only adds functions, and nothing calls them until 0.15's log is switched on (plan PR 10): 0.14's code serves on it as before.
--
-- Each function checks, from the database alone, what it can of the vault's reasons, so that the vault's login, which owns nothing, drops only what a retention change it can see has cut. The signer's checks (the change sealed in its pair, the pair fresh past the cut) are the vault's: the database cannot verify a signature.
--
-- The retention change (Seal.tla's RetAppend): an entry of the changes tree, its object log_object('log', 'retention'), naming the cut, the pair at or above the day's last use, by its upto, time and uses tree: {"op":"retention","day":"YYYY-MM-DD","cut":{"upto":"<n>","at":<ms>,"uses":<size>,"root":"<hex>"}}. Numbered under the fence shared, as a use is: it changes no decision input, so no use waits on it. A request ID names one: the same one again answers the number it has.
CREATE FUNCTION log_retention(p_request text, p_at bigint, p_payload text, p_mac bytea) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    op jsonb := p_payload::jsonb;
    n bigint;
BEGIN
    IF op ->> 'op' IS DISTINCT FROM 'retention' OR (op ->> 'day') IS NULL OR (op #>> '{cut,upto}') IS NULL OR (op #>> '{cut,uses}') IS NULL THEN
        RAISE EXCEPTION 'not a retention change: %', p_payload USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- Its cut is a checkpoint, of that many uses, at or past the end of its day by its floor of at: every use of the day took its number at or below it.
    IF NOT EXISTS (
        SELECT 1 FROM public.log_checkpoints k
         WHERE k.upto = (op #>> '{cut,upto}')::bigint AND k.uses_size = (op #>> '{cut,uses}')::bigint
           AND k.at_floor >= ((op ->> 'day')::date + 1 - date '1970-01-01')::bigint * 86400000
    ) THEN
        RAISE EXCEPTION 'the cut of % is no checkpoint past its end', op ->> 'day' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request;
    IF n IS NOT NULL THEN RETURN n; END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
    VALUES (nextval('public.log_number'), p_at, p_request, public.log_object('log', 'retention'), 'system:retention', p_payload, NULL, p_mac)
    RETURNING number INTO n;
    RETURN n;
END
$$;
--> statement-breakpoint
-- The newest cut the database holds as sealed: the newest retention change at or below the newest checkpoint, its uses tree's size and upto. The signer holds it to its own pair before it asks for anything below.
CREATE FUNCTION log_cut() RETURNS TABLE (upto bigint, uses bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (c.payload::jsonb #>> '{cut,upto}')::bigint, (c.payload::jsonb #>> '{cut,uses}')::bigint
      FROM public.log_changes c
     WHERE c.object = public.log_object('log', 'retention') AND c.number <= (SELECT max(k.upto) FROM public.log_checkpoints k)
     ORDER BY c.number DESC LIMIT 1
$$;
--> statement-breakpoint
-- A day of uses dropped, a step a call, each its own short transaction: 'detached', then 'dropped', then 'gone'. Only a day before yesterday, and only below the newest cut: the first checkpoint whose floor of at is past the day's end, which every use of the day took its number at or below (the floor holds a use's at to it), must be at or below log_cut()'s.
--
-- DETACH takes log_uses ACCESS EXCLUSIVE for its own few milliseconds: uses queue behind it meanwhile, and lock_timeout bounds how long it waits for a reader before it gives up and tries again later. (DETACH … CONCURRENTLY cannot run in a function, and the vault's login owns no table; measured, it buys nothing here: docs/design/0.15-plan.md, "As built: PR 7".) The DROP of the detached table locks nothing a use reads; the vault asks for it a run later, never right after the DETACH, whose invalidation every backend's plan of log_uses is still replanning from.
CREATE FUNCTION drop_day(p_day date) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '100ms' AS $$
DECLARE
    name text := 'log_uses_' || to_char(p_day, 'YYYYMMDD');
    hi bigint := (p_day + 1 - date '1970-01-01')::bigint * 86400000;
    relation regclass := to_regclass('public.' || quote_ident(name));
    attached boolean;
BEGIN
    IF p_day >= (clock_timestamp() AT TIME ZONE 'UTC')::date - 1 THEN RAISE EXCEPTION 'the uses of % are not past', p_day USING ERRCODE = 'invalid_parameter_value'; END IF;
    IF relation IS NULL THEN RETURN 'gone'; END IF;
    IF NOT coalesce((SELECT k.upto FROM public.log_checkpoints k WHERE k.at_floor >= hi ORDER BY k.at_floor, k.upto LIMIT 1) <= (SELECT c.upto FROM public.log_cut() c), false) THEN
        RAISE EXCEPTION 'no sealed retention change cuts the uses of %', p_day USING ERRCODE = 'invalid_parameter_value';
    END IF;
    attached := EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = relation AND i.inhparent = 'public.log_uses'::regclass);
    IF attached THEN
        -- The day as make_day made it, by its bound: a table of that name holding anything else is not dropped.
        IF pg_get_expr((SELECT c.relpartbound FROM pg_class c WHERE c.oid = relation), relation) IS DISTINCT FROM format('FOR VALUES FROM (%L) TO (%L)', hi - 86400000, hi) THEN
            RAISE EXCEPTION '% is not the uses of %', name, p_day;
        END IF;
        EXECUTE format('ALTER TABLE public.log_uses DETACH PARTITION public.%I', name);
        RETURN 'detached';
    END IF;
    -- Detached: only one this function detached is dropped, a table with log_uses's columns and no parent (make_day's, by name).
    IF EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = relation) OR (SELECT c.relkind FROM pg_class c WHERE c.oid = relation) <> 'r' THEN
        RAISE EXCEPTION '% is not a detached day of uses', name;
    END IF;
    EXECUTE format('DROP TABLE public.%I', name);
    RETURN 'dropped';
END
$$;
--> statement-breakpoint
-- The uses tree's tiles below a cut (W212): every tile whose leaves all lie below p_below, the cut's uses size, at most log_cut()'s, at every level; the tile that holds the cut, at each level, stays, and so does every proof of a leaf at or above it and every consistency proof from a size at or above it. The leaf tiles go a range at a time (make_tiles's partitions, those wholly below), detached then dropped, a step a call as drop_day's, the tiles above in one DELETE. Only the checkpointer and proofs read tiles. Answers what it did: 'detached <range>', 'dropped <range>', or 'done <rows deleted>'.
CREATE FUNCTION drop_tiles(p_below bigint) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '1s' AS $$
DECLARE
    part record;
    deleted integer;
BEGIN
    IF p_below IS NULL OR p_below < 0 OR p_below > coalesce((SELECT c.uses FROM public.log_cut() c), 0) THEN
        RAISE EXCEPTION 'no sealed retention change cuts the uses tree at %', p_below USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A detached range first (a call that stopped between the two), then the next attached one wholly below.
    FOR part IN
        SELECT c.relname, (regexp_match(pg_get_expr(c.relpartbound, c.oid), '^FOR VALUES FROM \(''?(\d+)''?\) TO \(''?(\d+)''?\)$'))[2]::bigint AS hi, i.inhparent IS NOT NULL AS attached
          FROM pg_class c LEFT JOIN pg_inherits i ON i.inhrelid = c.oid
         WHERE c.relnamespace = 'public'::regnamespace AND c.relname ~ '^log_tiles_uses_\d+$' AND c.relkind = 'r'
         ORDER BY i.inhparent IS NOT NULL, c.relname
    LOOP
        IF NOT part.attached THEN
            -- Detached by this function: no other way leaves one of make_tiles's names without its parent.
            EXECUTE format('DROP TABLE public.%I', part.relname);
            RETURN 'dropped ' || part.relname;
        END IF;
        IF part.hi IS NOT NULL AND part.hi <= p_below THEN
            EXECUTE format('ALTER TABLE public.log_tiles_uses_leaves DETACH PARTITION public.%I', part.relname);
            RETURN 'detached ' || part.relname;
        END IF;
    END LOOP;
    DELETE FROM public.log_tiles_uses_upper t WHERE t.leaf + (256::numeric ^ (t.level + 1)) <= p_below;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN 'done ' || deleted;
END
$$;
--> statement-breakpoint
-- A day's cut, the first checkpoint whose floor is past its end, by an index: floors only rise with upto (the barrier raises the floor, never lowers it, and the signer refuses a pair whose floor runs back), so the lowest floor past the end, then the lowest upto, is that checkpoint, however many there are.
CREATE INDEX log_checkpoints_floor_idx ON log_checkpoints USING btree (at_floor, upto);
--> statement-breakpoint
REVOKE ALL ON FUNCTION log_retention(text, bigint, text, bytea), log_cut(), drop_day(date), drop_tiles(bigint) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION log_retention(text, bigint, text, bytea), log_cut(), drop_day(date), drop_tiles(bigint) TO coffre_vault;
