-- The hot calls of simple-use-verdict.md, as plain SQL for the prototype: not wired into the app.
--
-- A hot call is one the isolate makes once it has decided (credential, place, key) on the rows of a cold call, at
-- the log's newest change `as_of`. It reads no input row. It takes the fence shared before its snapshot, holds the
-- request to the fence's floor, its retired keys, the clock and the deadline, and checks that the log's newest
-- change is still `as_of`; when it moved, that no object of the decision (`objects`) changed after `as_of`. Then it
-- writes the entry (`use_hot`) or checks the entry a cover rides (`use_ride`), and answers the key's version row.
-- `state` null: made. 'stale': ask the cold call; it is also the CASE's default, so a check that does not hold, or a
-- log that went backwards (a restore, a failover: the row `as_of` is gone or has another MAC), never serves.
-- The newest change is answered only with a call that served: a refusal answered before the probe moves no `as_of`.
-- `use_move` (the key's cap period moved) also takes the principal's cap lock shared and moves its `bulk_cap` row;
-- a key that left the set answers 'enter' (the cold path, under the lock exclusive).

CREATE OR REPLACE FUNCTION public.use_hot(p_entry public.log_uses, p_version uuid, p_as_of bigint, p_as_of_mac bytea, p_objects uuid[], p_deadline bigint)
 RETURNS TABLE (state text, number bigint, newest bigint, newest_mac bytea, version public.secret_versions)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
AS $function$
BEGIN
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    RETURN QUERY
    WITH g AS MATERIALIZED (
        SELECT CASE WHEN substring((p_entry).mac FROM 1 FOR 4) = ANY (f.retired) THEN 'superseded'
                    WHEN (p_entry).at < f.at_floor OR p_deadline > (p_entry).at + public.deadline_max() OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                    WHEN (p_entry).at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                    WHEN sv.id IS NULL THEN 'stale'
                    WHEN n.number = p_as_of AND n.mac = p_as_of_mac THEN NULL
                    WHEN EXISTS (SELECT 1 FROM public.log_changes x WHERE x.number = p_as_of AND x.mac = p_as_of_mac)
                         AND cardinality(p_objects) > 0 AND array_position(p_objects, NULL) IS NULL
                         AND NOT EXISTS (SELECT 1 FROM public.log_changes x WHERE x.object = ANY (p_objects) AND x.number > p_as_of) THEN NULL
                    ELSE 'stale' END AS state,
               n.number, n.mac, sv
          FROM public.checkpoint_fence f
          LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
          LEFT JOIN public.secret_versions sv ON sv.id = p_version AND sv.secret_id = (p_entry).secret
         WHERE f.only_row
    ),
    w AS (
        INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place, route, phased)
        SELECT nextval('public.log_number'), (p_entry).at, (p_entry).request_id, (p_entry).credential, (p_entry).secret,
               (p_entry).purpose, (p_entry).mac, (p_entry).place, (p_entry).route, true
          FROM g WHERE g.state IS NULL
        RETURNING log_uses.number
    )
    SELECT g.state, (SELECT w.number FROM w), CASE WHEN g.state IS NULL THEN g.number END, CASE WHEN g.state IS NULL THEN g.mac END,
           CASE WHEN g.state IS NULL THEN g.sv END FROM g;
    IF NOT FOUND THEN RAISE EXCEPTION 'no fence row' USING ERRCODE = 'P0002'; END IF;
    -- A call held past its deadline (by the fence, behind a change) writes nothing.
    IF (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN
        RAISE EXCEPTION 'past its deadline' USING ERRCODE = '57014';
    END IF;
END
$function$;

-- A repeat that rides the entry `p_cover` (the isolate's own, which it wrote): the same checks, no write.
CREATE OR REPLACE FUNCTION public.use_ride(p_cover public.log_uses, p_at bigint, p_version uuid, p_as_of bigint, p_as_of_mac bytea, p_objects uuid[], p_deadline bigint)
 RETURNS TABLE (state text, newest bigint, newest_mac bytea, version public.secret_versions)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
AS $function$
BEGIN
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    RETURN QUERY
    WITH g AS MATERIALIZED (
        SELECT CASE WHEN p_at < f.at_floor OR p_deadline > p_at + public.deadline_max() OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                    WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                    WHEN NOT EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = (p_cover).at AND u.request_id = (p_cover).request_id
                                        AND u.number = (p_cover).number AND u.credential = (p_cover).credential AND u.secret = (p_cover).secret
                                        AND u.purpose = (p_cover).purpose AND u.place IS NOT DISTINCT FROM (p_cover).place
                                        AND u.route IS NOT DISTINCT FROM (p_cover).route) THEN 'uncovered'
                    WHEN sv.id IS NULL THEN 'stale'
                    WHEN n.number = p_as_of AND n.mac = p_as_of_mac THEN NULL
                    WHEN EXISTS (SELECT 1 FROM public.log_changes x WHERE x.number = p_as_of AND x.mac = p_as_of_mac)
                         AND cardinality(p_objects) > 0 AND array_position(p_objects, NULL) IS NULL
                         AND NOT EXISTS (SELECT 1 FROM public.log_changes x WHERE x.object = ANY (p_objects) AND x.number > p_as_of) THEN NULL
                    ELSE 'stale' END AS state,
               n.number, n.mac, sv
          FROM public.checkpoint_fence f
          LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
          LEFT JOIN public.secret_versions sv ON sv.id = p_version AND sv.secret_id = (p_cover).secret
         WHERE f.only_row
    )
    SELECT g.state, CASE WHEN g.state IS NULL THEN g.number END, CASE WHEN g.state IS NULL THEN g.mac END,
           CASE WHEN g.state IS NULL THEN g.sv END FROM g;
    IF NOT FOUND THEN RAISE EXCEPTION 'no fence row' USING ERRCODE = 'P0002'; END IF;
END
$function$;

-- The key's cap period moved (at most once a refresh per key and isolate): the same checks as `use_hot`, under the
-- principal's cap lock shared (CapLockShared, beside every other move of the principal's keys, never an entry), then
-- the key's `bulk_cap` row moved to `p_period`, only ever up, before the entry goes in: an entry served is a period
-- recorded, as the replay moves it (`log-replay.ts`). A row out of the set (`last` at or before `at - p_window`, the
-- cap's window and one refresh) answers 'enter' (the cold path, under the lock exclusive).
-- R42's election, as 0085's: the one call that takes the (key, period, round) lock without waiting moves the row; the
-- others wait for that one's end alone and read the row again; if it rolled back they elect another on the next round.
-- (Review r2 finding 1: a SKIP LOCKED move answered as moved even when the mover then rolled back.)
CREATE OR REPLACE FUNCTION public.use_move(p_entry public.log_uses, p_version uuid, p_as_of bigint, p_as_of_mac bytea, p_objects uuid[], p_deadline bigint, p_principal text, p_period bigint, p_window bigint)
 RETURNS TABLE (state text, number bigint, newest bigint, newest_mac bytea, version public.secret_versions)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
 SET bytea_output TO 'hex'
AS $function$
DECLARE
    r record;
    v_lock bigint;
    v_round int := 0;
BEGIN
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    PERFORM pg_advisory_xact_lock_shared(1668244066, hashtext(p_principal));
    SELECT CASE WHEN substring((p_entry).mac FROM 1 FOR 4) = ANY (f.retired) THEN 'superseded'
                WHEN (p_entry).at < f.at_floor OR p_deadline > (p_entry).at + public.deadline_max() OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                WHEN (p_entry).at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                WHEN b.last IS NULL OR b.last <= (p_entry).at - p_window THEN 'enter'
                WHEN sv.id IS NULL THEN 'stale'
                WHEN n.number = p_as_of AND n.mac = p_as_of_mac THEN NULL
                WHEN EXISTS (SELECT 1 FROM public.log_changes x WHERE x.number = p_as_of AND x.mac = p_as_of_mac)
                     AND cardinality(p_objects) > 0 AND array_position(p_objects, NULL) IS NULL
                     AND NOT EXISTS (SELECT 1 FROM public.log_changes x WHERE x.object = ANY (p_objects) AND x.number > p_as_of) THEN NULL
                ELSE 'stale' END AS state,
           n.number, n.mac, sv, b.last
      INTO r
      FROM public.checkpoint_fence f
      LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
      LEFT JOIN public.secret_versions sv ON sv.id = p_version AND sv.secret_id = (p_entry).secret
      LEFT JOIN public.bulk_cap b ON b.principal = p_principal AND b.secret = (p_entry).secret
     WHERE f.only_row;
    IF NOT FOUND THEN RAISE EXCEPTION 'no fence row' USING ERRCODE = 'P0002'; END IF;
    IF r.state IS NULL AND r.last < p_period THEN
        LOOP
            v_lock := hashtextextended(p_principal || '/' || (p_entry).secret::text || '/' || p_period::text || '/' || v_round::text, 1668244066);
            IF pg_try_advisory_xact_lock(v_lock) THEN
                UPDATE public.bulk_cap SET last = p_period WHERE principal = p_principal AND secret = (p_entry).secret AND last < p_period;
                EXIT;
            END IF;
            PERFORM pg_advisory_xact_lock_shared(v_lock);
            EXIT WHEN NOT EXISTS (SELECT 1 FROM public.bulk_cap WHERE principal = p_principal AND secret = (p_entry).secret AND last < p_period);
            v_round := v_round + 1;
        END LOOP;
    END IF;
    RETURN QUERY
    WITH w AS (
        INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place, route, phased)
        SELECT nextval('public.log_number'), (p_entry).at, (p_entry).request_id, (p_entry).credential, (p_entry).secret,
               (p_entry).purpose, (p_entry).mac, (p_entry).place, (p_entry).route, true
         WHERE r.state IS NULL
        RETURNING log_uses.number
    )
    SELECT r.state, (SELECT w.number FROM w), CASE WHEN r.state IS NULL THEN r.number END,
           CASE WHEN r.state IS NULL THEN r.mac END, CASE WHEN r.state IS NULL THEN r.sv END;
    IF (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN
        RAISE EXCEPTION 'past its deadline' USING ERRCODE = '57014';
    END IF;
END
$function$;

DROP FUNCTION IF EXISTS public.use_hot_sqlfn(public.log_uses, uuid, bigint, bytea, uuid[], bigint);

REVOKE ALL ON FUNCTION public.use_hot(public.log_uses, uuid, bigint, bytea, uuid[], bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.use_ride(public.log_uses, bigint, uuid, bigint, bytea, uuid[], bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.use_move(public.log_uses, uuid, bigint, bytea, uuid[], bigint, text, bigint, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.use_hot(public.log_uses, uuid, bigint, bytea, uuid[], bigint) TO coffre_vault;
GRANT EXECUTE ON FUNCTION public.use_ride(public.log_uses, bigint, uuid, bigint, bytea, uuid[], bigint) TO coffre_vault;
GRANT EXECUTE ON FUNCTION public.use_move(public.log_uses, uuid, bigint, bytea, uuid[], bigint, text, bigint, bigint) TO coffre_vault;
