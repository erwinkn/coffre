-- The audit pages list 0.15's uses (T166): with 0.15's log, a read (a reveal, a run, the proxy's use, a read through a reference) writes no 0.14 `secret.read` entry, and its use is the record (R53), which the app reads as it reads the changes (0042). Three indexes of `log_uses`, each newest first by when the use was asked (`at`, then the number, as the pages order 0.15's log), so that a page reads as many as it shows however many other uses the log holds: by way in (a member's uses, through each of their credentials), by key (a place's, through the keys it holds), and by fork, over the few uses that have a place. Built on the partitioned table, so every day's partition has them, those `make_day` makes later included. A use writes three more index entries, and no statement more. And a member's credentials by their end, which a page of the member's uses walks; and the functions each read through, which hold its plan to its index. Additive: the previous release reads nothing here; until 0.15's log is on, `log_uses` is empty and the build is instant.
--> statement-breakpoint
CREATE INDEX "credentials_expiry_idx" ON "credentials" USING btree ("principal","expires_at","id","created_at");--> statement-breakpoint
CREATE INDEX "log_uses_credential_idx" ON "log_uses" USING btree ("credential","at","number") INCLUDE ("secret","place");--> statement-breakpoint
CREATE INDEX "log_uses_secret_idx" ON "log_uses" USING btree ("secret","at","number");--> statement-breakpoint
CREATE INDEX "log_uses_place_idx" ON "log_uses" USING btree ("place","at","number") WHERE "log_uses"."place" IS NOT NULL;--> statement-breakpoint
GRANT SELECT ON log_uses TO coffre_app;--> statement-breakpoint
-- The newest uses of one way in, one key, or read in one fork, below a point, at most `p_take`, each by its own index, newest first, filtered as asked: what a page of the audit log reads for each (T166). Functions, so that each reads its index in order and stops: weighing the empty days `make_day` makes ahead, the planner would otherwise read a busy credential's day whole and sort it (measured: a credential's every use, against its newest page). `enable_sort` and `enable_bitmapscan` off hold the plan to the index; a use names the times its reference lived, as the database's clock dates them, give or take five minutes (`SLACK_MS`).
CREATE FUNCTION log_uses_by(p_credential uuid, p_from bigint, p_to bigint, p_at bigint, p_number bigint, p_take integer)
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    SELECT u.at, u.number FROM public.log_uses u
     WHERE u.credential = p_credential AND u.at >= p_from AND u.at <= p_to AND (u.at, u.number) < (p_at, p_number)
     ORDER BY u.at DESC, u.number DESC LIMIT p_take
$$;--> statement-breakpoint
-- A way in's uses at some places: its index read newest first, `p_scan` entries at most, each kept or not by what the index includes, its key and fork (and the arrays the caller made of the places: the keys there, the forks there, each reference into them with when it lived, and what is left out). The kept ones, `p_take` at most; and when the scan ran out first, the last entry it read, not kept (`hit` false), below which nothing of this way in's was looked at.
CREATE FUNCTION log_uses_by_at(
    p_credential uuid, p_from bigint, p_to bigint, p_at bigint, p_number bigint, p_take integer, p_scan integer,
    p_keys uuid[], p_forks uuid[], p_held uuid[], p_held_from bigint[], p_held_to bigint[],
    p_left_keys uuid[], p_left uuid[], p_left_held uuid[], p_left_from bigint[], p_left_to bigint[]
) RETURNS TABLE (at bigint, number bigint, hit boolean)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    WITH scanned AS MATERIALIZED (
        SELECT u.at, u.number,
               (u.secret = ANY (p_keys) OR u.place = ANY (p_forks)
                 OR (u.secret = ANY (p_held) AND EXISTS (SELECT 1 FROM unnest(p_held, p_held_from, p_held_to) h(id, f, t) WHERE h.id = u.secret AND u.at BETWEEN h.f AND h.t)))
               AND u.secret <> ALL (p_left_keys) AND (u.place IS NULL OR u.place <> ALL (p_left))
               AND NOT (u.secret = ANY (p_left_held) AND EXISTS (SELECT 1 FROM unnest(p_left_held, p_left_from, p_left_to) h(id, f, t) WHERE h.id = u.secret AND u.at BETWEEN h.f AND h.t)) AS hit
          FROM public.log_uses u
         WHERE u.credential = p_credential AND u.at >= p_from AND u.at <= p_to AND (u.at, u.number) < (p_at, p_number)
         ORDER BY u.at DESC, u.number DESC LIMIT p_scan),
    kept AS (SELECT s.at, s.number FROM scanned s WHERE s.hit ORDER BY s.at DESC, s.number DESC LIMIT p_take)
    SELECT k.at, k.number, true FROM kept k
    UNION ALL
    SELECT l.at, l.number, false FROM (SELECT s.at, s.number FROM scanned s ORDER BY s.at, s.number LIMIT 1) l
     WHERE (SELECT count(*) FROM scanned) = p_scan AND (SELECT count(*) FROM kept) < p_take
$$;--> statement-breakpoint
CREATE FUNCTION log_uses_of(p_secret uuid, p_from bigint, p_to bigint, p_at bigint, p_number bigint, p_take integer,
    p_left uuid[], p_left_held uuid[], p_left_from bigint[], p_left_to bigint[])
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    SELECT u.at, u.number FROM public.log_uses u
     WHERE u.secret = p_secret AND u.at >= p_from AND u.at <= p_to AND (u.at, u.number) < (p_at, p_number)
       AND (u.place IS NULL OR u.place <> ALL (p_left))
       AND NOT (u.secret = ANY (p_left_held) AND EXISTS (SELECT 1 FROM unnest(p_left_held, p_left_from, p_left_to) h(id, f, t) WHERE h.id = u.secret AND u.at BETWEEN h.f AND h.t))
     ORDER BY u.at DESC, u.number DESC LIMIT p_take
$$;--> statement-breakpoint
CREATE FUNCTION log_uses_in(p_place uuid, p_at bigint, p_number bigint, p_take integer,
    p_left_keys uuid[], p_left_held uuid[], p_left_from bigint[], p_left_to bigint[])
    RETURNS TABLE (at bigint, number bigint)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp SET enable_sort = off SET enable_bitmapscan = off AS $$
    SELECT u.at, u.number FROM public.log_uses u
     WHERE u.place = p_place AND (u.at, u.number) < (p_at, p_number) AND u.secret <> ALL (p_left_keys)
       AND NOT (u.secret = ANY (p_left_held) AND EXISTS (SELECT 1 FROM unnest(p_left_held, p_left_from, p_left_to) h(id, f, t) WHERE h.id = u.secret AND u.at BETWEEN h.f AND h.t))
     ORDER BY u.at DESC, u.number DESC LIMIT p_take
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION log_uses_by(uuid, bigint, bigint, bigint, bigint, integer), log_uses_by_at(uuid, bigint, bigint, bigint, bigint, integer, integer, uuid[], uuid[], uuid[], bigint[], bigint[], uuid[], uuid[], uuid[], bigint[], bigint[]), log_uses_of(uuid, bigint, bigint, bigint, bigint, integer, uuid[], uuid[], bigint[], bigint[]), log_uses_in(uuid, bigint, bigint, integer, uuid[], uuid[], bigint[], bigint[]) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION log_uses_by(uuid, bigint, bigint, bigint, bigint, integer), log_uses_by_at(uuid, bigint, bigint, bigint, bigint, integer, integer, uuid[], uuid[], uuid[], bigint[], bigint[], uuid[], uuid[], uuid[], bigint[], bigint[]), log_uses_of(uuid, bigint, bigint, bigint, bigint, integer, uuid[], uuid[], bigint[], bigint[]), log_uses_in(uuid, bigint, bigint, integer, uuid[], uuid[], bigint[], bigint[]) TO coffre_app;
