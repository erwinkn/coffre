-- 0.16.0, W331 (D177; reviews r1 and r2 of #520): spent tokens forgotten as fast as sign-ins spend them. Until 0076 a binding made at most 60 credentials a minute, and the scheduled run forgot 5,000 spent tokens a beat, 60,000 an hour; at the 1,000 sign-ins a second coffre now takes (R44), 3.6 million are spent an hour, kept two hours. So the run forgets twice a beat's worth in one call (`SPENT_TOKENS_PER_BEAT` in server app.ts), and this deletes them by `ctid`, not through the primary key: 50,000 random lookups of a 7.5-million-record index were 1.85 s, measured on the compose Postgres. The records to forget are found by one scan of the table, no index: on 7.5 million (two hours at 1,000 a second), the scan and the delete of 300,000 to 360,000 took 0.9 s. An index on `consumed_at` would make the read cheaper (0.56 s for 600,000) at the cost of a write on every sign-in, and building it would block sign-ins' inserts for as long as it took on the table 0.15 left (2 s on 7.5 million, past their 1 s `lock_timeout`): the migrator runs every migration in one transaction, where CONCURRENTLY cannot.
-- Additive (AGENTS.md, "expand, then contract"): the signature and the answer are 0.15.0's, which calls it the same.
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.prune_consumed_tokens(at_most integer) RETURNS integer
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    -- Each record's `ctid` read and the row deleted in one statement, under one snapshot: nothing moves a row between.
    WITH pruned AS (
        DELETE FROM public.consumed_tokens
         WHERE ctid = ANY(ARRAY(SELECT c.ctid FROM public.consumed_tokens c WHERE c.consumed_at < now() - interval '2 hours' LIMIT at_most))
        RETURNING 1
    )
    SELECT count(*)::integer FROM pruned;
$$;
