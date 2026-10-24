-- Spent tokens (W157): a token's record goes once no exchange could take the token again. An exchange refuses one issued over an hour ago (MAX_TOKEN_AGE_SECONDS, 30 s of clock tolerance), so two hours after it was spent its record guards nothing. The runtime login still deletes no row itself: it asks this function, which deletes only such records, at most at_most a call. The release before never calls it.
CREATE FUNCTION prune_consumed_tokens(at_most integer) RETURNS integer
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH pruned AS (
        DELETE FROM public.consumed_tokens
         WHERE hash IN (SELECT hash FROM public.consumed_tokens WHERE consumed_at < now() - interval '2 hours' LIMIT at_most)
        RETURNING 1
    )
    SELECT count(*)::integer FROM pruned;
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION prune_consumed_tokens(integer) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION prune_consumed_tokens(integer) TO coffre_app;
