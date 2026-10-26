-- Releases pruned (W199, T111): the vault's checkpoint forgets the releases no window can count again, those over a day and an hour old by the database's clock, at most at_most a call. A bulk limit's window is a day at most (the vault's config), and the hour is a margin for the clock stepping back: no caller chooses what is kept, so the vault's login, which still deletes no row itself, cannot forget a release a window counts. The release before never calls it.
CREATE FUNCTION prune_vault_releases(at_most integer) RETURNS integer
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '3s' AS $$
    -- The bound in the DELETE's own WHERE too: a row a read moved on since the subquery's snapshot is checked again,
    -- as it is now, and kept.
    WITH bound AS (SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint - 25 * 3600000 AS before),
    pruned AS (
        DELETE FROM public.vault_releases
         WHERE released_at < (SELECT before FROM bound)
           AND ctid IN (
            -- Any of them, each past every window; a row an append holds is left to the next run, rather than waited for.
            SELECT ctid FROM public.vault_releases WHERE released_at < (SELECT before FROM bound) LIMIT at_most FOR UPDATE SKIP LOCKED
           )
        RETURNING 1
    )
    SELECT count(*)::integer FROM pruned;
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION prune_vault_releases(integer) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION prune_vault_releases(integer) TO coffre_vault;
