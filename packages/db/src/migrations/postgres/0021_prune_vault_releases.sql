-- Releases pruned (W199, T111): the vault's checkpoint forgets the releases no window can count again, those over keep_ms before the database's clock, at most at_most a call. The vault's login still deletes no row itself: it asks this function, which deletes only those. The release before never calls it.
CREATE FUNCTION prune_vault_releases(keep_ms bigint, at_most integer) RETURNS integer
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    -- The bound in the DELETE's own WHERE too: a row a read moved on since the subquery's snapshot is checked again,
    -- as it is now, and kept.
    WITH bound AS (SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint - keep_ms AS before),
    pruned AS (
        DELETE FROM public.vault_releases
         WHERE released_at < (SELECT before FROM bound)
           AND ctid IN (SELECT ctid FROM public.vault_releases WHERE released_at < (SELECT before FROM bound) LIMIT at_most)
        RETURNING 1
    )
    SELECT count(*)::integer FROM pruned;
$$;--> statement-breakpoint
REVOKE ALL ON FUNCTION prune_vault_releases(bigint, integer) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION prune_vault_releases(bigint, integer) TO coffre_vault;
