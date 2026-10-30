-- B2 (T167): a request's several keys in one statement, where each had a call of its own (docs/design/0.15-plan.md,
-- "As built: T167"; formal/Batching.tla). Each key's use is `use_credential`'s, by ids, as 0046 has it, made in the
-- request's order in this one transaction: the same reads, the same entry, the same row, so that every guarantee of a
-- use holds for each key, and the batch adds only what Batching.tla holds of several uses together.
--
-- - One fence span: the fence (shared) is taken by the first key's use and kept to the commit, so no change is numbered
--   among the batch's entries, and every key is decided on the same changes.
-- - One principal's lock, its strongest first (`p_lock`, StrongestFirst): a batch whose keys take the principal's lock
--   (the vault's second call, its keys decided) takes it exclusive, after the fence, before its first key. Each key's
--   use then takes it again as it needs, which its own transaction already holds. Shared for one key then exclusive for
--   the next, two batches of one principal's would each wait for the other (Postgres ends one after deadlock_timeout).
-- - Each key counts the cap's set as its own statements read it, the batch's earlier keys included (CountsOwnBatch):
--   inside the transaction, each sees what the ones before it wrote.
-- - Nothing else: a key that would take the lock in a first call (`p_decided` false) answers `decide` and writes and
--   locks nothing, as alone; whether there is a second call is the vault's, once it has every key's rows
--   (AllDecidedFirst).
--
-- Its answer is a JSON array of `use_credential`'s answers, in the request's order. Any key's raise (past the deadline
-- by Postgres's clock, a lock not had within the hot login's lock_timeout, a replayed request id) rolls the whole batch
-- back: nothing of it is written.
CREATE FUNCTION use_batch(
    p_credential uuid, p_secrets uuid[], p_requests bigint[], p_at bigint, p_purpose smallint, p_places uuid[], p_macs bytea[], p_deadline bigint,
    p_covers bigint[], p_cover_ats bigint[], p_cover_requests bigint[], p_knowns bigint[], p_known_macs bytea[], p_cap_counts integer[], p_cap_windows bigint[],
    p_decided boolean[], p_way smallint, p_principal text, p_lock text
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET bytea_output = 'hex' SET jit = off AS $$
DECLARE
    n integer := coalesce(cardinality(p_secrets), 0);
    answers json[] := '{}';
BEGIN
    IF n = 0
       OR cardinality(p_requests) IS DISTINCT FROM n OR cardinality(p_places) IS DISTINCT FROM n OR cardinality(p_macs) IS DISTINCT FROM n
       OR cardinality(p_covers) IS DISTINCT FROM n OR cardinality(p_cover_ats) IS DISTINCT FROM n OR cardinality(p_cover_requests) IS DISTINCT FROM n
       OR cardinality(p_knowns) IS DISTINCT FROM n OR cardinality(p_known_macs) IS DISTINCT FROM n
       OR cardinality(p_cap_counts) IS DISTINCT FROM n OR cardinality(p_cap_windows) IS DISTINCT FROM n OR cardinality(p_decided) IS DISTINCT FROM n THEN
        RAISE EXCEPTION 'a batch names a key at least, and each of its lists one entry a key' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_lock IS NOT NULL THEN
        -- The fence first, as every use takes it, then the principal's lock, exclusive, before any key (StrongestFirst).
        PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
        PERFORM pg_advisory_xact_lock(1668244066, hashtext(p_lock));
    END IF;
    FOR k IN 1 .. n LOOP
        answers := answers || public.use_credential(
            p_credential, p_secrets[k], p_requests[k], p_at, p_purpose, p_places[k], p_macs[k], p_deadline,
            p_covers[k], p_cover_ats[k], p_cover_requests[k], p_knowns[k], p_known_macs[k], p_cap_counts[k], p_cap_windows[k],
            NULL, NULL, NULL, NULL,
            coalesce(p_decided[k], false),
            false, NULL, NULL, NULL, NULL,
            p_way, p_principal
        );
    END LOOP;
    RETURN array_to_json(answers);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION use_batch(uuid, uuid[], bigint[], bigint, smallint, uuid[], bytea[], bigint, bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], boolean[], smallint, text, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION use_batch(uuid, uuid[], bigint[], bigint, smallint, uuid[], bytea[], bigint, bigint[], bigint[], bigint[], bigint[], bytea[], integer[], bigint[], boolean[], smallint, text, text) TO coffre_vault;
