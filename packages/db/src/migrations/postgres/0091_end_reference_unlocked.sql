-- 0.16.0: `end_reference` as 0069 made it, less its `FOR SHARE` of the holder's row. The lock held off a change of the
-- holder between the check and the end, and none can be under way: the vault ends a reference inside a decision that
-- holds the change lock, and every statement that writes a `secrets` row runs in a transaction that took that lock
-- first and holds it to its commit. So the lock waited for nobody, and the check reads the same row without it.
CREATE OR REPLACE FUNCTION end_reference(p_reference uuid, p_at bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    done integer;
BEGIN
    IF p_at IS NULL OR p_at < 0 THEN
        RAISE EXCEPTION 'a reference ends at a time, ms since the epoch' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.secret_references y JOIN public.secrets x ON x.id = y.secret_id
         WHERE y.id = p_reference AND y.ended_at IS NULL AND x.archived_at IS NULL AND x.current_version_id IS NULL
           AND y.id = (SELECT CASE WHEN z.secret_id = x.id THEN z.id END FROM public.secret_references z
                        WHERE z.secret_id <= x.id ORDER BY z.secret_id DESC, z.created_seq DESC LIMIT 1)
           AND (x.seal IS NOT NULL OR EXISTS (SELECT 1 FROM public.log_changes c WHERE c.object = public.log_object('secret', x.id::text)))
    ) THEN
        RAISE EXCEPTION 'reference % is its holder''s standing one: its end is a change of the holder', p_reference USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- No row (a write that stored none, abandoned) or one ended already: nothing to do.
    UPDATE public.secret_references SET ended_at = to_timestamp(p_at / 1000.0) WHERE id = p_reference AND ended_at IS NULL;
    GET DIAGNOSTICS done = ROW_COUNT;
    RETURN done > 0;
END
$$;
