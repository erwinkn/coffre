-- A change whose row moved raises (T179; `later` in @coffre/db, and packages/server/test/change-cost.test.ts). `app_change` and `change_input` answer null for a row whose seal moved since its writer read it (ChangeCAS), and the writer reads it again (ChangeRereads). A change that goes with its transaction's COMMIT, under one Sync, is one nothing awaits: a null would let the COMMIT keep the rows without their change. These two raise there instead, `coffre_moved` (SQLSTATE CF001), which fails the statement, so that Postgres skips the COMMIT, the transaction rolls back, and the writer reads it again, as before. Everything else is the functions' own: the locks, their order, the checks. Additive: only this release's code calls them.
CREATE FUNCTION app_change_strict(
    p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_seal_from bytea, p_seal bytea, p_mac bytea, p_restores bytea
) RETURNS bigint
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    n bigint := public.app_change(p_kind, p_id, p_request, p_at, p_actor, p_payload, p_seal_from, p_seal, p_mac, p_restores);
BEGIN
    IF n IS NULL THEN
        RAISE EXCEPTION 'coffre_moved: the % object % moved since it was read', p_kind, p_id USING ERRCODE = 'CF001';
    END IF;
    RETURN n;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app_change_strict(text, text, text, bigint, text, text, bytea, bytea, bytea, bytea) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app_change_strict(text, text, text, bigint, text, text, bytea, bytea, bytea, bytea) TO coffre_app;
--> statement-breakpoint
CREATE FUNCTION change_input_strict(
    p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_value text, p_seal_from bytea, p_seal bytea, p_mac bytea
) RETURNS bigint
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp SET jit = off AS $$
DECLARE
    n bigint := public.change_input(p_kind, p_id, p_request, p_at, p_actor, p_payload, p_value, p_seal_from, p_seal, p_mac);
BEGIN
    IF n IS NULL THEN
        RAISE EXCEPTION 'coffre_moved: the % object % moved since it was read', p_kind, p_id USING ERRCODE = 'CF001';
    END IF;
    RETURN n;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION change_input_strict(text, text, text, bigint, text, text, text, bytea, bytea, bytea) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION change_input_strict(text, text, text, bigint, text, text, text, bytea, bytea, bytea) TO coffre_vault;
