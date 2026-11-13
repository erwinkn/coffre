\set ON_ERROR_STOP on

-- 0.15's log, as the owner, after log-guarantees.sql: what only someone who
-- writes the tables behind the vault can try, each named for the protection of
-- the spec (formal/HotPathOne.tla, formal/Seal.tla) it holds. Each use's call is the one the vault makes once it has
-- decided the use (`p_decided`), which takes its principal's lock (0045).
DO $$
DECLARE
    r use_row;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    UPDATE log_config SET value = '{"bulk":{"count":99,"windowMs":86400000}}' WHERE name = 'policy';
    UPDATE policy SET bulk_count = 99, bulk_window_ms = 86400000;
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444442', 30, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 2000, p_decided => true));
    IF r.state IS NOT NULL OR r.cap_count <> 1 OR r.in_set OR EXISTS (SELECT 1 FROM bulk_cap WHERE secret = '44444444-4444-4444-4444-444444444442') THEN
        RAISE EXCEPTION 'FAIL: the policy''s row moved the cap: %', r;
    END IF;
    INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    VALUES (nextval('log_next'), t, 'policy-without-cap', log_object('policy', 'instance'), 'system:x', '{"op":"x","value":{}}', NULL, decode(repeat('00', 16), 'hex'));
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 31, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 2000, p_decided => true));
    IF r.state IS DISTINCT FROM 'unconfigured' OR EXISTS (SELECT 1 FROM log_uses WHERE request_id = 31) THEN
        RAISE EXCEPTION 'FAIL: a policy that names no cap logged a use: %', r.state;
    END IF;
    DELETE FROM log_changes WHERE request_id = 'policy-without-cap';
    RAISE NOTICE 'PASS: CapSealed, the cap is the policy''s newest change''s, and a policy without one logs nothing';
END
$$;

-- A day or a range of tiles is known by its bound, not its name.
DO $$
DECLARE
    today date := (now() AT TIME ZONE 'UTC')::date;
BEGIN
    PERFORM make_day(today);
    BEGIN
        PERFORM make_tiles(0, 33554432);
        RAISE EXCEPTION 'FAIL: make_tiles took a range for one it had made';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
    END;
    CREATE TABLE log_uses_19700102 (n integer);
    BEGIN
        PERFORM make_day(date '1970-01-02');
        RAISE EXCEPTION 'FAIL: make_day took a stranger''s table for a day';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
    END;
    DROP TABLE log_uses_19700102;
    RAISE NOTICE 'PASS: make_day and make_tiles check what they find by its bound';
END
$$;

-- ChangeChecksSeal: a row put back from before a change, validly sealed once,
-- is refused stale by the next change, which seals nothing and logs nothing.
DO $$
DECLARE
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    before bytea := (SELECT seal FROM principals WHERE principal = 'token:deploy');
    object record;
BEGIN
    IF change_input('principal', 'token:deploy', 'reseal-a', t, 'system:test', '{"op":"genesis"}', NULL, before, decode(repeat('6e', 16), 'hex'), decode(repeat('ee', 16), 'hex')) IS NULL THEN
        RAISE EXCEPTION 'FAIL: a change from the row''s own seal did nothing';
    END IF;
    UPDATE principals SET seal = before WHERE principal = 'token:deploy';
    BEGIN
        PERFORM change_input('principal', 'token:deploy', 'reseal-b', t, 'system:test', '{"op":"genesis"}', NULL, before, decode(repeat('7e', 16), 'hex'), decode(repeat('ee', 16), 'hex'));
        RAISE EXCEPTION 'FAIL: a change sealed a row put back from before the newest change';
    EXCEPTION WHEN data_corrupted THEN NULL;
    END;
    IF EXISTS (SELECT 1 FROM log_changes WHERE request_id = 'reseal-b') OR (SELECT seal FROM principals WHERE principal = 'token:deploy') <> before THEN
        RAISE EXCEPTION 'FAIL: a refused change left a trace';
    END IF;
    UPDATE principals SET seal = decode(repeat('6e', 16), 'hex') WHERE principal = 'token:deploy';
    -- And each other kind's row, a binding's (the credential that is no token) and the roles' among them.
    FOR object IN SELECT * FROM (VALUES
        ('credential', '66666666-6666-6666-6666-666666666666', 'service_bindings', 'id'),
        ('secret', '44444444-4444-4444-4444-444444444441', 'secrets', 'id'),
        ('environment', '22222222-2222-2222-2222-222222222222', 'environments', 'id'),
        ('roles', 'instance', 'log_config', 'name'),
        ('policy', 'instance', 'policy', 'name')
    ) AS o (kind, id, tbl, keycol) LOOP
        EXECUTE format('UPDATE %I SET seal = decode(repeat(''9e'', 16), ''hex'') WHERE %I::text = %L', object.tbl, object.keycol, CASE object.kind WHEN 'roles' THEN 'roles' ELSE object.id END);
        BEGIN
            PERFORM change_input(object.kind, object.id, 'stale-' || object.kind, t, 'system:test', '{"op":"genesis"}', NULL, decode(repeat('9e', 16), 'hex'), decode(repeat('7e', 16), 'hex'), decode(repeat('ee', 16), 'hex'));
            RAISE EXCEPTION 'FAIL: a % change sealed a row that is not its newest change''s', object.kind;
        EXCEPTION WHEN data_corrupted THEN NULL;
        END;
        EXECUTE format('UPDATE %I SET seal = decode(repeat(''5e'', 16), ''hex'') WHERE %I::text = %L', object.tbl, object.keycol, CASE object.kind WHEN 'roles' THEN 'roles' ELSE object.id END);
    END LOOP;
    RAISE NOTICE 'PASS: ChangeChecksSeal, a change refuses a row that is not its newest change''s, of every kind';
END
$$;

-- The barrier answers the floor it found, so that the checkpointer sees one lowered behind its back.
DO $$
DECLARE
    barrier record;
    lowered bigint;
BEGIN
    UPDATE checkpoint_fence SET at_floor = at_floor - 600000 RETURNING at_floor INTO lowered;
    SELECT * INTO barrier FROM close_one();
    IF barrier.floor_found <> lowered OR barrier.at_floor <= lowered THEN
        RAISE EXCEPTION 'FAIL: the barrier hid a lowered floor: found %, lowered %', barrier.floor_found, lowered;
    END IF;
    RAISE NOTICE 'PASS: BarrierChecksFloor, the barrier answers the floor it found';
END
$$;

-- The uses tree's tiles: a leaf tile goes to its range, one above to the
-- upper table, which needs no range made (W217).
DO $$
BEGIN
    INSERT INTO log_tiles (tree, level, leaf, hashes) VALUES ('uses', 0, 256, decode(repeat('aa', 32), 'hex')), ('uses', 2, 0, decode(repeat('bb', 32), 'hex'));
    IF (SELECT tableoid::regclass::text FROM log_tiles WHERE tree = 'uses' AND level = 0 AND leaf = 256) <> 'log_tiles_uses_0'
       OR (SELECT tableoid::regclass::text FROM log_tiles WHERE tree = 'uses' AND level = 2 AND leaf = 0) <> 'log_tiles_uses_upper' THEN
        RAISE EXCEPTION 'FAIL: a tile went to the wrong table';
    END IF;
    DELETE FROM log_tiles WHERE (tree, level, leaf) IN (('uses', 0, 256), ('uses', 2, 0));
    RAISE NOTICE 'PASS: leaf tiles by range, the levels above in one table';
END
$$;

-- 0.15's names for the tables 0.16 renamed (0076_table_renames, T178), kept one release: each a view of its table,
-- written through as the table (automatically updatable), checked as the caller (security_invoker), and granting
-- every role exactly what the table grants it, table and column privileges alike, so that neither is wider.
DO $$
DECLARE
    pair record;
    wider text;
BEGIN
    FOR pair IN SELECT * FROM (VALUES ('principals', 'vault_members'), ('grants', 'vault_grants'), ('device_logins', 'device_authorizations'),
        ('enrollment_codes', 'enrollments'), ('spent_id_tokens', 'consumed_tokens'), ('bulk_cap', 'log_bulk'), ('checkpoint_fence', 'log_fence')) AS v (tbl, old) LOOP
        IF NOT EXISTS (SELECT 1 FROM information_schema.views WHERE table_schema = 'public' AND table_name = pair.old
                         AND is_updatable = 'YES' AND is_insertable_into = 'YES' AND is_trigger_updatable = 'NO')
           OR NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = format('public.%I', pair.old)::regclass AND 'security_invoker=true' = ANY(reloptions))
           OR (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid = format('public.%I', pair.old)::regclass AND attnum > 0)
              IS DISTINCT FROM (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid = format('public.%I', pair.tbl)::regclass AND attnum > 0 AND NOT attisdropped) THEN
            RAISE EXCEPTION 'FAIL: % is not a plain view of every column of %, checked as its caller', pair.old, pair.tbl;
        END IF;
        SELECT string_agg(format('%s %s%s', r.rolname, p.privilege, coalesce(' (' || a.attname || ')', '')), ', ') INTO wider
          FROM pg_roles r
         CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p (privilege)
          LEFT JOIN pg_attribute a ON a.attrelid = format('public.%I', pair.tbl)::regclass AND a.attnum > 0 AND NOT a.attisdropped
                                  AND p.privilege IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
         WHERE r.rolname <> current_user AND NOT r.rolsuper
           AND CASE WHEN a.attname IS NULL
                    THEN has_table_privilege(r.oid, format('public.%I', pair.tbl), p.privilege) <> has_table_privilege(r.oid, format('public.%I', pair.old), p.privilege)
                    ELSE has_column_privilege(r.oid, format('public.%I', pair.tbl), a.attname, p.privilege) <> has_column_privilege(r.oid, format('public.%I', pair.old), a.attname, p.privilege) END;
        IF wider IS NOT NULL THEN
            RAISE EXCEPTION 'FAIL: % and its table % grant differently: %', pair.old, pair.tbl, wider;
        END IF;
    END LOOP;
    RAISE NOTICE 'PASS: 0.15''s seven names are plain views of their renamed tables, each granting what its table grants';
END
$$;
