\set ON_ERROR_STOP on

-- 0.15's log, as the owner, after log-guarantees.sql: what only someone who
-- writes the tables behind the vault can try, each named for the protection of
-- the spec (formal/HotPathOne.tla, formal/Seal.tla) it holds.
DO $$
DECLARE
    r use_row;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    UPDATE log_config SET value = '{"bulk":{"count":99,"windowMs":86400000}}' WHERE name = 'policy';
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444442', 30, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 2000);
    IF r.state IS NOT NULL OR r.cap_count <> 1 OR r.in_set OR EXISTS (SELECT 1 FROM log_bulk WHERE secret = '44444444-4444-4444-4444-444444444442') THEN
        RAISE EXCEPTION 'FAIL: the policy''s row moved the cap: %', r;
    END IF;
    INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    VALUES (nextval('log_number'), t, 'policy-without-cap', log_object('policy', 'instance'), 'system:x', '{"op":"x","value":{}}', NULL, decode(repeat('00', 16), 'hex'));
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 31, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 2000);
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
    before bytea := (SELECT seal FROM vault_members WHERE principal = 'token:deploy');
    object record;
BEGIN
    IF change_input('principal', 'token:deploy', 'reseal-a', t, 'system:test', '{"op":"genesis"}', NULL, before, decode(repeat('6e', 16), 'hex'), decode(repeat('ee', 16), 'hex')) IS NULL THEN
        RAISE EXCEPTION 'FAIL: a change from the row''s own seal did nothing';
    END IF;
    UPDATE vault_members SET seal = before WHERE principal = 'token:deploy';
    BEGIN
        PERFORM change_input('principal', 'token:deploy', 'reseal-b', t, 'system:test', '{"op":"genesis"}', NULL, before, decode(repeat('7e', 16), 'hex'), decode(repeat('ee', 16), 'hex'));
        RAISE EXCEPTION 'FAIL: a change sealed a row put back from before the newest change';
    EXCEPTION WHEN data_corrupted THEN NULL;
    END;
    IF EXISTS (SELECT 1 FROM log_changes WHERE request_id = 'reseal-b') OR (SELECT seal FROM vault_members WHERE principal = 'token:deploy') <> before THEN
        RAISE EXCEPTION 'FAIL: a refused change left a trace';
    END IF;
    UPDATE vault_members SET seal = decode(repeat('6e', 16), 'hex') WHERE principal = 'token:deploy';
    -- And each other kind's row, a binding's (the credential that is no token) and the roles' among them.
    FOR object IN SELECT * FROM (VALUES
        ('credential', '66666666-6666-6666-6666-666666666666', 'service_bindings', 'id'),
        ('secret', '44444444-4444-4444-4444-444444444441', 'secrets', 'id'),
        ('environment', '22222222-2222-2222-2222-222222222222', 'environments', 'id'),
        ('roles', 'instance', 'log_config', 'name')
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
    UPDATE log_fence SET at_floor = at_floor - 600000 RETURNING at_floor INTO lowered;
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
