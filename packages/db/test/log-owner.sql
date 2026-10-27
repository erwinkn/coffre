\set ON_ERROR_STOP on

-- 0.15's log, as the owner, after log-guarantees.sql: what only someone who
-- writes the tables behind the vault can try. The cap is the policy's newest
-- change's, never its row's (CapSealed): a row put back moves nothing, and a
-- policy that names no cap logs no use.
DO $$
DECLARE
    r use_view;
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
    RAISE NOTICE 'PASS: the cap is the policy''s newest change''s, and a policy without one logs nothing';
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
