\set ON_ERROR_STOP on

-- 0.15's log (0022_log_015.sql), as the vault's login: it reads every new
-- table and writes none of them but through the functions, which keep the
-- fence, the seals' CAS, the deadline, covers, the seal cache and the bulk
-- cap. Run as coffre_vault_runtime, after schema-fixture.sql and
-- log-fixture.sql. Nothing calls these yet (plan, PR 2): this holds them to
-- the prototype's behaviour until the 0.15 vault does.

-- Its writes go through the functions only.
DO $$
DECLARE
    attempt text;
BEGIN
    IF current_user <> 'coffre_vault_runtime' THEN
        RAISE EXCEPTION 'run as coffre_vault_runtime, not %', current_user;
    END IF;
    FOREACH attempt IN ARRAY ARRAY[
        $q$INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac) VALUES (1, 1, 1, gen_random_uuid(), gen_random_uuid(), 0, decode(repeat('00', 16), 'hex'))$q$,
        $q$INSERT INTO log_changes (number, at, request_id, object, actor, payload, mac) VALUES (1, 1, 'x', gen_random_uuid(), 'system:x', '{}', decode(repeat('00', 16), 'hex'))$q$,
        $q$INSERT INTO log_bulk VALUES ('token:deploy', gen_random_uuid(), 1)$q$,
        $q$INSERT INTO vault_config VALUES ('policy', '{}', NULL)$q$,
        $q$UPDATE log_fence SET at_floor = 0$q$,
        $q$DELETE FROM log_bulk$q$,
        $q$TRUNCATE log_changes$q$,
        $q$UPDATE credentials SET seal = NULL$q$,
        $q$UPDATE vault_members SET seal = NULL$q$,
        $q$SELECT nextval('log_number')$q$,
        $q$CREATE TABLE log_uses_19700101 PARTITION OF log_uses FOR VALUES FROM (0) TO (86400000)$q$
    ] LOOP
        BEGIN
            EXECUTE attempt;
            RAISE EXCEPTION 'FAIL: coffre_vault ran %', attempt;
        EXCEPTION WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    PERFORM count(*) FROM log_uses;
    PERFORM count(*) FROM log_changes, log_bulk, log_fence, log_checkpoints, log_tiles, vault_config;
    RAISE NOTICE 'PASS: coffre_vault reads the log and writes it only through its functions';
END
$$;

-- The app reads none of it, and nobody but the vault runs the functions.
DO $$
BEGIN
    IF has_table_privilege('coffre_app', 'log_uses', 'SELECT') OR has_table_privilege('coffre_app', 'vault_config', 'SELECT')
       OR has_function_privilege('coffre_app', 'close_one()', 'EXECUTE')
       OR has_function_privilege('coffre_backup', 'change_input(text, text, text, bigint, text, text, bytea, bytea, bytea)', 'EXECUTE') THEN
        RAISE EXCEPTION 'FAIL: the app or the backup reaches the 0.15 log';
    END IF;
    RAISE NOTICE 'PASS: only the vault reaches the 0.15 log';
END
$$;

-- The hot path's login: the vault's group, its own settings, unable to log in until it is given a password.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'coffre_vault_hot'
           AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AND rolinherit
    ) THEN
        RAISE EXCEPTION 'FAIL: coffre_vault_hot is missing or unsafe';
    END IF;
    IF (SELECT array_agg(format('%s admin=%s inherit=%s set=%s', roleid::regrole, admin_option, inherit_option, set_option))
          FROM pg_auth_members WHERE member = 'coffre_vault_hot'::regrole)
       IS DISTINCT FROM ARRAY['coffre_vault admin=f inherit=t set=f'] THEN
        RAISE EXCEPTION 'FAIL: coffre_vault_hot must be a member of coffre_vault alone, inheriting it, never setting it';
    END IF;
    IF NOT (SELECT setconfig @> ARRAY['lock_timeout=1s', 'statement_timeout=2s', 'plan_cache_mode=force_generic_plan']
              FROM pg_db_role_setting WHERE setrole = 'coffre_vault_hot'::regrole AND setdatabase = 0) THEN
        RAISE EXCEPTION 'FAIL: coffre_vault_hot lacks the hot path''s settings';
    END IF;
    IF NOT has_function_privilege('coffre_vault_hot', 'use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea)', 'EXECUTE')
       OR has_database_privilege('coffre_vault_hot', current_database(), 'CREATE') OR has_database_privilege('coffre_vault_hot', current_database(), 'TEMPORARY') THEN
        RAISE EXCEPTION 'FAIL: coffre_vault_hot holds what the vault does not, or not what it does';
    END IF;
    RAISE NOTICE 'PASS: coffre_vault_hot is the vault''s, with lock_timeout 1s, statement_timeout 2s and generic plans';
END
$$;

-- Days of uses, made ahead, once each.
DO $$
DECLARE
    today date := (now() AT TIME ZONE 'UTC')::date;
BEGIN
    PERFORM make_day(today - 1), make_day(today), make_day(today + 1);
    IF make_day(today) <> 'log_uses_' || to_char(today, 'YYYYMMDD') THEN RAISE EXCEPTION 'FAIL: make_day named another day'; END IF;
    IF (SELECT count(*) FROM pg_inherits WHERE inhparent = 'log_uses'::regclass) < 3 THEN RAISE EXCEPTION 'FAIL: make_day attached no day'; END IF;
    IF NOT has_table_privilege('coffre_backup', 'log_uses_' || to_char(today, 'YYYYMMDD'), 'SELECT') THEN
        RAISE EXCEPTION 'FAIL: the backup cannot read a day';
    END IF;
    PERFORM make_tiles(0, 16777216);
    IF NOT has_table_privilege('coffre_backup', 'log_tiles_uses_0', 'SELECT') THEN RAISE EXCEPTION 'FAIL: the backup cannot read a range of tiles'; END IF;
    RAISE NOTICE 'PASS: make_day and make_tiles make each partition once, readable by the backup';
END
$$;

-- Before the policy is logged, a use does nothing.
DO $$
DECLARE
    r use_view;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 1, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 2000);
    IF r.state IS DISTINCT FROM 'unconfigured' OR r.number IS NOT NULL OR EXISTS (SELECT 1 FROM log_uses) THEN
        RAISE EXCEPTION 'FAIL: a use without a policy answered % and wrote %', r.state, r.number;
    END IF;
    RAISE NOTICE 'PASS: a use with no policy logged writes nothing';
END
$$;

-- Genesis: each object sealed as it is, under its CAS, its retry finding its entry.
DO $$
DECLARE
    first bigint;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    tag bytea := decode(repeat('ee', 16), 'hex');
    sealed bytea := decode(repeat('5e', 16), 'hex');
BEGIN
    first := change_input('policy', '', 'genesis-policy', t, 'system:cutover', '{"op":"genesis","value":{"bulk":{"count":1,"windowMs":86400000}}}', NULL, sealed, tag);
    IF first IS NULL OR change_input('policy', '', 'genesis-policy', t, 'system:cutover', '{"op":"genesis","value":{"bulk":{"count":1,"windowMs":86400000}}}', NULL, sealed, tag) <> first THEN
        RAISE EXCEPTION 'FAIL: a retried change did not find its entry';
    END IF;
    BEGIN
        PERFORM change_input('policy', '', 'genesis-policy', t, 'system:cutover', '{"op":"genesis","value":{"bulk":{"count":9,"windowMs":86400000}}}', NULL, sealed, tag);
        RAISE EXCEPTION 'FAIL: a request id named two changes';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
    PERFORM change_input('member', 'token:deploy', 'genesis-member', t, 'system:cutover', '{"op":"genesis"}', NULL, sealed, tag);
    PERFORM change_input('credential', '33333333-3333-3333-3333-333333333333', 'genesis-credential', t, 'system:cutover', '{"op":"genesis"}', NULL, sealed, tag);
    PERFORM change_input('secret', '44444444-4444-4444-4444-444444444441', 'genesis-secret-1', t, 'system:cutover', '{"op":"genesis"}', NULL, sealed, tag);
    PERFORM change_input('secret', '44444444-4444-4444-4444-444444444442', 'genesis-secret-2', t, 'system:cutover', '{"op":"genesis"}', NULL, sealed, tag);
    PERFORM change_input('environment', '22222222-2222-2222-2222-222222222222', 'genesis-environment', t, 'system:cutover', '{"op":"genesis"}', NULL, sealed, tag);
    PERFORM change_input('project', '11111111-1111-1111-1111-111111111111', 'genesis-project', t, 'system:cutover', '{"op":"genesis"}', NULL, sealed, tag);
    IF (SELECT count(*) FROM log_changes) <> 7 OR (SELECT count(DISTINCT object) FROM log_changes) <> 7 THEN
        RAISE EXCEPTION 'FAIL: genesis logged % changes', (SELECT count(*) FROM log_changes);
    END IF;
    -- The row's seal is no longer the one read: nothing is done, and nothing logged.
    IF change_input('member', 'token:deploy', 'genesis-member-again', t, 'system:cutover', '{"op":"genesis"}', NULL, sealed, tag) IS NOT NULL
       OR change_input('member', 'token:nobody', 'genesis-nobody', t, 'system:cutover', '{"op":"genesis"}', NULL, sealed, tag) IS NOT NULL
       OR (SELECT count(*) FROM log_changes) <> 7 THEN
        RAISE EXCEPTION 'FAIL: a change moved a seal it had not read';
    END IF;
    BEGIN
        PERFORM change_input('member', 'token:deploy', 'grant', t, 'system:x', '{"op":"access.grant"}', sealed, sealed, tag);
        RAISE EXCEPTION 'FAIL: change_input applied an op this schema does not know';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    IF (SELECT seal FROM vault_members WHERE principal = 'token:deploy') IS DISTINCT FROM sealed
       OR (SELECT object FROM log_changes WHERE request_id = 'genesis-member') <> log_object('member', 'token:deploy') THEN
        RAISE EXCEPTION 'FAIL: genesis left the row or its object other than it said';
    END IF;
    RAISE NOTICE 'PASS: change_input seals each object once, from the seal it read, and a retry finds its entry';
END
$$;

-- A use: one entry, every input and its newest change's seal, the cap's row; its replay writes nothing more.
DO $$
DECLARE
    r use_view;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    tag bytea := decode(repeat('ab', 16), 'hex');
BEGIN
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 7, t, 258::smallint, '22222222-2222-2222-2222-222222222222', tag, t + 2000);
    IF r.state IS NOT NULL OR r.number IS NULL OR r.principal <> 'token:deploy' OR r.newest <> (SELECT max(number) FROM log_changes)
       OR r.inputs <> r.newest OR r.c_seal IS DISTINCT FROM r.c_last OR r.m_seal IS DISTINCT FROM r.m_last OR r.s_seal IS DISTINCT FROM r.s_last
       OR r.e_seal IS DISTINCT FROM r.e_last OR r.p_seal IS DISTINCT FROM r.p_last OR r.policy_seal IS DISTINCT FROM r.policy_last
       OR r.cap_count <> 1 OR r.cap_window <> 86400000 OR r.s_version <> '55555555-5555-5555-5555-555555555551' OR r.v_wrapped_dek <> decode('d0', 'hex')
       OR json_array_length(r.grants) <> 1 OR r.c_revoked OR r.c_kind <> 'service' OR r.in_set OR r.others <> 0 THEN
        RAISE EXCEPTION 'FAIL: the use read %', r;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM log_uses WHERE number = r.number AND at = t AND request_id = 7 AND purpose = 258 AND place = '22222222-2222-2222-2222-222222222222' AND log_uses.mac = tag
    ) OR (SELECT last FROM log_bulk WHERE principal = 'token:deploy' AND secret = '44444444-4444-4444-4444-444444444441') <> t THEN
        RAISE EXCEPTION 'FAIL: the use''s entry or its key''s bulk row is not as asked';
    END IF;
    BEGIN
        PERFORM use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 7, t, 258::smallint, NULL, tag, t + 2000);
        RAISE EXCEPTION 'FAIL: a replayed use decided again';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
    IF (SELECT count(*) FROM log_uses) <> 1 THEN RAISE EXCEPTION 'FAIL: a replay wrote an entry'; END IF;

    -- A repeat on its cover writes nothing; one whose cover has no entry writes its own.
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 8, t + 1, 258::smallint, NULL, tag, t + 2000,
        (SELECT number FROM log_uses), t, 7);
    IF r.state IS NOT NULL OR r.number IS NOT NULL OR r.covered IS DISTINCT FROM (SELECT number FROM log_uses) THEN
        RAISE EXCEPTION 'FAIL: a covered repeat answered % % %', r.state, r.number, r.covered;
    END IF;
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 9, t + 1, 258::smallint, NULL, tag, t + 2000,
        (SELECT number FROM log_uses), t, 6);
    IF r.covered IS NOT NULL OR r.number IS NULL THEN RAISE EXCEPTION 'FAIL: a cover with no entry covered'; END IF;

    -- The seal cache: the newest change named exactly skips the probes; a wrong MAC probes again.
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 10, t + 2, 258::smallint, NULL, tag, t + 2000,
        NULL, NULL, NULL, r.newest, r.newest_mac);
    IF r.state IS NOT NULL OR r.number IS NULL OR r.c_last IS NOT NULL OR r.inputs IS NOT NULL OR r.c_seal IS NULL THEN
        RAISE EXCEPTION 'FAIL: the cached form read %', r;
    END IF;
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 11, t + 2, 258::smallint, NULL, tag, t + 2000,
        NULL, NULL, NULL, r.newest, decode(repeat('00', 16), 'hex'));
    IF r.state IS NOT NULL OR r.c_last IS NULL OR r.inputs IS NULL THEN
        RAISE EXCEPTION 'FAIL: a stale cache was trusted';
    END IF;

    -- The cap at one key: the other key is asked for, logged, and not let in.
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444442', 12, t + 3, 1::smallint, NULL, tag, t + 2000);
    IF r.state IS NOT NULL OR r.number IS NULL OR r.in_set OR r.others <> 1
       OR EXISTS (SELECT 1 FROM log_bulk WHERE secret = '44444444-4444-4444-4444-444444444442') THEN
        RAISE EXCEPTION 'FAIL: the cap let a second key in: %', r;
    END IF;
    RAISE NOTICE 'PASS: a use logs its request once, reads every input sealed, and keeps covers, the cache and the cap';
END
$$;

-- The deadline, the floor and the barrier.
DO $$
DECLARE
    r use_view;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    barrier record;
BEGIN
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 20, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 3001);
    IF r.state <> 'late' THEN RAISE EXCEPTION 'FAIL: a deadline past deadline_max was taken'; END IF;
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 21, t - 2000, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t - 1);
    IF r.state <> 'late' THEN RAISE EXCEPTION 'FAIL: a use past its deadline was taken'; END IF;
    SELECT * INTO barrier FROM close_one();
    IF barrier.upto <> (SELECT max(n) FROM (SELECT max(number) AS n FROM log_uses UNION ALL SELECT max(number) FROM log_changes) x)
       OR barrier.at_floor < t - 3000 OR barrier.at_floor <> (SELECT at_floor FROM log_fence) THEN
        RAISE EXCEPTION 'FAIL: the barrier closed at % with floor %', barrier.upto, barrier.at_floor;
    END IF;
    r := use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 22, barrier.at_floor - 1, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 1000);
    IF r.state <> 'late' OR EXISTS (SELECT 1 FROM log_uses WHERE request_id IN (20, 21, 22)) THEN
        RAISE EXCEPTION 'FAIL: a use below the floor was written';
    END IF;
    IF prune_bulk(100) <> 0 THEN RAISE EXCEPTION 'FAIL: prune_bulk forgot a key its window counts'; END IF;
    RAISE NOTICE 'PASS: late uses write nothing, the barrier raises the floor, and pruning keeps what a window counts';
END
$$;
