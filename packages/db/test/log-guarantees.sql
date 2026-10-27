\set ON_ERROR_STOP on

-- 0.15's log (0022_log_015.sql), as the vault's login, each check named for the
-- protection of the spec (formal/HotPathOne.tla, formal/Seal.tla) it holds: it reads every new
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
        $q$INSERT INTO log_config VALUES ('policy', '{}', NULL)$q$,
        $q$UPDATE log_fence SET at_floor = 0$q$,
        $q$DELETE FROM log_bulk$q$,
        $q$TRUNCATE log_changes$q$,
        $q$INSERT INTO log_tiles VALUES ('changes', 0, 0, decode(repeat('00', 32), 'hex'))$q$,
        $q$INSERT INTO log_checkpoints VALUES (1, 1, 1, 0, decode(repeat('00', 32), 'hex'), 'n', 0, decode(repeat('00', 32), 'hex'), 'n')$q$,
        $q$UPDATE credentials SET seal = NULL$q$,
        $q$UPDATE vault_members SET seal = NULL$q$,
        $q$UPDATE service_bindings SET seal = NULL$q$,
        $q$UPDATE environments SET seal = NULL$q$,
        $q$UPDATE secrets SET seal = NULL$q$,
        $q$UPDATE log_config SET seal = NULL$q$,
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
    PERFORM count(*) FROM log_changes, log_bulk, log_fence, log_checkpoints, log_tiles, log_config;
    RAISE NOTICE 'PASS: coffre_vault reads the log and writes it only through its functions';
END
$$;

-- The verifier (0028, plan PR 8) reads the columns the credentials', bindings' and references' objects are made of,
-- never a token's hash or MAC.
DO $$
DECLARE
    attempt text;
BEGIN
    PERFORM count(*) FROM (SELECT id, principal, kind, scope, revoked_at, expires_at, not_after, seal FROM credentials) c;
    PERFORM count(*) FROM (SELECT id, seal FROM service_bindings) b;
    PERFORM count(*) FROM (SELECT secret_id, source_secret_id, created_seq FROM secret_references) r;
    FOREACH attempt IN ARRAY ARRAY[
        $q$SELECT token_hash FROM credentials$q$,
        $q$SELECT auth_mac FROM credentials$q$,
        $q$SELECT * FROM service_bindings$q$,
        $q$SELECT * FROM secret_references$q$
    ] LOOP
        BEGIN
            EXECUTE attempt;
            RAISE EXCEPTION 'FAIL: coffre_vault ran %', attempt;
        EXCEPTION WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_vault reads the objects'' columns, no more';
END
$$;

-- The app reads none of it, and nobody but the vault runs the functions.
DO $$
BEGIN
    IF has_table_privilege('coffre_app', 'log_uses', 'SELECT') OR has_table_privilege('coffre_app', 'log_config', 'SELECT')
       OR has_function_privilege('coffre_app', 'close_one()', 'EXECUTE')
       OR has_function_privilege('coffre_backup', 'change_input(text, text, text, bigint, text, text, text, bytea, bytea, bytea)', 'EXECUTE') THEN
        RAISE EXCEPTION 'FAIL: the app or the backup reaches the 0.15 log';
    END IF;
    RAISE NOTICE 'PASS: only the vault reaches the 0.15 log';
END
$$;

-- Retention's functions (0027): the vault's alone, each holding it to what a sealed retention change cuts.
DO $$
DECLARE
    f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['log_retention(text, bigint, text, bytea)', 'log_cut()', 'drop_day(date)', 'drop_tiles(bigint)'] LOOP
        IF NOT has_function_privilege('coffre_vault', f, 'EXECUTE') OR has_function_privilege('coffre_app', f, 'EXECUTE')
           OR has_function_privilege('coffre_backup', f, 'EXECUTE') THEN
            RAISE EXCEPTION 'FAIL: % is not the vault''s alone', f;
        END IF;
    END LOOP;
    RAISE NOTICE 'PASS: retention''s functions are the vault''s alone';
END
$$;

-- But the app's own changes, sealed by the vault, which its transactions commit (0025's app_change): the app runs it,
-- and no other function of the log; the vault and the backup never run it.
DO $$
BEGIN
    IF NOT has_function_privilege('coffre_app', 'app_change(text, text, text, bigint, text, text, bytea, bytea, bytea)', 'EXECUTE')
       OR has_function_privilege('coffre_app', 'change_input(text, text, text, bigint, text, text, text, bytea, bytea, bytea)', 'EXECUTE')
       OR has_function_privilege('coffre_vault', 'app_change(text, text, text, bigint, text, text, bytea, bytea, bytea)', 'EXECUTE')
       OR has_function_privilege('coffre_backup', 'app_change(text, text, text, bigint, text, text, bytea, bytea, bytea)', 'EXECUTE') THEN
        RAISE EXCEPTION 'FAIL: app_change is not the app''s alone';
    END IF;
    RAISE NOTICE 'PASS: the app logs its own changes through app_change, and runs no other function of the log';
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
    IF NOT has_function_privilege('coffre_vault_hot', 'use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint)', 'EXECUTE')
       OR has_database_privilege('coffre_vault_hot', current_database(), 'CREATE') OR has_database_privilege('coffre_vault_hot', current_database(), 'TEMPORARY') THEN
        RAISE EXCEPTION 'FAIL: coffre_vault_hot holds what the vault does not, or not what it does';
    END IF;
    RAISE NOTICE 'PASS: coffre_vault_hot is the vault''s, with lock_timeout 1s, statement_timeout 2s and generic plans';
END
$$;

-- An object's key is W216's objectKey, byte for byte (its vectors, packages/vault/test/object-keys.json on PR 3's branch).
DO $$
BEGIN
    IF (SELECT array_agg(log_object(kind, id) = key::uuid) FROM (VALUES
        ('principal', 'user:ada@acme.example', 'e357e51a-07d4-a671-34f3-d3b47e0522c3'),
        ('principal', 'token:ci', 'aea468b6-61e8-9582-0262-8b22f69e6812'),
        ('principal', 'user:zoë@exämple.fr', '759bfca0-9425-57c2-1902-154fe7c8d0a7'),
        ('credential', '00000000-0000-4000-8002-000000000001', '3462b400-6f10-7337-5d8a-43257d15ffbc'),
        ('secret', '00000000-0000-4000-8001-000000000001', '05aed852-dcc4-ea15-1a9d-e75712c15c40'),
        ('environment', '00000000-0000-4000-8000-0000000000d1', '1e5f5d8d-b9e7-631a-f27f-778d634a545e'),
        ('roles', 'instance', 'f7efff01-4561-2159-b22c-87275ad9837d'),
        ('policy', 'instance', '8b635b60-7b8e-30c1-1e14-118bf7ef71dd')
    ) AS vector (kind, id, key)) <> ARRAY[true, true, true, true, true, true, true, true] THEN
        RAISE EXCEPTION 'FAIL: log_object disagrees with the vault''s objectKey';
    END IF;
    RAISE NOTICE 'PASS: log_object is the vault''s objectKey';
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
    r use_row;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 1, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 2000));
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
    first := change_input('policy', 'instance', 'genesis-policy', t, 'system:cutover', '{"op":"genesis","value":{"bulk":{"count":1,"windowMs":86400000}}}', NULL, NULL, sealed, tag);
    IF first IS NULL OR change_input('policy', 'instance', 'genesis-policy', t, 'system:cutover', '{"op":"genesis","value":{"bulk":{"count":1,"windowMs":86400000}}}', NULL, NULL, sealed, tag) <> first THEN
        RAISE EXCEPTION 'FAIL: a retried change did not find its entry';
    END IF;
    BEGIN
        PERFORM change_input('policy', 'instance', 'genesis-policy', t, 'system:cutover', '{"op":"genesis","value":{"bulk":{"count":9,"windowMs":86400000}}}', NULL, NULL, sealed, tag);
        RAISE EXCEPTION 'FAIL: a request id named two changes';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
    PERFORM change_input('roles', 'instance', 'genesis-roles', t, 'system:cutover', '{"op":"genesis","value":{"kind":"roles","roles":{},"instanceRoles":{}}}', NULL, NULL, sealed, tag);
    PERFORM change_input('principal', 'token:deploy', 'genesis-member', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag);
    PERFORM change_input('credential', '33333333-3333-3333-3333-333333333333', 'genesis-credential', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag);
    PERFORM change_input('credential', '66666666-6666-6666-6666-666666666666', 'genesis-binding', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag);
    PERFORM change_input('secret', '44444444-4444-4444-4444-444444444441', 'genesis-secret-1', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag);
    PERFORM change_input('secret', '44444444-4444-4444-4444-444444444442', 'genesis-secret-2', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag);
    PERFORM change_input('environment', '22222222-2222-2222-2222-222222222222', 'genesis-environment', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag);
    IF (SELECT count(*) FROM log_changes) <> 8 OR (SELECT count(DISTINCT object) FROM log_changes) <> 8 THEN
        RAISE EXCEPTION 'FAIL: genesis logged % changes', (SELECT count(*) FROM log_changes);
    END IF;
    -- The row's seal is no longer the one read: nothing is done, and nothing logged.
    IF change_input('principal', 'token:deploy', 'genesis-member-again', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag) IS NOT NULL
       OR change_input('credential', '66666666-6666-6666-6666-666666666666', 'genesis-binding-again', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag) IS NOT NULL
       OR change_input('principal', 'token:nobody', 'genesis-nobody', t, 'system:cutover', '{"op":"genesis"}', NULL, NULL, sealed, tag) IS NOT NULL
       OR (SELECT count(*) FROM log_changes) <> 8 THEN
        RAISE EXCEPTION 'FAIL: a change moved a seal it had not read';
    END IF;
    BEGIN
        PERFORM change_input('principal', 'token:deploy', 'grant', t, 'system:x', '{"op":"credential.revoke"}', NULL, sealed, sealed, tag);
        RAISE EXCEPTION 'FAIL: change_input applied an op this schema does not know';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    IF (SELECT seal FROM vault_members WHERE principal = 'token:deploy') IS DISTINCT FROM sealed
       OR (SELECT object FROM log_changes WHERE request_id = 'genesis-member') <> log_object('principal', 'token:deploy') THEN
        RAISE EXCEPTION 'FAIL: genesis left the row or its object other than it said';
    END IF;
    RAISE NOTICE 'PASS: ChangeCAS, change_input seals each object once, from the seal it read, and a retry finds its entry';
END
$$;

-- A use: one entry, every input and its newest change's seal, the cap's row; its replay writes nothing more.
DO $$
DECLARE
    r use_row;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    tag bytea := decode(repeat('ab', 16), 'hex');
BEGIN
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 7, t, 258::smallint, '22222222-2222-2222-2222-222222222222', tag, t + 2000));
    IF r.state IS NOT NULL OR r.number IS NULL OR r.c_principal <> 'token:deploy' OR r.newest <> (SELECT max(number) FROM log_changes)
       OR r.inputs <> r.newest OR r.c_seal IS DISTINCT FROM r.c_last OR r.m_seal IS DISTINCT FROM r.m_last OR r.s_seal IS DISTINCT FROM r.s_last
       OR r.e2_seal IS DISTINCT FROM r.e2_last OR r.p_seal IS DISTINCT FROM r.p_last OR r.r_seal IS DISTINCT FROM r.r_last
       OR r.cap_count <> 1 OR r.cap_window <> 86400000 OR r.s_version <> '55555555-5555-5555-5555-555555555551' OR r.v_wrapped_dek <> decode('d0', 'hex')
       OR cardinality(r.g_role) <> 1 OR r.c_revoked OR r.c_kind <> 'service' OR r.in_set OR r.others <> 0 THEN
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
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 8, t + 1, 258::smallint, '22222222-2222-2222-2222-222222222222', tag, t + 2000,
        (SELECT number FROM log_uses), t, 7));
    IF r.state IS NOT NULL OR r.number IS NOT NULL OR r.covered IS DISTINCT FROM (SELECT number FROM log_uses) THEN
        RAISE EXCEPTION 'FAIL: a covered repeat answered % % %', r.state, r.number, r.covered;
    END IF;
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 9, t + 1, 258::smallint, '22222222-2222-2222-2222-222222222222', tag, t + 2000,
        (SELECT number FROM log_uses), t, 6));
    IF r.covered IS NOT NULL OR r.number IS NULL THEN RAISE EXCEPTION 'FAIL: a cover with no entry covered'; END IF;
    -- A cover is its own credential's and secret's: another secret's entry, its key's row fresh, covers nothing, in either form.
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444442', 13, t + 1, 1::smallint, NULL, tag, t + 2000));
    IF r.number IS NULL THEN RAISE EXCEPTION 'FAIL: the other secret''s use wrote no entry'; END IF;
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 14, t + 1, 258::smallint, NULL, tag, t + 2000,
        r.number, t + 1, 13));
    IF r.covered IS NOT NULL OR r.number IS NULL THEN RAISE EXCEPTION 'FAIL: one secret''s entry covered another''s use'; END IF;
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 15, t + 1, 258::smallint, NULL, tag, t + 2000,
        (SELECT number FROM log_uses WHERE request_id = 13), t + 1, 13, r.newest, r.newest_mac, r.cap_count, r.cap_window));
    IF r.covered IS NOT NULL OR r.number IS NULL OR r.c_last IS NOT NULL THEN RAISE EXCEPTION 'FAIL: one secret''s entry covered another''s use, from the cache'; END IF;

    -- The seal cache: the newest change named exactly skips the probes; a wrong MAC probes again.
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 10, t + 2, 258::smallint, NULL, tag, t + 2000,
        NULL, NULL, NULL, r.newest, r.newest_mac, r.cap_count, r.cap_window));
    IF r.state IS NOT NULL OR r.number IS NULL OR r.c_last IS NOT NULL OR r.inputs IS NOT NULL OR r.c_seal IS NULL THEN
        RAISE EXCEPTION 'FAIL: the cached form read %', r;
    END IF;
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 11, t + 2, 258::smallint, NULL, tag, t + 2000,
        NULL, NULL, NULL, r.newest, decode(repeat('00', 16), 'hex'), r.cap_count, r.cap_window));
    IF r.state IS NOT NULL OR r.c_last IS NULL OR r.inputs IS NULL THEN
        RAISE EXCEPTION 'FAIL: a stale cache was trusted';
    END IF;

    -- The cap at one key: the other key is asked for, logged, and not let in.
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444442', 12, t + 3, 1::smallint, NULL, tag, t + 2000));
    IF r.state IS NOT NULL OR r.number IS NULL OR r.in_set OR r.others <> 1
       OR EXISTS (SELECT 1 FROM log_bulk WHERE secret = '44444444-4444-4444-4444-444444444442') THEN
        RAISE EXCEPTION 'FAIL: the cap let a second key in: %', r;
    END IF;
    RAISE NOTICE 'PASS: a use logs its request once, reads every input sealed, and keeps covers (CoverExists), the cache (CacheSameChange) and the cap';
END
$$;

-- The deadline, the floor and the barrier.
DO $$
DECLARE
    r use_row;
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    barrier record;
    pruned integer;
    before bigint;
    last bigint;
BEGIN
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 20, t, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 3001));
    IF r.state <> 'late' THEN RAISE EXCEPTION 'FAIL: a deadline past deadline_max was taken'; END IF;
    -- A use from a clock running ahead: a proof would not find it from its window.
    last := (SELECT b.last FROM log_bulk b WHERE b.principal = 'token:deploy' AND b.secret = '44444444-4444-4444-4444-444444444441');
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 23, t + 61000, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 63000));
    IF r.state IS DISTINCT FROM 'ahead' OR r.number IS NOT NULL OR r.covered IS NOT NULL OR EXISTS (SELECT 1 FROM log_uses WHERE request_id = 23)
       OR (SELECT b.last FROM log_bulk b WHERE b.principal = 'token:deploy' AND b.secret = '44444444-4444-4444-4444-444444444441') IS DISTINCT FROM last THEN
        RAISE EXCEPTION 'FAIL: a use stamped ahead of the database wrote something';
    END IF;
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 21, t - 2000, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t - 1));
    IF r.state <> 'late' THEN RAISE EXCEPTION 'FAIL: a use past its deadline was taken'; END IF;
    before := (SELECT at_floor FROM log_fence);
    SELECT * INTO barrier FROM close_one();
    IF barrier.floor_found <> before THEN RAISE EXCEPTION 'FAIL: the barrier misreported the floor it found'; END IF;
    IF barrier.upto <> (SELECT max(n) FROM (SELECT max(number) AS n FROM log_uses UNION ALL SELECT max(number) FROM log_changes) x)
       OR barrier.at_floor < t - 3000 OR barrier.at_floor <> (SELECT at_floor FROM log_fence) THEN
        RAISE EXCEPTION 'FAIL: the barrier closed at % with floor %', barrier.upto, barrier.at_floor;
    END IF;
    r := json_populate_record(NULL::use_row, use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', 22, barrier.at_floor - 1, 1::smallint, NULL, decode(repeat('00', 16), 'hex'), t + 1000));
    IF r.state <> 'late' OR EXISTS (SELECT 1 FROM log_uses WHERE request_id IN (20, 21, 22)) THEN
        RAISE EXCEPTION 'FAIL: a use below the floor was written';
    END IF;
    -- Each its own statement: one statement's snapshot would not see the rows its call deleted.
    pruned := prune_bulk(100);
    IF pruned <> 1 OR EXISTS (SELECT 1 FROM log_bulk WHERE principal = 'token:gone') THEN RAISE EXCEPTION 'FAIL: prune_bulk kept a key no window counts'; END IF;
    pruned := prune_bulk(100);
    IF pruned <> 0 OR NOT EXISTS (SELECT 1 FROM log_bulk WHERE principal = 'token:deploy') THEN RAISE EXCEPTION 'FAIL: prune_bulk forgot a key its window counts'; END IF;
    RAISE NOTICE 'PASS: late uses, and uses stamped ahead, write nothing (DeadlineChecked, FloorChecked), the barrier raises the floor, and pruning keeps what a window counts';
END
$$;

-- PairWrittenTogether: a checkpoint's tiles and its pair of heads, in one call;
-- a tile only grows; one pair a place.
DO $$
DECLARE
    h bytea := decode(repeat('11', 32), 'hex');
    h2 bytea := decode(repeat('11', 32) || repeat('22', 32), 'hex');
    root bytea := decode(repeat('33', 32), 'hex');
    bad record;
BEGIN
    PERFORM write_checkpoint(100, 1, 1, 1, root, 'changes note', 1, root, 'uses note',
        ARRAY['changes', 'uses', 'uses'], ARRAY[0, 0, 1]::smallint[], ARRAY[0, 0, 0]::bigint[], ARRAY[h, h, h]);
    -- Grown, and written again with the same bytes: both fine.
    PERFORM write_checkpoint(101, 2, 1, 2, root, 'changes note', 1, root, 'uses note',
        ARRAY['changes', 'uses'], ARRAY[0, 0]::smallint[], ARRAY[0, 0]::bigint[], ARRAY[h2, h]);
    IF (SELECT hashes FROM log_tiles WHERE tree = 'changes' AND level = 0 AND leaf = 0) <> h2
       OR (SELECT count(*) FROM log_tiles) <> 3 OR (SELECT count(*) FROM log_checkpoints) <> 2 THEN
        RAISE EXCEPTION 'FAIL: write_checkpoint did not write its tiles and its pair';
    END IF;
    -- A tile that would shrink, change at one width, or grow from other bytes; and a call whose leaf tile has no range.
    FOR bad IN SELECT * FROM (VALUES (h), (decode(repeat('44', 64), 'hex')), (decode(repeat('44', 32) || repeat('22', 32), 'hex'))) AS b (hashes) LOOP
        BEGIN
            PERFORM write_checkpoint(102, 3, 1, 2, root, 'n', 1, root, 'n', ARRAY['changes'], ARRAY[0]::smallint[], ARRAY[0]::bigint[], ARRAY[bad.hashes]);
            RAISE EXCEPTION 'FAIL: a tile became %', bad.hashes;
        EXCEPTION WHEN data_corrupted THEN NULL;
        END;
    END LOOP;
    BEGIN
        PERFORM write_checkpoint(102, 3, 1, 2, root, 'n', 1, root, 'n', ARRAY['uses'], ARRAY[0]::smallint[], ARRAY[4294967296]::bigint[], ARRAY[h]);
        RAISE EXCEPTION 'FAIL: a leaf tile with no range was written';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    -- A caller's own mistakes: a tile twice, lists of other lengths, no lists.
    BEGIN
        PERFORM write_checkpoint(102, 3, 1, 2, root, 'n', 1, root, 'n', ARRAY['changes', 'changes'], ARRAY[0, 0]::smallint[], ARRAY[0, 0]::bigint[], ARRAY[h2, h2]);
        RAISE EXCEPTION 'FAIL: one tile was written twice in a call';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    BEGIN
        PERFORM write_checkpoint(102, 3, 1, 2, root, 'n', 1, root, 'n', ARRAY['changes', 'uses'], ARRAY[0]::smallint[], ARRAY[0]::bigint[], ARRAY[h2]);
        RAISE EXCEPTION 'FAIL: lists of other lengths were taken';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    BEGIN
        PERFORM write_checkpoint(102, 3, 1, 2, root, 'n', 1, root, 'n', NULL, NULL, NULL, NULL);
        RAISE EXCEPTION 'FAIL: no lists were taken for none';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    IF (SELECT hashes FROM log_tiles WHERE tree = 'changes' AND level = 0 AND leaf = 0) <> h2 OR EXISTS (SELECT 1 FROM log_checkpoints WHERE upto = 102) THEN
        RAISE EXCEPTION 'FAIL: a refused checkpoint changed a tile or wrote its pair';
    END IF;
    -- No tile grew this tick: an empty list writes the pair alone.
    PERFORM write_checkpoint(103, 4, 1, 2, root, 'n', 1, root, 'n', ARRAY[]::text[], ARRAY[]::smallint[], ARRAY[]::bigint[], ARRAY[]::bytea[]);
    BEGIN
        PERFORM write_checkpoint(101, 3, 1, 3, root, 'n', 1, root, 'n', ARRAY['uses'], ARRAY[1]::smallint[], ARRAY[0]::bigint[], ARRAY[h2]);
        RAISE EXCEPTION 'FAIL: a second pair was written at one place';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
    IF (SELECT count(*) FROM log_checkpoints) <> 3 OR (SELECT hashes FROM log_tiles WHERE tree = 'uses' AND level = 1) <> h THEN
        RAISE EXCEPTION 'FAIL: a refused checkpoint left a trace';
    END IF;
    RAISE NOTICE 'PASS: PairWrittenTogether, write_checkpoint writes tiles and pair as one, tiles only growing, one pair a place';
END
$$;

-- The change path's ops (0023, plan PR 4a), on the objects genesis sealed above: an environment's change writes the
-- object it carries, the policy's moves its value from its seal, a payload names its object, and a value comes exactly
-- when the function writes the object's row. All of it rolled back after (a subtransaction ended by an error of its
-- own), so that log-owner.sql finds the objects as genesis left them.
DO $$
DECLARE
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    tag bytea := decode(repeat('ee', 16), 'hex');
    sealed bytea := (SELECT seal FROM environments WHERE id = '22222222-2222-2222-2222-222222222222');
    next bytea := decode(repeat('6e', 16), 'hex');
    held bytea := (SELECT seal FROM log_config WHERE name = 'policy');
    env jsonb;
    n bigint;
    cap text := '{"kind":"policy","bulk":{"count":5,"windowMs":60000}}';
BEGIN
BEGIN
    SELECT jsonb_build_object('kind', 'environment', 'id', e.id::text, 'projectId', e.project_id::text, 'slug', 'renamed', 'owner', e.owner,
                              'parentId', e.parent_id, 'protected', true, 'deleted', false, 'archived', true)
      INTO env FROM environments e WHERE e.id = '22222222-2222-2222-2222-222222222222';
    -- Each call its own statement: a check in the call's statement would read from before what the call wrote.
    n := change_input('environment', '22222222-2222-2222-2222-222222222222', 'environment-renamed', t, 'user:admin@acme.example',
                      '{"op":"environment.rename","ref":{"kind":"environment","id":"22222222-2222-2222-2222-222222222222"},"slug":"renamed"}',
                      env::text, sealed, next, tag);
    IF n IS NULL OR NOT EXISTS (SELECT 1 FROM environments WHERE id = '22222222-2222-2222-2222-222222222222'
                       AND slug = 'renamed' AND protected AND archived_at IS NOT NULL AND seal = next) THEN
        RAISE EXCEPTION 'FAIL: an environment''s change did not write the object it carried';
    END IF;
    -- An object whose project is not the row's: nothing is done.
    IF change_input('environment', '22222222-2222-2222-2222-222222222222', 'environment-moved', t, 'user:admin@acme.example',
                    '{"op":"environment.protect","ref":{"kind":"environment","id":"22222222-2222-2222-2222-222222222222"},"protected":false}',
                    jsonb_set(env, '{projectId}', to_jsonb(gen_random_uuid()::text))::text, next, sealed, tag) IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: an environment''s change moved it to another project';
    END IF;
    n := change_input('policy', 'instance', 'cap', t, 'system:vault', '{"op":"bulk.limit","ref":{"kind":"policy","id":"instance"},"value":' || cap || '}',
                      cap, held, next, tag);
    IF n IS NULL OR (SELECT value::jsonb FROM log_config WHERE name = 'policy') <> cap::jsonb THEN
        RAISE EXCEPTION 'FAIL: the policy''s change did not write its value';
    END IF;
    BEGIN
        PERFORM change_input('policy', 'instance', 'cap-elsewhere', t, 'system:vault', '{"op":"bulk.limit","ref":{"kind":"roles","id":"instance"},"value":' || cap || '}',
                             cap, next, sealed, tag);
        RAISE EXCEPTION 'FAIL: a payload naming another object was taken';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    BEGIN
        PERFORM change_input('policy', 'instance', 'cap-unnamed', t, 'system:vault', '{"op":"bulk.limit","value":' || cap || '}', cap, next, sealed, tag);
        RAISE EXCEPTION 'FAIL: a payload naming no object was taken';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    BEGIN
        PERFORM change_input('principal', 'token:deploy', 'member-valued', t, 'system:vault', '{"op":"member.remove","ref":{"kind":"principal","id":"token:deploy"}}',
                             '{}', (SELECT seal FROM vault_members WHERE principal = 'token:deploy'), next, tag);
        RAISE EXCEPTION 'FAIL: a principal''s change carried a value its row is not written from';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    BEGIN
        PERFORM change_input('environment', '22222222-2222-2222-2222-222222222222', 'environment-unvalued', t, 'system:vault',
                             '{"op":"environment.protect","ref":{"kind":"environment","id":"22222222-2222-2222-2222-222222222222"},"protected":false}',
                             NULL, next, sealed, tag);
        RAISE EXCEPTION 'FAIL: an environment''s change carried no object to write';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
    IF (SELECT count(*) FROM log_changes WHERE request_id IN ('environment-renamed', 'cap')) <> 2
       OR EXISTS (SELECT 1 FROM log_changes WHERE request_id IN ('environment-moved', 'cap-elsewhere', 'cap-unnamed', 'member-valued', 'environment-unvalued')) THEN
        RAISE EXCEPTION 'FAIL: a refused change was logged, or a change was not';
    END IF;
    RAISE EXCEPTION 'rolled back' USING ERRCODE = 'C0FFE';
EXCEPTION WHEN SQLSTATE 'C0FFE' THEN
    RAISE NOTICE 'PASS: change_input writes an environment''s and the policy''s object from its value, under its CAS, and refuses a payload or value out of place';
END;
END
$$;
