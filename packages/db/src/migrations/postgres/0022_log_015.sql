-- 0.15's log (docs/design/hot-path-one.md, docs/design/0.15-plan.md, PR 2): its tables, the seals on the decision inputs, the functions every use and change will be, and a login of its own for the hot path. It only adds, and nothing calls any of it yet: 0.14's code serves on it as before. The vault login reads the new tables and writes them only through the functions, which run as their owner, so that every number is taken under the fence's lock whatever the vault's code does (and 0.14's conformance holds: the vault writes no table but its own).
CREATE TABLE "log_config" (
	"name" text PRIMARY KEY NOT NULL,
	"value" text NOT NULL,
	"seal" "bytea",
	CONSTRAINT "log_config_name_check" CHECK ("log_config"."name" IN ('policy', 'roles')),
	CONSTRAINT "log_config_value_check" CHECK ("log_config"."value"::jsonb IS NOT NULL),
	CONSTRAINT "log_config_seal_check" CHECK ("log_config"."seal" IS NULL OR octet_length("log_config"."seal") = 16)
);
--> statement-breakpoint
-- CACHE 1 (the default) matters: numbers rise in the order they are taken, across sessions, and the barrier reads the last one taken. A cache per session would hand a later call a smaller number.
CREATE SEQUENCE "log_number" AS bigint CACHE 1;
--> statement-breakpoint
CREATE TABLE "log_changes" (
	"number" bigint PRIMARY KEY NOT NULL,
	"at" bigint NOT NULL,
	"request_id" text NOT NULL,
	"object" uuid NOT NULL,
	"actor" text NOT NULL,
	"payload" text NOT NULL,
	"seal" "bytea",
	"mac" "bytea" NOT NULL,
	CONSTRAINT "log_changes_request_id_key" UNIQUE("request_id"),
	CONSTRAINT "log_changes_seal_check" CHECK ("log_changes"."seal" IS NULL OR octet_length("log_changes"."seal") = 16),
	CONSTRAINT "log_changes_mac_check" CHECK (octet_length("log_changes"."mac") = 16)
);
--> statement-breakpoint
-- Each input's newest change, its seal included, from the index alone: one probe per input.
CREATE INDEX "log_changes_object_idx" ON "log_changes" USING btree ("object","number") INCLUDE ("seal");
--> statement-breakpoint
-- Uses, by the day of their `at` (make_day): retention drops a day whole. Fixed-width columns first, and eight of them: a ninth makes the null bitmap two bytes, and the header 32 bytes instead of 24 (117 B a use against 109, measured). So `purpose` carries whether the use may keep a sensitive value, as 256 added to its code.
CREATE TABLE "log_uses" (
	"number" bigint NOT NULL,
	"at" bigint NOT NULL,
	"request_id" bigint NOT NULL,
	"credential" uuid NOT NULL,
	"secret" uuid NOT NULL,
	"purpose" smallint NOT NULL,
	"mac" "bytea" NOT NULL,
	"place" uuid,
	CONSTRAINT "log_uses_mac_check" CHECK (octet_length("log_uses"."mac") = 16)
) PARTITION BY RANGE ("at");
--> statement-breakpoint
-- The replay's index, and the only one: a unique index on a partitioned table must hold its partition key, so a use's number is unique by the sequence alone (the verifier checks it), and the checkpointer finds its window by `at`, from the floor (log_fence).
CREATE UNIQUE INDEX "log_uses_request_idx" ON "log_uses" USING btree ("at","request_id");
--> statement-breakpoint
CREATE TABLE "log_bulk" (
	"principal" text NOT NULL,
	"secret" uuid NOT NULL,
	"last" bigint NOT NULL,
	CONSTRAINT "log_bulk_pkey" PRIMARY KEY("principal","secret")
);
--> statement-breakpoint
CREATE TABLE "log_fence" (
	"only_row" boolean PRIMARY KEY DEFAULT true NOT NULL,
	"at_floor" bigint NOT NULL,
	CONSTRAINT "log_fence_only_row_check" CHECK ("log_fence"."only_row")
);
--> statement-breakpoint
-- The floor starts below every use to come, by the deadline (deadline_max, below): the first barrier raises it.
INSERT INTO "log_fence" ("only_row", "at_floor") VALUES (true, (extract(epoch FROM clock_timestamp()) * 1000)::bigint - 3000);
--> statement-breakpoint
CREATE TABLE "log_checkpoints" (
	"upto" bigint PRIMARY KEY NOT NULL,
	"at" bigint NOT NULL,
	"at_floor" bigint NOT NULL,
	"changes_size" bigint NOT NULL,
	"changes_root" "bytea" NOT NULL,
	"changes_note" text NOT NULL,
	"uses_size" bigint NOT NULL,
	"uses_root" "bytea" NOT NULL,
	"uses_note" text NOT NULL,
	CONSTRAINT "log_checkpoints_changes_root_check" CHECK (octet_length("log_checkpoints"."changes_root") = 32),
	CONSTRAINT "log_checkpoints_uses_root_check" CHECK (octet_length("log_checkpoints"."uses_root") = 32)
);
--> statement-breakpoint
-- The two trees' tiles: the changes tree's kept for good in one table, the uses tree's by leaf range (make_tiles), so that retention drops a table.
CREATE TABLE "log_tiles" (
	"tree" text NOT NULL,
	"level" smallint NOT NULL,
	"leaf" bigint NOT NULL,
	"hashes" "bytea" NOT NULL,
	CONSTRAINT "log_tiles_pkey" PRIMARY KEY("tree","level","leaf"),
	CONSTRAINT "log_tiles_tree_check" CHECK ("log_tiles"."tree" IN ('changes', 'uses')),
	CONSTRAINT "log_tiles_level_check" CHECK ("log_tiles"."level" BETWEEN 0 AND 7),
	CONSTRAINT "log_tiles_leaf_check" CHECK ("log_tiles"."leaf" >= 0 AND "log_tiles"."leaf" % (256::numeric ^ ("log_tiles"."level" + 1)) = 0),
	CONSTRAINT "log_tiles_hashes_check" CHECK (octet_length("log_tiles"."hashes") BETWEEN 32 AND 8192 AND octet_length("log_tiles"."hashes") % 32 = 0)
) PARTITION BY LIST ("tree");
--> statement-breakpoint
CREATE TABLE "log_tiles_changes" PARTITION OF "log_tiles" FOR VALUES IN ('changes');
--> statement-breakpoint
-- The uses tree by level: its leaves' tiles (level 0) by leaf range, which retention drops whole (W212: 1.16 s against 13.8 s for a DELETE); the levels above, 1/256 of the bytes, in one table, where retention deletes the few tiles that end at or below the cut. A tile above level 0 starts low and spans far (2/0 covers 16.7M leaves), so a range of first leaves would drop one that still holds the cut (W217, #370's keptAbove).
CREATE TABLE "log_tiles_uses" PARTITION OF "log_tiles" FOR VALUES IN ('uses') PARTITION BY LIST ("level");
--> statement-breakpoint
CREATE TABLE "log_tiles_uses_leaves" PARTITION OF "log_tiles_uses" FOR VALUES IN (0) PARTITION BY RANGE ("leaf");
--> statement-breakpoint
CREATE TABLE "log_tiles_uses_upper" PARTITION OF "log_tiles_uses" FOR VALUES IN (1, 2, 3, 4, 5, 6, 7);
--> statement-breakpoint
-- The seals, null until 0.15's cutover seals each row: one on each table an object of W216's lives in, a member's covering its grants, a secret's its current version and a reference's source. Adding a nullable column rewrites nothing; the checks are NOT VALID so that adding them scans nothing either (every row is null, and every new row is checked).
ALTER TABLE "credentials" ADD COLUMN "seal" "bytea";--> statement-breakpoint
ALTER TABLE "environments" ADD COLUMN "seal" "bytea";--> statement-breakpoint
-- Whether the environment is protected: 0.14 keeps it in the policy's entries, 0.15 on the environment's object (W216). Null until the cutover writes it.
ALTER TABLE "environments" ADD COLUMN "protected" boolean;--> statement-breakpoint
ALTER TABLE "secrets" ADD COLUMN "seal" "bytea";--> statement-breakpoint
ALTER TABLE "service_bindings" ADD COLUMN "seal" "bytea";--> statement-breakpoint
ALTER TABLE "vault_members" ADD COLUMN "seal" "bytea";--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_seal_check" CHECK ("credentials"."seal" IS NULL OR octet_length("credentials"."seal") = 16) NOT VALID;--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_seal_check" CHECK ("environments"."seal" IS NULL OR octet_length("environments"."seal") = 16) NOT VALID;--> statement-breakpoint
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_seal_check" CHECK ("secrets"."seal" IS NULL OR octet_length("secrets"."seal") = 16) NOT VALID;--> statement-breakpoint
ALTER TABLE "service_bindings" ADD CONSTRAINT "service_bindings_seal_check" CHECK ("service_bindings"."seal" IS NULL OR octet_length("service_bindings"."seal") = 16) NOT VALID;--> statement-breakpoint
ALTER TABLE "vault_members" ADD CONSTRAINT "vault_members_seal_check" CHECK ("vault_members"."seal" IS NULL OR octet_length("vault_members"."seal") = 16) NOT VALID;--> statement-breakpoint
-- An object's key in the log: the first 16 bytes of SHA-256('coffre.object.v1' 0x00 kind 0x00 id), read as a uuid, which the vault computes the same way. Kinds (W216's objectKey, in @coffre/vault): principal (a member, by its principal), credential (a token or a binding, by its id), secret, environment (each by its id), roles and policy (id 'instance'). Plain SQL, so that each probe inlines it, and STABLE as convert_to is: declared IMMUTABLE, it would not be inlined, and a statement would call it as a function of its own, 32 µs a call against 3.7 (measured).
CREATE FUNCTION log_object(p_kind text, p_id text) RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT pg_catalog.encode(pg_catalog.substr(pg_catalog.sha256(
        '\x636f666672652e6f626a6563742e763100'::bytea || pg_catalog.convert_to(p_kind, 'UTF8') || '\x00'::bytea || pg_catalog.convert_to(p_id, 'UTF8')
    ), 1, 16), 'hex')::uuid
$$;
--> statement-breakpoint
-- The longest a use may take, from its `at` to its deadline, in ms (R53, R54): sealing trusts that nothing stamped longer ago still arrives.
CREATE FUNCTION deadline_max() RETURNS bigint
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS 'SELECT 3000::bigint';
--> statement-breakpoint
-- A day of uses, [day, day + 1) in ms since the epoch, UTC, made ahead of time: a use at a time no day holds fails. Made apart, then attached: CREATE TABLE … PARTITION OF takes the parent ACCESS EXCLUSIVE and queues every use behind whatever reads it (10.7 s measured at 10M), ATTACH takes SHARE UPDATE EXCLUSIVE, which inserts do not wait for (12 ms).
CREATE FUNCTION make_day(p_day date) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    name text := 'log_uses_' || to_char(p_day, 'YYYYMMDD');
    lo bigint := (p_day - date '1970-01-01')::bigint * 86400000;
BEGIN
    -- A day made already, by its bound: a table of that name that is not that day is no day.
    IF to_regclass('public.' || quote_ident(name)) IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = 'public.log_uses'::regclass AND c.oid = to_regclass('public.' || quote_ident(name))
               AND pg_get_expr(c.relpartbound, c.oid) = format('FOR VALUES FROM (%L) TO (%L)', lo, lo + 86400000)
        ) THEN
            RAISE EXCEPTION '% exists, and is not the uses of %', name, p_day;
        END IF;
        RETURN name;
    END IF;
    BEGIN
        EXECUTE format('CREATE TABLE public.%I (LIKE public.log_uses INCLUDING DEFAULTS INCLUDING CONSTRAINTS)', name);
        EXECUTE format('CREATE UNIQUE INDEX ON public.%I (at, request_id)', name);
        -- pg_dump reads each partition as a table of its own.
        EXECUTE format('GRANT SELECT ON public.%I TO coffre_backup', name);
        EXECUTE format('ALTER TABLE public.log_uses ATTACH PARTITION public.%I FOR VALUES FROM (%s) TO (%s)', name, lo, lo + 86400000);
    EXCEPTION WHEN duplicate_table OR unique_violation THEN
        -- Another call made it meanwhile, and committed: it is checked as any day found.
        RETURN public.make_day(p_day);
    END;
    RETURN name;
END
$$;
--> statement-breakpoint
-- A range of the uses tree's leaf tiles (level 0), those whose first leaf is in [p_from, p_to), made apart and attached as make_day makes a day. What ranges, and when, is the checkpointer's.
CREATE FUNCTION make_tiles(p_from bigint, p_to bigint) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    name text := 'log_tiles_uses_' || p_from;
BEGIN
    IF p_from < 0 OR p_to <= p_from THEN RAISE EXCEPTION 'no leaves in [%, %)', p_from, p_to; END IF;
    IF to_regclass('public.' || quote_ident(name)) IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = 'public.log_tiles_uses_leaves'::regclass AND c.oid = to_regclass('public.' || quote_ident(name))
               AND pg_get_expr(c.relpartbound, c.oid) = format('FOR VALUES FROM (%L) TO (%L)', p_from, p_to)
        ) THEN
            RAISE EXCEPTION '% exists, and does not hold the tiles of [%, %)', name, p_from, p_to;
        END IF;
        RETURN name;
    END IF;
    BEGIN
        EXECUTE format('CREATE TABLE public.%I (LIKE public.log_tiles_uses_leaves INCLUDING DEFAULTS INCLUDING CONSTRAINTS)', name);
        EXECUTE format('ALTER TABLE public.%I ADD PRIMARY KEY (tree, level, leaf)', name);
        EXECUTE format('GRANT SELECT ON public.%I TO coffre_backup', name);
        EXECUTE format('ALTER TABLE public.log_tiles_uses_leaves ATTACH PARTITION public.%I FOR VALUES FROM (%s) TO (%s)', name, p_from, p_to);
    EXCEPTION WHEN duplicate_table OR unique_violation THEN
        RETURN public.make_tiles(p_from, p_to);
    END;
    RETURN name;
END
$$;
--> statement-breakpoint
-- What a use reads, as use_credential returns it. `state` is null when it did its work; otherwise it did nothing, and the rest is to be ignored: 'late' (past its deadline, or below the floor), 'unconfigured' (no policy), 'reprobe' and 'lock' never leave the function. `inputs` is the newest change of any of its inputs; each `*_seal` is a row's, each `*_last` its object's newest change's (null in the cached form, where the isolate holds them).
CREATE TYPE use_view AS (
    state text, number bigint, covered bigint, principal text, newest bigint, newest_mac bytea, inputs bigint,
    c_kind text, c_generation integer, c_scope text, c_places text, c_constraints text, c_revoked boolean, c_expires bigint, c_not_after bigint, c_seal bytea, c_last bytea,
    m_status text, m_role text, m_scope text, m_generation integer, grants json, m_seal bytea, m_last bytea,
    s_environment uuid, s_archived boolean, s_version uuid, s_seal bytea, s_last bytea,
    v_envelope integer, v_ciphertext bytea, v_iv bytea, v_auth_tag bytea, v_wrapped_dek bytea, v_kek_provider text, v_kek_id text, v_kek_version text, v_sensitive boolean,
    e_project uuid, e_parent uuid, e_owner text, e_archived boolean, e_deleted boolean, e_protected boolean, e_seal bytea, e_last bytea,
    cap_count integer, cap_window bigint, policy_seal bytea, policy_last bytea,
    in_set boolean, others integer
);
--> statement-breakpoint
-- A use (hot-path-one.md, "A use"; formal/HotPathOne.tla): the fence shared, then one statement, with a snapshot of its own taken after the lock (each of a volatile function's statements takes a new one under READ COMMITTED), that reads every input the decision needs and inserts the entry, numbered now. The lock goes with the commit. The Worker decides on what it returns; the log records the request, not the outcome.
--
-- The deadline: a call that comes after it, or with a deadline more than deadline_max() after its `at`, or an `at` below the floor (or no floor row), writes nothing and answers 'late'; one that runs past it, waiting for its principal's lock say, rolls back (57014). A replay of a call that wrote fails on (at, request_id), 23505: deciding again on today's state could allow, after a revocation, a use the log has before it. (Not ON CONFLICT: its speculative insertion doubles a use's buffers and WAL, measured.)
--
-- The bulk cap (R28, R52), its count and window the policy object's newest change's, read in the statement's own snapshot (CapSealed, CapFromPolicy): a policy row put back cannot move the cap, and a use before the policy is logged, or with a policy that names no count or window, answers 'unconfigured' and writes nothing. The cap's row moves for every request it admits, whatever the seals say: the Worker refuses a stale use after (HotPathOneStaleBulk), and the replay counts it the same. A key is in the principal's set at t if its log_bulk row's `last` > t - window - refresh, with refresh a minute or a tenth of the window. A key in the set passes; one not in it passes if fewer than count others are (counted over a deadline more: uses are decided in number order, not by `at`), and enters. A row older than t - refresh moves on to t. Every request counts, allowed or refused for any reason but the cap. Both writes are made under the principal's own lock: a use that may write takes it and reads again, so the writes come in number order and the replay decides each the same.
--
-- Covers (p_cover, with its entry's at and request id): a repeat of an allowed use this isolate wrote, of the same credential and secret, with no change to any input numbered after it and the key's bulk row fresh, writes nothing; the Worker decides on what was read. The cover's entry must still be in the log.
--
-- The seal cache (p_known, p_known_mac): if the log's newest change is still exactly the one the isolate read its seals at, by number and MAC, no input changed since, and the statement probes nothing. Otherwise it writes nothing, answers 'reprobe' inside the function, and the probing statement runs. Two statements, not one with its probes skipped: a probe's plan nodes cost most of it even when it does not run (measured).
--
-- Five inputs, each one object (W216's): the credential, its principal (the member, with its grants, under the member's seal), the secret (with its current version, under the secret's seal), its environment (whose `deleted` says its project's too), and the policy (the cap). Roles, the environment asked at (`place`) and a reference's source are read by the 0.15 vault's statement when it is built (plan, PR 5).
CREATE FUNCTION use_credential(
    p_credential uuid, p_secret uuid, p_request bigint, p_at bigint, p_purpose smallint, p_place uuid, p_mac bytea, p_deadline bigint,
    p_cover bigint DEFAULT NULL, p_cover_at bigint DEFAULT NULL, p_cover_request bigint DEFAULT NULL, p_known bigint DEFAULT NULL, p_known_mac bytea DEFAULT NULL
) RETURNS use_view
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r public.use_view;
    locked boolean := false;
    probe boolean := p_known IS NULL;
BEGIN
    IF p_deadline IS NULL OR p_deadline > p_at + public.deadline_max() THEN r.state := 'late'; RETURN r; END IF;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    LOOP
        IF probe THEN
            WITH n AS MATERIALIZED (
                SELECT x.number AS newest, x.mac AS newest_mac, coalesce(x.number = p_known AND x.mac = p_known_mac, false) AS cached
                  FROM public.log_changes x ORDER BY x.number DESC LIMIT 1
            ),
            -- The rows, and each input's object key, computed once: a key in a probe's own condition is computed again for every row the probe reads.
            i AS MATERIALIZED (
                SELECT n.newest, n.newest_mac, coalesce(n.cached, false) AS cached,
                    f.at_floor, cap.count AS cap_count, cap.window_ms AS cap_window, cap.refresh AS cap_refresh, b.last AS bulk_last,
                    c.principal AS p, c.kind AS c_kind, c.generation AS c_generation, c.scope AS c_scope, c.places AS c_places, c.constraints AS c_constraints,
                    c.revoked_at IS NOT NULL AS c_revoked, (extract(epoch FROM c.expires_at) * 1000)::bigint AS c_expires,
                    (extract(epoch FROM c.not_after) * 1000)::bigint AS c_not_after, c.seal AS c_seal,
                    m.status AS m_status, m.role AS m_role, m.scope AS m_scope, m.generation AS m_generation, m.seal AS m_seal,
                    s.environment_id AS s_environment, s.archived_at IS NOT NULL AS s_archived, s.current_version_id AS s_version, s.seal AS s_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive,
                    e.project_id AS e_project, e.parent_id AS e_parent, e.owner AS e_owner, e.archived_at IS NOT NULL AS e_archived, strpos(e.slug, '~') > 0 AS e_deleted,
                    e.protected AS e_protected, e.seal AS e_seal,
                    pol.seal AS policy_seal, lpol.number AS policy_number, lpol.seal AS policy_last,
                    public.log_object('credential', p_credential::text) AS k_credential,
                    public.log_object('principal', c.principal) AS k_member,
                    public.log_object('secret', p_secret::text) AS k_secret,
                    public.log_object('environment', s.environment_id::text) AS k_environment
                  FROM (SELECT 1) one
                  LEFT JOIN n ON true
                  LEFT JOIN public.log_fence f ON f.only_row
                  LEFT JOIN public.log_config pol ON pol.name = 'policy'
                  -- The cap as the policy's newest change says it, not as its row does (CapSealed): every policy change logs the whole policy as its `value`.
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
                  ) lpol ON true
                  LEFT JOIN LATERAL (
                      SELECT (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS window_ms
                  ) cap0 ON true
                  LEFT JOIN LATERAL (SELECT cap0.count, cap0.window_ms, least(60000, cap0.window_ms / 10) AS refresh) cap ON true
                  LEFT JOIN public.credentials c ON c.id = p_credential
                  LEFT JOIN public.vault_members m ON m.principal = c.principal
                  LEFT JOIN public.secrets s ON s.id = p_secret
                  LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
                  LEFT JOIN public.environments e ON e.id = s.environment_id
                  LEFT JOIN public.log_bulk b ON b.principal = c.principal AND b.secret = p_secret
            ),
            v AS MATERIALIZED (
                SELECT i.*,
                    CASE WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         WHEN i.p IS NOT NULL AND NOT locked AND coalesce(i.bulk_last <= p_at - i.cap_refresh, true) THEN 'lock' END AS state,
                    greatest(lc.number, lm.number, ls.number, le.number, i.policy_number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, ls.seal AS s_last, le.seal AS e_last,
                    p_cover IS NOT NULL AND i.bulk_last > p_at - i.cap_refresh
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover AND u.credential = p_credential AND u.secret = p_secret)
                        AND p_cover > coalesce(greatest(lc.number, lm.number, ls.number, le.number, i.policy_number), 0) AS is_covered,
                    coalesce(i.bulk_last > p_at - i.cap_window - i.cap_refresh, false) AS is_in,
                    coalesce(i.bulk_last <= p_at - i.cap_refresh, true) AS stale,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - i.cap_refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - i.cap_window - i.cap_refresh - public.deadline_max()
                             LIMIT i.cap_count
                        ) x
                    ) ELSE 0 END AS n_others,
                    i.cap_count AS n_cap
                  FROM i
                  -- Each input's newest change, unless the isolate's seals are known current (the other form).
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_credential ORDER BY x.number DESC LIMIT 1) lc ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_member ORDER BY x.number DESC LIMIT 1) lm ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_secret ORDER BY x.number DESC LIMIT 1) ls ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_environment ORDER BY x.number DESC LIMIT 1) le ON true
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered
                RETURNING log_uses.number
            ),
            k AS (
                INSERT INTO public.log_bulk (principal, secret, last)
                SELECT v.p, p_secret, p_at FROM v
                 WHERE v.state IS NULL AND v.p IS NOT NULL AND NOT v.is_covered AND v.stale AND (v.is_in OR v.n_others < v.n_cap)
                ON CONFLICT ON CONSTRAINT log_bulk_pkey DO UPDATE SET last = EXCLUDED.last
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.is_covered THEN p_cover END, v.p, v.newest, v.newest_mac, CASE WHEN NOT v.cached THEN v.inputs END,
                v.c_kind, v.c_generation, v.c_scope, v.c_places, v.c_constraints, v.c_revoked, v.c_expires, v.c_not_after, v.c_seal, v.c_last,
                v.m_status, v.m_role, v.m_scope, v.m_generation,
                (SELECT json_agg(json_build_array(g.project_id, g.environment_id, g.environment_slug, g.role, g.expires_at)) FROM public.vault_grants g WHERE g.principal = v.p),
                v.m_seal, v.m_last,
                v.s_environment, v.s_archived, v.s_version, v.s_seal, v.s_last,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive,
                v.e_project, v.e_parent, v.e_owner, v.e_archived, v.e_deleted, v.e_protected, v.e_seal, v.e_last,
                v.cap_count, v.cap_window, v.policy_seal, v.policy_last,
                v.is_in, v.n_others
              INTO r FROM v;
        ELSE
            -- The isolate's seals: no probe, only whether a change came since (then nothing is written: 'reprobe').
            WITH n AS MATERIALIZED (
                SELECT x.number AS newest, x.mac AS newest_mac, coalesce(x.number = p_known AND x.mac = p_known_mac, false) AS cached
                  FROM public.log_changes x ORDER BY x.number DESC LIMIT 1
            ),
            v AS MATERIALIZED (
                SELECT n.newest, n.newest_mac, coalesce(n.cached, false) AS cached,
                    CASE WHEN NOT coalesce(n.cached, false) THEN 'reprobe'
                         WHEN f.at_floor IS NULL OR p_at < f.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN cap.count IS NULL OR cap.window_ms IS NULL THEN 'unconfigured'
                         WHEN c.principal IS NOT NULL AND NOT locked AND coalesce(b.last <= p_at - cap.refresh, true) THEN 'lock' END AS state,
                    c.principal AS p, c.kind AS c_kind, c.generation AS c_generation, c.scope AS c_scope, c.places AS c_places, c.constraints AS c_constraints,
                    c.revoked_at IS NOT NULL AS c_revoked, (extract(epoch FROM c.expires_at) * 1000)::bigint AS c_expires,
                    (extract(epoch FROM c.not_after) * 1000)::bigint AS c_not_after, c.seal AS c_seal,
                    m.status AS m_status, m.role AS m_role, m.scope AS m_scope, m.generation AS m_generation, m.seal AS m_seal,
                    s.environment_id AS s_environment, s.archived_at IS NOT NULL AS s_archived, s.current_version_id AS s_version, s.seal AS s_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive,
                    e.project_id AS e_project, e.parent_id AS e_parent, e.owner AS e_owner, e.archived_at IS NOT NULL AS e_archived, strpos(e.slug, '~') > 0 AS e_deleted,
                    e.protected AS e_protected, e.seal AS e_seal,
                    cap.count AS cap_count, cap.window_ms AS cap_window, pol.seal AS policy_seal,
                    -- The isolate checked its cover against the seals' numbers when it read them.
                    p_cover IS NOT NULL AND b.last > p_at - cap.refresh
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover AND u.credential = p_credential AND u.secret = p_secret) AS is_covered,
                    coalesce(b.last > p_at - cap.window_ms - cap.refresh, false) AS is_in,
                    coalesce(b.last <= p_at - cap.refresh, true) AS stale,
                    CASE WHEN locked AND c.principal IS NOT NULL AND NOT coalesce(b.last > p_at - cap.window_ms - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = c.principal AND o.secret <> p_secret AND o.last > p_at - cap.window_ms - cap.refresh - public.deadline_max()
                             LIMIT cap.count
                        ) x
                    ) ELSE 0 END AS n_others,
                    cap.count AS n_cap
                  FROM (SELECT 1) one
                  LEFT JOIN n ON true
                  LEFT JOIN public.log_fence f ON f.only_row
                  LEFT JOIN public.log_config pol ON pol.name = 'policy'
                  -- The cap as the policy's newest change says it, not as its row does (CapSealed): every policy change logs the whole policy as its `value`.
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
                  ) lpol ON true
                  LEFT JOIN LATERAL (
                      SELECT (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS window_ms
                  ) cap0 ON true
                  LEFT JOIN LATERAL (SELECT cap0.count, cap0.window_ms, least(60000, cap0.window_ms / 10) AS refresh) cap ON true
                  LEFT JOIN public.credentials c ON c.id = p_credential
                  LEFT JOIN public.vault_members m ON m.principal = c.principal
                  LEFT JOIN public.secrets s ON s.id = p_secret
                  LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
                  LEFT JOIN public.environments e ON e.id = s.environment_id
                  LEFT JOIN public.log_bulk b ON b.principal = c.principal AND b.secret = p_secret
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered
                RETURNING log_uses.number
            ),
            k AS (
                INSERT INTO public.log_bulk (principal, secret, last)
                SELECT v.p, p_secret, p_at FROM v
                 WHERE v.state IS NULL AND v.p IS NOT NULL AND NOT v.is_covered AND v.stale AND (v.is_in OR v.n_others < v.n_cap)
                ON CONFLICT ON CONSTRAINT log_bulk_pkey DO UPDATE SET last = EXCLUDED.last
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.is_covered THEN p_cover END, v.p, v.newest, v.newest_mac, NULL::bigint,
                v.c_kind, v.c_generation, v.c_scope, v.c_places, v.c_constraints, v.c_revoked, v.c_expires, v.c_not_after, v.c_seal, NULL::bytea,
                v.m_status, v.m_role, v.m_scope, v.m_generation,
                (SELECT json_agg(json_build_array(g.project_id, g.environment_id, g.environment_slug, g.role, g.expires_at)) FROM public.vault_grants g WHERE g.principal = v.p),
                v.m_seal, NULL::bytea,
                v.s_environment, v.s_archived, v.s_version, v.s_seal, NULL::bytea,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive,
                v.e_project, v.e_parent, v.e_owner, v.e_archived, v.e_deleted, v.e_protected, v.e_seal, NULL::bytea,
                v.cap_count, v.cap_window, v.policy_seal, NULL::bytea,
                v.is_in, v.n_others
              INTO r FROM v;
        END IF;
        IF r.state = 'reprobe' THEN probe := true; CONTINUE; END IF;
        EXIT WHEN r.state IS DISTINCT FROM 'lock';
        -- Its key's bulk row is stale or missing: this use may write it, so it takes its principal's lock and reads again.
        PERFORM pg_advisory_xact_lock(1668244066, hashtext(r.principal));
        locked := true;
    END LOOP;
    -- The deadline holds in Postgres to the end: a call that ran past it rolls back and writes nothing. The hot-path login's lock_timeout and statement_timeout bound the waits.
    IF r.state IS NULL AND (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN
        RAISE EXCEPTION 'past its deadline' USING ERRCODE = '57014';
    END IF;
    RETURN r;
END
$$;
--> statement-breakpoint
-- A change (hot-path-one.md, "A change"): the fence exclusive, so that no use overlaps it; a retry finds its entry and answers its number (a request id names one change: another under it is refused); a row that is not its object's newest change's is refused, as a use refuses it (ChangeChecksSeal: else a row put back from before a change, validly sealed once, would be sealed again under the next change, and serve what the log says was taken away); the object's row moves only from the seal the vault read (ChangeCAS: of two changes to one object, the second finds another seal and does nothing: null); then its entry, numbered now. It answers the number, which a change waits to see sealed (R51).
--
-- This schema knows one op, `genesis`: the object's row sealed as it is, or, for the policy and the roles, made from the payload's `value`. That is the cutover's (plan, PR 9); the ops that change what a row says come with the 0.15 change path (PR 4), each applied as its payload says.
CREATE FUNCTION change_input(
    p_kind text, p_id text, p_request text, p_at bigint, p_actor text, p_payload text, p_seal_from bytea, p_seal bytea, p_mac bytea
) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    op jsonb := p_payload::jsonb;
    target uuid := public.log_object(p_kind, p_id);
    n bigint;
    done integer;
    member text;
    held bytea;
    newest bytea;
BEGIN
    -- Its locks in the order 0.14's writers take theirs, so that none waits on the other in a circle until 0.16 (row,
    -- head, fence): the member's queue (MEMBER_QUEUE, 0x636f666d) and row first, a principal's own or a credential's
    -- (0.14's vault locks them before the head, lockMembers; a change that fences 0.14 too moves the member's
    -- access_seq, plan PR 9), then 0.14's head (its app takes it before its rows), then the fence (0.14's appends
    -- take it after the head, audit_log_fence). The head held, no 0.14 write lands between this change and its entry
    -- (ChangeHeadFirst).
    member := CASE p_kind
        WHEN 'principal' THEN p_id
        WHEN 'credential' THEN coalesce(
            (SELECT c.principal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.principal FROM public.service_bindings b WHERE b.id = p_id::uuid))
    END;
    IF member IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(1668245101, hashtext(m.principal)) FROM public.vault_members m WHERE m.principal = member FOR NO KEY UPDATE;
    END IF;
    PERFORM 1 FROM public.audit_chain_head WHERE only_row FOR UPDATE;
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request;
    IF FOUND THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.log_changes c
             WHERE c.request_id = p_request AND c.object = target AND c.payload = p_payload AND c.seal IS NOT DISTINCT FROM p_seal
        ) THEN
            RAISE EXCEPTION 'request % names another change', p_request USING ERRCODE = 'unique_violation';
        END IF;
        RETURN n;
    END IF;
    IF op ->> 'op' IS DISTINCT FROM 'genesis' THEN
        RAISE EXCEPTION 'this schema knows no change %', op ->> 'op' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- ChangeChecksSeal: the row's seal is its object's newest change's, or the object has neither yet (one probe, as
    -- a use makes). A row deleted outright, or a seal no change wrote, is stale too.
    held := CASE p_kind
        WHEN 'principal' THEN (SELECT m.seal FROM public.vault_members m WHERE m.principal = p_id)
        WHEN 'credential' THEN coalesce(
            (SELECT c.seal FROM public.credentials c WHERE c.id = p_id::uuid),
            (SELECT b.seal FROM public.service_bindings b WHERE b.id = p_id::uuid))
        WHEN 'environment' THEN (SELECT e.seal FROM public.environments e WHERE e.id = p_id::uuid)
        WHEN 'secret' THEN (SELECT x.seal FROM public.secrets x WHERE x.id = p_id::uuid)
        WHEN 'policy' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'policy')
        WHEN 'roles' THEN (SELECT g.seal FROM public.log_config g WHERE g.name = 'roles')
    END;
    newest := (SELECT c.seal FROM public.log_changes c WHERE c.object = target ORDER BY c.number DESC LIMIT 1);
    IF held IS DISTINCT FROM newest THEN
        RAISE EXCEPTION 'the % object''s row is not its newest change''s: stale', p_kind USING ERRCODE = 'data_corrupted';
    END IF;
    CASE p_kind
        WHEN 'principal' THEN
            UPDATE public.vault_members SET seal = p_seal WHERE principal = p_id AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'credential' THEN
            -- A token's row, or a trust binding's: one kind of object, ids that never meet.
            UPDATE public.credentials SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            GET DIAGNOSTICS done = ROW_COUNT;
            IF done = 0 THEN
                UPDATE public.service_bindings SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
            END IF;
        WHEN 'environment' THEN
            UPDATE public.environments SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'secret' THEN
            UPDATE public.secrets SET seal = p_seal WHERE id = p_id::uuid AND seal IS NOT DISTINCT FROM p_seal_from;
        WHEN 'policy', 'roles' THEN
            IF p_id <> 'instance' OR p_seal_from IS NOT NULL OR op -> 'value' IS NULL THEN
                RAISE EXCEPTION 'the % object is one, made once from its value', p_kind USING ERRCODE = 'invalid_parameter_value';
            END IF;
            INSERT INTO public.log_config (name, value, seal) VALUES (p_kind, (op -> 'value')::text, p_seal) ON CONFLICT (name) DO NOTHING;
        ELSE
            RAISE EXCEPTION 'no object kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END CASE;
    -- A row gone, a row whose seal is no longer the one read, or an object made already: nothing was done.
    GET DIAGNOSTICS done = ROW_COUNT;
    IF done = 0 THEN RETURN NULL; END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
        VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, p_seal, p_mac)
        RETURNING number INTO n;
    RETURN n;
END
$$;
--> statement-breakpoint
-- The checkpointer's barrier: under the fence exclusive, no use or change is in flight, so every number handed out so far is final (committed, or a gap for good). It answers the last one, which the next checkpoint closes up to: no lag, and no number check in the uses. It raises the floor of `at` to its clock less deadline_max(), never lowers it; the uses after it are held to it. It also answers the floor it found: the one the last barrier set, which the checkpointer holds against the floor of its last signed checkpoint and alarms on any other (W211's spec: a writer who lowers the floor puts uses where no checkpoint reads).
CREATE FUNCTION close_one() RETURNS TABLE (upto bigint, at_floor bigint, floor_found bigint)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    found_floor bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    SELECT f.at_floor INTO found_floor FROM public.log_fence f WHERE f.only_row;
    UPDATE public.log_fence f SET at_floor = greatest(f.at_floor, (extract(epoch FROM clock_timestamp()) * 1000)::bigint - public.deadline_max()) WHERE f.only_row;
    RETURN QUERY SELECT pg_sequence_last_value('public.log_number'), f.at_floor, found_floor FROM public.log_fence f WHERE f.only_row;
END
$$;
--> statement-breakpoint
-- The bulk cap's rows that count for nothing any more, at most p_limit a call: older than the policy's window (its newest change's, as a use reads it), its refresh and the deadline, by the database's clock, less an hour for the clock stepping back (as prune_vault_releases). No caller chooses the bound, so the vault's login, which deletes no row itself, cannot forget a key the window counts; the replay keeps them, which changes none of its decisions. A row a use holds is left to the next call.
CREATE FUNCTION prune_bulk(p_limit integer) RETURNS integer
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '3s' AS $$
    WITH bound AS (
        SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint - w.window_ms - least(60000, w.window_ms / 10) - public.deadline_max() - 3600000 AS before
          FROM (
              SELECT (x.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS window_ms FROM public.log_changes x
               WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
          ) w
         WHERE w.window_ms IS NOT NULL
    ),
    pruned AS (
        DELETE FROM public.log_bulk
         WHERE last < (SELECT before FROM bound)
           AND ctid IN (SELECT ctid FROM public.log_bulk WHERE last < (SELECT before FROM bound) LIMIT p_limit FOR UPDATE SKIP LOCKED)
        RETURNING 1
    )
    SELECT count(*)::integer FROM pruned;
$$;
--> statement-breakpoint
-- OldWritesFence (plan, PR 9: "old uses in flight"): until 0.16 removes 0.14's path, 0.14 still writes decision inputs, nearly always with an entry in audit_log in the transaction that writes them. Each such entry takes the 0.15 fence exclusive, as a 0.15 change does, so that no 0.15 use is in flight across it: one that read before it commits first, and one after reads what it wrote (refused stale until the vault adopts it). It runs after 0.14's append took the log's head, so 0.14's order is head then fence, the order a 0.15 change that fences 0.14 too takes them (the reverse deadlocks). Every allowed entry fences but those that change no input, the list W211's spec (Migration015.tla, OldWritesFence) names: reads and uses, sign-ins (a credential nobody holds yet; a sign-out revokes one, and fences), and the log's own bookkeeping and alarms. So 0.14's uses never wait on it, and an action this list does not name fences rather than slips past. A refused entry changes nothing. Nothing takes the fence before 0.15 runs: until then it costs an uncontended lock per change. The fence orders only what has an entry: 0.14's entry-less writes (a session's renewal, renewSession, moving a credential's expiry; last-use stamps) are ordered by the seals instead, a renewed row matching no change until the vault adopts it, and a stamp no part of any object (W216).
CREATE FUNCTION log_fence_old_write() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(1668244070, 0);
    RETURN NULL;
END
$$;
--> statement-breakpoint
-- A trigger runs its function whoever may execute it: no login may call it otherwise.
REVOKE ALL ON FUNCTION log_fence_old_write() FROM PUBLIC;
--> statement-breakpoint
CREATE TRIGGER audit_log_fence AFTER INSERT ON audit_log FOR EACH ROW
    WHEN (NEW.decision = 'allow' AND NEW.action NOT IN (
        'credential.use', 'token.use', 'secret.read', 'secret.use', 'secret.list', 'secret.history', 'secret.version', 'missing.list', 'personal.list',
        'roles.list', 'roles.preview', 'mcp.read', 'mcp.view', 'audit.read',
        'sign_in', 'device.approve', 'device.deny',
        'audit.heartbeat', 'audit.checkpoint', 'audit.finding', 'audit.finding_cleared', 'key.check', 'key.intent', 'workload.alert', 'vault.tampered'
    ))
    EXECUTE FUNCTION log_fence_old_write();
--> statement-breakpoint
REVOKE ALL ON FUNCTION make_day(date), make_tiles(bigint, bigint), use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea), change_input(text, text, text, bigint, text, text, bytea, bytea, bytea), close_one(), prune_bulk(integer) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION make_day(date), make_tiles(bigint, bigint), use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea), change_input(text, text, text, bigint, text, text, bytea, bytea, bytea), close_one(), prune_bulk(integer) TO coffre_vault;
--> statement-breakpoint
-- The vault reads all of it; the backup reads every table, partitions included (pg_dump reads each), and the sequence. The app reads none: it never decides.
GRANT SELECT ON log_config, log_changes, log_uses, log_bulk, log_fence, log_checkpoints, log_tiles TO coffre_vault;
--> statement-breakpoint
GRANT SELECT ON log_config, log_changes, log_uses, log_bulk, log_fence, log_checkpoints, log_tiles, log_tiles_changes, log_tiles_uses, log_tiles_uses_leaves, log_tiles_uses_upper TO coffre_backup;
--> statement-breakpoint
GRANT SELECT ON SEQUENCE log_number TO coffre_backup;
--> statement-breakpoint
-- The 0.15 hot path's login (plan, PR 2): the vault's, through coffre_vault, with the hot path's settings, which set on coffre_vault_runtime would change 0.14's behaviour from this migration to the deploy. lock_timeout and statement_timeout bound what a use waits for and runs (R53); generic plans, because Postgres's auto mode planned use_credential's statement about ten times as often, 26 ms a plan under load (hot-path-one.md, decision 7). A role's settings apply to the role that logs in, never through a group, so they are this role's own. Made here unable to log in, as 0019 makes coffre_backup: `coffre setup`, or the host, gives it a password (plan, PR 5), which is never ours.
DO $$
DECLARE
    held text[];
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_vault_hot') THEN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolcreaterole)) THEN
            RAISE EXCEPTION '% may not create roles, and this migration makes coffre_vault_hot: migrate as a login with CREATEROLE, or have one run CREATE ROLE coffre_vault_hot NOLOGIN; ALTER ROLE coffre_vault_hot SET lock_timeout = ''1s''; ALTER ROLE coffre_vault_hot SET statement_timeout = ''2s''; ALTER ROLE coffre_vault_hot SET plan_cache_mode = force_generic_plan; GRANT coffre_vault TO coffre_vault_hot WITH ADMIN FALSE, INHERIT TRUE, SET FALSE first', current_user;
        END IF;
        -- Roles are the server's, and the migration lock each database's: another database's 0022 may make it meanwhile.
        BEGIN
            CREATE ROLE coffre_vault_hot NOLOGIN INHERIT NOCREATEDB NOCREATEROLE;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN
            NULL;
        END;
    END IF;
    -- As 0019 holds coffre_backup: the superuser-only attributes refused (managed owners cannot ALTER them, even
    -- off), the others turned off, only when they must be (altering a role takes CREATEROLE too). Whether it logs in is
    -- left as found: a role made here cannot, one a host made for 0.15 may.
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'coffre_vault_hot'
        AND (rolsuper OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'coffre_vault_hot has unsafe role attributes: SUPERUSER, REPLICATION and BYPASSRLS must be off';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_shdepend
         WHERE refclassid = 'pg_authid'::regclass AND refobjid = 'coffre_vault_hot'::regrole AND deptype = 'o'
    ) THEN
        RAISE EXCEPTION 'coffre_vault_hot owns database objects';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members WHERE member = 'coffre_vault_hot'::regrole AND roleid <> 'coffre_vault'::regrole
    ) THEN
        RAISE EXCEPTION 'coffre_vault_hot is a member of a role other than coffre_vault: revoke its memberships';
    END IF;
    -- Memberships are kept per grantor: one that may set the group, or grant it, stays in force beside the one made here.
    IF EXISTS (
        SELECT 1 FROM pg_auth_members WHERE member = 'coffre_vault_hot'::regrole AND roleid = 'coffre_vault'::regrole AND (set_option OR admin_option)
    ) THEN
        RAISE EXCEPTION 'coffre_vault_hot may set or grant coffre_vault: have its grantor run REVOKE coffre_vault FROM coffre_vault_hot, then migrate again';
    END IF;
    -- A setting for this database alone would override the role's at login: one of the three there is refused.
    IF EXISTS (
        SELECT 1 FROM pg_db_role_setting s, unnest(s.setconfig) AS setting
         WHERE s.setrole = 'coffre_vault_hot'::regrole AND s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
           AND split_part(setting, '=', 1) IN ('lock_timeout', 'statement_timeout', 'plan_cache_mode')
    ) THEN
        RAISE EXCEPTION 'coffre_vault_hot has its own lock_timeout, statement_timeout or plan_cache_mode in this database, over the hot path''s: run ALTER ROLE coffre_vault_hot IN DATABASE % RESET ALL, then migrate again', quote_ident(current_database());
    END IF;
    -- Only what differs, each tried, and a refusal said with what to run: changing a role another made takes, on
    -- Postgres 16, CREATEROLE and its ADMIN, and granting the group its ADMIN (as setup's changeRole says it).
    SELECT setconfig INTO held FROM pg_db_role_setting WHERE setrole = 'coffre_vault_hot'::regrole AND setdatabase = 0;
    BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_vault_hot' AND (NOT rolinherit OR rolcreatedb OR rolcreaterole)) THEN
            ALTER ROLE coffre_vault_hot INHERIT NOCREATEDB NOCREATEROLE;
        END IF;
        IF NOT coalesce(held @> ARRAY['lock_timeout=1s'], false) THEN ALTER ROLE coffre_vault_hot SET lock_timeout = '1s'; END IF;
        IF NOT coalesce(held @> ARRAY['statement_timeout=2s'], false) THEN ALTER ROLE coffre_vault_hot SET statement_timeout = '2s'; END IF;
        IF NOT coalesce(held @> ARRAY['plan_cache_mode=force_generic_plan'], false) THEN ALTER ROLE coffre_vault_hot SET plan_cache_mode = force_generic_plan; END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_auth_members WHERE member = 'coffre_vault_hot'::regrole AND roleid = 'coffre_vault'::regrole AND inherit_option
        ) THEN
            GRANT coffre_vault TO coffre_vault_hot WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
        END IF;
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION '% may not make coffre_vault_hot what 0.15 needs (%): have a login with CREATEROLE and ADMIN on both roles run ALTER ROLE coffre_vault_hot INHERIT NOCREATEDB NOCREATEROLE; ALTER ROLE coffre_vault_hot SET lock_timeout = ''1s''; ALTER ROLE coffre_vault_hot SET statement_timeout = ''2s''; ALTER ROLE coffre_vault_hot SET plan_cache_mode = force_generic_plan; GRANT coffre_vault TO coffre_vault_hot WITH ADMIN FALSE, INHERIT TRUE, SET FALSE first', current_user, SQLERRM;
    END;
END
$$;
