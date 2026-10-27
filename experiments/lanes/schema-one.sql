-- Variant `one` (W208, then W211): the simple hot path in one round trip, with no revision. Synthetic data only.
--
-- A use is one call, use_credential: the fence lock shared, then one statement that reads
-- everything the decision needs and inserts the use's entry, numbered from the sequence. A change
-- is one call, change_input: the lock exclusive, the write, its entry, from the same sequence.
-- Every number is taken under the lock and the lock goes with the commit, so no use overlaps a
-- change, and the number alone orders uses against changes (formal/HotPathOne.tla).
--
-- An entry is the request, not the outcome: the outcome is recomputed from the changes numbered
-- before it (verify-one.ts). So every input a decision reads is sealed to the log (W211): each row
-- carries `seal`, the vault's MAC over it, and the change that wrote it last records the same seal.
-- A row put back from before a change (validly sealed once) no longer matches its object's newest
-- change, and the use is refused `stale`. The vault MACs everything in an entry but its number,
-- which it does not know when it calls; a checkpoint binds numbers to MACs. MACs and seals are
-- HMAC-SHA256 cut to 16 bytes.
DROP TABLE IF EXISTS environments, members, grants, secrets, credentials, log, head, lane_log, lanes, pending, revision,
  audit, audit_head, checkpoints, entries, changes, uses, bulk, fence CASCADE;
DROP SEQUENCE IF EXISTS audit_seq, entry_number;
DROP FUNCTION IF EXISTS deadline_max(), close_one(), make_day(date);
DROP FUNCTION IF EXISTS use_credential, change_member, change_input;
DROP TYPE IF EXISTS use_view CASCADE;

-- The decision's inputs, each sealed: a member with its grants, a credential, a secret with its
-- wrapped key, an environment. Each is one object of the log: `member:<principal>`,
-- `credential:<id>`, `secret:<id>`, `environment:<id>`.
CREATE TABLE environments (id uuid PRIMARY KEY, deleted boolean NOT NULL DEFAULT false, seal bytea NOT NULL);
CREATE TABLE members (principal text PRIMARY KEY, status text NOT NULL, role text, seal bytea NOT NULL);
CREATE TABLE grants (principal text NOT NULL, environment_id uuid NOT NULL, role text NOT NULL, PRIMARY KEY (principal, environment_id));
CREATE TABLE secrets (id uuid PRIMARY KEY, environment_id uuid NOT NULL, nature text NOT NULL, wrapped bytea NOT NULL, iv bytea NOT NULL, seal bytea NOT NULL);
-- expires_at: decided at the entry's time, so a replay decides the same.
CREATE TABLE credentials (id uuid PRIMARY KEY, principal text NOT NULL, revoked boolean NOT NULL DEFAULT false, expires_at bigint, seal bytea NOT NULL);

-- CACHE 1 (the default): numbers rise in the order they are taken, across sessions. A cache per
-- session would hand a later call a smaller number and break the order.
CREATE SEQUENCE entry_number CACHE 1;

-- The log, in two tables numbered from one sequence.
--
-- Changes, kept for good: a decision reads the seal of each input's newest one, and a replay
-- starts from them. `object` names what it changes, `seal` is that object's seal after it (null
-- for configuration, which no row holds), `payload` what it does, as change_input applies it.
CREATE TABLE changes (
  number bigint PRIMARY KEY,
  at bigint NOT NULL,                 -- ms, the vault's clock when it asked
  request_id text NOT NULL UNIQUE,    -- a request id names one change: its replay finds it
  object text NOT NULL,
  actor text NOT NULL,
  payload text NOT NULL,
  seal bytea,
  mac bytea NOT NULL                  -- the vault's, over everything above but `number`
);
-- Each input's newest change, from the index alone (its seal included): one probe per input.
CREATE INDEX changes_object ON changes (object, number) INCLUDE (seal);

-- Uses, slim (W211): number, time, request id, credential, secret, MAC. No principal (the
-- credential's, which never changes: the replay maps it from its `credential.issue`), no
-- environment (the secret's), no kind (the table says it). Partitioned by the day of their `at`,
-- which retention drops whole.
--
-- A call replayed after its answer was lost (by Hyperdrive or the driver) must find its entry, not
-- write a second one: (at, request_id) is unique, and both are the request's own, under its MAC, so a
-- replay repeats them and lands in the same day. That is why the day is the request's time and not
-- its number: a replay across midnight would get a number in the next day's range and miss the index.
-- (W209 proposes days by number instead, recorded in signed day entries: open, docs/design/hot-path-one.md.)
--
-- A use row has one index, its replay's: `at` first, so that inserts go to the index's right edge.
-- A unique index on a partitioned table must include its partition key, so a use's `number` is unique
-- by the sequence alone (the verifier checks it), and has no index: every checkpoint barrier raises
-- `fence.at_floor`, under the lock exclusive, and a use whose `at` is below it writes nothing
-- (use_credential). So every use numbered after a barrier has an `at` at or above that barrier's
-- floor, and the next checkpoint finds its window through this index from there (`ENTRIES` in
-- src/one.ts). This holds by what the rows say, whatever any clock does: a clock that steps back
-- can only refuse uses, never hide one from a checkpoint.
CREATE TABLE uses (
  number bigint NOT NULL,
  at bigint NOT NULL,
  request_id bigint NOT NULL,         -- random, unique within its millisecond
  credential uuid NOT NULL,
  secret uuid NOT NULL,
  mac bytea NOT NULL
) PARTITION BY RANGE (at);
CREATE UNIQUE INDEX uses_request ON uses (at, request_id);

-- The bulk cap (R28, R52: `count` distinct keys per principal per rolling window, both the
-- deployment's): the last logged use of each key by each principal. Written only by uses that hold
-- the principal's lock (use_credential), at most once per `refresh` per key, so a hot key costs no
-- write per use. A row older than the window and a refresh counts for nothing; pruning may delete it.
CREATE TABLE bulk (principal text NOT NULL, secret uuid NOT NULL, last bigint NOT NULL, PRIMARY KEY (principal, secret));

CREATE OR REPLACE FUNCTION deadline_max() RETURNS bigint LANGUAGE sql IMMUTABLE AS 'SELECT 3000::bigint';
-- The lowest `at` a use may still be written with: raised by each barrier, never lowered. Its one
-- row is made here, below every use to come; without it, use_credential refuses every use.
CREATE TABLE fence (only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row), at_floor bigint NOT NULL);
INSERT INTO fence VALUES (true, (extract(epoch FROM clock_timestamp()) * 1000)::bigint - deadline_max());

-- A day's partition of uses, [day, day + 1) in ms since the epoch, UTC. Made ahead of time: a use at a
-- time no partition holds fails. Made apart, then attached: CREATE TABLE … PARTITION OF would take the
-- parent ACCESS EXCLUSIVE and queue every use behind whatever reads it; ATTACH takes SHARE UPDATE
-- EXCLUSIVE, which inserts do not wait for.
CREATE OR REPLACE FUNCTION make_day(p_day date) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  name text := 'uses_' || to_char(p_day, 'YYYYMMDD');
  lo bigint := (p_day - date '1970-01-01')::bigint * 86400000;
BEGIN
  IF to_regclass(name) IS NOT NULL THEN RETURN name; END IF;
  EXECUTE format('CREATE TABLE %I (LIKE uses INCLUDING DEFAULTS INCLUDING CONSTRAINTS)', name);
  EXECUTE format('CREATE UNIQUE INDEX ON %I (at, request_id)', name);
  EXECUTE format('ALTER TABLE uses ATTACH PARTITION %I FOR VALUES FROM (%s) TO (%s)', name, lo, lo + 86400000);
  RETURN name;
END $$;
-- A checkpoint: the vault's signature over every entry in (from, upto], in number order, chained to the one before.
-- at_floor: the floor its barrier set: the next window's uses have an `at` at or above it.
CREATE TABLE checkpoints (upto bigint PRIMARY KEY, from_number bigint NOT NULL, entries int NOT NULL, hash bytea NOT NULL, signature bytea NOT NULL,
  at_floor bigint NOT NULL, at bigint NOT NULL);

-- What a use reads, as use_credential returns it: `state` null if it did its work, 'late' if it did
-- nothing (the rest is then to be ignored).
CREATE TYPE use_view AS (state text, number bigint, covered bigint, principal text, newest bigint, newest_mac bytea, inputs bigint,
  c_revoked boolean, c_expires bigint, c_seal bytea, c_last bytea,
  m_status text, m_role text, m_seal bytea, m_last bytea, grants text[],
  s_environment uuid, s_nature text, s_wrapped bytea, s_iv bytea, s_seal bytea, s_last bytea,
  e_deleted boolean, e_seal bytea, e_last bytea,
  in_set boolean, others int);

-- A use: the lock shared, then one statement, with a snapshot of its own taken after the lock (a
-- volatile function's statements each take a new one under READ COMMITTED), that reads everything
-- the decision needs and inserts the entry, numbered now. The lock goes with the commit.
--
-- A call that comes after its deadline (Hyperdrive held it while the Worker gave up) writes nothing
-- and answers 'late', as does one with a deadline more than deadline_max() after its `at`, or an `at`
-- below the barrier's floor (or no floor row at all). A replay of a call that did write fails on
-- (at, request_id), 23505, and the Worker answers 503: deciding again on today's state could allow,
-- after a revocation, a use the log has before it. (Not ON CONFLICT: its speculative insertion
-- doubles a use's buffers and WAL records, for the rare replay.)
--
-- The bulk cap, with p_count, p_window and p_refresh (ms) the deployment's. A key is in the
-- principal's set at time t if its bulk row's `last` > t - window - refresh. A use of a key in the
-- set passes the cap; of a key not in it, only if fewer than p_count other keys are, and the key
-- enters (`last` := at). The others are counted over a longer bound, `last` > t - window - refresh -
-- deadline_max(): uses are decided in number order, not in the order of their `at`, so a key that
-- entered at a later `at` may already be in when an earlier one is decided (formal/HotPathOneClock.tla
-- finds two keys in one window without it). A use whose key's `last` is older than t - refresh moves it on to t. Every
-- request counts, allowed or refused for any reason but the cap itself: the log records requests.
-- Both writes happen under the principal's own lock: a use that finds its key's row stale (or
-- missing) writes nothing, takes that lock and runs the statement again, whose new snapshot sees
-- every earlier write. So the writes come in number order and a replay of the log decides each the
-- same (verify-one.ts). A key's row goes stale at most once per refresh, so nearly every use is the
-- one statement, takes no lock but the fence's and writes no row but its entry. `last` lags the
-- newest use by at most `refresh`, which the + refresh in the set's bound covers: however the uses
-- fall, no rolling window of `window` ms releases more than p_count keys (formal/HotPathOneClock.tla).
--
-- p_cover (fewer rows): the number of an allowed use of the same credential and secret that this
-- isolate wrote earlier. If no change to any of the decision's inputs was numbered after it, and
-- the key's bulk row is fresh (so the cap neither moves nor counts it), the use is a repeat of it:
-- nothing is written (a read-only transaction, no WAL), and the Worker still decides on what was
-- read. The first use after any change writes its own entry (formal/HotPathOne.tla, Covers). The
-- cover's entry must still be in the log (the isolate passes its `at` and request id: one probe of the
-- uses' index): a database restored to before it was written would otherwise let a repeat release a
-- value with no entry on disk (review r1).
--
-- Each input's newest change is one probe of changes_object, from the index alone: four probes, and
-- the plan nodes around them, about half of the call's server time. So the isolate keeps the four
-- seals it last read for a credential and secret, with the log's newest change at the time (its
-- number and MAC), and passes that change back (p_known, p_known_mac). If it is still the log's
-- newest, no input changed since, and the four seals the isolate holds are still each input's newest:
-- the call runs a statement with no probes at all. Else that statement writes nothing and answers
-- 'reprobe', the call runs the one that probes, and the isolate keeps what it read. The change is
-- named exactly, not as "nothing numbered above it": a database restored from a backup, or made
-- again, has its own changes under the same numbers, and older seals would pass (measured on
-- Cloudflare: isolates outlive a reseed). The check is in the statement's own snapshot, under the
-- fence shared, so no change can come between it and the reads. A cover the isolate passes with its
-- seals it has checked against their numbers; when the cache is stale, the statement checks it
-- against the probes. Two statements, not one with its probes skipped: a probe's plan nodes cost
-- most of it even when it does not run (measured).
CREATE OR REPLACE FUNCTION use_credential(p_credential uuid, p_secret uuid, p_request bigint, p_at bigint, p_mac bytea, p_deadline bigint,
  p_cover bigint, p_count int, p_window bigint, p_refresh bigint, p_known bigint DEFAULT NULL, p_known_mac bytea DEFAULT NULL,
  p_cover_at bigint DEFAULT NULL, p_cover_request bigint DEFAULT NULL)
RETURNS use_view LANGUAGE plpgsql AS $$
DECLARE
  r use_view;
  locked boolean := false;
  probe boolean := p_known IS NULL;
BEGIN
  IF p_deadline IS NULL OR p_deadline > p_at + deadline_max() THEN r.state := 'late'; RETURN r; END IF;
  PERFORM pg_advisory_xact_lock_shared(208);
  LOOP
    IF probe THEN
      WITH n AS MATERIALIZED (
        -- The log's newest change: whether the isolate's seals are still each input's newest.
        SELECT x.number AS newest, x.mac AS newest_mac, coalesce(x.number = p_known AND x.mac = p_known_mac, false) AS cached FROM changes x ORDER BY x.number DESC LIMIT 1
      ),
      v AS MATERIALIZED (
        SELECT n.newest, n.newest_mac, coalesce(n.cached, false) AS cached,
          CASE WHEN f.at_floor IS NULL OR p_at < f.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
               WHEN c.principal IS NOT NULL AND NOT locked AND coalesce(b.last <= p_at - p_refresh, true) THEN 'lock' END AS state,
          greatest(lc.number, lm.number, ls.number, le.number) AS inputs,
          c.principal AS p, c.revoked, c.expires_at, c.seal AS c_seal, lc.seal AS c_last,
          m.status, m.role, m.seal AS m_seal, lm.seal AS m_last,
          s.environment_id, s.nature, s.wrapped, s.iv, s.seal AS s_seal, ls.seal AS s_last,
          e.deleted, e.seal AS e_seal, le.seal AS e_last,
          p_cover IS NOT NULL AND b.last > p_at - p_refresh
            AND EXISTS (SELECT 1 FROM uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover)
            AND (p_cover > coalesce(greatest(lc.number, lm.number, ls.number, le.number), 0)) AS is_covered,
          coalesce(b.last > p_at - p_window - p_refresh, false) AS is_in,
          coalesce(b.last <= p_at - p_refresh, true) AS stale,
          -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
          CASE WHEN locked AND c.principal IS NOT NULL AND NOT coalesce(b.last > p_at - p_window - p_refresh, false) THEN (
            SELECT count(*)::int FROM (SELECT 1 FROM bulk o WHERE o.principal = c.principal AND o.secret <> p_secret AND o.last > p_at - p_window - p_refresh - deadline_max() LIMIT p_count) x
          ) ELSE 0 END AS n_others
        FROM (SELECT 1) one
        LEFT JOIN n ON true
        LEFT JOIN fence f ON f.only_row
        LEFT JOIN credentials c ON c.id = p_credential
        LEFT JOIN members m ON m.principal = c.principal
        LEFT JOIN secrets s ON s.id = p_secret
        LEFT JOIN environments e ON e.id = s.environment_id
        LEFT JOIN bulk b ON b.principal = c.principal AND b.secret = p_secret
        -- Each input's newest change, unless the isolate's seals are known current (`cached`: no probe at all).
        LEFT JOIN LATERAL (SELECT x.number, x.seal FROM changes x WHERE x.object = 'credential:' || p_credential ORDER BY x.number DESC LIMIT 1) lc ON true
        LEFT JOIN LATERAL (SELECT x.number, x.seal FROM changes x WHERE x.object = 'member:' || c.principal ORDER BY x.number DESC LIMIT 1) lm ON true
        LEFT JOIN LATERAL (SELECT x.number, x.seal FROM changes x WHERE x.object = 'secret:' || p_secret ORDER BY x.number DESC LIMIT 1) ls ON true
        LEFT JOIN LATERAL (SELECT x.number, x.seal FROM changes x WHERE x.object = 'environment:' || s.environment_id ORDER BY x.number DESC LIMIT 1) le ON true
      ),
      e AS (
        INSERT INTO uses (number, at, request_id, credential, secret, mac)
        SELECT nextval('entry_number'), p_at, p_request, p_credential, p_secret, p_mac FROM v WHERE v.state IS NULL AND NOT v.is_covered
        RETURNING uses.number
      ),
      w AS (
        INSERT INTO bulk (principal, secret, last)
        SELECT v.p, p_secret, p_at FROM v
        WHERE v.state IS NULL AND v.p IS NOT NULL AND NOT v.is_covered AND v.stale AND (v.is_in OR v.n_others < p_count)
        ON CONFLICT ON CONSTRAINT bulk_pkey DO UPDATE SET last = EXCLUDED.last
      )
      SELECT v.state, (SELECT e.number FROM e), CASE WHEN v.is_covered THEN p_cover END, v.p, v.newest, v.newest_mac, CASE WHEN NOT v.cached THEN v.inputs END,
        v.revoked, v.expires_at, v.c_seal, v.c_last,
        v.status, v.role, v.m_seal, v.m_last,
        (SELECT array_agg(g.environment_id::text || ':' || g.role) FROM grants g WHERE g.principal = v.p),
        v.environment_id, v.nature, v.wrapped, v.iv, v.s_seal, v.s_last,
        v.deleted, v.e_seal, v.e_last,
        v.is_in, v.n_others
      INTO r FROM v;
    ELSE
      -- The isolate's seals: no probe, only whether a change came since (then nothing is written: 'reprobe').
      WITH n AS MATERIALIZED (
        -- The log's newest change: whether the isolate's seals are still each input's newest.
        SELECT x.number AS newest, x.mac AS newest_mac, coalesce(x.number = p_known AND x.mac = p_known_mac, false) AS cached FROM changes x ORDER BY x.number DESC LIMIT 1
      ),
      v AS MATERIALIZED (
        SELECT n.newest, n.newest_mac, coalesce(n.cached, false) AS cached,
          CASE WHEN NOT coalesce(n.cached, false) THEN 'reprobe'
               WHEN f.at_floor IS NULL OR p_at < f.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
               WHEN c.principal IS NOT NULL AND NOT locked AND coalesce(b.last <= p_at - p_refresh, true) THEN 'lock' END AS state,
          NULL::bigint AS inputs,
          c.principal AS p, c.revoked, c.expires_at, c.seal AS c_seal, NULL::bytea AS c_last,
          m.status, m.role, m.seal AS m_seal, NULL::bytea AS m_last,
          s.environment_id, s.nature, s.wrapped, s.iv, s.seal AS s_seal, NULL::bytea AS s_last,
          e.deleted, e.seal AS e_seal, NULL::bytea AS e_last,
          p_cover IS NOT NULL AND b.last > p_at - p_refresh
            AND EXISTS (SELECT 1 FROM uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover)
            AS is_covered,
          coalesce(b.last > p_at - p_window - p_refresh, false) AS is_in,
          coalesce(b.last <= p_at - p_refresh, true) AS stale,
          -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
          CASE WHEN locked AND c.principal IS NOT NULL AND NOT coalesce(b.last > p_at - p_window - p_refresh, false) THEN (
            SELECT count(*)::int FROM (SELECT 1 FROM bulk o WHERE o.principal = c.principal AND o.secret <> p_secret AND o.last > p_at - p_window - p_refresh - deadline_max() LIMIT p_count) x
          ) ELSE 0 END AS n_others
        FROM (SELECT 1) one
        LEFT JOIN n ON true
        LEFT JOIN fence f ON f.only_row
        LEFT JOIN credentials c ON c.id = p_credential
        LEFT JOIN members m ON m.principal = c.principal
        LEFT JOIN secrets s ON s.id = p_secret
        LEFT JOIN environments e ON e.id = s.environment_id
        LEFT JOIN bulk b ON b.principal = c.principal AND b.secret = p_secret
      ),
      e AS (
        INSERT INTO uses (number, at, request_id, credential, secret, mac)
        SELECT nextval('entry_number'), p_at, p_request, p_credential, p_secret, p_mac FROM v WHERE v.state IS NULL AND NOT v.is_covered
        RETURNING uses.number
      ),
      w AS (
        INSERT INTO bulk (principal, secret, last)
        SELECT v.p, p_secret, p_at FROM v
        WHERE v.state IS NULL AND v.p IS NOT NULL AND NOT v.is_covered AND v.stale AND (v.is_in OR v.n_others < p_count)
        ON CONFLICT ON CONSTRAINT bulk_pkey DO UPDATE SET last = EXCLUDED.last
      )
      SELECT v.state, (SELECT e.number FROM e), CASE WHEN v.is_covered THEN p_cover END, v.p, v.newest, v.newest_mac, CASE WHEN NOT v.cached THEN v.inputs END,
        v.revoked, v.expires_at, v.c_seal, v.c_last,
        v.status, v.role, v.m_seal, v.m_last,
        (SELECT array_agg(g.environment_id::text || ':' || g.role) FROM grants g WHERE g.principal = v.p),
        v.environment_id, v.nature, v.wrapped, v.iv, v.s_seal, v.s_last,
        v.deleted, v.e_seal, v.e_last,
        v.is_in, v.n_others
      INTO r FROM v;
    END IF;
    IF r.state = 'reprobe' THEN probe := true; CONTINUE; END IF;
    EXIT WHEN r.state IS DISTINCT FROM 'lock';
    -- Its key's bulk row is stale or missing: this use may write it, so it takes its principal's lock and reads again.
    PERFORM pg_advisory_xact_lock(209, hashtext(r.principal));
    locked := true;
  END LOOP;
  -- The deadline holds in Postgres itself, to the end (R54: sealing trusts that nothing stamped more than
  -- deadline_max() ago still arrives): a call that ran past it, waiting for its principal's lock say,
  -- rolls back and writes nothing. The login's lock_timeout and statement_timeout bound the wait.
  IF r.state IS NULL AND (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN
    RAISE EXCEPTION 'past its deadline' USING ERRCODE = '57014';
  END IF;
  RETURN r;
END $$;

-- A change to one input, or to configuration (`config:…`, no row): under the lock exclusive, a
-- replay answers its entry's number (a request id names one change: another payload under it is
-- refused); the object's seal moves only from the one the vault read (of two changes to one object,
-- the second reads again: null), the payload is applied as logged, and its entry numbered now. It
-- returns the number, which a change waits to see sealed (R51).
CREATE OR REPLACE FUNCTION change_input(p_object text, p_request text, p_at bigint, p_actor text, p_payload text, p_seal_from bytea, p_seal bytea, p_mac bytea)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
  op json := p_payload::json;
  v_id text := split_part(p_object, ':', 2);
  n bigint;
  done boolean := true;
BEGIN
  PERFORM pg_advisory_xact_lock(208);
  SELECT c.number INTO n FROM changes c WHERE c.request_id = p_request;
  IF FOUND THEN
    IF NOT EXISTS (SELECT 1 FROM changes c WHERE c.request_id = p_request AND c.payload = p_payload AND c.object = p_object) THEN
      RAISE EXCEPTION 'request % names another change', p_request;
    END IF;
    RETURN n;
  END IF;
  CASE op->>'op'
    WHEN 'member.add' THEN
      INSERT INTO members VALUES (v_id, op->>'status', op->>'role', p_seal) ON CONFLICT DO NOTHING;
      done := FOUND;
    WHEN 'access.grant' THEN
      UPDATE members SET seal = p_seal WHERE principal = v_id AND seal = p_seal_from;
      done := FOUND;
      IF done THEN
        INSERT INTO grants VALUES (v_id, (op->>'environment')::uuid, op->>'role') ON CONFLICT (principal, environment_id) DO UPDATE SET role = EXCLUDED.role;
      END IF;
    WHEN 'access.revoke' THEN
      UPDATE members SET seal = p_seal WHERE principal = v_id AND seal = p_seal_from;
      done := FOUND;
      IF done THEN DELETE FROM grants WHERE principal = v_id AND environment_id = (op->>'environment')::uuid; END IF;
    WHEN 'credential.issue' THEN
      INSERT INTO credentials VALUES (v_id::uuid, op->>'principal', false, (op->>'expiresAt')::bigint, p_seal) ON CONFLICT DO NOTHING;
      done := FOUND;
    WHEN 'credential.revoke', 'credential.restore' THEN
      UPDATE credentials SET revoked = (op->>'op' = 'credential.revoke'), seal = p_seal WHERE credentials.id = v_id::uuid AND seal = p_seal_from;
      done := FOUND;
    WHEN 'environment.create' THEN
      INSERT INTO environments VALUES (v_id::uuid, false, p_seal) ON CONFLICT DO NOTHING;
      done := FOUND;
    WHEN 'environment.delete', 'environment.restore' THEN
      UPDATE environments SET deleted = (op->>'op' = 'environment.delete'), seal = p_seal WHERE environments.id = v_id::uuid AND seal = p_seal_from;
      done := FOUND;
    WHEN 'secret.create' THEN
      INSERT INTO secrets VALUES (v_id::uuid, (op->>'environment')::uuid, op->>'nature', decode(op->>'wrapped', 'hex'), decode(op->>'iv', 'hex'), p_seal) ON CONFLICT DO NOTHING;
      done := FOUND;
    WHEN 'secret.rotate' THEN
      UPDATE secrets SET wrapped = decode(op->>'wrapped', 'hex'), iv = decode(op->>'iv', 'hex'), seal = p_seal WHERE secrets.id = v_id::uuid AND seal = p_seal_from;
      done := FOUND;
    WHEN 'bulk.limit' THEN
      NULL;
  END CASE;
  -- A create that found its row, or a move from a seal the row no longer has: nothing was done.
  IF NOT done THEN RETURN NULL; END IF;
  INSERT INTO changes (number, at, request_id, object, actor, payload, seal, mac)
    VALUES (nextval('entry_number'), p_at, p_request, p_object, p_actor, p_payload, p_seal, p_mac)
    RETURNING changes.number INTO n;
  RETURN n;
END $$;

-- The checkpointer's barrier: under the lock exclusive, no use or change is in flight, so every
-- number handed out so far is final (committed, or a gap for good). It returns the last one: the
-- next checkpoint closes up to it. No lag, and no number check in the uses. It raises the floor of
-- `at` to its clock less deadline_max() (never lowers it), which the uses after it are held to.
CREATE OR REPLACE FUNCTION close_one() RETURNS TABLE (upto bigint, at_floor bigint) LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(208);
  UPDATE fence f SET at_floor = greatest(f.at_floor, (extract(epoch FROM clock_timestamp()) * 1000)::bigint - deadline_max()) WHERE only_row;
  RETURN QUERY SELECT pg_sequence_last_value('entry_number'), f.at_floor FROM fence f WHERE only_row;
END $$;

-- Pruning the bulk cap's rows that count for nothing any more (older than the window and its refresh, at
-- `p_before`), a batch at a time; the replay keeps them, which changes none of its decisions.
CREATE OR REPLACE FUNCTION prune_bulk(p_before bigint, p_limit int) RETURNS int LANGUAGE sql AS $$
  WITH gone AS (DELETE FROM bulk b WHERE b.ctid = ANY (ARRAY(SELECT o.ctid FROM bulk o WHERE o.last < p_before LIMIT p_limit)) RETURNING 1)
  SELECT count(*)::int FROM gone
$$;
