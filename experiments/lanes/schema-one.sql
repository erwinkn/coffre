-- Variant `one` (W208): the simple hot path in one round trip, with no revision. Synthetic data only.
--
-- A use is one call, use_credential: the fence lock shared, then one statement that reads
-- everything the decision needs and inserts the use's entry, numbered from the sequence. A change
-- is one call, change_member: the lock exclusive, the write, its entry, from the same sequence.
-- Every number is taken under the lock and the lock goes with the commit, so no use overlaps a
-- change, and the number alone orders uses against changes (formal/HotPathOne.tla).
--
-- An entry is the request, not the outcome: the outcome is recomputed from the changes numbered
-- before it (verify-one.ts). The vault MACs everything in it but its number, which it does not
-- know when it calls; a checkpoint binds numbers to MACs.
DROP TABLE IF EXISTS environments, members, grants, secrets, credentials, log, head, lane_log, lanes, pending, revision,
  audit, audit_head, checkpoints, entries, fence CASCADE;
DROP SEQUENCE IF EXISTS audit_seq, entry_number;
DROP FUNCTION IF EXISTS deadline_max(), close_one(), use_credential(text, text, text, bigint, text, bytea, bigint), use_credential(text, text, text, bigint, text, bytea, bigint, bigint), change_member(text, text, bigint, text, bytea, bytea, bytea), make_day(date);

CREATE TABLE environments (id uuid PRIMARY KEY, deleted boolean NOT NULL DEFAULT false);
-- seal: the vault's MAC over the member and its grants. A use is refused unless it is also the seal
-- the member's newest change wrote: a row put back from before a change (with its grants) is refused.
CREATE TABLE members (principal text PRIMARY KEY, status text NOT NULL, role text, seal bytea NOT NULL);
CREATE TABLE grants (principal text NOT NULL, environment_id uuid NOT NULL, role text NOT NULL, PRIMARY KEY (principal, environment_id));
CREATE TABLE secrets (id uuid PRIMARY KEY, environment_id uuid NOT NULL, nature text NOT NULL, wrapped bytea NOT NULL, iv bytea NOT NULL);
-- expires_at: decided at the entry's time, so a replay decides the same.
CREATE TABLE credentials (id text PRIMARY KEY, principal text NOT NULL, revoked boolean NOT NULL DEFAULT false, expires_at bigint);

-- CACHE 1 (the default): numbers rise in the order they are taken, across sessions. A cache per
-- session would hand a later call a smaller number and break the order.
CREATE SEQUENCE entry_number CACHE 1;

-- The log. Changes in a partition of their own, kept for good (a decision reads its member's newest
-- one; a replay starts from them); uses by the day of their `at`, which retention drops whole.
--
-- A call replayed after its answer was lost (by Hyperdrive or the driver) must find its entry, not
-- write a second one: (at, request_id) is unique, and both are the request's own, under its MAC, so a
-- replay repeats them and lands in the same day. That is why the day is the request's time and not
-- its number: a replay across midnight would get a number in the next day's range and miss the index.
CREATE TABLE entries (
  number bigint NOT NULL,
  at bigint NOT NULL,                 -- ms, the vault's clock when it asked: expiries are decided at it
  kind text NOT NULL,                 -- 'use' | 'change'
  principal text NOT NULL,
  credential text,
  request_id text NOT NULL,
  payload text NOT NULL,              -- use: what it asks for; change: what it does, as change_member applies it
  seal bytea,                         -- change: the member's seal it leaves
  mac bytea NOT NULL,                 -- the vault's, over everything above but `number`
  -- When the row was written, inside the lock: for the benches' check of commit order, not signed.
  written_at timestamptz NOT NULL DEFAULT clock_timestamp()
) PARTITION BY LIST (kind);
CREATE TABLE entries_changes PARTITION OF entries FOR VALUES IN ('change');
CREATE TABLE entries_uses PARTITION OF entries FOR VALUES IN ('use') PARTITION BY RANGE (at);
-- A use row has one index, its replay's: `at` first, so that inserts go to the index's right edge.
-- A unique index on a partitioned table must include its partition key, so a use's `number` is unique
-- by the sequence alone (the verifier checks it), and has no index: every checkpoint barrier raises
-- `fence.at_floor`, under the lock exclusive, and a use whose `at` is below it writes nothing
-- (use_credential). So every use numbered after a barrier has an `at` at or above that barrier's
-- floor, and the next checkpoint finds its window through this index from there (`ENTRIES` in
-- src/one.ts). This holds by what the rows say, whatever any clock does: a clock that steps back
-- can only refuse uses, never hide one from a checkpoint.
ALTER TABLE entries_changes ADD PRIMARY KEY (number);
CREATE UNIQUE INDEX entries_uses_request ON entries_uses (at, request_id);
CREATE OR REPLACE FUNCTION deadline_max() RETURNS bigint LANGUAGE sql IMMUTABLE AS 'SELECT 3000::bigint';
-- The lowest `at` a use may still be written with: raised by each barrier, never lowered.
CREATE TABLE fence (only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row), at_floor bigint NOT NULL);
CREATE UNIQUE INDEX entries_changes_request ON entries_changes (request_id);
CREATE INDEX entries_changes_principal ON entries_changes (principal, number);

-- A day's partition of uses, [day, day + 1) in ms since the epoch, UTC. Made ahead of time: a use at a
-- time no partition holds fails. Made apart, then attached: CREATE TABLE … PARTITION OF would take the
-- parent ACCESS EXCLUSIVE and queue every use behind whatever reads it; ATTACH takes SHARE UPDATE
-- EXCLUSIVE, which inserts do not wait for.
CREATE OR REPLACE FUNCTION make_day(p_day date) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  name text := 'entries_uses_' || to_char(p_day, 'YYYYMMDD');
  lo bigint := (p_day - date '1970-01-01')::bigint * 86400000;
BEGIN
  IF to_regclass(name) IS NOT NULL THEN RETURN name; END IF;
  EXECUTE format('CREATE TABLE %I (LIKE entries_uses INCLUDING DEFAULTS INCLUDING CONSTRAINTS)', name);
  EXECUTE format('CREATE UNIQUE INDEX ON %I (at, request_id)', name);
  EXECUTE format('ALTER TABLE entries_uses ATTACH PARTITION %I FOR VALUES FROM (%s) TO (%s)', name, lo, lo + 86400000);
  RETURN name;
END $$;
-- A checkpoint: the vault's signature over every entry in (from, upto], in number order, chained to the one before.
-- at_floor: the floor its barrier set: the next window's uses have an `at` at or above it.
CREATE TABLE checkpoints (upto bigint PRIMARY KEY, from_number bigint NOT NULL, entries int NOT NULL, hash bytea NOT NULL, signature bytea NOT NULL,
  at_floor bigint NOT NULL, at bigint NOT NULL);

-- A use: the lock shared; then, in a statement of its own (a volatile function's statements each
-- take a new snapshot under READ COMMITTED, after the lock), everything the decision reads and the
-- entry, numbered now. The lock goes with the commit. A call that comes after its deadline (Hyperdrive
-- held it while the Worker gave up) writes nothing and answers null, as does one with no deadline, a
-- deadline more than deadline_max() after its `at`, or an `at` below the barrier's floor. A replay of a call that did
-- write fails on (at, request_id), 23505, and the Worker answers 503: deciding again on today's state
-- could allow, after a revocation, a use the log has before it. (Not ON CONFLICT: its speculative
-- insertion doubles a use's buffers and WAL records, for the rare replay.)
--
-- p_cover (fewer rows): the number of an allowed use of the same credential and secret that this
-- isolate wrote earlier. If no change to the member was numbered after it, the use is a repeat of
-- it: nothing is written (a read-only transaction, no WAL), and the Worker still decides on what was
-- read. The first use after any change writes its own entry (formal/HotPathOne.tla, Covers). The
-- check is in the statement that reads, so one snapshot answers both (the shared lock already keeps
-- any change from committing in between).
CREATE OR REPLACE FUNCTION use_credential(p_principal text, p_credential text, p_request text, p_at bigint, p_payload text, p_mac bytea,
  p_deadline bigint, p_cover bigint DEFAULT NULL) RETURNS json LANGUAGE plpgsql AS $$
DECLARE
  v json;
BEGIN
  IF p_deadline IS NULL OR p_deadline > p_at + deadline_max() THEN RETURN NULL; END IF;
  PERFORM pg_advisory_xact_lock_shared(208);
  IF (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline OR p_at < (SELECT at_floor FROM fence WHERE only_row) THEN RETURN NULL; END IF;
  WITH c AS (
    SELECT p_cover IS NOT NULL AND p_cover > coalesce((SELECT max(number) FROM entries_changes WHERE principal = p_principal), 0) AS covered
  ),
  e AS (
    INSERT INTO entries_uses (number, at, kind, principal, credential, request_id, payload, mac)
    SELECT nextval('entry_number'), p_at, 'use', p_principal, p_credential, p_request, p_payload, p_mac FROM c WHERE NOT c.covered
    RETURNING number
  )
  SELECT json_build_object(
    'number', (SELECT number FROM e)::text,
    'covered', (SELECT CASE WHEN c.covered THEN p_cover::text END FROM c),
    'member', (SELECT json_build_object('principal', principal, 'status', status, 'role', role, 'seal', encode(seal, 'hex')) FROM members WHERE principal = p_principal),
    'grants', (SELECT coalesce(json_agg(json_build_object('environment_id', environment_id, 'role', role)), '[]') FROM grants WHERE principal = p_principal),
    'lastSeal', (SELECT encode(seal, 'hex') FROM entries_changes WHERE principal = p_principal ORDER BY number DESC LIMIT 1),
    'credential', (SELECT json_build_object('principal', principal, 'revoked', revoked, 'expiresAt', expires_at::text) FROM credentials WHERE id = p_credential),
    'environment', (SELECT json_build_object('id', id, 'deleted', deleted) FROM environments WHERE id = (p_payload::json->>'environment')::uuid),
    'secret', (SELECT json_build_object('id', id, 'environmentId', environment_id, 'nature', nature, 'wrapped', encode(wrapped, 'hex'), 'iv', encode(iv, 'hex'))
               FROM secrets WHERE id = (p_payload::json->>'secret')::uuid)
  ) INTO v;
  RETURN v;
END $$;

-- A change to a member: its grant taken or given, its credential revoked or restored. Under the lock
-- exclusive: a replay answers its entry's number; the member's seal moves only from the one the vault
-- read (of two changes to one member, the second reads again: null), the payload is applied as
-- logged, and its entry numbered now. It returns the number, which a change waits to see sealed.
CREATE OR REPLACE FUNCTION change_member(p_principal text, p_request text, p_at bigint, p_payload text, p_seal_from bytea, p_seal bytea, p_mac bytea)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
  op json := p_payload::json;
  n bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(208);
  SELECT number INTO n FROM entries_changes WHERE request_id = p_request;
  IF FOUND THEN RETURN n; END IF;
  UPDATE members SET seal = p_seal WHERE principal = p_principal AND seal = p_seal_from;
  IF NOT FOUND THEN RETURN NULL; END IF;
  CASE op->>'op'
    WHEN 'access.grant' THEN
      INSERT INTO grants VALUES (p_principal, (op->>'environment')::uuid, op->>'role') ON CONFLICT (principal, environment_id) DO UPDATE SET role = EXCLUDED.role;
    WHEN 'access.revoke' THEN
      DELETE FROM grants WHERE principal = p_principal AND environment_id = (op->>'environment')::uuid;
    WHEN 'credential.revoke' THEN
      UPDATE credentials SET revoked = true WHERE id = op->>'credential' AND principal = p_principal;
    WHEN 'credential.restore' THEN
      UPDATE credentials SET revoked = false WHERE id = op->>'credential' AND principal = p_principal;
  END CASE;
  INSERT INTO entries_changes (number, at, kind, principal, credential, request_id, payload, seal, mac)
    VALUES (nextval('entry_number'), p_at, 'change', p_principal, op->>'credential', p_request, p_payload, p_seal, p_mac)
    RETURNING number INTO n;
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
