-- The prototype's database: a cut-down coffre, the rows a read decides on,
-- and its audit log twice, as one chain (today) and as lanes (the proposal).
-- Synthetic data only.
DROP TABLE IF EXISTS environments, members, grants, secrets, credentials, log, head, lane_log, lanes CASCADE;

CREATE TABLE environments (id uuid PRIMARY KEY, deleted boolean NOT NULL DEFAULT false);
CREATE TABLE members (
  principal text PRIMARY KEY,
  status text NOT NULL,
  role text,
  access_seq bigint NOT NULL,
  mac bytea NOT NULL
);
CREATE TABLE grants (principal text NOT NULL, environment_id uuid NOT NULL, role text NOT NULL, PRIMARY KEY (principal, environment_id));
CREATE TABLE secrets (id uuid PRIMARY KEY, environment_id uuid NOT NULL, nature text NOT NULL, wrapped bytea NOT NULL, iv bytea NOT NULL);
CREATE TABLE credentials (id text PRIMARY KEY, principal text NOT NULL, revoked boolean NOT NULL DEFAULT false);

-- Today: one chain, one head.
CREATE TABLE log (
  seq bigint PRIMARY KEY,
  author text NOT NULL, actor text NOT NULL, action text NOT NULL, decision text NOT NULL,
  subject text, environment_id uuid, control_seq bigint, occurred_at bigint NOT NULL, metadata text NOT NULL,
  prev_hash bytea NOT NULL, mac bytea NOT NULL, hash bytea NOT NULL
);
CREATE INDEX log_access ON log (subject, seq) WHERE action LIKE 'access.%';
CREATE INDEX log_action ON log (action, seq);
CREATE TABLE head (only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row), next_seq bigint NOT NULL, head_hash bytea NOT NULL);

-- Proposed: lanes. Lane 0 is the control lane (every change a read decides on), lanes 1..N the reads, by principal.
CREATE TABLE lane_log (
  lane integer NOT NULL, seq bigint NOT NULL,
  author text NOT NULL, actor text NOT NULL, action text NOT NULL, decision text NOT NULL,
  subject text, environment_id uuid, control_seq bigint, occurred_at bigint NOT NULL, metadata text NOT NULL,
  prev_hash bytea NOT NULL, mac bytea NOT NULL, hash bytea NOT NULL,
  PRIMARY KEY (lane, seq)
);
CREATE INDEX lane_log_access ON lane_log (subject, seq) WHERE lane = 0 AND action LIKE 'access.%';
CREATE INDEX lane_log_action ON lane_log (lane, action, seq);
CREATE TABLE lanes (lane integer PRIMARY KEY, next_seq bigint NOT NULL, head_hash bytea NOT NULL);

-- The Postgres-only leader (v4): each call leaves its entry here, unchained; whoever takes the leader's
-- advisory lock chains every waiting entry into `log` in one transaction, and each call polls for its own.
DROP TABLE IF EXISTS pending;
CREATE TABLE pending (
  id bigserial PRIMARY KEY,
  actor text NOT NULL, action text NOT NULL, decision text NOT NULL, subject text, environment_id uuid,
  access_seq bigint NOT NULL, metadata text NOT NULL
);
ALTER TABLE log ADD COLUMN pending_id bigint;
CREATE UNIQUE INDEX log_pending ON log (pending_id) WHERE pending_id IS NOT NULL;

-- Shards (v5): one revision for everything a use decides on, raised by every change, which fences the shards first.
DROP TABLE IF EXISTS revision;
-- The epoch is new at every migration and every restore: a shard that meets another epoch forgets everything it kept.
CREATE TABLE revision (only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row), value bigint NOT NULL, epoch text NOT NULL);
INSERT INTO revision VALUES (true, 1, gen_random_uuid()::text);

-- Simple (W201): Postgres only. One log; a use is one read and one append statement; the
-- revision fences changes. Two ways to take an entry's place in the log:
--   head  the brief's: the head row locked for the append statement only, the chain link a
--         plain hash computed in SQL; the revision lives in the head row, so the append's
--         lock re-reads it (a change bumps it in the same row).
--   seq   no head: the read takes a sequence number, which the entry's MAC covers; the append
--         holds a shared advisory lock that a change (or a checkpoint) takes exclusively, and
--         checks the revision and the checkpoint floor under it. Checkpoints link the entries.
DROP TABLE IF EXISTS audit, audit_head, checkpoints CASCADE;
DROP SEQUENCE IF EXISTS audit_seq;
DROP FUNCTION IF EXISTS change_grant(text, bigint, bigint, text, boolean, uuid, text, bigint, bytea, bytea);
CREATE TABLE audit (
  seq bigint PRIMARY KEY,
  revision bigint NOT NULL,
  actor text NOT NULL, action text NOT NULL, decision text NOT NULL, subject text, environment_id uuid,
  occurred_at bigint NOT NULL, metadata text NOT NULL,
  mac bytea NOT NULL,
  -- head: the entry before's hash, and sha256(prev_hash || mac); seq: null, linked by checkpoints.
  prev_hash bytea, hash bytea,
  -- When the row was written, inside its statement's lock: for the benches' check of commit order, not signed.
  written_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX audit_access ON audit (subject, seq) WHERE action LIKE 'access.%';
-- next_seq and hash: the head (head only). revision: raised by every change. floor: the highest seq a
-- checkpoint has closed (seq only): an append at or below it is refused.
CREATE TABLE audit_head (
  only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
  next_seq bigint NOT NULL, hash bytea NOT NULL, revision bigint NOT NULL, floor bigint NOT NULL DEFAULT 0, epoch text NOT NULL
);
CREATE SEQUENCE audit_seq START 1;
-- A checkpoint: the vault's signature over every entry in (from, upto], in seq order, chained to the one before.
CREATE TABLE checkpoints (upto bigint PRIMARY KEY, from_seq bigint NOT NULL, revision bigint NOT NULL, entries int NOT NULL, hash bytea NOT NULL, signature bytea NOT NULL, at bigint NOT NULL);

-- seq: a use's append. The shared lock first; then, in a statement of its own (a volatile function's
-- statements each take a new snapshot under READ COMMITTED), the fence: the revision the read decided
-- at is still current, and no checkpoint has closed this seq. Nothing is written otherwise.
CREATE OR REPLACE FUNCTION append_use(p_seq bigint, p_revision bigint, p_actor text, p_action text, p_decision text, p_subject text,
  p_environment uuid, p_at bigint, p_metadata text, p_mac bytea) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock_shared(201);
  IF NOT EXISTS (SELECT 1 FROM audit_head WHERE only_row AND revision = p_revision AND floor < p_seq) THEN
    RETURN false;
  END IF;
  INSERT INTO audit (seq, revision, actor, action, decision, subject, environment_id, occurred_at, metadata, mac)
    VALUES (p_seq, p_revision, p_actor, p_action, p_decision, p_subject, p_environment, p_at, p_metadata, p_mac);
  RETURN true;
END $$;

-- A change to a grant (give or take) or to a credential (p_kind 'credential'), its entry, and the member row sealed
-- over it (grants), at revision
-- p_from + 1, in one statement: refused (null) if another change moved the revision since the
-- caller read it. head: under the head row's lock, linked in SQL. seq: under the exclusive lock, at
-- the seq the caller took.
CREATE OR REPLACE FUNCTION change_grant(p_mode text, p_kind text, p_from bigint, p_seq bigint, p_principal text, p_give boolean, p_environment uuid,
  p_actor text, p_at bigint, p_mac bytea, p_member_mac bytea) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
  s bigint;
  prev bytea;
BEGIN
  IF p_mode = 'head' THEN
    SELECT next_seq, hash INTO s, prev FROM audit_head WHERE only_row AND revision = p_from FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
  ELSE
    PERFORM pg_advisory_xact_lock(201);
    IF NOT EXISTS (SELECT 1 FROM audit_head WHERE only_row AND revision = p_from AND floor < p_seq) THEN RETURN NULL; END IF;
    s := p_seq;
  END IF;
  IF p_kind = 'credential' THEN
    -- A credential revoked or restored: a decision input like any other, so a fenced change too.
    UPDATE credentials SET revoked = NOT p_give WHERE principal = p_principal;
  ELSE
    -- The prototype's one environment: a principal's grants are its grant there.
    IF p_give THEN
      INSERT INTO grants VALUES (p_principal, p_environment, 'viewer') ON CONFLICT DO NOTHING;
    ELSE
      DELETE FROM grants WHERE principal = p_principal;
    END IF;
    UPDATE members SET access_seq = p_from + 1, mac = p_member_mac WHERE principal = p_principal;
  END IF;
  INSERT INTO audit (seq, revision, actor, action, decision, subject, environment_id, occurred_at, metadata, mac, prev_hash, hash)
    VALUES (s, p_from + 1, p_actor,
      CASE WHEN p_kind = 'credential' THEN (CASE WHEN p_give THEN 'credential.restore' ELSE 'credential.revoke' END)
           WHEN p_give THEN 'access.grant' ELSE 'access.revoke' END, 'allow', p_principal, p_environment,
      p_at, '{}', p_mac, prev, sha256(prev || p_mac));
  IF p_mode = 'head' THEN
    UPDATE audit_head SET revision = p_from + 1, next_seq = s + 1, hash = sha256(prev || p_mac) WHERE only_row;
  ELSE
    UPDATE audit_head SET revision = p_from + 1 WHERE only_row;
  END IF;
  RETURN s;
END $$;

-- seq: close the entries a checkpoint will sign. Under the exclusive lock, so no append with a seq at
-- or below the new floor is in flight or can commit later: the floor becomes p_upto (the sequence's
-- value the previous tick saw, so a use between its read and its append is not refused by it), and
-- the sequence's value now is returned, for the next tick.
CREATE OR REPLACE FUNCTION close_checkpoint(p_upto bigint) RETURNS TABLE (floor_from bigint, floor_to bigint, revision bigint, next_upto bigint)
LANGUAGE plpgsql AS $$
DECLARE
  f bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(201);
  SELECT h.floor INTO f FROM audit_head h WHERE only_row;
  IF p_upto > f THEN UPDATE audit_head h SET floor = p_upto WHERE only_row; END IF;
  RETURN QUERY SELECT f, greatest(f, p_upto), h.revision, coalesce(pg_sequence_last_value('audit_seq'), 0) FROM audit_head h WHERE only_row;
END $$;
