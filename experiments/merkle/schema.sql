-- W209's audit log: entries numbered by a sequence, each with a MAC over
-- everything but its number, sealed into one growing RFC 9162 Merkle tree by
-- a checkpointer. Synthetic data only.
--
-- Laid out as W208's: one table partitioned by kind. Changes are kept forever
-- (decisions read a member's newest change). Uses are partitioned by day, and
-- retention drops a day's partition, in one of two ways (retention.ts):
--   number  day d holds the numbers [d·10^12, (d+1)·10^12): the checkpointer
--           moves the sequence to the next day under the fence's lock, so a
--           day is exactly a run of numbers;
--   at      day d holds the uses whose `at` (the Worker's clock) falls in it,
--           a day being `day_ms` long, so its numbers interleave with the
--           next day's near midnight.
-- A partitioned table can have no unique index without its partition key: only
-- the sequence keeps numbers unique, and the verifier checks they are.
DROP TABLE IF EXISTS audit, audit_tiles, checkpoints, audit_layout CASCADE;
DROP SEQUENCE IF EXISTS audit_number;
DROP FUNCTION IF EXISTS append_entry, seal_window, new_day, lay_out;

-- CACHE 1 (the default) matters: the checkpointer reads the sequence's last value as the newest number handed out.
CREATE SEQUENCE audit_number CACHE 1;

CREATE TABLE audit (
  number bigint NOT NULL,
  -- What the MAC covers: when (the Worker's clock, ms), who, with what, what kind ('use' or 'change'), which
  -- request, what it says, and a change's seal over the member row it leaves (null for a use).
  at bigint NOT NULL,
  principal text NOT NULL,
  credential text,
  kind text NOT NULL,
  request_id text NOT NULL,
  payload text NOT NULL,
  seal bytea,
  mac bytea NOT NULL,
  -- When the row was written, inside its statement: to measure the sealing window. Not signed.
  written_at timestamptz NOT NULL DEFAULT clock_timestamp()
) PARTITION BY LIST (kind);
CREATE INDEX audit_number_idx ON audit (number);
CREATE TABLE audit_changes PARTITION OF audit FOR VALUES IN ('change');

CREATE TABLE audit_layout (only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row), mode text NOT NULL, day_ms bigint NOT NULL);

-- Uses by number range or by `at`; `day_ms` is a day's length in `at` (shorter in the demos).
CREATE FUNCTION lay_out(p_mode text, p_day_ms bigint DEFAULT 86400000) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO audit_layout VALUES (true, p_mode, p_day_ms);
  EXECUTE format('CREATE TABLE audit_uses PARTITION OF audit FOR VALUES IN (%L) PARTITION BY RANGE (%I)', 'use', CASE WHEN p_mode = 'number' THEN 'number' ELSE 'at' END);
END $$;

CREATE FUNCTION new_day(d bigint) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  l audit_layout;
  w bigint;
BEGIN
  SELECT * INTO l FROM audit_layout;
  w := CASE WHEN l.mode = 'number' THEN 1000000000000 ELSE l.day_ms END;
  EXECUTE format('CREATE TABLE IF NOT EXISTS audit_uses_d%s PARTITION OF audit_uses FOR VALUES FROM (%s) TO (%s)', d, d * w, (d + 1) * w);
END $$;

-- The tree's tiles (tiles.ts): level, index, the hashes (32 bytes each), growing at the right edge only.
CREATE TABLE audit_tiles (level smallint NOT NULL, idx bigint NOT NULL, hashes bytea NOT NULL, PRIMARY KEY (level, idx));

-- Each signed tree head: its size, the highest number it seals (every number at or below it is final: in the tree or
-- never to be), its head, and the signed note itself.
-- Keyed by `upto`: two checkpoints may share a size when only gaps came between them.
CREATE TABLE checkpoints (
  upto bigint PRIMARY KEY,
  size bigint NOT NULL,
  root bytea NOT NULL,
  note text NOT NULL,
  -- The day whose last number this checkpoint seals, when it closed one.
  closed_day bigint,
  written_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX checkpoints_size ON checkpoints (size);

-- A use's entry, in one statement. The number is taken under the fence's shared lock, so once the checkpointer holds
-- that lock exclusively, every number up to the sequence's last value belongs to an append that has ended, and every
-- later append gets a larger one: the floor needs no lag at all.
CREATE FUNCTION append_entry(p_at bigint, p_principal text, p_credential text, p_kind text, p_request text, p_payload text, p_seal bytea, p_mac bytea)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
BEGIN
  PERFORM pg_advisory_xact_lock_shared(209);
  n := nextval('audit_number');
  INSERT INTO audit (number, at, principal, credential, kind, request_id, payload, seal, mac)
    VALUES (n, p_at, p_principal, p_credential, p_kind, p_request, p_payload, p_seal, p_mac);
  RETURN n;
END $$;

-- The checkpointer's one read: the entries above `p_from` and up to the newest number handed out, every one of which
-- has committed or never will. The fence's lock is taken exclusively for as long as it takes to read the sequence
-- (and, at a day's end, move it to the next day), then let go before the read: appends wait for a few hundred
-- microseconds, never for the read. The first row carries only `upto`.
CREATE FUNCTION seal_window(p_from bigint, p_next_day bigint DEFAULT NULL)
RETURNS TABLE (upto bigint, number bigint, at bigint, principal text, credential text, kind text, request_id text, payload text, seal bytea, mac bytea, written_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE
  u bigint;
BEGIN
  PERFORM pg_advisory_lock(209);
  BEGIN
    u := greatest(p_from, coalesce(pg_sequence_last_value('audit_number'), p_from));
    -- The next day's partition is made ahead of time (CREATE … PARTITION OF locks the whole table to the end of
    -- the statement): here the sequence only jumps to it.
    -- Only ever forward: a clock stepped back, or a day closed twice, leaves the sequence where it is (a missed
    -- midnight just makes a long day).
    IF p_next_day IS NOT NULL AND p_next_day * 1000000000000 > u THEN
      PERFORM setval('audit_number', p_next_day * 1000000000000, false);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    PERFORM pg_advisory_unlock(209);
    RAISE;
  END;
  PERFORM pg_advisory_unlock(209);
  upto := u;
  RETURN NEXT;
  RETURN QUERY SELECT u, a.number, a.at, a.principal, a.credential, a.kind, a.request_id, a.payload, a.seal, a.mac, a.written_at
    FROM audit a WHERE a.number > p_from AND a.number <= u ORDER BY a.number;
END $$;
