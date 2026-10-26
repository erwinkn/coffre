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
CREATE TABLE revision (only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row), value bigint NOT NULL);
INSERT INTO revision VALUES (true, 1);
