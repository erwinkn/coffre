-- coffre M0: the audit log.
--
-- This table is the entire point of the project. Design notes that are
-- load-bearing rather than decorative:
--
--  * `seq` is assigned from audit_chain_head, NOT from a bigserial sequence.
--    A rolled-back transaction burns a sequence value, and the resulting gap
--    is indistinguishable from a deleted row. Gaps must mean tampering.
--
--  * Appends are serialised by locking the single audit_chain_head row. A hash
--    chain has no meaning under concurrent unordered appends. The throughput
--    ceiling this imposes is irrelevant at secrets-manager volumes.
--
--  * `occurred_at` defaults to the database's now(), never a clock read on an
--    application server. CDR (EU) 2024/1774 Art 12(2)(f) requires clocks
--    synchronised to a documented reference source; one clock is easier to
--    document than N.
--
--  * source_ip is text, not inet, and metadata is text, not jsonb. Both are
--    covered by the hash chain, and both of those richer types normalise their
--    input on the way in -- which would silently change the bytes the hash was
--    computed over.

CREATE TABLE audit_log (
    seq             bigint PRIMARY KEY,
    id              uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    occurred_at     timestamptz NOT NULL DEFAULT now(),

    -- Who. 'user' is a Cloudflare Access identity (email); 'service' is an
    -- Access service token (common_name). 'system' covers background jobs.
    actor_type      text NOT NULL CHECK (actor_type IN ('user', 'service', 'system')),
    actor_id        text NOT NULL,

    action          text NOT NULL,
    decision        text NOT NULL CHECK (decision IN ('allow', 'deny')),

    -- What. Nullable because denials can occur before the target resolves
    -- (for example, a read of a secret the caller may not learn the existence of).
    project_id      uuid REFERENCES projects (id) ON DELETE RESTRICT,
    environment_id  uuid REFERENCES environments (id) ON DELETE RESTRICT,
    secret_id       uuid REFERENCES secrets (id) ON DELETE RESTRICT,

    -- Groups the rows emitted by one bulk fetch. A bulk read writes one row
    -- per secret returned, all sharing a bundle_id -- otherwise the answer to
    -- "who read which secret" degrades to "they read the whole environment",
    -- which is true and useless.
    bundle_id       uuid,

    request_id      text,
    source_ip       text,
    metadata        text NOT NULL DEFAULT '{}' CHECK (metadata::jsonb IS NOT NULL),

    prev_hash       bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash            bytea NOT NULL CHECK (octet_length(hash) = 32)
);

CREATE INDEX audit_log_occurred_idx    ON audit_log (occurred_at DESC);
CREATE INDEX audit_log_actor_idx       ON audit_log (actor_type, actor_id, occurred_at DESC);
CREATE INDEX audit_log_secret_idx      ON audit_log (secret_id, occurred_at DESC);
CREATE INDEX audit_log_environment_idx ON audit_log (environment_id, occurred_at DESC);
CREATE INDEX audit_log_bundle_idx      ON audit_log (bundle_id) WHERE bundle_id IS NOT NULL;

-- Single-row table holding the chain head. Locked FOR UPDATE by every append.
CREATE TABLE audit_chain_head (
    only_row   boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    next_seq   bigint NOT NULL DEFAULT 0,
    head_hash  bytea  NOT NULL CHECK (octet_length(head_hash) = 32),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO audit_chain_head (only_row, next_seq, head_hash)
VALUES (true, 0, decode(repeat('00', 32), 'hex'));

-- Periodic checkpoints of the chain head, published somewhere the application
-- cannot reach. A hash chain detects mutation, deletion and reordering on its
-- own, but NOT truncation of the tail: a short chain is internally consistent.
-- Comparing the head against an externally held checkpoint is what closes that.
CREATE TABLE audit_checkpoints (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq          bigint NOT NULL,
    head_hash    bytea NOT NULL CHECK (octet_length(head_hash) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    exported_at  timestamptz,
    export_target text
);

-- CDR (EU) 2024/1774 Art 12(2)(e): "measures to detect a failure of logging
-- systems". This is the exact failure we are replacing Infisical over -- its
-- audit queue returned early and dropped every entry, silently, for months.
--
-- A writer updates this row on a fixed interval. An alert fires when it goes
-- stale, so "the audit log stopped receiving writes" is a paging event rather
-- than something discovered during an audit.
CREATE TABLE audit_heartbeat (
    only_row     boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    last_beat_at timestamptz NOT NULL DEFAULT now(),
    last_seq     bigint NOT NULL DEFAULT 0
);

INSERT INTO audit_heartbeat (only_row) VALUES (true);
