-- coffre M0: core schema.
--
-- Plain SQL, applied in filename order. No ORM-generated migrations: the
-- schema of a service that holds every credential we own should be readable
-- without running a tool.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Projects and environments
-- ---------------------------------------------------------------------------

CREATE TABLE projects (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE environments (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    slug        text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, slug)
);

-- ---------------------------------------------------------------------------
-- Secrets and their versions
-- ---------------------------------------------------------------------------

CREATE TABLE secrets (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    environment_id  uuid NOT NULL REFERENCES environments (id) ON DELETE RESTRICT,
    key             text NOT NULL CHECK (key ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- Pointer to the version currently served. Set after the first version is
    -- written; rollback is repointing this at an older row.
    current_version_id uuid,
    UNIQUE (project_id, environment_id, key)
);

-- The environment must belong to the project the secret claims. Without this,
-- a secret could reference a project/environment pair that does not exist,
-- and the AAD context would bind to a combination the data model never checked.
ALTER TABLE environments ADD CONSTRAINT environments_project_scoped
    UNIQUE (id, project_id);

ALTER TABLE secrets ADD CONSTRAINT secrets_environment_in_project
    FOREIGN KEY (environment_id, project_id)
    REFERENCES environments (id, project_id);

-- Append-only. A new value is a new row; nothing is ever updated in place.
CREATE TABLE secret_versions (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id         uuid NOT NULL REFERENCES secrets (id) ON DELETE RESTRICT,
    version           integer NOT NULL CHECK (version > 0),

    -- Envelope. See packages/core/src/envelope.ts for the format.
    envelope_version  integer NOT NULL,
    ciphertext        bytea   NOT NULL,
    iv                bytea   NOT NULL CHECK (octet_length(iv) = 12),
    auth_tag          bytea   NOT NULL CHECK (octet_length(auth_tag) = 16),

    -- The wrapped DEK carries its own provider metadata, per row, never a
    -- single global key id. This is what makes KEK rotation and migrating
    -- between KEK providers the same operation.
    wrapped_dek       bytea   NOT NULL,
    kek_provider      text    NOT NULL,
    kek_id            text    NOT NULL,
    kek_version       text    NOT NULL,

    created_at        timestamptz NOT NULL DEFAULT now(),
    created_by        text    NOT NULL,

    UNIQUE (secret_id, version)
);

ALTER TABLE secrets ADD CONSTRAINT secrets_current_version_fk
    FOREIGN KEY (current_version_id) REFERENCES secret_versions (id);

CREATE INDEX secret_versions_secret_idx ON secret_versions (secret_id, version DESC);
CREATE INDEX secrets_lookup_idx ON secrets (project_id, environment_id, key);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

-- Deliberately a table, not a policy language. A grant scopes one principal to
-- one environment with one capability.
--
-- principal_type distinguishes a human (Cloudflare Access identity, matched on
-- email) from a machine (Cloudflare Access service token, matched on the
-- common_name claim). Service-token JWTs carry no email claim at all and an
-- empty sub, so machine callers cannot be represented by email.
CREATE TABLE grants (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_type  text NOT NULL CHECK (principal_type IN ('user', 'service')),
    principal_id    text NOT NULL,
    environment_id  uuid NOT NULL REFERENCES environments (id) ON DELETE RESTRICT,
    capability      text NOT NULL CHECK (capability IN ('read', 'write', 'admin')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    created_by      text NOT NULL,
    UNIQUE (principal_type, principal_id, environment_id, capability)
);

CREATE INDEX grants_lookup_idx ON grants (principal_type, principal_id, environment_id);
