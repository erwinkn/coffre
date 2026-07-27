-- Project-scoped grants, and archiving in place of deletion.
--
-- Two changes, both forced by the same discovery: the audit log holds
-- ON DELETE RESTRICT references to projects, environments and secrets, so
-- nothing that has ever been read or written can be deleted. That is correct --
-- a cascade would destroy the evidence this service exists to keep -- but it
-- means "delete" has to mean "archive".

-- ---------------------------------------------------------------------------
-- Grants can now target a project as well as a single environment
-- ---------------------------------------------------------------------------
--
-- Previously every grant was environment-scoped, which left nothing able to
-- authorise "create an environment in this project". A project grant confers
-- its capability on every environment in that project, so 'admin' on a project
-- is what lets someone add environments and manage grants within it.

ALTER TABLE grants ADD COLUMN project_id uuid REFERENCES projects (id) ON DELETE RESTRICT;
ALTER TABLE grants ALTER COLUMN environment_id DROP NOT NULL;

ALTER TABLE grants
    DROP CONSTRAINT grants_principal_type_principal_id_environment_id_capabilit_key;

-- Exactly one scope. A grant that targeted both would have ambiguous meaning,
-- and one that targeted neither would be a grant over nothing.
ALTER TABLE grants ADD CONSTRAINT grants_exactly_one_scope
    CHECK ((project_id IS NULL) <> (environment_id IS NULL));

CREATE UNIQUE INDEX grants_environment_unique
    ON grants (principal_type, principal_id, environment_id, capability)
    WHERE environment_id IS NOT NULL;

CREATE UNIQUE INDEX grants_project_unique
    ON grants (principal_type, principal_id, project_id, capability)
    WHERE project_id IS NOT NULL;

CREATE INDEX grants_project_lookup_idx
    ON grants (principal_type, principal_id, project_id)
    WHERE project_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Archiving
-- ---------------------------------------------------------------------------
--
-- An archived project or environment disappears from listings and refuses
-- reads and writes, but every row it owns stays in place so the audit log's
-- references remain valid and its history stays readable.
--
-- Actually destroying data is deliberately NOT exposed. That belongs to a
-- retention policy under CDR (EU) 2024/1774 Art 12(2)(a), which is a decision
-- to be written down and applied on purpose -- not a button in an admin UI.

ALTER TABLE projects     ADD COLUMN archived_at timestamptz;
ALTER TABLE environments ADD COLUMN archived_at timestamptz;

CREATE INDEX projects_active_idx     ON projects (slug)                WHERE archived_at IS NULL;
CREATE INDEX environments_active_idx ON environments (project_id, slug) WHERE archived_at IS NULL;

-- The application role needs no new privileges: it already has UPDATE on
-- projects and environments, and INSERT/DELETE on grants. It still has no
-- UPDATE or DELETE on audit_log or secret_versions.
