-- Roles with explicit permissions, and archiving for secrets.
--
-- The previous model was a fixed ladder: read < write < admin. It could not
-- express the two separations that matter most in a tool whose purpose is
-- audit:
--
--   * an auditor who can read the audit log but NOT secret values
--   * an access manager who administers grants but NOT secret values
--
-- Under the ladder, both required 'admin', which included every secret. Giving
-- someone audit visibility meant giving them the whole vault.
--
-- Permissions are a FIXED CATALOGUE, not a policy language. Roles are named
-- bundles of them. That keeps authorisation readable end to end, which the
-- original design was right to insist on.

-- ---------------------------------------------------------------------------
-- The permission catalogue
-- ---------------------------------------------------------------------------

CREATE TABLE permissions (
    slug        text PRIMARY KEY,
    description text NOT NULL,
    -- Where this permission can meaningfully be granted.
    --   'environment' -- valid at either project or environment scope
    --   'project'     -- project scope only; meaningless on one environment
    min_scope   text NOT NULL CHECK (min_scope IN ('environment', 'project'))
);

INSERT INTO permissions (slug, description, min_scope) VALUES
    ('secret.read',        'Read secret values',                          'environment'),
    ('secret.write',       'Create secrets and write new versions',       'environment'),
    ('secret.archive',     'Retire and restore secrets',                  'environment'),
    ('audit.read',         'Read the audit log',                          'environment'),
    ('environment.manage', 'Create, rename and archive environments',     'project'),
    ('grant.manage',       'Grant and revoke access',                     'project'),
    ('project.manage',     'Rename and archive the project',              'project');

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------

CREATE TABLE roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    -- Built-in roles are seeded here and may not be edited or removed.
    is_builtin  boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions (
    role_id    uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission text NOT NULL REFERENCES permissions (slug) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission)
);

INSERT INTO roles (slug, name, description, is_builtin) VALUES
    ('viewer',         'Viewer',         'Read secret values.', true),
    ('developer',      'Developer',      'Read and write secrets.', true),
    ('maintainer',     'Maintainer',     'Read, write and retire secrets, and manage environments.', true),
    ('access-manager', 'Access manager', 'Manage who has access. Cannot read secret values.', true),
    ('auditor',        'Auditor',        'Read the audit log. Cannot read secret values.', true),
    ('owner',          'Owner',          'Everything, including reading secret values.', true);

INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.permission
  FROM roles r
  JOIN (VALUES
        ('viewer',         'secret.read'),
        ('developer',      'secret.read'),
        ('developer',      'secret.write'),
        ('maintainer',     'secret.read'),
        ('maintainer',     'secret.write'),
        ('maintainer',     'secret.archive'),
        ('maintainer',     'environment.manage'),
        -- Deliberately no secret.read: administering access must not require
        -- being able to read what you are granting access to.
        ('access-manager', 'grant.manage'),
        -- Deliberately no secret.read: this is the whole point of the role.
        ('auditor',        'audit.read'),
        ('owner',          'secret.read'),
        ('owner',          'secret.write'),
        ('owner',          'secret.archive'),
        ('owner',          'audit.read'),
        ('owner',          'environment.manage'),
        ('owner',          'grant.manage'),
        ('owner',          'project.manage')
       ) AS p(role_slug, permission) ON p.role_slug = r.slug;

-- ---------------------------------------------------------------------------
-- Grants now carry a role instead of a capability
-- ---------------------------------------------------------------------------

ALTER TABLE grants ADD COLUMN role_id uuid REFERENCES roles (id) ON DELETE RESTRICT;

-- Map the old ladder onto the built-in roles.
UPDATE grants SET role_id = (
    SELECT id FROM roles WHERE slug = CASE grants.capability
        WHEN 'read'  THEN 'viewer'
        WHEN 'write' THEN 'developer'
        ELSE              'owner'
    END
);

ALTER TABLE grants ALTER COLUMN role_id SET NOT NULL;

DROP INDEX grants_environment_unique;
DROP INDEX grants_project_unique;
ALTER TABLE grants DROP COLUMN capability;

CREATE UNIQUE INDEX grants_environment_unique
    ON grants (principal_type, principal_id, environment_id, role_id)
    WHERE environment_id IS NOT NULL;

CREATE UNIQUE INDEX grants_project_unique
    ON grants (principal_type, principal_id, project_id, role_id)
    WHERE project_id IS NOT NULL;

-- Optional expiry. NULL means it does not expire.
ALTER TABLE grants ADD COLUMN expires_at timestamptz;

-- ---------------------------------------------------------------------------
-- Secret archiving
-- ---------------------------------------------------------------------------
--
-- Same reasoning as projects and environments: audit_log references secrets
-- with ON DELETE RESTRICT, so a secret that has ever been read or written
-- cannot be deleted. Archiving retires it -- it stops being served and stops
-- appearing in bulk fetch -- while its versions and its history stay intact.

ALTER TABLE secrets ADD COLUMN archived_at timestamptz;

CREATE INDEX secrets_active_idx
    ON secrets (project_id, environment_id, key)
    WHERE archived_at IS NULL;

GRANT SELECT ON permissions, roles, role_permissions TO coffre_app;
