-- Objects and data that are deliberately outside Drizzle's generated table
-- model. The Terraform-managed coffre_runtime login must already exist; this
-- migration owns its application-role membership, never its password.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
--> statement-breakpoint

INSERT INTO audit_chain_head (only_row, next_seq, head_hash)
VALUES (true, 0, decode(repeat('00', 32), 'hex'));
--> statement-breakpoint

INSERT INTO audit_heartbeat (only_row, last_seq)
VALUES (true, 0);
--> statement-breakpoint

INSERT INTO permissions (slug, description, min_scope) VALUES
    ('secret.read',        'Read secret values',                      'environment'),
    ('secret.write',       'Create secrets and write new versions',   'environment'),
    ('secret.archive',     'Retire and restore secrets',              'environment'),
    ('audit.read',         'Read the audit log',                      'environment'),
    ('environment.manage', 'Create, rename and archive environments', 'project'),
    ('grant.manage',       'Grant and revoke access',                 'project'),
    ('project.manage',     'Rename and archive the project',          'project');
--> statement-breakpoint

INSERT INTO roles (slug, name, description, is_builtin) VALUES
    ('viewer',         'Viewer',         'Read secret values.', true),
    ('developer',      'Developer',      'Read and write secrets.', true),
    ('maintainer',     'Maintainer',     'Read, write and retire secrets, and manage environments.', true),
    ('access-manager', 'Access manager', 'Manage who has access. Cannot read secret values.', true),
    ('auditor',        'Auditor',        'Read the audit log. Cannot read secret values.', true),
    ('owner',          'Owner',          'Everything, including reading secret values.', true);
--> statement-breakpoint

INSERT INTO role_permissions (role_id, permission)
SELECT role.id, mapping.permission
  FROM roles role
  JOIN (VALUES
        ('viewer',         'secret.read'),
        ('developer',      'secret.read'),
        ('developer',      'secret.write'),
        ('maintainer',     'secret.read'),
        ('maintainer',     'secret.write'),
        ('maintainer',     'secret.archive'),
        ('maintainer',     'environment.manage'),
        ('access-manager', 'grant.manage'),
        ('auditor',        'audit.read'),
        ('owner',          'secret.read'),
        ('owner',          'secret.write'),
        ('owner',          'secret.archive'),
        ('owner',          'audit.read'),
        ('owner',          'environment.manage'),
        ('owner',          'grant.manage'),
        ('owner',          'project.manage')
       ) AS mapping(role_slug, permission) ON mapping.role_slug = role.slug;
--> statement-breakpoint

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_app') THEN
        CREATE ROLE coffre_app;
    END IF;
END
$$;
--> statement-breakpoint

ALTER ROLE coffre_app
    NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
--> statement-breakpoint

DO $$
DECLARE
    runtime_role oid;
BEGIN
    SELECT oid INTO runtime_role FROM pg_roles WHERE rolname = 'coffre_runtime';
    IF runtime_role IS NULL THEN
        RAISE EXCEPTION 'coffre_runtime must be provisioned before migrations';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_roles
         WHERE oid = runtime_role
           AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'coffre_runtime has unsafe role attributes';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_shdepend
         WHERE refclassid = 'pg_authid'::regclass
           AND refobjid = runtime_role
           AND deptype = 'o'
    ) THEN
        RAISE EXCEPTION 'coffre_runtime owns database objects';
    END IF;
END
$$;
--> statement-breakpoint

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM coffre_app, coffre_runtime;
--> statement-breakpoint
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM coffre_app, coffre_runtime;
--> statement-breakpoint
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM coffre_app, coffre_runtime;
--> statement-breakpoint
REVOKE ALL PRIVILEGES ON SCHEMA public FROM coffre_app, coffre_runtime;
--> statement-breakpoint
GRANT USAGE ON SCHEMA public TO coffre_app;
--> statement-breakpoint
GRANT USAGE ON SCHEMA drizzle TO coffre_app;
--> statement-breakpoint
GRANT SELECT ON drizzle.__drizzle_migrations TO coffre_app;
--> statement-breakpoint

GRANT SELECT, INSERT ON
    projects,
    environments,
    secrets,
    grants,
    principals,
    secret_versions,
    audit_log
TO coffre_app;
--> statement-breakpoint

GRANT SELECT ON
    permissions,
    roles,
    role_permissions,
    audit_chain_head,
    audit_checkpoints,
    audit_heartbeat
TO coffre_app;
--> statement-breakpoint

GRANT UPDATE (slug, name, archived_at) ON projects TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (slug, name, archived_at) ON environments TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (key, current_version_id, updated_at, archived_at) ON secrets TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (role_id, expires_at, created_by) ON grants TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (instance_role, active, created_at, created_by) ON principals TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (next_seq, head_hash, updated_at) ON audit_chain_head TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (last_beat_at, last_seq) ON audit_heartbeat TO coffre_app;
--> statement-breakpoint

REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM coffre_app;
--> statement-breakpoint
REVOKE UPDATE ON audit_log, secret_versions FROM coffre_app;
--> statement-breakpoint
REVOKE CREATE ON SCHEMA public FROM PUBLIC, coffre_app, coffre_runtime;
--> statement-breakpoint

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES FROM coffre_app, coffre_runtime;
--> statement-breakpoint
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM coffre_app, coffre_runtime;
--> statement-breakpoint
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL PRIVILEGES ON ROUTINES FROM coffre_app, coffre_runtime;
--> statement-breakpoint

DO $$
DECLARE
    membership record;
BEGIN
    EXECUTE format(
        'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC, coffre_app, coffre_runtime',
        current_database()
    );

    FOR membership IN
        SELECT granted.rolname
          FROM pg_auth_members member_of
          JOIN pg_roles member ON member.oid = member_of.member
          JOIN pg_roles granted ON granted.oid = member_of.roleid
         WHERE member.rolname = 'coffre_runtime'
           AND granted.rolname <> 'coffre_app'
    LOOP
        EXECUTE format('REVOKE %I FROM coffre_runtime', membership.rolname);
    END LOOP;
END
$$;
--> statement-breakpoint

GRANT coffre_app TO coffre_runtime WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
