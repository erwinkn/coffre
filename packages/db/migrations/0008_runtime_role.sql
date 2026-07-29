-- Minimal runtime privileges.
--
-- Migrations run as the database owner. The API login inherits coffre_app and
-- receives only the data access used by the application SQL.

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM coffre_app;

GRANT SELECT, INSERT ON
    projects,
    environments,
    secrets,
    grants,
    principals,
    secret_versions,
    audit_log
TO coffre_app;

GRANT SELECT ON permissions, roles, role_permissions TO coffre_app;

GRANT UPDATE (slug, name, archived_at) ON projects TO coffre_app;
GRANT UPDATE (slug, name, archived_at) ON environments TO coffre_app;
GRANT UPDATE (key, current_version_id, updated_at, archived_at)
    ON secrets TO coffre_app;
GRANT UPDATE (role_id, expires_at, created_by) ON grants TO coffre_app;
GRANT UPDATE (instance_role, active, created_at, created_by)
    ON principals TO coffre_app;

GRANT SELECT ON audit_chain_head, audit_checkpoints, audit_heartbeat TO coffre_app;
GRANT UPDATE (next_seq, head_hash, updated_at) ON audit_chain_head TO coffre_app;
GRANT UPDATE (last_beat_at, last_seq) ON audit_heartbeat TO coffre_app;

-- Deletion is represented by archived_at, active, or expires_at updates.
REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM coffre_app;
REVOKE UPDATE ON audit_log, secret_versions FROM coffre_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC, coffre_app;

DO $$
BEGIN
    EXECUTE format(
        'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC, coffre_app',
        current_database()
    );
END
$$;
