-- Run as the migration role after creating a LOGIN role named coffre_runtime.
-- Set its password out of band; never commit it here.
GRANT USAGE ON SCHEMA public TO coffre_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO coffre_runtime;
GRANT INSERT, UPDATE ON coffre_projects, coffre_environments, coffre_secrets, coffre_principals, coffre_grants, coffre_meta TO coffre_runtime;
GRANT INSERT ON coffre_versions, coffre_audit, coffre_receipts TO coffre_runtime;
GRANT INSERT, DELETE ON coffre_guard, coffre_outbox TO coffre_runtime;
GRANT DELETE ON coffre_grants TO coffre_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON coffre_audit, coffre_versions FROM coffre_runtime;
