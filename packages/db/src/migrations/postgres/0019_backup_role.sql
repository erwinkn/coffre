-- Backups (W2356): the group coffre_backup reads every row and writes none, so a nightly pg_dump need not hold the owner's password. Its login, coffre_backup_login, is provisioned outside the migrations, as the runtime logins are, and every `coffre migrate` grants it this group. Reading every table is not enough: the audit log's row-level security shows its rows only to the roles a policy names, so pg_dump as a role that reads every table (pg_read_all_data) is refused the log, or with --enable-row-security dumps no entry. It only adds a role, read grants and a read policy: the release before never meets them.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_backup') THEN
        -- No migration since the baseline made a role: a login that migrates as a member of the owner inherits its privileges, never its CREATEROLE.
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolcreaterole)) THEN
            RAISE EXCEPTION '% may not create roles, and this migration makes coffre_backup: migrate as a login with CREATEROLE, or have one run CREATE ROLE coffre_backup NOLOGIN; GRANT coffre_backup TO % WITH ADMIN TRUE, INHERIT FALSE, SET FALSE first', current_user, current_user;
        END IF;
        CREATE ROLE coffre_backup NOLOGIN INHERIT NOCREATEDB NOCREATEROLE;
    ELSE
        -- Managed owners cannot ALTER the superuser-only attributes, even to turn them off.
        IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'coffre_backup'
            AND (rolsuper OR rolreplication OR rolbypassrls)
        ) THEN
            RAISE EXCEPTION 'coffre_backup has unsafe role attributes: SUPERUSER, REPLICATION and BYPASSRLS must be off';
        END IF;
        -- It would pass on what it is a member of to the backup login.
        IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = 'coffre_backup'::regrole) THEN
            RAISE EXCEPTION 'coffre_backup is a member of another role, whose privileges the backup login would inherit: revoke its memberships';
        END IF;
        -- Nor may anyone but the backup login hold what this grants it. A role's creator holds ADMIN on it, which neither inherits nor sets it.
        IF EXISTS (
            SELECT 1 FROM pg_auth_members
             WHERE roleid = 'coffre_backup'::regrole AND member::regrole::text <> 'coffre_backup_login'
               AND (inherit_option OR set_option)
        ) THEN
            RAISE EXCEPTION 'coffre_backup has members other than coffre_backup_login, who would read every row: revoke their memberships';
        END IF;
        -- Only when it must: altering a role takes CREATEROLE too.
        IF EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'coffre_backup'
            AND (rolcanlogin OR NOT rolinherit OR rolcreatedb OR rolcreaterole)
        ) THEN
            ALTER ROLE coffre_backup NOLOGIN INHERIT NOCREATEDB NOCREATEROLE;
        END IF;
    END IF;
END
$$;
--> statement-breakpoint
-- coffre's own, by name, as the baseline grants: public may hold a database's other tables (FOREIGN_OWNERS in migrate.ts), which are not coffre's to grant, whichever login migrates, a superuser included. A group made before this keeps no other privilege on them. Each migrate grants what later migrations make, by the names in their SQL (`grantBackup` in migrate.ts), rather than default privileges, which would give it every table the login makes, coffre's or not, and none another login makes.
REVOKE ALL ON SCHEMA public, drizzle FROM coffre_backup;
--> statement-breakpoint
GRANT USAGE ON SCHEMA public, drizzle TO coffre_backup;
--> statement-breakpoint
REVOKE ALL ON audit_chain_head, audit_log, capped_alerts, consumed_tokens, credentials, device_authorizations, dismissed_keys, enrollments, environments, identities, mcp_approvals, mcp_connections, oauth_clients, projects, secret_references, secret_versions, secrets, service_bindings, vault_grants, vault_members FROM coffre_backup;
--> statement-breakpoint
REVOKE ALL ON ALL TABLES IN SCHEMA drizzle FROM coffre_backup;
--> statement-breakpoint
REVOKE ALL ON ALL SEQUENCES IN SCHEMA drizzle FROM coffre_backup;
--> statement-breakpoint
REVOKE ALL ON FUNCTION audit_log_append_only(), secret_versions_erase_only(), prune_consumed_tokens(integer) FROM coffre_backup;
--> statement-breakpoint
GRANT SELECT ON audit_chain_head, audit_log, capped_alerts, consumed_tokens, credentials, device_authorizations, dismissed_keys, enrollments, environments, identities, mcp_approvals, mcp_connections, oauth_clients, projects, secret_references, secret_versions, secrets, service_bindings, vault_grants, vault_members TO coffre_backup;
--> statement-breakpoint
GRANT SELECT ON ALL TABLES IN SCHEMA drizzle TO coffre_backup;
--> statement-breakpoint
GRANT SELECT ON ALL SEQUENCES IN SCHEMA drizzle TO coffre_backup;
--> statement-breakpoint
CREATE POLICY audit_log_backup_read ON audit_log FOR SELECT TO coffre_backup USING (true);
