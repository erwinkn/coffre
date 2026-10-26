-- Backups (W2356): the group coffre_backup reads every row and writes none, so a nightly pg_dump need not hold the owner's password. No login is made or granted here: `coffre migrate --backup-login <role>` grants the group to the role it names. Reading every table is not enough: the audit log's row-level security shows its rows only to the roles a policy names, so pg_dump as a role that reads every table (pg_read_all_data) is refused the log, or with --enable-row-security dumps no entry. It only adds a role, read grants and a read policy: the release before never meets them.
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
        -- It would pass on what it is a member of to its members.
        IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = 'coffre_backup'::regrole) THEN
            RAISE EXCEPTION 'coffre_backup is a member of another role, whose privileges its members would inherit: revoke its memberships';
        END IF;
        -- Revoking cannot take an owner's rights away: its members would write what it owns.
        IF EXISTS (
            SELECT 1 FROM pg_shdepend
             WHERE refclassid = 'pg_authid'::regclass AND refobjid = 'coffre_backup'::regrole AND deptype = 'o'
        ) THEN
            RAISE EXCEPTION 'coffre_backup owns database objects, which its members could change: reassign them';
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
-- coffre's own, by name, as the baseline grants: public may hold a database's other tables (FOREIGN_OWNERS in migrate.ts), which are not coffre's to grant, whichever login migrates, a superuser included. A group made before this keeps no other privilege on them. A later migration that makes a table grants it SELECT too, as it grants coffre_app, rather than default privileges, which would give it every table the login makes, coffre's or not, and none another login makes.
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
