-- coffre M0: database roles.
--
-- Append-only in the schema, not by convention. The application connects as
-- coffre_app, which has no UPDATE and no DELETE on audit_log. A bug, an
-- injection, or a compromised application process cannot rewrite history --
-- it can only append to it.
--
-- This is necessary but not sufficient, which is why the hash chain exists:
-- the owner and superuser roles below can still rewrite the table. What they
-- cannot do is recompute the chain, because the chain key is not in the
-- database. See packages/core/src/audit/chain.ts.

-- The migration owner. Created by the operator out of band; this file assumes
-- it is the role running these migrations.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffre_app') THEN
        CREATE ROLE coffre_app NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO coffre_app;

-- Ordinary tables: full CRUD except that secret_versions is append-only too.
GRANT SELECT, INSERT, UPDATE, DELETE ON projects, environments, secrets, grants TO coffre_app;

-- Secret versions are immutable once written. A new value is a new row, which
-- is what makes rollback free and history intact.
GRANT SELECT, INSERT ON secret_versions TO coffre_app;

-- The audit log: append and read only. No UPDATE. No DELETE. No TRUNCATE.
GRANT SELECT, INSERT ON audit_log TO coffre_app;

-- The chain head must be updatable -- it is how seq and prev_hash are assigned
-- under a row lock -- but never deletable.
GRANT SELECT, UPDATE ON audit_chain_head TO coffre_app;
GRANT SELECT, INSERT, UPDATE ON audit_checkpoints TO coffre_app;
GRANT SELECT, UPDATE ON audit_heartbeat TO coffre_app;

-- Explicitly revoke, in case a future migration grants more broadly by default.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM coffre_app;
REVOKE UPDATE, DELETE, TRUNCATE ON secret_versions FROM coffre_app;
REVOKE DELETE, TRUNCATE ON audit_chain_head FROM coffre_app;

-- Anything added later is not silently granted to the application.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM coffre_app;
