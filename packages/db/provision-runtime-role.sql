\set ON_ERROR_STOP on

BEGIN;

SELECT format(
    $check$
    DO $block$
    DECLARE
        target oid;
    BEGIN
        IF %L IN ('postgres', 'coffre_owner', 'coffre_app') THEN
            RAISE EXCEPTION 'refusing reserved runtime role';
        END IF;

        SELECT oid INTO target FROM pg_roles WHERE rolname = %L;
        IF target IS NOT NULL AND EXISTS (
            SELECT 1
              FROM pg_shdepend
             WHERE refclassid = 'pg_authid'::regclass
               AND refobjid = target
               AND deptype = 'o'
        ) THEN
            RAISE EXCEPTION 'runtime role owns database objects';
        END IF;
    END
    $block$
    $check$,
    :'runtime_role',
    :'runtime_role'
)
\gexec

SELECT format('CREATE ROLE %I', :'runtime_role')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime_role')
\gexec

SELECT format(
    'ALTER ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'runtime_role',
    :'runtime_password'
)
\gexec

-- The login receives application access only through coffre_app.
SELECT format(
    'REVOKE %I FROM %I',
    granted.rolname,
    :'runtime_role'
)
  FROM pg_auth_members membership
  JOIN pg_roles member ON member.oid = membership.member
  JOIN pg_roles granted ON granted.oid = membership.roleid
 WHERE member.rolname = :'runtime_role'
   AND granted.rolname <> 'coffre_app'
\gexec

SELECT format(
    'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I',
    :'runtime_role'
)
\gexec
SELECT format(
    'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %I',
    :'runtime_role'
)
\gexec
SELECT format(
    'REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM %I',
    :'runtime_role'
)
\gexec
SELECT format(
    'REVOKE ALL PRIVILEGES ON SCHEMA public FROM %I',
    :'runtime_role'
)
\gexec
SELECT format(
    'REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I',
    current_database(),
    :'runtime_role'
)
\gexec

SELECT format(
    'GRANT coffre_app TO %I WITH ADMIN FALSE, INHERIT TRUE, SET FALSE',
    :'runtime_role'
)
\gexec

COMMIT;
