\set ON_ERROR_STOP on

-- What the backup login may do, through its group coffre_backup: read every
-- row and nothing else (0019_backup_role.sql, and 0022_smaller_vault.sql for
-- 0.16's tables). Run as coffre_backup_login, with
-- -v entries=<the log's row count>.

DO $$
BEGIN
    IF current_user <> 'coffre_backup_login' THEN
        RAISE EXCEPTION 'run as coffre_backup_login, not %', current_user;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname IN (current_user, 'coffre_backup')
        AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'the backup login or its group has unsafe role attributes';
    END IF;
    IF (SELECT array_agg(format('%s admin=%s inherit=%s set=%s', roleid::regrole, admin_option, inherit_option, set_option))
          FROM pg_auth_members WHERE member = current_user::regrole)
       IS DISTINCT FROM ARRAY['coffre_backup admin=f inherit=t set=f'] THEN
        RAISE EXCEPTION 'the backup login must be a member of coffre_backup alone, inheriting it, never setting it';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = 'coffre_backup'::regrole) THEN
        RAISE EXCEPTION 'coffre_backup is a member of another role';
    END IF;
    IF has_database_privilege(current_database(), 'CREATE') OR has_database_privilege(current_database(), 'TEMPORARY') THEN
        RAISE EXCEPTION 'the backup login may create in the database';
    END IF;
    IF has_schema_privilege('public', 'CREATE') OR has_schema_privilege('drizzle', 'CREATE') THEN
        RAISE EXCEPTION 'the backup login may create in a schema';
    END IF;
END
$$;

-- Every table and sequence reads; none writes, by any statement.
DO $$
DECLARE
    relation record;
    attempt text;
BEGIN
    FOR relation IN
        SELECT c.oid::regclass AS name, c.relkind,
               (SELECT quote_ident(attname) FROM pg_attribute WHERE attrelid = c.oid AND attnum > 0 AND NOT attisdropped AND attgenerated = '' AND attidentity = '' ORDER BY attnum LIMIT 1) AS col
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname IN ('public', 'drizzle') AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
    LOOP
        IF relation.relkind = 'S' THEN
            IF NOT has_sequence_privilege(relation.name, 'SELECT') OR has_sequence_privilege(relation.name, 'USAGE, UPDATE') THEN
                RAISE EXCEPTION 'the backup login does not hold exactly SELECT on sequence %', relation.name;
            END IF;
            BEGIN
                PERFORM nextval(relation.name);
                RAISE EXCEPTION 'the backup login advanced %', relation.name;
            EXCEPTION WHEN insufficient_privilege THEN NULL;
            END;
            CONTINUE;
        END IF;
        IF NOT has_table_privilege(relation.name, 'SELECT')
           OR has_table_privilege(relation.name, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
           OR has_any_column_privilege(relation.name, 'INSERT, UPDATE, REFERENCES') THEN
            RAISE EXCEPTION 'the backup login does not hold exactly SELECT on %', relation.name;
        END IF;
        FOREACH attempt IN ARRAY ARRAY[
            format('INSERT INTO %s DEFAULT VALUES', relation.name),
            format('UPDATE %s SET %s = %s', relation.name, relation.col, relation.col),
            format('DELETE FROM %s', relation.name),
            format('TRUNCATE %s', relation.name)
        ] LOOP
            BEGIN
                EXECUTE attempt;
                RAISE EXCEPTION 'the backup login ran %', attempt;
            EXCEPTION WHEN insufficient_privilege THEN NULL;
            END;
        END LOOP;
    END LOOP;
END
$$;

-- No function that writes as its owner.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname IN ('public', 'drizzle') AND p.prosecdef AND has_function_privilege(p.oid, 'EXECUTE')
    ) THEN
        RAISE EXCEPTION 'the backup login may run a SECURITY DEFINER function';
    END IF;
END
$$;

-- Row-level security shows coffre_backup the rows of a table only through a
-- policy for it that shows every row, and no restrictive one that hides
-- some: otherwise pg_dump --enable-row-security dumps the table short, and
-- says nothing.
DO $$
DECLARE
    unread text;
BEGIN
    SELECT string_agg(c.oid::regclass::text, ', ') INTO unread
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('public', 'drizzle') AND c.relrowsecurity
       AND (NOT EXISTS (
           SELECT 1 FROM pg_policy p
            WHERE p.polrelid = c.oid AND p.polcmd IN ('r', '*') AND p.polpermissive
              AND (p.polroles && ARRAY['coffre_backup'::regrole::oid, 0::oid])
              AND pg_get_expr(p.polqual, p.polrelid) = 'true'
       ) OR EXISTS (
           SELECT 1 FROM pg_policy p
            WHERE p.polrelid = c.oid AND p.polcmd IN ('r', '*') AND NOT p.polpermissive
              AND (p.polroles && ARRAY['coffre_backup'::regrole::oid, 0::oid])
              AND pg_get_expr(p.polqual, p.polrelid) IS DISTINCT FROM 'true'
       ));
    IF unread IS NOT NULL THEN
        RAISE EXCEPTION 'no policy shows coffre_backup the rows of %', unread;
    END IF;
END
$$;

-- And the log reads whole: every entry the owner counted.
SELECT set_config('coffre.entries', :'entries', false) \gset
DO $$
BEGIN
    IF (SELECT count(*) FROM log) <> current_setting('coffre.entries')::bigint THEN
        RAISE EXCEPTION 'the backup login reads % of % log entries', (SELECT count(*) FROM log), current_setting('coffre.entries');
    END IF;
END
$$;
