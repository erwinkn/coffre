-- Adversarial checks through the app's login, coffre_runtime, a member of
-- coffre_app.
--
-- In 0.16 the app's login only reads (docs/design/0.16.md, "Four rules"):
-- the vault writes every row, and 0022_smaller_vault.sql grants coffre_app
-- SELECT and nothing else. Every block below asserts that something the app
-- must NOT be able to do fails. A passing run prints only 'PASS' lines.

\set ON_ERROR_STOP on
\set QUIET on

\echo '--- running through the app login ---'

-- 1. Every table reads, and holds no other privilege: not on the table, not
-- on a column of it. A table added without its grant fails here too.
DO $$
DECLARE
    relation record;
BEGIN
    FOR relation IN
        SELECT c.oid::regclass AS name
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
    LOOP
        IF NOT has_table_privilege(relation.name, 'SELECT') THEN
            RAISE EXCEPTION 'FAIL: coffre_app cannot read %', relation.name;
        END IF;
        EXECUTE format('SELECT count(*) FROM %s', relation.name);
        IF has_table_privilege(relation.name, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
           OR has_any_column_privilege(relation.name, 'INSERT, UPDATE, REFERENCES') THEN
            RAISE EXCEPTION 'FAIL: coffre_app holds more than SELECT on %', relation.name;
        END IF;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_app reads every table and holds nothing else on any';
END
$$;

-- 2. And every write, tried, is refused: an insert, an update of a column to
-- itself, a delete and a truncate, on every table.
DO $$
DECLARE
    relation record;
    attempt text;
BEGIN
    FOR relation IN
        SELECT c.oid::regclass AS name,
               (SELECT quote_ident(attname) FROM pg_attribute
                 WHERE attrelid = c.oid AND attnum > 0 AND NOT attisdropped AND attgenerated = '' AND attidentity = ''
                 ORDER BY attnum LIMIT 1) AS col
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind = 'r'
    LOOP
        FOREACH attempt IN ARRAY ARRAY[
            format('INSERT INTO %s DEFAULT VALUES', relation.name),
            format('UPDATE %s SET %s = %s', relation.name, relation.col, relation.col),
            format('DELETE FROM %s', relation.name),
            format('TRUNCATE %s', relation.name)
        ] LOOP
            BEGIN
                EXECUTE attempt;
                RAISE EXCEPTION 'FAIL: coffre_app ran %', attempt;
            EXCEPTION
                WHEN insufficient_privilege THEN NULL;
            END;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_app inserts, updates, deletes and truncates nothing';
END
$$;

-- 3. Nor through a sequence, or a function that runs as its owner.
DO $$
DECLARE
    sequence record;
BEGIN
    FOR sequence IN
        SELECT c.oid::regclass AS name
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind = 'S'
    LOOP
        IF has_sequence_privilege(sequence.name, 'USAGE, UPDATE') THEN
            RAISE EXCEPTION 'FAIL: coffre_app may advance %', sequence.name;
        END IF;
        BEGIN
            PERFORM nextval(sequence.name);
            RAISE EXCEPTION 'FAIL: coffre_app advanced %', sequence.name;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    IF EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname IN ('public', 'drizzle') AND p.prosecdef AND has_function_privilege(p.oid, 'EXECUTE')
    ) THEN
        RAISE EXCEPTION 'FAIL: coffre_app may run a SECURITY DEFINER function';
    END IF;
    RAISE NOTICE 'PASS: coffre_app advances no sequence and runs no function as its owner';
END
$$;

-- 4. It reads which migrations ran, to answer 503 below them, and writes none.
DO $$
BEGIN
    PERFORM count(*) FROM drizzle.__drizzle_migrations;
    IF has_table_privilege('drizzle.__drizzle_migrations', 'INSERT, UPDATE, DELETE, TRUNCATE') THEN
        RAISE EXCEPTION 'FAIL: coffre_app may write the migrations table';
    END IF;
    RAISE NOTICE 'PASS: coffre_app reads the migrations it runs on, and writes none';
END
$$;

-- 5. The runtime login cannot create database objects.
DO $$
BEGIN
    CREATE TABLE runtime_must_not_create_objects (id integer);
    RAISE EXCEPTION 'FAIL: runtime login was able to run DDL';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: runtime login cannot run DDL';
END
$$;

DO $$
BEGIN
    CREATE TEMP TABLE runtime_must_not_create_temp_objects (id integer);
    RAISE EXCEPTION 'FAIL: runtime login was able to create a temporary table';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: runtime login cannot create temporary tables';
END
$$;

-- 6. Nor become the vault, or the backups.
DO $$
DECLARE
    statement text;
BEGIN
    FOREACH statement IN ARRAY ARRAY['SET ROLE coffre_vault', 'SET ROLE coffre_backup'] LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION 'FAIL: coffre_app was able to run: %', statement;
        EXCEPTION
            WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
    RAISE NOTICE 'PASS: coffre_app acts as no one else';
END
$$;

\echo '--- all schema guarantees held ---'
