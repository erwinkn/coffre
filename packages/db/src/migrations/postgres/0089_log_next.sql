-- 0.16.0, T289: the log numbers from `log_next`, and `log_number` goes, so that a 0.15.0 call already inside a function
-- body when the upgrade commits cannot append (the 0.16 plan, #569: "After the commit, 0.15.0 cannot append").
-- Postgres runs the body a call entered to its end, whatever became of the function; but every append to `log_changes`
-- or `log_uses` draws from the sequence inside its INSERT, so a held one fails, 42P01, once the sequence is gone. Under
-- its old name again it would not: the INSERT, planned after the commit, would find the new one.
--
-- The tables first: an append that drew from `log_number` after `log_next` was set would hand its number out twice.
LOCK TABLE "log_changes", "log_uses" IN ACCESS EXCLUSIVE MODE;--> statement-breakpoint
CREATE SEQUENCE "log_next" AS bigint CACHE 1;--> statement-breakpoint
SELECT setval('log_next', nextval('log_number'), false);--> statement-breakpoint
GRANT SELECT ON SEQUENCE "log_next" TO coffre_backup;--> statement-breakpoint
-- The same bodies, but for the sequence: CREATE OR REPLACE keeps each function's owner, grants and settings.
DO $$
DECLARE
    f oid;
BEGIN
    FOR f IN SELECT p.oid FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.prosrc LIKE '%log_number%' LOOP
        EXECUTE replace(pg_get_functiondef(f), 'public.log_number', 'public.log_next');
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_proc p WHERE p.prosrc LIKE '%log_number%') THEN
        RAISE EXCEPTION 'a function still names log_number';
    END IF;
END
$$;--> statement-breakpoint
DROP SEQUENCE "log_number";--> statement-breakpoint
-- The one appender whose argument list 0.16 keeps from 0.15.0: a call sent after the commit resolves to no function.
ALTER FUNCTION public.log_retention(text, bigint, text, bytea) RENAME TO append_retention;
