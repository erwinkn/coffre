-- A secret carries the number of its current version, so the next one is
-- that plus one, read from the row the writer already locks, rather than a
-- max() over its history.

ALTER TABLE "secrets" ADD COLUMN "current_version" integer DEFAULT 0 NOT NULL;
--> statement-breakpoint

UPDATE "secrets"
   SET "current_version" = (
       SELECT coalesce(max("version"), 0) FROM "secret_versions"
        WHERE "secret_versions"."secret_id" = "secrets"."id"
   );
--> statement-breakpoint

GRANT UPDATE ("current_version") ON "secrets" TO coffre_app;
