-- Roles move into code (packages/core/src/access.ts). A grant stores its
-- role's name, and a member holds at most one grant per place.
--
-- Where someone holds several roles on one place, the live grant whose role
-- covers all the others is kept. If no role covers the rest, the migration
-- stops and lists the grants, so a person decides rather than a guess.

ALTER TABLE "grants" ADD COLUMN "role" text;
--> statement-breakpoint

UPDATE "grants" SET "role" = "roles"."slug" FROM "roles" WHERE "roles"."id" = "grants"."role_id";
--> statement-breakpoint

CREATE TEMP TABLE "grants_0003" ON COMMIT DROP AS
SELECT "id", "principal_type", "principal_id", "project_id", "environment_id", "role_id",
       "expires_at", "created_at",
       ("expires_at" IS NULL OR "expires_at" > now()) AS "live",
       count(*) OVER place AS "siblings",
       bool_or("expires_at" IS NULL OR "expires_at" > now()) OVER place AS "place_live"
  FROM "grants"
WINDOW place AS (PARTITION BY "principal_type", "principal_id", "project_id", "environment_id");
--> statement-breakpoint

DO $$
DECLARE
    unresolved text;
BEGIN
    -- The competitors on a shared place: its live grants, or all of them if
    -- every one has expired.
    CREATE TEMP TABLE "grants_0003_keep" ON COMMIT DROP AS
    WITH competing AS (
        SELECT * FROM "grants_0003"
         WHERE "siblings" > 1 AND ("live" OR NOT "place_live")
    ),
    covering AS (
        SELECT candidate.*
          FROM competing candidate
         WHERE NOT candidate."place_live"
            OR NOT EXISTS (
                SELECT 1
                  FROM competing other
                  JOIN "role_permissions" needed ON needed."role_id" = other."role_id"
                 WHERE other."principal_type" = candidate."principal_type"
                   AND other."principal_id" = candidate."principal_id"
                   AND other."project_id" IS NOT DISTINCT FROM candidate."project_id"
                   AND other."environment_id" IS NOT DISTINCT FROM candidate."environment_id"
                   AND NOT EXISTS (
                       SELECT 1 FROM "role_permissions" held
                        WHERE held."role_id" = candidate."role_id"
                          AND held."permission" = needed."permission"
                   )
            )
    )
    SELECT DISTINCT ON ("principal_type", "principal_id", "project_id", "environment_id") "id"
      FROM covering
     ORDER BY "principal_type", "principal_id", "project_id", "environment_id",
              "expires_at" DESC NULLS FIRST, "created_at" DESC;

    SELECT string_agg(
               format('%s %s:%s on %s holds %s (grant %s)',
                      CASE WHEN g."environment_id" IS NULL THEN 'project' ELSE 'environment' END,
                      g."principal_type", g."principal_id",
                      coalesce(g."environment_id", g."project_id"), r."slug", g."id"),
               E'\n' ORDER BY g."principal_id", g."id")
      INTO unresolved
      FROM "grants_0003" g
      JOIN "roles" r ON r."id" = g."role_id"
     WHERE g."siblings" > 1 AND g."live"
       AND NOT EXISTS (
           SELECT 1 FROM "grants_0003" kept
             JOIN "grants_0003_keep" keep ON keep."id" = kept."id"
            WHERE kept."principal_type" = g."principal_type"
              AND kept."principal_id" = g."principal_id"
              AND kept."project_id" IS NOT DISTINCT FROM g."project_id"
              AND kept."environment_id" IS NOT DISTINCT FROM g."environment_id"
       );

    IF unresolved IS NOT NULL THEN
        RAISE EXCEPTION E'one role per member per place: no role covers the others on these places; revoke all but one and migrate again:\n%', unresolved;
    END IF;

    DELETE FROM "grants"
     WHERE "id" IN (SELECT "id" FROM "grants_0003" WHERE "siblings" > 1)
       AND "id" NOT IN (SELECT "id" FROM "grants_0003_keep");
END
$$;
--> statement-breakpoint

-- People are their email address, lowercased, so sign-in can match a
-- provider's verified email with plain equality. Rows that differ only in
-- case would merge two people, so those stop the migration instead.
DO $$
DECLARE
    person record;
    clashes text;
BEGIN
    SELECT string_agg(mixed."principal_id", ', ' ORDER BY mixed."principal_id")
      INTO clashes
      FROM "principals" mixed
     WHERE mixed."principal_type" = 'user'
       AND mixed."principal_id" <> lower(mixed."principal_id")
       AND (
           SELECT count(*) FROM "principals" twin
            WHERE twin."principal_type" = 'user'
              AND lower(twin."principal_id") = lower(mixed."principal_id")
       ) > 1;
    IF clashes IS NOT NULL THEN
        RAISE EXCEPTION 'these people exist twice, differing only in case; remove one of each and migrate again: %', clashes;
    END IF;

    FOR person IN
        SELECT * FROM "principals"
         WHERE "principal_type" = 'user' AND "principal_id" <> lower("principal_id")
    LOOP
        INSERT INTO "principals" ("principal_type", "principal_id", "instance_role", "created_at", "created_by", "active")
        VALUES ('user', lower(person."principal_id"), person."instance_role", person."created_at", person."created_by", person."active");
        UPDATE "grants" SET "principal_id" = lower("principal_id")
         WHERE "principal_type" = 'user' AND "principal_id" = person."principal_id";
        UPDATE "identities" SET "principal_id" = lower("principal_id")
         WHERE "principal_type" = 'user' AND "principal_id" = person."principal_id";
        UPDATE "credentials" SET "principal_id" = lower("principal_id")
         WHERE "principal_type" = 'user' AND "principal_id" = person."principal_id";
        UPDATE "device_authorizations" SET "principal_id" = lower("principal_id")
         WHERE "principal_type" = 'user' AND "principal_id" = person."principal_id";
        DELETE FROM "principals"
         WHERE "principal_type" = 'user' AND "principal_id" = person."principal_id";
    END LOOP;
END
$$;
--> statement-breakpoint

ALTER TABLE "grants" ALTER COLUMN "role" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "grants" DROP CONSTRAINT "grants_role_id_fkey";--> statement-breakpoint
DROP INDEX "grants_environment_unique";--> statement-breakpoint
DROP INDEX "grants_project_unique";--> statement-breakpoint
ALTER TABLE "grants" DROP COLUMN "role_id";--> statement-breakpoint
DROP TABLE "role_permissions";--> statement-breakpoint
DROP TABLE "roles";--> statement-breakpoint
DROP TABLE "permissions";--> statement-breakpoint
CREATE UNIQUE INDEX "grants_environment_unique" ON "grants" USING btree ("principal_type","principal_id","environment_id") WHERE "grants"."environment_id" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "grants_project_unique" ON "grants" USING btree ("principal_type","principal_id","project_id") WHERE "grants"."project_id" IS NOT NULL;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_role_check" CHECK ("grants"."role" IN ('viewer', 'developer', 'maintainer', 'access-manager', 'auditor', 'owner'));--> statement-breakpoint
ALTER TABLE "principals" ADD CONSTRAINT "principals_user_id_lowercase" CHECK ("principals"."principal_type" <> 'user' OR "principals"."principal_id" = lower("principals"."principal_id"));--> statement-breakpoint

GRANT UPDATE ("role") ON "grants" TO coffre_app;
