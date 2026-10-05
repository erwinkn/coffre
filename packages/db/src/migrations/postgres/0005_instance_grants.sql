-- Grants on every project, or on one environment slug in every project
-- (docs/design/instance-grants.md): a column, and the checks loosened to
-- allow a grant with neither id. Every row the previous release writes
-- passes them, and it never reads the column.
ALTER TABLE "vault_grants" ADD COLUMN "environment_slug" text;
--> statement-breakpoint
ALTER TABLE "vault_grants" DROP CONSTRAINT "vault_grants_one_place";
--> statement-breakpoint
ALTER TABLE "vault_grants" ADD CONSTRAINT "vault_grants_one_place" CHECK ((("vault_grants"."project_id" IS NULL) <> ("vault_grants"."environment_id" IS NULL) AND "vault_grants"."environment_slug" IS NULL) OR ("vault_grants"."project_id" IS NULL AND "vault_grants"."environment_id" IS NULL));
--> statement-breakpoint
ALTER TABLE "vault_grants" DROP CONSTRAINT "vault_grants_environment_role_check";
--> statement-breakpoint
ALTER TABLE "vault_grants" ADD CONSTRAINT "vault_grants_environment_role_check" CHECK (("vault_grants"."environment_id" IS NULL AND "vault_grants"."environment_slug" IS NULL) OR "vault_grants"."role" IN ('viewer', 'developer', 'auditor'));
--> statement-breakpoint
ALTER TABLE "vault_grants" ADD CONSTRAINT "vault_grants_environment_slug_check" CHECK ("vault_grants"."environment_slug" IS NULL OR "vault_grants"."environment_slug" ~ '^[a-z0-9][a-z0-9-]{0,62}$');
--> statement-breakpoint
ALTER TABLE "vault_grants" ADD CONSTRAINT "vault_grants_on_environment_slug" UNIQUE("principal","environment_slug");
--> statement-breakpoint
CREATE UNIQUE INDEX "vault_grants_on_every_project" ON "vault_grants" USING btree ("principal") WHERE "vault_grants"."project_id" IS NULL AND "vault_grants"."environment_id" IS NULL AND "vault_grants"."environment_slug" IS NULL;