-- The app sets parent_id and owner when it makes an environment, and never after: they get no UPDATE grant, so a parent cannot change.
ALTER TABLE "environments" ADD COLUMN "parent_id" uuid;--> statement-breakpoint
ALTER TABLE "environments" ADD COLUMN "owner" text;--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_parent_in_project" FOREIGN KEY ("parent_id","project_id") REFERENCES "public"."environments"("id","project_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "environments_parent_idx" ON "environments" USING btree ("parent_id");--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_parent_id_owner_key" UNIQUE("parent_id","owner");--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_parent_check" CHECK ("environments"."parent_id" IS NULL OR "environments"."parent_id" <> "environments"."id");--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_owner_check" CHECK ("environments"."owner" IS NULL OR ("environments"."parent_id" IS NOT NULL AND "environments"."owner" LIKE 'user:_%'));
