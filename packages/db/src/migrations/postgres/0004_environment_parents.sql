-- The app sets parent_id when it makes an environment, and never after: it gets no UPDATE grant, so a parent cannot change.
ALTER TABLE "environments" ADD COLUMN "parent_id" uuid;--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_parent_in_project" FOREIGN KEY ("parent_id","project_id") REFERENCES "public"."environments"("id","project_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "environments_parent_idx" ON "environments" USING btree ("parent_id");--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_parent_check" CHECK ("environments"."parent_id" IS NULL OR "environments"."parent_id" <> "environments"."id");