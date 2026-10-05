CREATE TABLE "secret_references" (
	"id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"environment_id" uuid NOT NULL,
	"secret_id" uuid NOT NULL,
	"source_project_id" uuid NOT NULL,
	"source_environment_id" uuid NOT NULL,
	"source_secret_id" uuid NOT NULL,
	"created_seq" bigint NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	CONSTRAINT "secret_references_created_seq_key" UNIQUE("created_seq")
);
--> statement-breakpoint
ALTER TABLE "secret_references" ADD CONSTRAINT "secret_references_secret_id_fkey" FOREIGN KEY ("secret_id") REFERENCES "public"."secrets"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret_references" ADD CONSTRAINT "secret_references_source_secret_id_fkey" FOREIGN KEY ("source_secret_id") REFERENCES "public"."secrets"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret_references" ADD CONSTRAINT "secret_references_created_seq_fkey" FOREIGN KEY ("created_seq") REFERENCES "public"."audit_log"("seq") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "secret_references_holder_idx" ON "secret_references" USING btree ("secret_id","created_seq");--> statement-breakpoint
CREATE INDEX "secret_references_source_idx" ON "secret_references" USING btree ("source_secret_id");--> statement-breakpoint
CREATE INDEX "secret_references_project_idx" ON "secret_references" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "secret_references_source_project_idx" ON "secret_references" USING btree ("source_project_id");--> statement-breakpoint
CREATE INDEX "secret_references_created_by_idx" ON "secret_references" USING btree ("created_by");--> statement-breakpoint
CREATE INDEX "audit_log_reference_end_idx" ON "audit_log" USING btree ("related_seq") WHERE "audit_log"."author" = 'vault' AND "audit_log"."action" = 'reference.end' AND "audit_log"."decision" = 'allow';--> statement-breakpoint
CREATE INDEX "audit_log_also_project_idx" ON "audit_log" USING btree (((("metadata")::jsonb -> 'also') ->> 'projectId'),"seq") WHERE (("audit_log"."metadata")::jsonb -> 'also') IS NOT NULL;--> statement-breakpoint
CREATE INDEX "audit_log_also_environment_idx" ON "audit_log" USING btree (((("metadata")::jsonb -> 'also') ->> 'environmentId'),"seq") WHERE (("audit_log"."metadata")::jsonb -> 'also') IS NOT NULL;--> statement-breakpoint
CREATE INDEX "audit_log_also_secret_idx" ON "audit_log" USING btree (((("metadata")::jsonb -> 'also') ->> 'secretId'),"seq") WHERE (("audit_log"."metadata")::jsonb -> 'also') IS NOT NULL;--> statement-breakpoint
-- The app adds references and reads them; it never changes or deletes one:
-- the vault's log says which have ended. The vault reads none of it: a
-- reference is its own entry, which a read names.
GRANT SELECT, INSERT ON secret_references TO coffre_app;
