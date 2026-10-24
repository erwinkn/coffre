-- Workload access (docs/design/workload-access.md, section 11): key-bound sessions, their enrollment codes, and bindings' policies. It only adds: the release before neither reads nor writes any of it, and every check is only looser for its rows, so it serves on this schema unchanged.
CREATE TABLE "enrollments" (
	"id" uuid PRIMARY KEY NOT NULL,
	"auth_mac" "bytea" NOT NULL,
	"binding_id" uuid NOT NULL,
	"code_hash" "bytea" NOT NULL,
	"code_hint" text NOT NULL,
	"scope" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"created_with" uuid,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "enrollments_code_hash_key" UNIQUE("code_hash"),
	CONSTRAINT "enrollments_auth_mac_check" CHECK (octet_length("enrollments"."auth_mac") = 32),
	CONSTRAINT "enrollments_code_hash_check" CHECK (octet_length("enrollments"."code_hash") = 32),
	CONSTRAINT "enrollments_scope_check" CHECK ("enrollments"."scope"::jsonb IS NOT NULL)
);
--> statement-breakpoint
-- The checks widen to a workload's session, a service's credential like a service token; a session carries the key it is bound to.
ALTER TABLE "credentials" DROP CONSTRAINT "credentials_kind_check";--> statement-breakpoint
ALTER TABLE "credentials" DROP CONSTRAINT "credentials_kind_matches_principal";--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "jkt" text;--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "not_after" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "ancestors" text;--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "constraints" text;--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "enrollment_id" uuid;--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "approved_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "approved_by" text;--> statement-breakpoint
-- A binding's policy, inserted with it under the table-wide INSERT, and named by no UPDATE grant: as immutable as the rest of it.
ALTER TABLE "service_bindings" ADD COLUMN "policy" text;--> statement-breakpoint
ALTER TABLE "enrollments" ADD CONSTRAINT "enrollments_binding_id_fkey" FOREIGN KEY ("binding_id") REFERENCES "public"."service_bindings"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "enrollments_binding_idx" ON "enrollments" USING btree ("binding_id","created_at" DESC NULLS LAST);--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_enrollment_id_fkey" FOREIGN KEY ("enrollment_id") REFERENCES "public"."enrollments"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
-- Freezes are the log's: a target's newest allowed freeze or lift, and a code's supersession, its tombstone.
CREATE INDEX "audit_log_freeze_idx" ON "audit_log" USING btree ((("metadata")::jsonb ->> 'target'),"seq" DESC NULLS LAST) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" IN ('workload.freeze', 'workload.unfreeze') AND "audit_log"."decision" = 'allow';--> statement-breakpoint
CREATE INDEX "audit_log_supersede_idx" ON "audit_log" USING btree ((("metadata")::jsonb ->> 'enrollmentId')) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" = 'enrollment.supersede' AND "audit_log"."decision" = 'allow';--> statement-breakpoint
CREATE INDEX "credentials_enrollment_roots_idx" ON "credentials" USING btree ("enrollment_id","created_at") WHERE "credentials"."kind" = 'workload' AND "credentials"."ancestors" IS NULL;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_workload_jkt_check" CHECK ("credentials"."kind" <> 'workload' OR "credentials"."jkt" IS NOT NULL);--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_kind_check" CHECK ("credentials"."kind" IN ('browser', 'cli', 'service', 'personal', 'handle', 'workload'));--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_kind_matches_principal" CHECK (("credentials"."kind" IN ('service', 'workload')) = ("credentials"."principal" LIKE 'token:%'));--> statement-breakpoint
-- The app makes codes and never changes one; a session's key, hard end, ancestors, limits and code are set when it is made, and never after: renewal moves its expiry, and an approval is the one other change.
GRANT SELECT, INSERT ON enrollments TO coffre_app;--> statement-breakpoint
GRANT UPDATE (expires_at, approved_at, approved_by) ON credentials TO coffre_app;
