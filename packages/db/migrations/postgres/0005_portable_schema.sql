-- The schema that MySQL and SQLite can also express, so the three trees start
-- from the same place. Nothing is lost: every row stays as it is.

-- A partial unique index becomes a plain one. The grant indexes were partial
-- on the scope they key on, and nulls never collide in a unique index, so the
-- plain index accepts and rejects exactly the same rows.
DROP INDEX "grants_environment_unique";--> statement-breakpoint
DROP INDEX "grants_project_unique";--> statement-breakpoint
CREATE UNIQUE INDEX "grants_environment_unique" ON "grants" USING btree ("principal_type","principal_id","environment_id");--> statement-breakpoint
CREATE UNIQUE INDEX "grants_project_unique" ON "grants" USING btree ("principal_type","principal_id","project_id");--> statement-breakpoint

-- An account was bound to one person at a time by a unique index on
-- (provider, subject) over the rows not revoked. The same rule, as a column
-- that is the subject while bound and null once revoked.
ALTER TABLE "identities" ADD COLUMN "active_subject" text GENERATED ALWAYS AS (CASE WHEN revoked_at IS NULL THEN subject END) STORED;--> statement-breakpoint
DROP INDEX "identities_active_subject";--> statement-breakpoint
CREATE UNIQUE INDEX "identities_active_subject" ON "identities" USING btree ("provider","active_subject");--> statement-breakpoint

-- Partial lookup indexes: the ones a unique index already covers go, the
-- others cover every row.
DROP INDEX "projects_active_idx";--> statement-breakpoint
DROP INDEX "environments_active_idx";--> statement-breakpoint
DROP INDEX "secrets_active_idx";--> statement-breakpoint
DROP INDEX "grants_project_lookup_idx";--> statement-breakpoint
DROP INDEX "audit_log_bundle_idx";--> statement-breakpoint
DROP INDEX "credentials_principal_idx";--> statement-breakpoint
DROP INDEX "syncs_environment_idx";--> statement-breakpoint
CREATE INDEX "audit_log_bundle_idx" ON "audit_log" USING btree ("bundle_id");--> statement-breakpoint
CREATE INDEX "credentials_principal_idx" ON "credentials" USING btree ("principal_type","principal_id");--> statement-breakpoint
CREATE INDEX "syncs_environment_idx" ON "syncs" USING btree ("environment_id");
