-- The pages read the audit projection (docs/design/state-rows.md, section 7): what served them before goes. 0.15's reads' projection, `log_reads` with its two day tables and its cursor, its six functions (its writer, its
-- days' upkeep, the pages' two reads, its places' trigger) and its two triggers; the partial indexes of `log_changes`
-- that only the audit pages read, all but `admitted_idx`, which `missingMembers` still reads; and of `audit_log`'s, the
-- two only the page read (an actor's, a reference's other environment). An environment's and a key's stay: the
-- foreign keys to `environments` and `secrets` check through them. Each checked for a
-- reader left in the code, and by EXPLAIN on a seeded log where one was not plain: a member's references (`sealedBy`)
-- read `audit_log_releases_idx` without `actor_idx`. Plain DROP INDEX, inside the migrator's transaction.
DROP TABLE IF EXISTS "log_reads" CASCADE;--> statement-breakpoint
DROP TABLE IF EXISTS "log_read_days" CASCADE;--> statement-breakpoint
DROP TABLE IF EXISTS "log_read_place_days" CASCADE;--> statement-breakpoint
DROP TABLE IF EXISTS "log_reads_cursor" CASCADE;--> statement-breakpoint
DROP FUNCTION IF EXISTS project_reads(jsonb, bigint, bigint, bigint, bigint, bytea);--> statement-breakpoint
DROP FUNCTION IF EXISTS make_reads_day(date);--> statement-breakpoint
DROP FUNCTION IF EXISTS drop_reads_day(date);--> statement-breakpoint
DROP FUNCTION IF EXISTS log_reads_by(text, bigint, bigint, integer);--> statement-breakpoint
DROP FUNCTION IF EXISTS log_reads_at(uuid, text, bigint, bigint, integer);--> statement-breakpoint
DROP FUNCTION IF EXISTS log_reads_placed();--> statement-breakpoint
DROP INDEX IF EXISTS "audit_log_actor_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "audit_log_also_environment_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_sign_in_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_sign_in_actor_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_issue_revoke_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_issue_revoke_actor_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_written_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_written_actor_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_written_environment_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_written_object_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_written_actor_environment_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_written_actor_object_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_admitted_actor_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_refused_write_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_refused_write_actor_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_refused_write_environment_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_refused_write_actor_environment_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_refused_add_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "log_changes_refused_add_actor_idx";
