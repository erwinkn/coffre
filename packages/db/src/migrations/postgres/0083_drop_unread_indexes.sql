-- 0.16.0, T269: drop the eight indexes no query reads (at most two secondary indexes a table, unless measured).
-- 0.16 upgrades offline from exactly 0.15.0 (D197): no 0.15 code serves on this schema, so the drops need no release
-- between them and their last reader, and plain DROP INDEX runs inside the migrator's transaction (CONCURRENTLY cannot).
-- audit_log: by operation (no reader filters on operation_id), the freeze lookup's first index (audit_log_frozen_idx
-- serves it since 0082), an enrollment code's tombstone (nothing reads `enrollment.supersede`).
DROP INDEX IF EXISTS "audit_log_operation_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "audit_log_freeze_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "audit_log_supersede_idx";--> statement-breakpoint
-- credentials: no reader asks for an enrollment code's sessions, and no login deletes a code.
DROP INDEX IF EXISTS "credentials_enrollment_roots_idx";--> statement-breakpoint
-- secret_references: every read is by id, by holder (`secret_references_holder_idx`) or by `created_seq` (its unique
-- key). `secret_references_source_idx` stays: the foreign key to the source reads it on a delete of a secret.
DROP INDEX IF EXISTS "secret_references_project_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "secret_references_source_project_idx";--> statement-breakpoint
DROP INDEX IF EXISTS "secret_references_created_by_idx";--> statement-breakpoint
-- secrets: the same columns as `secrets_project_id_environment_id_key_key`, which serves every read it served.
DROP INDEX IF EXISTS "secrets_lookup_idx";
