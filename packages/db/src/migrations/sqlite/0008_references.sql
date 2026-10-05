CREATE TABLE `secret_references` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`environment_id` text NOT NULL,
	`secret_id` text NOT NULL,
	`source_project_id` text NOT NULL,
	`source_environment_id` text NOT NULL,
	`source_secret_id` text NOT NULL,
	`created_seq` integer NOT NULL,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`created_by` text NOT NULL,
	FOREIGN KEY (`secret_id`) REFERENCES `secrets`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`source_secret_id`) REFERENCES `secrets`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`created_seq`) REFERENCES `audit_log`(`seq`) ON UPDATE no action ON DELETE restrict
);
--> statement-breakpoint
CREATE INDEX `secret_references_holder_idx` ON `secret_references` (`secret_id`,`created_seq`);--> statement-breakpoint
CREATE INDEX `secret_references_source_idx` ON `secret_references` (`source_secret_id`);--> statement-breakpoint
CREATE INDEX `secret_references_project_idx` ON `secret_references` (`project_id`);--> statement-breakpoint
CREATE INDEX `secret_references_source_project_idx` ON `secret_references` (`source_project_id`);--> statement-breakpoint
CREATE INDEX `secret_references_created_by_idx` ON `secret_references` (`created_by`);--> statement-breakpoint
CREATE UNIQUE INDEX `secret_references_created_seq_key` ON `secret_references` (`created_seq`);--> statement-breakpoint
CREATE INDEX `audit_log_reference_end_idx` ON `audit_log` (`related_seq`) WHERE "audit_log"."author" = 'vault' AND "audit_log"."action" = 'reference.end' AND "audit_log"."decision" = 'allow';--> statement-breakpoint
-- Expressions by hand: drizzle-kit splits one at its comma.
CREATE INDEX `audit_log_also_project_idx` ON `audit_log` (json_extract("metadata", '$.also.projectId'), `seq`) WHERE json_extract("audit_log"."metadata", '$.also') IS NOT NULL;--> statement-breakpoint
CREATE INDEX `audit_log_also_environment_idx` ON `audit_log` (json_extract("metadata", '$.also.environmentId'), `seq`) WHERE json_extract("audit_log"."metadata", '$.also') IS NOT NULL;--> statement-breakpoint
CREATE INDEX `audit_log_also_secret_idx` ON `audit_log` (json_extract("metadata", '$.also.secretId'), `seq`) WHERE json_extract("audit_log"."metadata", '$.also') IS NOT NULL;