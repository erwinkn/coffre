CREATE TABLE `checkpoints` (
	`seq` integer PRIMARY KEY NOT NULL,
	`head_hash` text NOT NULL,
	`signed_at` integer NOT NULL,
	`key_id` text NOT NULL,
	`signature` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `grants` (
	`principal` text NOT NULL,
	`project_id` text NOT NULL,
	`environment_id` text,
	`role` text NOT NULL,
	`expires_at` integer,
	`granted_at` integer NOT NULL,
	`granted_by` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `grants_on_project` ON `grants` (`principal`,`project_id`) WHERE "grants"."environment_id" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `grants_on_environment` ON `grants` (`principal`,`environment_id`) WHERE "grants"."environment_id" IS NOT NULL;--> statement-breakpoint
CREATE TABLE `log` (
	`seq` integer PRIMARY KEY NOT NULL,
	`at` integer NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`outcome` text NOT NULL,
	`code` text,
	`subject` text,
	`detail` text NOT NULL,
	`prev_hash` text NOT NULL,
	`hash` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `log_by_actor` ON `log` (`actor`,`action`,`at`);--> statement-breakpoint
CREATE TABLE `principals` (
	`principal` text PRIMARY KEY NOT NULL,
	`status` text NOT NULL,
	`owner` integer DEFAULT false NOT NULL,
	`since` integer NOT NULL,
	`by` text NOT NULL
);
