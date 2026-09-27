CREATE TABLE `audit_chain_head` (
	`only_row` integer PRIMARY KEY NOT NULL,
	`next_seq` integer NOT NULL,
	`head_hash` blob NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `audit_log` (
	`seq` integer PRIMARY KEY NOT NULL,
	`id` text NOT NULL,
	`occurred_at` integer NOT NULL,
	`actor_id` text NOT NULL,
	`action` text NOT NULL,
	`metadata` text NOT NULL,
	`prev_hash` blob NOT NULL,
	`hash` blob NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `audit_log_id_unique` ON `audit_log` (`id`);--> statement-breakpoint
CREATE INDEX `audit_log_actor_idx` ON `audit_log` (`actor_id`,`occurred_at`);--> statement-breakpoint
CREATE TABLE `environments` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL,
	`archived_at` integer,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `environments_project_slug_key` ON `environments` (`project_id`,`slug`);--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY NOT NULL,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL,
	`archived_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `projects_slug_key` ON `projects` (`slug`);--> statement-breakpoint
CREATE TABLE `secret_versions` (
	`id` text PRIMARY KEY NOT NULL,
	`secret_id` text NOT NULL,
	`version` integer NOT NULL,
	`ciphertext` blob NOT NULL,
	`wrapped_dek` blob NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`secret_id`) REFERENCES `secrets`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `secret_versions_secret_version_key` ON `secret_versions` (`secret_id`,`version`);--> statement-breakpoint
CREATE TABLE `secrets` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`environment_id` text NOT NULL,
	`key` text NOT NULL,
	`current_version_id` text,
	`created_at` integer NOT NULL,
	`archived_at` integer,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `secrets_lookup_idx` ON `secrets` (`project_id`,`environment_id`,`key`);--> statement-breakpoint
CREATE UNIQUE INDEX `secrets_environment_key_key` ON `secrets` (`environment_id`,`key`);