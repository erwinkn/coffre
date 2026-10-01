CREATE TABLE `audit_chain_head` (
	`only_row` int NOT NULL,
	`next_seq` int NOT NULL,
	`head_hash` longblob NOT NULL,
	`updated_at` datetime(3) NOT NULL,
	CONSTRAINT `audit_chain_head_only_row` PRIMARY KEY(`only_row`)
);
--> statement-breakpoint
CREATE TABLE `audit_log` (
	`seq` int NOT NULL,
	`id` varchar(36) NOT NULL,
	`occurred_at` datetime(3) NOT NULL,
	`actor_id` varchar(255) NOT NULL,
	`action` varchar(255) NOT NULL,
	`metadata` json NOT NULL,
	`prev_hash` longblob NOT NULL,
	`hash` longblob NOT NULL,
	CONSTRAINT `audit_log_seq` PRIMARY KEY(`seq`),
	CONSTRAINT `audit_log_id_unique` UNIQUE(`id`)
);
--> statement-breakpoint
CREATE TABLE `environments` (
	`id` varchar(36) NOT NULL,
	`project_id` varchar(36) NOT NULL,
	`slug` varchar(63) NOT NULL,
	`name` varchar(255) NOT NULL,
	`created_at` datetime(3) NOT NULL,
	`archived_at` datetime(3),
	CONSTRAINT `environments_id` PRIMARY KEY(`id`),
	CONSTRAINT `environments_project_slug_key` UNIQUE(`project_id`,`slug`)
);
--> statement-breakpoint
CREATE TABLE `projects` (
	`id` varchar(36) NOT NULL,
	`slug` varchar(63) NOT NULL,
	`name` varchar(255) NOT NULL,
	`created_at` datetime(3) NOT NULL,
	`archived_at` datetime(3),
	CONSTRAINT `projects_id` PRIMARY KEY(`id`),
	CONSTRAINT `projects_slug_key` UNIQUE(`slug`)
);
--> statement-breakpoint
CREATE TABLE `secret_versions` (
	`id` varchar(36) NOT NULL,
	`secret_id` varchar(36) NOT NULL,
	`version` int NOT NULL,
	`ciphertext` longblob NOT NULL,
	`wrapped_dek` longblob NOT NULL,
	`created_at` datetime(3) NOT NULL,
	CONSTRAINT `secret_versions_id` PRIMARY KEY(`id`),
	CONSTRAINT `secret_versions_secret_version_key` UNIQUE(`secret_id`,`version`)
);
--> statement-breakpoint
CREATE TABLE `secrets` (
	`id` varchar(36) NOT NULL,
	`project_id` varchar(36) NOT NULL,
	`environment_id` varchar(36) NOT NULL,
	`key` varchar(128) NOT NULL,
	`current_version_id` varchar(36),
	`created_at` datetime(3) NOT NULL,
	`archived_at` datetime(3),
	CONSTRAINT `secrets_id` PRIMARY KEY(`id`),
	CONSTRAINT `secrets_environment_key_key` UNIQUE(`environment_id`,`key`)
);
--> statement-breakpoint
ALTER TABLE `environments` ADD CONSTRAINT `environments_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `secret_versions` ADD CONSTRAINT `secret_versions_secret_id_secrets_id_fk` FOREIGN KEY (`secret_id`) REFERENCES `secrets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `secrets` ADD CONSTRAINT `secrets_project_id_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `secrets` ADD CONSTRAINT `secrets_environment_id_environments_id_fk` FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `audit_log_actor_idx` ON `audit_log` (`actor_id`,`occurred_at`);--> statement-breakpoint
CREATE INDEX `secrets_lookup_idx` ON `secrets` (`project_id`,`environment_id`,`key`);
