CREATE TABLE `project_folders` (
	`project_id` text PRIMARY KEY NOT NULL,
	`folder` text,
	`moved_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`moved_by` text NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "project_folders_folder_check" CHECK("project_folders"."folder" IS NULL OR (length("project_folders"."folder") BETWEEN 1 AND 64 AND "project_folders"."folder" NOT GLOB '*/*' AND "project_folders"."folder" = trim("project_folders"."folder")))
);
--> statement-breakpoint
CREATE TABLE `secret_folders` (
	`secret_id` text PRIMARY KEY NOT NULL,
	`folder` text,
	`moved_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`moved_by` text NOT NULL,
	FOREIGN KEY (`secret_id`) REFERENCES `secrets`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "secret_folders_folder_check" CHECK("secret_folders"."folder" IS NULL OR (length("secret_folders"."folder") BETWEEN 1 AND 64 AND "secret_folders"."folder" NOT GLOB '*/*' AND "secret_folders"."folder" = trim("secret_folders"."folder")))
);
