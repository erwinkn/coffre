-- A deleted project or environment stays, as a tombstone the log's entries
-- name, under a slug no live place can take: `market~deleted-2026-10-05`.
-- SQLite changes a check by rebuilding its table; libSQL runs a migration
-- with foreign keys off, so the rebuild drops nothing that refers to it.
CREATE TABLE `__new_environments` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`archived_at` integer,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "environments_slug_check" CHECK((length("__new_environments"."slug") BETWEEN 1 AND 63 AND "__new_environments"."slug" GLOB '[a-z0-9]*' AND "__new_environments"."slug" NOT GLOB '*[^a-z0-9-]*') OR (instr("__new_environments"."slug", '~') BETWEEN 2 AND 64 AND substr("__new_environments"."slug", 1, instr("__new_environments"."slug", '~') - 1) GLOB '[a-z0-9]*' AND substr("__new_environments"."slug", 1, instr("__new_environments"."slug", '~') - 1) NOT GLOB '*[^a-z0-9-]*' AND length(substr("__new_environments"."slug", instr("__new_environments"."slug", '~') + 1)) BETWEEN 1 AND 40 AND substr("__new_environments"."slug", instr("__new_environments"."slug", '~') + 1) NOT GLOB '*[^a-z0-9-]*'))
);
--> statement-breakpoint
INSERT INTO `__new_environments`("id", "project_id", "slug", "name", "created_at", "archived_at") SELECT "id", "project_id", "slug", "name", "created_at", "archived_at" FROM `environments`;--> statement-breakpoint
DROP TABLE `environments`;--> statement-breakpoint
ALTER TABLE `__new_environments` RENAME TO `environments`;--> statement-breakpoint
CREATE UNIQUE INDEX `environments_project_id_slug_key` ON `environments` (`project_id`,`slug`);--> statement-breakpoint
CREATE UNIQUE INDEX `environments_project_scoped` ON `environments` (`id`,`project_id`);--> statement-breakpoint
CREATE TABLE `__new_projects` (
	`id` text PRIMARY KEY NOT NULL,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`archived_at` integer,
	CONSTRAINT "projects_slug_check" CHECK((length("__new_projects"."slug") BETWEEN 1 AND 63 AND "__new_projects"."slug" GLOB '[a-z0-9]*' AND "__new_projects"."slug" NOT GLOB '*[^a-z0-9-]*') OR (instr("__new_projects"."slug", '~') BETWEEN 2 AND 64 AND substr("__new_projects"."slug", 1, instr("__new_projects"."slug", '~') - 1) GLOB '[a-z0-9]*' AND substr("__new_projects"."slug", 1, instr("__new_projects"."slug", '~') - 1) NOT GLOB '*[^a-z0-9-]*' AND length(substr("__new_projects"."slug", instr("__new_projects"."slug", '~') + 1)) BETWEEN 1 AND 40 AND substr("__new_projects"."slug", instr("__new_projects"."slug", '~') + 1) NOT GLOB '*[^a-z0-9-]*'))
);
--> statement-breakpoint
INSERT INTO `__new_projects`("id", "slug", "name", "created_at", "archived_at") SELECT "id", "slug", "name", "created_at", "archived_at" FROM `projects`;--> statement-breakpoint
DROP TABLE `projects`;--> statement-breakpoint
ALTER TABLE `__new_projects` RENAME TO `projects`;--> statement-breakpoint
CREATE UNIQUE INDEX `projects_slug_key` ON `projects` (`slug`);--> statement-breakpoint
-- Its versions stay too, and lose what they sealed: the app empties their
-- ciphertext and wrapped data key. That is the one change a version takes:
-- a value is never rewritten in place, only erased.
CREATE TRIGGER `secret_versions_erase_only` BEFORE UPDATE ON `secret_versions`
WHEN length(NEW.`ciphertext`) <> 0 OR length(NEW.`wrapped_dek`) <> 0
    OR NEW.`id` IS NOT OLD.`id` OR NEW.`secret_id` IS NOT OLD.`secret_id` OR NEW.`version` IS NOT OLD.`version`
    OR NEW.`envelope_version` IS NOT OLD.`envelope_version` OR NEW.`iv` IS NOT OLD.`iv` OR NEW.`auth_tag` IS NOT OLD.`auth_tag`
    OR NEW.`kek_provider` IS NOT OLD.`kek_provider` OR NEW.`kek_id` IS NOT OLD.`kek_id` OR NEW.`kek_version` IS NOT OLD.`kek_version`
    OR NEW.`created_at` IS NOT OLD.`created_at` OR NEW.`created_by` IS NOT OLD.`created_by`
BEGIN
    SELECT RAISE(ABORT, 'a secret version is only ever erased');
END;
