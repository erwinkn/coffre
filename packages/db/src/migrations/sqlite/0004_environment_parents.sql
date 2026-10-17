-- Added in place, not by rebuilding the table as drizzle-kit would: a migration runs in one transaction, where SQLite ignores `foreign_keys=OFF`, so dropping a table other rows reference fails. SQLite adds no table constraint to an existing table, so the parent's same-project rule (`environments_parent_in_project` on Postgres) is the app's here.
ALTER TABLE `environments` ADD `parent_id` text REFERENCES `environments`(`id`) ON DELETE no action CONSTRAINT "environments_parent_check" CHECK(`parent_id` IS NULL OR `parent_id` <> `id`);--> statement-breakpoint
ALTER TABLE `environments` ADD `owner` text CONSTRAINT "environments_owner_check" CHECK(`owner` IS NULL OR (`parent_id` IS NOT NULL AND `owner` LIKE 'user:_%'));--> statement-breakpoint
CREATE INDEX `environments_parent_idx` ON `environments` (`parent_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `environments_parent_id_owner_key` ON `environments` (`parent_id`,`owner`) WHERE instr("environments"."slug", '~') = 0;
