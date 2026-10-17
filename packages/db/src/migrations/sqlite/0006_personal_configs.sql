-- Added in place, not by rebuilding the table as drizzle-kit would: a migration runs in one transaction, where SQLite ignores `foreign_keys=OFF`, so dropping a table other rows reference fails (as 0004).
ALTER TABLE `environments` ADD `owner` text CONSTRAINT "environments_owner_check" CHECK(`owner` IS NULL OR (`parent_id` IS NOT NULL AND `owner` LIKE 'user:_%'));--> statement-breakpoint
CREATE UNIQUE INDEX `environments_parent_id_owner_key` ON `environments` (`parent_id`,`owner`) WHERE instr("environments"."slug", '~') = 0;
