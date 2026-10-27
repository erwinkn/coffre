-- 0.15's log (the Postgres migration, 0022_log_015, says what each part is): its tables and the seals, for tests and local development. SQLite has one writer, so the fence is implicit and nothing is partitioned; it has no functions and no logins. It only adds. Each seal's check is on its column: added with the column, it rebuilds no table.
CREATE TABLE `log_bulk` (
	`principal` text NOT NULL,
	`secret` text NOT NULL,
	`last` integer NOT NULL,
	PRIMARY KEY(`principal`, `secret`)
);
--> statement-breakpoint
CREATE TABLE `log_changes` (
	`number` integer PRIMARY KEY NOT NULL,
	`at` integer NOT NULL,
	`request_id` text NOT NULL,
	`object` text NOT NULL,
	`actor` text NOT NULL,
	`payload` text NOT NULL,
	`seal` blob,
	`mac` blob NOT NULL,
	CONSTRAINT "log_changes_seal_check" CHECK("log_changes"."seal" IS NULL OR octet_length("log_changes"."seal") = 16),
	CONSTRAINT "log_changes_mac_check" CHECK(octet_length("log_changes"."mac") = 16)
);
--> statement-breakpoint
CREATE INDEX `log_changes_object_idx` ON `log_changes` (`object`,`number`);--> statement-breakpoint
CREATE UNIQUE INDEX `log_changes_request_id_key` ON `log_changes` (`request_id`);--> statement-breakpoint
CREATE TABLE `log_checkpoints` (
	`upto` integer PRIMARY KEY NOT NULL,
	`at` integer NOT NULL,
	`at_floor` integer NOT NULL,
	`changes_size` integer NOT NULL,
	`changes_root` blob NOT NULL,
	`changes_note` text NOT NULL,
	`uses_size` integer NOT NULL,
	`uses_root` blob NOT NULL,
	`uses_note` text NOT NULL,
	CONSTRAINT "log_checkpoints_changes_root_check" CHECK(octet_length("log_checkpoints"."changes_root") = 32),
	CONSTRAINT "log_checkpoints_uses_root_check" CHECK(octet_length("log_checkpoints"."uses_root") = 32)
);
--> statement-breakpoint
CREATE TABLE `log_fence` (
	`only_row` integer PRIMARY KEY DEFAULT true NOT NULL,
	`at_floor` integer NOT NULL,
	CONSTRAINT "log_fence_only_row_check" CHECK("log_fence"."only_row")
);
--> statement-breakpoint
CREATE TABLE `log_tiles` (
	`tree` text NOT NULL,
	`level` integer NOT NULL,
	`leaf` integer NOT NULL,
	`hashes` blob NOT NULL,
	PRIMARY KEY(`tree`, `level`, `leaf`),
	CONSTRAINT "log_tiles_tree_check" CHECK("log_tiles"."tree" IN ('changes', 'uses')),
	CONSTRAINT "log_tiles_level_check" CHECK("log_tiles"."level" BETWEEN 0 AND 7),
	CONSTRAINT "log_tiles_leaf_check" CHECK("log_tiles"."leaf" >= 0 AND (("log_tiles"."level" = 7 AND "log_tiles"."leaf" = 0) OR ("log_tiles"."level" < 7 AND "log_tiles"."leaf" % (1 << (8 * ("log_tiles"."level" + 1))) = 0))),
	CONSTRAINT "log_tiles_hashes_check" CHECK(octet_length("log_tiles"."hashes") BETWEEN 32 AND 8192 AND octet_length("log_tiles"."hashes") % 32 = 0)
);
--> statement-breakpoint
CREATE TABLE `log_uses` (
	`number` integer NOT NULL,
	`at` integer NOT NULL,
	`request_id` integer NOT NULL,
	`credential` text NOT NULL,
	`secret` text NOT NULL,
	`purpose` integer NOT NULL,
	`mac` blob NOT NULL,
	`place` text,
	CONSTRAINT "log_uses_mac_check" CHECK(octet_length("log_uses"."mac") = 16)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `log_uses_request_idx` ON `log_uses` (`at`,`request_id`);--> statement-breakpoint
CREATE TABLE `vault_config` (
	`name` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL,
	`seal` blob,
	CONSTRAINT "vault_config_name_check" CHECK("vault_config"."name" IN ('policy', 'roles')),
	CONSTRAINT "vault_config_value_check" CHECK(json_valid("vault_config"."value")),
	CONSTRAINT "vault_config_seal_check" CHECK("vault_config"."seal" IS NULL OR octet_length("vault_config"."seal") = 16)
);
--> statement-breakpoint
ALTER TABLE `credentials` ADD COLUMN `seal` blob CONSTRAINT "credentials_seal_check" CHECK("seal" IS NULL OR octet_length("seal") = 16);--> statement-breakpoint
ALTER TABLE `environments` ADD COLUMN `protected` integer;--> statement-breakpoint
ALTER TABLE `environments` ADD COLUMN `seal` blob CONSTRAINT "environments_seal_check" CHECK("seal" IS NULL OR octet_length("seal") = 16);--> statement-breakpoint
ALTER TABLE `secrets` ADD COLUMN `seal` blob CONSTRAINT "secrets_seal_check" CHECK("seal" IS NULL OR octet_length("seal") = 16);--> statement-breakpoint
ALTER TABLE `service_bindings` ADD COLUMN `seal` blob CONSTRAINT "service_bindings_seal_check" CHECK("seal" IS NULL OR octet_length("seal") = 16);--> statement-breakpoint
ALTER TABLE `vault_members` ADD COLUMN `seal` blob CONSTRAINT "vault_members_seal_check" CHECK("seal" IS NULL OR octet_length("seal") = 16);--> statement-breakpoint
INSERT INTO `log_fence` (`only_row`, `at_floor`) VALUES (1, CAST(unixepoch('subsec') * 1000 AS INTEGER) - 3000);
