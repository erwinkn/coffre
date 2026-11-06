-- 0.16.0, T178: the tables renamed (postgres/0073_table_renames.sql says why). SQLite, which serves tests and local
-- development and no deployment, keeps no view under the old names: it cannot upsert into a view, and a write through
-- one counts no row changed, so no view would hold the previous release's code anyway (`pnpm test:compat` renames
-- them back for a release that predates this, scripts/compat-check.sh). Each table is renamed, which moves every
-- reference to it (foreign keys, the fence's trigger), then made again under constraints of its new name, as
-- drizzle-kit makes a table again; the trigger that reads the fence is dropped while its table is, then made again.
-- The migrator runs with foreign keys off (libsql's `migrate`), as a table made again needs.
ALTER TABLE `vault_members` RENAME TO `principals`;--> statement-breakpoint
ALTER TABLE `vault_grants` RENAME TO `grants`;--> statement-breakpoint
ALTER TABLE `device_authorizations` RENAME TO `device_logins`;--> statement-breakpoint
ALTER TABLE `enrollments` RENAME TO `enrollment_codes`;--> statement-breakpoint
ALTER TABLE `consumed_tokens` RENAME TO `spent_id_tokens`;--> statement-breakpoint
ALTER TABLE `log_bulk` RENAME TO `bulk_cap`;--> statement-breakpoint
ALTER TABLE `log_fence` RENAME TO `checkpoint_fence`;--> statement-breakpoint
DROP TRIGGER `log_changes_refuse_retired`;--> statement-breakpoint
CREATE TABLE `__new_principals` (
	`principal` text PRIMARY KEY NOT NULL,
	`status` text NOT NULL,
	`owner` integer DEFAULT false NOT NULL,
	`role` text,
	`scope` text,
	`generation` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	`created_by` text NOT NULL,
	`status_changed_at` integer NOT NULL,
	`status_changed_by` text NOT NULL,
	`access_seq` integer NOT NULL,
	`mac` blob NOT NULL,
	`seal` blob,
	CONSTRAINT "principals_seal_check" CHECK("__new_principals"."seal" IS NULL OR octet_length("__new_principals"."seal") = 16),
	CONSTRAINT "principals_mac_check" CHECK(octet_length("__new_principals"."mac") = 32),
	CONSTRAINT "principals_principal_check" CHECK(("__new_principals"."principal" GLOB 'user:?*' OR "__new_principals"."principal" GLOB 'token:?*')
        AND substr("__new_principals"."principal", instr("__new_principals"."principal", ':') + 1, 1) <> ':'
        AND instr("__new_principals"."principal", ' ') = 0 AND instr("__new_principals"."principal", char(9)) = 0
        AND instr("__new_principals"."principal", char(10)) = 0 AND instr("__new_principals"."principal", char(13)) = 0),
	CONSTRAINT "principals_user_lowercase" CHECK("__new_principals"."principal" NOT LIKE 'user:%' OR "__new_principals"."principal" = lower("__new_principals"."principal")),
	CONSTRAINT "principals_status_check" CHECK("__new_principals"."status" IN ('active', 'removed')),
	CONSTRAINT "principals_owner_check" CHECK(NOT "__new_principals"."owner" OR ("__new_principals"."status" = 'active' AND "__new_principals"."principal" LIKE 'user:%')),
	CONSTRAINT "principals_generation_check" CHECK("__new_principals"."generation" >= 0)
);--> statement-breakpoint
INSERT INTO `__new_principals`("principal", "status", "owner", "role", "scope", "generation", "created_at", "created_by", "status_changed_at", "status_changed_by", "access_seq", "mac", "seal") SELECT "principal", "status", "owner", "role", "scope", "generation", "created_at", "created_by", "status_changed_at", "status_changed_by", "access_seq", "mac", "seal" FROM `principals`;--> statement-breakpoint
DROP TABLE `principals`;--> statement-breakpoint
ALTER TABLE `__new_principals` RENAME TO `principals`;--> statement-breakpoint
CREATE TABLE `__new_grants` (
	`principal` text NOT NULL,
	`project_id` text,
	`environment_id` text,
	`environment_slug` text,
	`role` text NOT NULL,
	`expires_at` integer,
	`granted_at` integer NOT NULL,
	`granted_by` text NOT NULL,
	FOREIGN KEY (`principal`) REFERENCES `principals`(`principal`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "grants_one_place" CHECK((("__new_grants"."project_id" IS NULL) <> ("__new_grants"."environment_id" IS NULL) AND "__new_grants"."environment_slug" IS NULL) OR ("__new_grants"."project_id" IS NULL AND "__new_grants"."environment_id" IS NULL)),
	CONSTRAINT "grants_environment_slug_check" CHECK("__new_grants"."environment_slug" IS NULL OR (length("__new_grants"."environment_slug") BETWEEN 1 AND 63 AND "__new_grants"."environment_slug" GLOB '[a-z0-9]*' AND "__new_grants"."environment_slug" NOT GLOB '*[^a-z0-9-]*')),
	CONSTRAINT "grants_role_check" CHECK(length("__new_grants"."role") BETWEEN 2 AND 32 AND "__new_grants"."role" GLOB '[a-z]*' AND "__new_grants"."role" NOT GLOB '*[^a-z0-9-]*')
);--> statement-breakpoint
INSERT INTO `__new_grants`("principal", "project_id", "environment_id", "environment_slug", "role", "expires_at", "granted_at", "granted_by") SELECT "principal", "project_id", "environment_id", "environment_slug", "role", "expires_at", "granted_at", "granted_by" FROM `grants`;--> statement-breakpoint
DROP TABLE `grants`;--> statement-breakpoint
ALTER TABLE `__new_grants` RENAME TO `grants`;--> statement-breakpoint
CREATE UNIQUE INDEX `grants_on_every_project` ON `grants` (`principal`) WHERE "grants"."project_id" IS NULL AND "grants"."environment_id" IS NULL AND "grants"."environment_slug" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `grants_on_project` ON `grants` (`principal`,`project_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `grants_on_environment` ON `grants` (`principal`,`environment_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `grants_on_environment_slug` ON `grants` (`principal`,`environment_slug`);--> statement-breakpoint
CREATE TABLE `__new_device_logins` (
	`id` text PRIMARY KEY NOT NULL,
	`device_code_hash` blob NOT NULL,
	`auth_mac` blob NOT NULL,
	`user_code` text NOT NULL,
	`client_label` text,
	`client_ip` text,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`expires_at` integer NOT NULL,
	`decided_at` integer,
	`decision` text,
	`generation` integer DEFAULT 0 NOT NULL,
	`principal` text,
	`consumed_at` integer,
	`passkey_id` text,
	FOREIGN KEY (`passkey_id`) REFERENCES `passkeys`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`principal`) REFERENCES `principals`(`principal`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "device_logins_passkey_check" CHECK("__new_device_logins"."passkey_id" IS NULL OR ("__new_device_logins"."decision" IS NOT NULL AND "__new_device_logins"."decision" = 'approved')),
	CONSTRAINT "device_logins_auth_mac_check" CHECK(octet_length("__new_device_logins"."auth_mac") = 32),
	CONSTRAINT "device_logins_decision_check" CHECK("__new_device_logins"."decision" IS NULL OR "__new_device_logins"."decision" IN ('approved', 'denied')),
	CONSTRAINT "device_logins_approval_names_principal" CHECK(("__new_device_logins"."decision" IS NULL AND "__new_device_logins"."decided_at" IS NULL AND "__new_device_logins"."principal" IS NULL AND "__new_device_logins"."generation" = 0 AND "__new_device_logins"."consumed_at" IS NULL)
        OR ("__new_device_logins"."decision" IS NOT NULL AND "__new_device_logins"."decided_at" IS NOT NULL AND (
          ("__new_device_logins"."decision" = 'denied' AND "__new_device_logins"."principal" IS NULL AND "__new_device_logins"."generation" = 0 AND "__new_device_logins"."consumed_at" IS NULL)
          OR ("__new_device_logins"."decision" = 'approved' AND "__new_device_logins"."principal" IS NOT NULL AND "__new_device_logins"."principal" LIKE 'user:%')
        )))
);--> statement-breakpoint
INSERT INTO `__new_device_logins`("id", "device_code_hash", "auth_mac", "user_code", "client_label", "client_ip", "created_at", "expires_at", "decided_at", "decision", "generation", "principal", "consumed_at", "passkey_id") SELECT "id", "device_code_hash", "auth_mac", "user_code", "client_label", "client_ip", "created_at", "expires_at", "decided_at", "decision", "generation", "principal", "consumed_at", "passkey_id" FROM `device_logins`;--> statement-breakpoint
DROP TABLE `device_logins`;--> statement-breakpoint
ALTER TABLE `__new_device_logins` RENAME TO `device_logins`;--> statement-breakpoint
CREATE UNIQUE INDEX `device_logins_device_code_hash_key` ON `device_logins` (`device_code_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `device_logins_user_code_key` ON `device_logins` (`user_code`);--> statement-breakpoint
CREATE TABLE `__new_enrollment_codes` (
	`id` text PRIMARY KEY NOT NULL,
	`auth_mac` blob NOT NULL,
	`binding_id` text NOT NULL,
	`code_hash` blob NOT NULL,
	`code_hint` text NOT NULL,
	`scope` text NOT NULL,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`created_by` text NOT NULL,
	`created_with` text,
	`expires_at` integer NOT NULL,
	FOREIGN KEY (`binding_id`) REFERENCES `service_bindings`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "enrollment_codes_auth_mac_check" CHECK(octet_length("__new_enrollment_codes"."auth_mac") = 32),
	CONSTRAINT "enrollment_codes_code_hash_check" CHECK(octet_length("__new_enrollment_codes"."code_hash") = 32),
	CONSTRAINT "enrollment_codes_scope_check" CHECK(json_valid("__new_enrollment_codes"."scope"))
);--> statement-breakpoint
INSERT INTO `__new_enrollment_codes`("id", "auth_mac", "binding_id", "code_hash", "code_hint", "scope", "created_at", "created_by", "created_with", "expires_at") SELECT "id", "auth_mac", "binding_id", "code_hash", "code_hint", "scope", "created_at", "created_by", "created_with", "expires_at" FROM `enrollment_codes`;--> statement-breakpoint
DROP TABLE `enrollment_codes`;--> statement-breakpoint
ALTER TABLE `__new_enrollment_codes` RENAME TO `enrollment_codes`;--> statement-breakpoint
CREATE INDEX `enrollment_codes_binding_idx` ON `enrollment_codes` (`binding_id`,`created_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_codes_code_hash_key` ON `enrollment_codes` (`code_hash`);--> statement-breakpoint
CREATE TABLE `__new_spent_id_tokens` (
	`hash` blob PRIMARY KEY NOT NULL,
	`consumed_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	CONSTRAINT "spent_id_tokens_hash_check" CHECK(octet_length("__new_spent_id_tokens"."hash") = 32)
);--> statement-breakpoint
INSERT INTO `__new_spent_id_tokens`("hash", "consumed_at") SELECT "hash", "consumed_at" FROM `spent_id_tokens`;--> statement-breakpoint
DROP TABLE `spent_id_tokens`;--> statement-breakpoint
ALTER TABLE `__new_spent_id_tokens` RENAME TO `spent_id_tokens`;--> statement-breakpoint
CREATE TABLE `__new_bulk_cap` (
	`principal` text NOT NULL,
	`secret` text NOT NULL,
	`last` integer NOT NULL,
	PRIMARY KEY(`principal`, `secret`)
);--> statement-breakpoint
INSERT INTO `__new_bulk_cap`("principal", "secret", "last") SELECT "principal", "secret", "last" FROM `bulk_cap`;--> statement-breakpoint
DROP TABLE `bulk_cap`;--> statement-breakpoint
ALTER TABLE `__new_bulk_cap` RENAME TO `bulk_cap`;--> statement-breakpoint
CREATE TABLE `__new_checkpoint_fence` (
	`only_row` integer PRIMARY KEY DEFAULT true NOT NULL,
	`at_floor` integer NOT NULL,
	`retired` text DEFAULT '[]' NOT NULL,
	CONSTRAINT "checkpoint_fence_only_row_check" CHECK("__new_checkpoint_fence"."only_row")
);--> statement-breakpoint
INSERT INTO `__new_checkpoint_fence`("only_row", "at_floor", "retired") SELECT "only_row", "at_floor", "retired" FROM `checkpoint_fence`;--> statement-breakpoint
DROP TABLE `checkpoint_fence`;--> statement-breakpoint
ALTER TABLE `__new_checkpoint_fence` RENAME TO `checkpoint_fence`;--> statement-breakpoint
CREATE TRIGGER `log_changes_refuse_retired` BEFORE INSERT ON `log_changes` FOR EACH ROW
    WHEN EXISTS (SELECT 1 FROM `checkpoint_fence` f, json_each(f.`retired`) j WHERE f.`only_row` AND j.value = lower(hex(substr(NEW.`mac`, 1, 4))))
BEGIN
    SELECT RAISE(ABORT, 'the log moved on from the signing key this entry is under: a vault given a newer key replaced this one, and a replaced key writes nothing more (ask again)');
END;
