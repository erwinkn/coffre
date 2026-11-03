-- Passkeys (0.16, T176; postgres 0063_passkeys says what each part is), for tests and local development. It only adds, and rebuilds no table: each check on an existing table is on its new column, as 0018's seals were.
CREATE TABLE `passkeys` (
	`id` text PRIMARY KEY NOT NULL,
	`auth_mac` blob NOT NULL,
	`principal` text NOT NULL,
	`generation` integer NOT NULL,
	`user_handle` blob NOT NULL,
	`credential_id` blob NOT NULL,
	`public_key` blob NOT NULL,
	`algorithm` integer NOT NULL,
	`sign_count` integer DEFAULT 0 NOT NULL,
	`last_challenge_at` integer,
	`transports` text DEFAULT '[]' NOT NULL,
	`aaguid` blob,
	`synced` integer NOT NULL,
	`name` text NOT NULL,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`created_by` text NOT NULL,
	`last_used_at` integer,
	`removed_at` integer,
	`removed_by` text,
	FOREIGN KEY (`principal`) REFERENCES `vault_members`(`principal`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "passkeys_auth_mac_check" CHECK(octet_length("passkeys"."auth_mac") = 32),
	CONSTRAINT "passkeys_principal_check" CHECK("passkeys"."principal" LIKE 'user:%'),
	CONSTRAINT "passkeys_user_handle_check" CHECK(octet_length("passkeys"."user_handle") = 16),
	CONSTRAINT "passkeys_credential_id_check" CHECK(octet_length("passkeys"."credential_id") BETWEEN 16 AND 1023),
	CONSTRAINT "passkeys_algorithm_check" CHECK("passkeys"."algorithm" IN (-8, -7, -257)),
	CONSTRAINT "passkeys_sign_count_check" CHECK("passkeys"."sign_count" BETWEEN 0 AND 4294967295),
	CONSTRAINT "passkeys_transports_check" CHECK(json_type("passkeys"."transports") = 'array'),
	CONSTRAINT "passkeys_aaguid_check" CHECK("passkeys"."aaguid" IS NULL OR octet_length("passkeys"."aaguid") = 16),
	CONSTRAINT "passkeys_name_check" CHECK(length("passkeys"."name") BETWEEN 1 AND 64),
	CONSTRAINT "passkeys_removed_check" CHECK(("passkeys"."removed_at" IS NULL) = ("passkeys"."removed_by" IS NULL))
);
--> statement-breakpoint
CREATE INDEX `passkeys_live_idx` ON `passkeys` (`principal`,`generation`) WHERE "passkeys"."removed_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `passkeys_credential_id_key` ON `passkeys` (`credential_id`);--> statement-breakpoint
ALTER TABLE `credentials` ADD COLUMN `passkey_id` text REFERENCES passkeys(id) ON DELETE restrict;--> statement-breakpoint
ALTER TABLE `credentials` ADD COLUMN `confirmed_at` integer CONSTRAINT "credentials_confirmed_check" CHECK("confirmed_at" IS NULL OR "passkey_id" IS NOT NULL);--> statement-breakpoint
ALTER TABLE `device_authorizations` ADD COLUMN `passkey_id` text REFERENCES passkeys(id) ON DELETE restrict CONSTRAINT "device_authorizations_passkey_check" CHECK("passkey_id" IS NULL OR "decision" = 'approved');--> statement-breakpoint
ALTER TABLE `mcp_connections` ADD COLUMN `passkey_id` text REFERENCES passkeys(id) ON DELETE restrict;
