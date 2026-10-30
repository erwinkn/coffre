-- MCP connections are sealed objects of 0.15's log (T147; postgres/0046_way_in_uses.sql): their seal. SQLite adds a check by making the table again.
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_mcp_connections` (
	`id` text PRIMARY KEY NOT NULL,
	`auth_mac` blob NOT NULL,
	`principal` text NOT NULL,
	`generation` integer NOT NULL,
	`client_id` text NOT NULL,
	`client_name` text NOT NULL,
	`client_host` text,
	`registration` text NOT NULL,
	`scopes` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`code_hash` blob,
	`code_challenge` text,
	`code_expires_at` integer,
	`refresh_hash` blob,
	`refresh_previous_hash` blob,
	`expires_at` integer NOT NULL,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`last_used_at` integer,
	`last_used_ip` text,
	`revoked_at` integer,
	`revoked_by` text,
	`seal` blob,
	FOREIGN KEY (`principal`) REFERENCES `vault_members`(`principal`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "mcp_connections_seal_check" CHECK("__new_mcp_connections"."seal" IS NULL OR octet_length("__new_mcp_connections"."seal") = 16),
	CONSTRAINT "mcp_connections_principal_check" CHECK("__new_mcp_connections"."principal" LIKE 'user:%'),
	CONSTRAINT "mcp_connections_registration_check" CHECK("__new_mcp_connections"."registration" IN ('cimd', 'dcr')),
	CONSTRAINT "mcp_connections_auth_mac_check" CHECK(octet_length("__new_mcp_connections"."auth_mac") = 32),
	CONSTRAINT "mcp_connections_code_hash_check" CHECK("__new_mcp_connections"."code_hash" IS NULL OR octet_length("__new_mcp_connections"."code_hash") = 32),
	CONSTRAINT "mcp_connections_refresh_hash_check" CHECK("__new_mcp_connections"."refresh_hash" IS NULL OR octet_length("__new_mcp_connections"."refresh_hash") = 32)
);
--> statement-breakpoint
INSERT INTO `__new_mcp_connections`("id", "auth_mac", "principal", "generation", "client_id", "client_name", "client_host", "registration", "scopes", "redirect_uri", "code_hash", "code_challenge", "code_expires_at", "refresh_hash", "refresh_previous_hash", "expires_at", "created_at", "last_used_at", "last_used_ip", "revoked_at", "revoked_by") SELECT "id", "auth_mac", "principal", "generation", "client_id", "client_name", "client_host", "registration", "scopes", "redirect_uri", "code_hash", "code_challenge", "code_expires_at", "refresh_hash", "refresh_previous_hash", "expires_at", "created_at", "last_used_at", "last_used_ip", "revoked_at", "revoked_by" FROM `mcp_connections`;--> statement-breakpoint
DROP TABLE `mcp_connections`;--> statement-breakpoint
ALTER TABLE `__new_mcp_connections` RENAME TO `mcp_connections`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `mcp_connections_refresh_previous_idx` ON `mcp_connections` (`refresh_previous_hash`);--> statement-breakpoint
CREATE INDEX `mcp_connections_live_idx` ON `mcp_connections` (`principal`,`expires_at`) WHERE "mcp_connections"."revoked_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `mcp_connections_code_hash_key` ON `mcp_connections` (`code_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `mcp_connections_refresh_hash_key` ON `mcp_connections` (`refresh_hash`);