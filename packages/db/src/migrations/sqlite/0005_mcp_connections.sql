CREATE TABLE `mcp_connections` (
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
	FOREIGN KEY (`principal`) REFERENCES `vault_members`(`principal`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "mcp_connections_principal_check" CHECK("mcp_connections"."principal" LIKE 'user:%'),
	CONSTRAINT "mcp_connections_registration_check" CHECK("mcp_connections"."registration" IN ('cimd', 'dcr')),
	CONSTRAINT "mcp_connections_auth_mac_check" CHECK(octet_length("mcp_connections"."auth_mac") = 32),
	CONSTRAINT "mcp_connections_code_hash_check" CHECK("mcp_connections"."code_hash" IS NULL OR octet_length("mcp_connections"."code_hash") = 32),
	CONSTRAINT "mcp_connections_refresh_hash_check" CHECK("mcp_connections"."refresh_hash" IS NULL OR octet_length("mcp_connections"."refresh_hash") = 32)
);
--> statement-breakpoint
CREATE INDEX `mcp_connections_refresh_previous_idx` ON `mcp_connections` (`refresh_previous_hash`);--> statement-breakpoint
CREATE INDEX `mcp_connections_live_idx` ON `mcp_connections` (`principal`,`expires_at`) WHERE "mcp_connections"."revoked_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `mcp_connections_code_hash_key` ON `mcp_connections` (`code_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `mcp_connections_refresh_hash_key` ON `mcp_connections` (`refresh_hash`);--> statement-breakpoint
CREATE TABLE `oauth_clients` (
	`id` text PRIMARY KEY NOT NULL,
	`auth_mac` blob NOT NULL,
	`name` text NOT NULL,
	`redirect_uris` text NOT NULL,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`created_ip` text,
	`revoked_at` integer,
	CONSTRAINT "oauth_clients_auth_mac_check" CHECK(octet_length("oauth_clients"."auth_mac") = 32),
	CONSTRAINT "oauth_clients_redirect_uris_check" CHECK(json_valid("oauth_clients"."redirect_uris"))
);
