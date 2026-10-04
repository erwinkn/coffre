CREATE TABLE `service_bindings` (
	`id` text PRIMARY KEY NOT NULL,
	`auth_mac` blob NOT NULL,
	`principal` text NOT NULL,
	`generation` integer NOT NULL,
	`profile` text NOT NULL,
	`issuer` text NOT NULL,
	`jwks_uri` text NOT NULL,
	`claims` text NOT NULL,
	`label` text,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`created_by` text NOT NULL,
	`last_used_at` integer,
	`revoked_at` integer,
	`revoked_by` text,
	FOREIGN KEY (`principal`) REFERENCES `vault_members`(`principal`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "service_bindings_principal_check" CHECK("service_bindings"."principal" LIKE 'token:%'),
	CONSTRAINT "service_bindings_auth_mac_check" CHECK(octet_length("service_bindings"."auth_mac") = 32),
	CONSTRAINT "service_bindings_claims_check" CHECK(json_valid("service_bindings"."claims"))
);
--> statement-breakpoint
CREATE INDEX `service_bindings_principal_idx` ON `service_bindings` (`principal`,`issuer`);--> statement-breakpoint
CREATE INDEX `audit_log_unbind_idx` ON `audit_log` (json_extract("metadata", '$.bindingId')) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" = 'token.unbind' AND "audit_log"."decision" = 'allow';