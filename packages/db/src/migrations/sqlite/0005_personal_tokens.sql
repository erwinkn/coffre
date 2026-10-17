PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_credentials` (
	`id` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`auth_mac` blob NOT NULL,
	`token_hash` blob NOT NULL,
	`token_hint` text NOT NULL,
	`generation` integer NOT NULL,
	`principal` text NOT NULL,
	`identity_id` text,
	`scope` text,
	`label` text,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`created_by` text NOT NULL,
	`expires_at` integer NOT NULL,
	`last_used_at` integer,
	`last_used_ip` text,
	`revoked_at` integer,
	`revoked_by` text,
	FOREIGN KEY (`principal`) REFERENCES `vault_members`(`principal`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`identity_id`,`principal`,`generation`) REFERENCES `identities`(`id`,`principal`,`generation`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "credentials_kind_check" CHECK("__new_credentials"."kind" IN ('browser', 'cli', 'service', 'personal')),
	CONSTRAINT "credentials_principal_check" CHECK("__new_credentials"."principal" LIKE 'user:%' OR "__new_credentials"."principal" LIKE 'token:%'),
	CONSTRAINT "credentials_kind_matches_principal" CHECK(("__new_credentials"."kind" = 'service') = ("__new_credentials"."principal" LIKE 'token:%')),
	CONSTRAINT "credentials_token_hash_check" CHECK(octet_length("__new_credentials"."token_hash") = 32),
	CONSTRAINT "credentials_auth_mac_check" CHECK(octet_length("__new_credentials"."auth_mac") = 32)
);
--> statement-breakpoint
INSERT INTO `__new_credentials`("id", "kind", "auth_mac", "token_hash", "token_hint", "generation", "principal", "identity_id", "scope", "label", "created_at", "created_by", "expires_at", "last_used_at", "last_used_ip", "revoked_at", "revoked_by") SELECT "id", "kind", "auth_mac", "token_hash", "token_hint", "generation", "principal", "identity_id", "scope", "label", "created_at", "created_by", "expires_at", "last_used_at", "last_used_ip", "revoked_at", "revoked_by" FROM `credentials`;--> statement-breakpoint
DROP TABLE `credentials`;--> statement-breakpoint
ALTER TABLE `__new_credentials` RENAME TO `credentials`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `credentials_principal_idx` ON `credentials` (`principal`,`generation`);--> statement-breakpoint
CREATE INDEX `credentials_live_idx` ON `credentials` (`principal`,`expires_at`) WHERE "credentials"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX `credentials_issued_by_idx` ON `credentials` (`principal`,`created_by`,`created_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `credentials_token_hash_key` ON `credentials` (`token_hash`);--> statement-breakpoint
CREATE INDEX `audit_log_token_create_idx` ON `audit_log` (json_extract("metadata", '$.targetCredentialId')) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" = 'token.create' AND "audit_log"."decision" = 'allow';