CREATE TABLE `consumed_tokens` (
	`hash` blob PRIMARY KEY NOT NULL,
	`consumed_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	CONSTRAINT "consumed_tokens_hash_check" CHECK(octet_length("consumed_tokens"."hash") = 32)
);
--> statement-breakpoint
CREATE INDEX `audit_log_exchange_idx` ON `audit_log` (json_extract("metadata", '$.credentialId')) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" = 'token.exchange' AND "audit_log"."decision" = 'allow';