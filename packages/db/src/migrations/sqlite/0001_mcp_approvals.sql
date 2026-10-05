CREATE TABLE `mcp_approvals` (
	`id` text PRIMARY KEY NOT NULL,
	`connection_id` text NOT NULL,
	`tool` text NOT NULL,
	`arguments` text NOT NULL,
	`digest` blob NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`outcome` text,
	`created_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`expires_at` integer NOT NULL,
	`decided_at` integer,
	`reported_at` integer,
	FOREIGN KEY (`connection_id`) REFERENCES `mcp_connections`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "mcp_approvals_status_check" CHECK("mcp_approvals"."status" IN ('pending', 'approved', 'denied', 'cancelled', 'failed')),
	CONSTRAINT "mcp_approvals_digest_check" CHECK(octet_length("mcp_approvals"."digest") = 32),
	CONSTRAINT "mcp_approvals_arguments_check" CHECK(json_valid("mcp_approvals"."arguments"))
);
--> statement-breakpoint
CREATE INDEX `mcp_approvals_open_idx` ON `mcp_approvals` (`connection_id`,`digest`) WHERE "mcp_approvals"."reported_at" IS NULL;