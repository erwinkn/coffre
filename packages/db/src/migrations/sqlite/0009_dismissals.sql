CREATE TABLE `dismissed_keys` (
	`environment_id` text NOT NULL,
	`key` text NOT NULL,
	`dismissed_at` integer DEFAULT (CAST(unixepoch('subsec') * 1000 AS INTEGER)) NOT NULL,
	`dismissed_by` text NOT NULL,
	`restored_at` integer,
	`restored_by` text,
	PRIMARY KEY(`environment_id`, `key`),
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "dismissed_keys_key_check" CHECK(length("dismissed_keys"."key") BETWEEN 1 AND 128 AND "dismissed_keys"."key" GLOB '[A-Za-z_]*' AND "dismissed_keys"."key" NOT GLOB '*[^A-Za-z0-9_]*')
);
