-- Proxy definitions written in the UI (0.16, T186; postgres 0056_proxy_definitions): one row per environment holds its items, their index and the vault's seal over it, kind `proxy`; one row the names the deployment's code reserved, kind `proxy-reserved`. Only the vault writes them, through its change path (`changeOnSqlite`).
CREATE TABLE `proxy_definitions` (
	`environment_id` text PRIMARY KEY NOT NULL,
	`items` text NOT NULL,
	`digests` blob NOT NULL,
	`seal` blob NOT NULL,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE no action,
	CONSTRAINT "proxy_definitions_items_check" CHECK(json_type("proxy_definitions"."items") = 'object'),
	CONSTRAINT "proxy_definitions_seal_check" CHECK(octet_length("proxy_definitions"."seal") = 16)
);
--> statement-breakpoint
CREATE TABLE `proxy_reserved` (
	`id` integer PRIMARY KEY NOT NULL,
	`names` text NOT NULL,
	`seal` blob NOT NULL,
	CONSTRAINT "proxy_reserved_id_check" CHECK("proxy_reserved"."id" = 1),
	CONSTRAINT "proxy_reserved_names_check" CHECK(json_type("proxy_reserved"."names") = 'array'),
	CONSTRAINT "proxy_reserved_seal_check" CHECK(octet_length("proxy_reserved"."seal") = 16)
);
