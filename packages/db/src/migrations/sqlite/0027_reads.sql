-- The audit pages' reads, a sealed projection of 0.15's uses (T166; postgres 0049_reads). SQLite has one writer and no partitions: the projector writes these directly.
CREATE TABLE `log_read_partners` (
	`environment` text NOT NULL,
	`partner` text NOT NULL,
	PRIMARY KEY(`environment`, `partner`)
);
--> statement-breakpoint
CREATE TABLE `log_read_places` (
	`environment` text NOT NULL,
	`partner` text NOT NULL,
	`at` integer NOT NULL,
	`number` integer NOT NULL,
	`principal` text NOT NULL,
	`secret` text NOT NULL,
	`partners` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `log_read_places_place_idx` ON `log_read_places` (`environment`,`partner`,`at`,`number`);--> statement-breakpoint
CREATE INDEX `log_read_places_member_idx` ON `log_read_places` (`principal`,`environment`,`partner`,`at`,`number`);--> statement-breakpoint
CREATE INDEX `log_read_places_key_idx` ON `log_read_places` (`secret`,`environment`,`partner`,`at`,`number`);--> statement-breakpoint
CREATE TABLE `log_reads` (
	`number` integer NOT NULL,
	`at` integer NOT NULL,
	`credential` text NOT NULL,
	`purpose` integer NOT NULL,
	`principal` text NOT NULL,
	`secret` text NOT NULL,
	`environment` text NOT NULL,
	`project` text NOT NULL,
	`place` text,
	`source` text,
	`source_environment` text,
	`source_project` text,
	`version` text,
	`mac` blob NOT NULL,
	CONSTRAINT "log_reads_mac_check" CHECK(octet_length("log_reads"."mac") = 16)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `log_reads_number_idx` ON `log_reads` (`at`,`number`);--> statement-breakpoint
CREATE INDEX `log_reads_principal_idx` ON `log_reads` (`principal`,`at`,`number`);--> statement-breakpoint
CREATE TABLE `log_reads_cursor` (
	`only_row` integer PRIMARY KEY DEFAULT true NOT NULL,
	`through` integer NOT NULL,
	`pair` integer NOT NULL,
	`at` integer NOT NULL,
	`mac` blob,
	CONSTRAINT "log_reads_cursor_only_row_check" CHECK("log_reads_cursor"."only_row"),
	CONSTRAINT "log_reads_cursor_mac_check" CHECK("log_reads_cursor"."mac" IS NULL OR octet_length("log_reads_cursor"."mac") = 16)
);--> statement-breakpoint
INSERT INTO `log_reads_cursor` (`only_row`, `through`, `pair`, `at`) VALUES (1, 0, 0, 0);
