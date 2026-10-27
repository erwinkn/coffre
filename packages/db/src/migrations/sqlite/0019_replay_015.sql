CREATE TABLE `log_replays` (
	`upto` integer PRIMARY KEY NOT NULL,
	`at` integer NOT NULL,
	`state` text,
	`state_hash` blob,
	`verdict` text,
	`mac` blob NOT NULL,
	CONSTRAINT "log_replays_mac_check" CHECK(octet_length("log_replays"."mac") = 32),
	CONSTRAINT "log_replays_state_check" CHECK(("log_replays"."state" IS NULL) = ("log_replays"."state_hash" IS NULL) AND ("log_replays"."state_hash" IS NULL OR octet_length("log_replays"."state_hash") = 32))
);
