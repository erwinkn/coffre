CREATE TABLE `log_replays` (
	`upto` integer PRIMARY KEY NOT NULL,
	`at` integer NOT NULL,
	`state` text NOT NULL,
	`mac` blob NOT NULL,
	CONSTRAINT "log_replays_mac_check" CHECK(octet_length("log_replays"."mac") = 32)
);
