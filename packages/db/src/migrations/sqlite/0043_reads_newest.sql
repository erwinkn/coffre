-- Each member's newest read of each key and version, which an offboarding report reads (T252; postgres 0084_reads_newest): triggers write it whoever writes the reads, its time only moved up, and a read deleted deletes its entry unless a later read keeps it newer: retention's `dropDay` drops a day's reads, 0.15's (which runs on this schema until this release is deployed) as this release's, and their entries go with them, the days going oldest first (NewestRetired).
CREATE TABLE `log_read_newest` (
	`principal` text NOT NULL,
	`secret` text NOT NULL,
	`version` text NOT NULL,
	`at` integer NOT NULL,
	PRIMARY KEY(`principal`, `secret`, `version`)
);
--> statement-breakpoint
CREATE INDEX `log_read_newest_at_idx` ON `log_read_newest` (`at`);--> statement-breakpoint
CREATE TRIGGER `log_reads_newest_insert` AFTER INSERT ON `log_reads` WHEN NEW.`version` IS NOT NULL BEGIN
	INSERT INTO `log_read_newest` (`principal`, `secret`, `version`, `at`) VALUES (NEW.`principal`, coalesce(NEW.`source`, NEW.`secret`), NEW.`version`, NEW.`at`)
	ON CONFLICT (`principal`, `secret`, `version`) DO UPDATE SET `at` = excluded.`at` WHERE `log_read_newest`.`at` < excluded.`at`;
END;--> statement-breakpoint
CREATE TRIGGER `log_reads_newest_update` AFTER UPDATE ON `log_reads` WHEN NEW.`version` IS NOT NULL BEGIN
	INSERT INTO `log_read_newest` (`principal`, `secret`, `version`, `at`) VALUES (NEW.`principal`, coalesce(NEW.`source`, NEW.`secret`), NEW.`version`, NEW.`at`)
	ON CONFLICT (`principal`, `secret`, `version`) DO UPDATE SET `at` = excluded.`at` WHERE `log_read_newest`.`at` < excluded.`at`;
END;--> statement-breakpoint
CREATE TRIGGER `log_reads_newest_delete` AFTER DELETE ON `log_reads` WHEN OLD.`version` IS NOT NULL BEGIN
	DELETE FROM `log_read_newest` WHERE `principal` = OLD.`principal` AND `secret` = coalesce(OLD.`source`, OLD.`secret`) AND `version` = OLD.`version` AND `at` <= OLD.`at`;
END;--> statement-breakpoint
-- The reads 0.15 listed.
INSERT INTO `log_read_newest` (`principal`, `secret`, `version`, `at`)
SELECT `principal`, coalesce(`source`, `secret`), `version`, max(`at`) FROM `log_reads` WHERE `version` IS NOT NULL
GROUP BY `principal`, coalesce(`source`, `secret`), `version`
ON CONFLICT (`principal`, `secret`, `version`) DO UPDATE SET `at` = excluded.`at` WHERE `log_read_newest`.`at` < excluded.`at`;
