-- A place's audit page lists its reads (T175; postgres 0050_reads_by_place): an index on each column of `log_reads` that names a place, and each place's days of reads, which triggers write whoever writes the reads. SQLite has no partitions: its pages read the indexes alone, and the whole log's check holds the days as on Postgres.
CREATE TABLE `log_read_place_days` (
	`place` text NOT NULL,
	`day` integer NOT NULL,
	PRIMARY KEY(`place`, `day`)
);
--> statement-breakpoint
CREATE INDEX `log_read_place_days_day_idx` ON `log_read_place_days` (`day`);--> statement-breakpoint
CREATE INDEX `log_reads_secret_idx` ON `log_reads` (`secret`,`at`,`number`);--> statement-breakpoint
CREATE INDEX `log_reads_environment_idx` ON `log_reads` (`environment`,`at`,`number`);--> statement-breakpoint
CREATE INDEX `log_reads_project_idx` ON `log_reads` (`project`,`at`,`number`);--> statement-breakpoint
CREATE INDEX `log_reads_place_idx` ON `log_reads` (`place`,`at`,`number`) WHERE "log_reads"."place" IS NOT NULL;--> statement-breakpoint
CREATE INDEX `log_reads_source_idx` ON `log_reads` (`source`,`at`,`number`) WHERE "log_reads"."source" IS NOT NULL;--> statement-breakpoint
CREATE INDEX `log_reads_source_environment_idx` ON `log_reads` (`source_environment`,`at`,`number`) WHERE "log_reads"."source_environment" IS NOT NULL;--> statement-breakpoint
CREATE INDEX `log_reads_source_project_idx` ON `log_reads` (`source_project`,`at`,`number`) WHERE "log_reads"."source_project" IS NOT NULL;--> statement-breakpoint
CREATE TRIGGER `log_reads_placed_insert` AFTER INSERT ON `log_reads` BEGIN
	INSERT OR IGNORE INTO `log_read_place_days` (`place`, `day`)
	SELECT id, NEW.`at` / 86400000 FROM (SELECT NEW.`secret` AS id UNION ALL SELECT NEW.`environment` UNION ALL SELECT NEW.`project` UNION ALL SELECT NEW.`place`
		UNION ALL SELECT NEW.`source` UNION ALL SELECT NEW.`source_environment` UNION ALL SELECT NEW.`source_project`) WHERE id IS NOT NULL;
END;--> statement-breakpoint
CREATE TRIGGER `log_reads_placed_update` AFTER UPDATE ON `log_reads` BEGIN
	INSERT OR IGNORE INTO `log_read_place_days` (`place`, `day`)
	SELECT id, NEW.`at` / 86400000 FROM (SELECT NEW.`secret` AS id UNION ALL SELECT NEW.`environment` UNION ALL SELECT NEW.`project` UNION ALL SELECT NEW.`place`
		UNION ALL SELECT NEW.`source` UNION ALL SELECT NEW.`source_environment` UNION ALL SELECT NEW.`source_project`) WHERE id IS NOT NULL;
END;--> statement-breakpoint
-- The reads 0.15.0 listed, placed.
INSERT OR IGNORE INTO `log_read_place_days` (`place`, `day`)
SELECT id, day FROM (
	SELECT `secret` AS id, `at` / 86400000 AS day FROM `log_reads` UNION SELECT `environment`, `at` / 86400000 FROM `log_reads`
	UNION SELECT `project`, `at` / 86400000 FROM `log_reads` UNION SELECT `place`, `at` / 86400000 FROM `log_reads`
	UNION SELECT `source`, `at` / 86400000 FROM `log_reads` UNION SELECT `source_environment`, `at` / 86400000 FROM `log_reads`
	UNION SELECT `source_project`, `at` / 86400000 FROM `log_reads`
) WHERE id IS NOT NULL;
