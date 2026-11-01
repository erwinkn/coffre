-- 0.15's log across a rotation of the vault's signing key (the Postgres migration, 0050_key_rotation, says why): the fence's retired tags, hex, a JSON array, and the trigger that refuses a change under one. SQLite has one writer and no functions: the vault writes the rotation and refuses a use itself, in the transaction that takes its number.
ALTER TABLE `log_fence` ADD `retired` text DEFAULT '[]' NOT NULL;
--> statement-breakpoint
CREATE TRIGGER `log_changes_refuse_retired` BEFORE INSERT ON `log_changes` FOR EACH ROW
    WHEN EXISTS (SELECT 1 FROM `log_fence` f, json_each(f.`retired`) j WHERE f.`only_row` AND j.value = lower(hex(substr(NEW.`mac`, 1, 4))))
BEGIN
    SELECT RAISE(ABORT, 'the log moved on from the signing key this entry is under: a vault given a newer key replaced this one, and a replaced key writes nothing more (ask again)');
END;
