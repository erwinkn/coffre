-- 0.15's retention (the Postgres migration, 0027_retention, says what it is): a day's cut, the first checkpoint whose floor of at is past the day's end, by an index. SQLite has no partitions and no functions: retention deletes rows (log-store.ts).
CREATE INDEX `log_checkpoints_floor_idx` ON `log_checkpoints` (`at_floor`,`upto`);
