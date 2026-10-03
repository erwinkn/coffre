-- The migrator's transaction holds the SQLite write lock through this guard
-- and both drops. Failure rolls back the entire migration.
CREATE TABLE coffre_sync_removal_guard (
  records INTEGER CONSTRAINT syncs_must_be_cleared_before_upgrade CHECK (records = 0)
);
--> statement-breakpoint
INSERT INTO coffre_sync_removal_guard SELECT (SELECT count(*) FROM syncs) + (SELECT count(*) FROM sync_keys);
--> statement-breakpoint
DROP TABLE coffre_sync_removal_guard;
--> statement-breakpoint
DROP TABLE sync_keys;
--> statement-breakpoint
DROP TABLE syncs;
