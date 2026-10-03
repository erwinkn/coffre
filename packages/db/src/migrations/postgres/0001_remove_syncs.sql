-- Stop old app instances before upgrading. Never silently discard a configured
-- destination, including archived ones. Keep the audit and sealed legacy rows.
LOCK TABLE syncs, sync_keys IN ACCESS EXCLUSIVE MODE;
--> statement-breakpoint
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM syncs) OR EXISTS (SELECT 1 FROM sync_keys) THEN
    RAISE EXCEPTION 'syncs are removed: migrate destinations to service tokens, back up and clear syncs and sync_keys before upgrading';
  END IF;
END $$;
--> statement-breakpoint
DROP TABLE sync_keys;
--> statement-breakpoint
DROP TABLE syncs;
