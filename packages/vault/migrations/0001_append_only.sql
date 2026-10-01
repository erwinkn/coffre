-- The log is append-only. The vault's code never updates or deletes a row;
-- these make a bug that tried fail instead of rewriting history.
CREATE TRIGGER `log_no_update` BEFORE UPDATE ON `log`
BEGIN
    SELECT RAISE(ABORT, 'the vault log is append-only');
END;
--> statement-breakpoint
CREATE TRIGGER `log_no_delete` BEFORE DELETE ON `log`
BEGIN
    SELECT RAISE(ABORT, 'the vault log is append-only');
END;
