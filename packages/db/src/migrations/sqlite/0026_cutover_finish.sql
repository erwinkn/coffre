-- 0.14's writes refused once the cutover is there (the Postgres migration, 0047_cutover_finish, says why): the column every entry a writer under 0.15's log appends carries, and the trigger. SQLite has one writer and no functions: the cutover's change is found by its object's key, `log_object('log', 'cutover')` as the vault computes it (log-entry.ts, CUTOVER_OBJECT).
ALTER TABLE `audit_log` ADD `log015` integer;
--> statement-breakpoint
CREATE TRIGGER `audit_log_refuse_old` BEFORE INSERT ON `audit_log` FOR EACH ROW
    WHEN NEW.`decision` = 'allow' AND NEW.`log015` IS NULL AND NEW.`action` NOT LIKE 'audit.%' AND NEW.`action` NOT IN (
        'credential.use', 'token.use', 'secret.read', 'secret.use', 'secret.list', 'secret.history', 'secret.version', 'missing.list', 'personal.list',
        'roles.list', 'roles.preview', 'mcp.read', 'mcp.view', 'key.check', 'key.intent', 'workload.alert', 'vault.tampered'
    ) AND EXISTS (SELECT 1 FROM `log_changes` WHERE `object` = '60b3bfb2-d45c-96d7-5c0c-be2d45fc15dc')
BEGIN
    SELECT RAISE(ABORT, '0.15''s log is cut over from 0.14: every write of 0.14''s after it is refused (an isolate of the earlier release still serving: ask again)');
END;
