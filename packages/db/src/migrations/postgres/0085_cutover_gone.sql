-- 0.16.0, T273: 0.15's cutover from 0.14 is gone. 0.16 upgrades offline from a 0.15.0 whose vault cut its log over (D197), and `coffre migrate` refuses any other database before it applies this (`requireCutOver` in migrate.ts), so no database here has a cutover left to make. Its functions go: the vault's writes and reads of the cutover (0041, 0046, 0047), and 0047's trigger, which refused an entry of 0.14's once the cutover was there, from an isolate of 0.14 still serving beside 0.15, which an offline upgrade has none of. Nothing else changes: the cutover's change stays in `log_changes`, the anchor of every object it sealed.
DROP TRIGGER audit_log_refuse_old ON audit_log;
--> statement-breakpoint
DROP FUNCTION log_refuse_old_write();
--> statement-breakpoint
DROP FUNCTION log_cutover(text, bigint, text, text, bytea);
--> statement-breakpoint
DROP FUNCTION cutover_places(bigint, uuid[], uuid[]);
--> statement-breakpoint
DROP FUNCTION cutover_credentials(uuid[]);
--> statement-breakpoint
DROP FUNCTION cutover_bindings(uuid[]);
--> statement-breakpoint
DROP FUNCTION cutover_connections(uuid[]);
--> statement-breakpoint
DROP FUNCTION seal_binding(uuid, text, bigint, text, text, bytea, bytea);
