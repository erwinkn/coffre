CREATE INDEX `audit_log_key_idx` ON `audit_log` (`author`,`key_id`,`seq`);--> statement-breakpoint
CREATE INDEX `audit_log_vault_idx` ON `audit_log` (`author`,`seq`) WHERE "audit_log"."author" = 'vault';--> statement-breakpoint
CREATE INDEX `audit_log_app_idx` ON `audit_log` (`author`,`seq`) WHERE "audit_log"."author" = 'app';--> statement-breakpoint
CREATE INDEX `log_reads_by_number_idx` ON `log_reads` (`number`);--> statement-breakpoint
CREATE INDEX `log_uses_by_number_idx` ON `log_uses` (`number`);--> statement-breakpoint
CREATE INDEX `audit_log_vault_allowed_idx` ON `audit_log` (`author`,`action`,`decision`,`seq`) WHERE "audit_log"."author" = 'vault' AND "audit_log"."decision" = 'allow';--> statement-breakpoint
CREATE INDEX `audit_log_vault_refused_idx` ON `audit_log` (`author`,`action`,`decision`,`code`,`seq`) WHERE "audit_log"."author" = 'vault' AND "audit_log"."decision" = 'deny';