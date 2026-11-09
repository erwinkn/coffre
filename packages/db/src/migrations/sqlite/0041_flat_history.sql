CREATE INDEX `audit_log_vault_key_idx` ON `audit_log` (`author`,`key_id`,`seq`) WHERE author = 'vault';--> statement-breakpoint
CREATE INDEX `audit_log_app_key_idx` ON `audit_log` (`author`,`key_id`,`seq`) WHERE author = 'app';--> statement-breakpoint
CREATE INDEX `audit_log_vault_idx` ON `audit_log` (`author`,`seq`) WHERE "audit_log"."author" = 'vault';--> statement-breakpoint
CREATE INDEX `audit_log_app_idx` ON `audit_log` (`author`,`seq`) WHERE "audit_log"."author" = 'app';--> statement-breakpoint
CREATE INDEX `log_reads_by_number_idx` ON `log_reads` (`number`);--> statement-breakpoint
CREATE INDEX `log_uses_by_number_idx` ON `log_uses` (`number`);--> statement-breakpoint
CREATE INDEX `audit_log_signed_idx` ON `audit_log` (`author`,`action`,`decision`,`seq`) WHERE author = 'vault' AND action = 'audit.checkpoint' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX `audit_log_checkpoint_idx` ON `audit_log` (`author`,`action`,`seq`) WHERE author = 'vault' AND action = 'audit.checkpoint';--> statement-breakpoint
CREATE INDEX `audit_log_broken_log_idx` ON `audit_log` (`author`,`action`,`decision`,`code`,`seq`) WHERE author = 'vault' AND action = 'audit.checkpoint' AND decision = 'deny' AND code = 'log_broken';--> statement-breakpoint
CREATE INDEX `audit_log_policy_idx` ON `audit_log` (`author`,`action`,`decision`,`seq`) WHERE author = 'vault' AND action = 'policy.change' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX `audit_log_settings_idx` ON `audit_log` (`author`,`action`,`decision`,`seq`) WHERE author = 'vault' AND action = 'settings.change' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX `audit_log_rotation_idx` ON `audit_log` (`author`,`action`,`decision`,`seq`) WHERE author = 'vault' AND action = 'key.rotate' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX `audit_log_intent_idx` ON `audit_log` (`author`,`action`,`decision`,`seq`) WHERE author = 'vault' AND action = 'key.intent' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX `audit_log_key_check_idx` ON `audit_log` (`author`,`action`,`decision`,`seq`) WHERE author = 'vault' AND action = 'key.check' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX `audit_log_tamper_idx` ON `audit_log` (`author`,`subject_principal`,`action`,`seq`) WHERE author = 'vault' AND action = 'vault.tampered' AND code IN ('mac', 'stale');--> statement-breakpoint
CREATE INDEX `audit_log_moves_idx` ON `audit_log` (`author`,`seq`) WHERE author = 'app' AND action IN ('key.reseal', 'key.rotate');--> statement-breakpoint
CREATE INDEX `audit_log_frozen_idx` ON `audit_log` (json_extract("metadata", '$.target'),`seq`) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" IN ('workload.freeze', 'workload.unfreeze') AND "audit_log"."decision" = 'allow';
