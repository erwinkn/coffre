CREATE INDEX `credentials_expiry_idx` ON `credentials` (`principal`,`expires_at`,`id`,`created_at`);--> statement-breakpoint
CREATE INDEX `log_uses_credential_idx` ON `log_uses` (`credential`,`at`,`number`);--> statement-breakpoint
CREATE INDEX `log_uses_secret_idx` ON `log_uses` (`secret`,`at`,`number`);--> statement-breakpoint
CREATE INDEX `log_uses_place_idx` ON `log_uses` (`place`,`at`,`number`) WHERE "log_uses"."place" IS NOT NULL;