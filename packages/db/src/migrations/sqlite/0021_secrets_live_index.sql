CREATE INDEX `secrets_live_idx` ON `secrets` (`environment_id`) WHERE `archived_at` IS NULL;
