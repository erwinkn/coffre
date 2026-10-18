-- Plain values (0.9): a version of a key marked not secret holds its value in the clear too. Nullable, so the release before writes on as it did.
ALTER TABLE `secret_versions` ADD `plaintext` text;--> statement-breakpoint
-- A version is still only ever erased, and an erased one holds no value, in the clear or not.
DROP TRIGGER `secret_versions_erase_only`;--> statement-breakpoint
CREATE TRIGGER `secret_versions_erase_only` BEFORE UPDATE ON `secret_versions`
WHEN length(NEW.`ciphertext`) <> 0 OR length(NEW.`wrapped_dek`) <> 0 OR NEW.`plaintext` IS NOT NULL
    OR NEW.`id` IS NOT OLD.`id` OR NEW.`secret_id` IS NOT OLD.`secret_id` OR NEW.`version` IS NOT OLD.`version`
    OR NEW.`envelope_version` IS NOT OLD.`envelope_version` OR NEW.`iv` IS NOT OLD.`iv` OR NEW.`auth_tag` IS NOT OLD.`auth_tag`
    OR NEW.`kek_provider` IS NOT OLD.`kek_provider` OR NEW.`kek_id` IS NOT OLD.`kek_id` OR NEW.`kek_version` IS NOT OLD.`kek_version`
    OR NEW.`created_at` IS NOT OLD.`created_at` OR NEW.`created_by` IS NOT OLD.`created_by`
    OR NEW.`recipe` IS NOT OLD.`recipe` OR NEW.`pair_id` IS NOT OLD.`pair_id` OR NEW.`pair_half` IS NOT OLD.`pair_half`
BEGIN
    SELECT RAISE(ABORT, 'a secret version is only ever erased');
END;
