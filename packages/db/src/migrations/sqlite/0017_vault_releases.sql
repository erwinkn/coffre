-- Releases (W199): each key the vault released to a principal, and when last, which its bulk limit counts from a row per key, not from every read the principal ever made. A trigger keeps it from each vault `secret.read` allowed, as on Postgres. It only adds.
CREATE TABLE `vault_releases` (
	`principal` text NOT NULL,
	`key` text NOT NULL,
	`released_at` integer NOT NULL,
	PRIMARY KEY(`principal`, `key`)
);
--> statement-breakpoint
-- Each key the entry names, as the count read them before (vault_releases_keep on Postgres). The SELECT's WHERE keeps
-- SQLite from reading ON CONFLICT as a join's.
CREATE TRIGGER `audit_log_releases` AFTER INSERT ON `audit_log`
WHEN NEW.`author` = 'vault' AND NEW.`action` = 'secret.read' AND NEW.`decision` = 'allow'
BEGIN
    INSERT INTO `vault_releases` (`principal`, `key`, `released_at`)
    SELECT DISTINCT NEW.`actor`, coalesce(NEW.`secret_id`, CASE WHEN one.type = 'object' AND json_type(one.value, '$.secretId') = 'text' THEN json_extract(one.value, '$.secretId') END, 'entry:' || NEW.`seq`), NEW.`occurred_at`
      FROM (SELECT 1) AS entry
      LEFT JOIN json_each(CASE WHEN NEW.`secret_id` IS NULL AND json_valid(NEW.`metadata`) THEN CASE WHEN json_type(NEW.`metadata`, '$.secrets') = 'array' THEN NEW.`metadata` END END, '$.secrets') AS one
     WHERE true
    ON CONFLICT (`principal`, `key`) DO UPDATE SET `released_at` = max(`released_at`, excluded.`released_at`);
END;--> statement-breakpoint
INSERT INTO `vault_releases` (`principal`, `key`, `released_at`)
SELECT e.`actor`, coalesce(e.`secret_id`, CASE WHEN one.type = 'object' AND json_type(one.value, '$.secretId') = 'text' THEN json_extract(one.value, '$.secretId') END, 'entry:' || e.`seq`), max(e.`occurred_at`)
  FROM `audit_log` e
  LEFT JOIN json_each(CASE WHEN e.`secret_id` IS NULL AND json_valid(e.`metadata`) THEN CASE WHEN json_type(e.`metadata`, '$.secrets') = 'array' THEN e.`metadata` END END, '$.secrets') AS one
 WHERE e.`author` = 'vault' AND e.`action` = 'secret.read' AND e.`decision` = 'allow'
 GROUP BY 1, 2;
