-- 0.16, T178: the policy out of `log_config`, its bulk cap typed (postgres/0074_policy_table.sql). `log_config`'s row
-- stays, written beside it, one release.
CREATE TABLE `policy` (
	`name` text PRIMARY KEY NOT NULL,
	`bulk_count` integer NOT NULL,
	`bulk_window_ms` integer NOT NULL,
	`seal` blob NOT NULL,
	CONSTRAINT "policy_name_check" CHECK("policy"."name" = 'instance'),
	CONSTRAINT "policy_bulk_count_check" CHECK("policy"."bulk_count" >= 1),
	CONSTRAINT "policy_bulk_window_ms_check" CHECK("policy"."bulk_window_ms" > 0 AND "policy"."bulk_window_ms" <= 86400000),
	CONSTRAINT "policy_seal_check" CHECK(octet_length("policy"."seal") = 16)
);
--> statement-breakpoint
-- The row from `log_config`'s, when that one is a policy these columns hold, sealed: a writer's is left out.
INSERT INTO `policy` (`name`, `bulk_count`, `bulk_window_ms`, `seal`)
SELECT 'instance', json_extract(g.`value`, '$.bulk.count'), json_extract(g.`value`, '$.bulk.windowMs'), g.`seal`
  FROM `log_config` g
 WHERE g.`name` = 'policy' AND octet_length(g.`seal`) = 16
   AND json_type(g.`value`, '$.bulk.count') = 'integer' AND json_type(g.`value`, '$.bulk.windowMs') = 'integer'
   AND json_extract(g.`value`, '$.bulk.count') >= 1
   AND json_extract(g.`value`, '$.bulk.windowMs') > 0 AND json_extract(g.`value`, '$.bulk.windowMs') <= 86400000
   AND json(g.`value`) = json_object('kind', 'policy', 'bulk', json_object('count', json_extract(g.`value`, '$.bulk.count'), 'windowMs', json_extract(g.`value`, '$.bulk.windowMs')));
