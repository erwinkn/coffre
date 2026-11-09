-- 0.16, T178: the policy out of `log_config`, its bulk cap typed, and the roles, one row each, made by the vault's start
-- (postgres/0081_roles_policy.sql). `log_config`'s rows stay, written beside them, until 0.18.
CREATE TABLE `roles` (
	`scope` text NOT NULL,
	`name` text NOT NULL,
	`definition` text,
	`seal` blob,
	PRIMARY KEY(`scope`, `name`),
	CONSTRAINT "roles_scope_check" CHECK("roles"."scope" IN ('project', 'instance')),
	CONSTRAINT "roles_name_check" CHECK(length("roles"."name") BETWEEN 2 AND 32 AND "roles"."name" GLOB '[a-z]*' AND "roles"."name" NOT GLOB '*[^a-z0-9-]*'),
	CONSTRAINT "roles_definition_check" CHECK("roles"."definition" IS NULL OR json_type("roles"."definition") = 'object'),
	CONSTRAINT "roles_seal_check" CHECK("roles"."seal" IS NULL OR octet_length("roles"."seal") = 16)
);
--> statement-breakpoint
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
-- Whatever its keys' order: SQLite's `json()` keeps it, and the vault writes them sorted, `bulk` before `kind`
-- (Postgres's jsonb compares objects without it). So the value is an object of exactly two keys, `kind` and
-- `bulk`, and `bulk` one of exactly two, `count` and `windowMs`.
INSERT INTO `policy` (`name`, `bulk_count`, `bulk_window_ms`, `seal`)
SELECT 'instance', json_extract(g.`value`, '$.bulk.count'), json_extract(g.`value`, '$.bulk.windowMs'), g.`seal`
  FROM `log_config` g
 WHERE g.`name` = 'policy' AND octet_length(g.`seal`) = 16
   AND json_type(g.`value`) = 'object' AND (SELECT count(*) FROM json_each(g.`value`)) = 2
   AND json_type(g.`value`, '$.kind') = 'text' AND json_extract(g.`value`, '$.kind') = 'policy'
   AND json_type(g.`value`, '$.bulk') = 'object' AND (SELECT count(*) FROM json_each(g.`value`, '$.bulk')) = 2
   AND json_type(g.`value`, '$.bulk.count') = 'integer' AND json_type(g.`value`, '$.bulk.windowMs') = 'integer'
   AND json_extract(g.`value`, '$.bulk.count') >= 1
   AND json_extract(g.`value`, '$.bulk.windowMs') > 0 AND json_extract(g.`value`, '$.bulk.windowMs') <= 86400000;
