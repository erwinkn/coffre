-- Grants on every project, or on one environment slug in every project
-- (docs/design/instance-grants.md): a column, and the checks loosened to
-- allow a grant with neither id. SQLite changes a check only by building
-- the table again; no table refers to this one.
CREATE TABLE `__new_vault_grants` (
	`principal` text NOT NULL,
	`project_id` text,
	`environment_id` text,
	`environment_slug` text,
	`role` text NOT NULL,
	`expires_at` integer,
	`granted_at` integer NOT NULL,
	`granted_by` text NOT NULL,
	FOREIGN KEY (`principal`) REFERENCES `vault_members`(`principal`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "vault_grants_one_place" CHECK((("__new_vault_grants"."project_id" IS NULL) <> ("__new_vault_grants"."environment_id" IS NULL) AND "__new_vault_grants"."environment_slug" IS NULL) OR ("__new_vault_grants"."project_id" IS NULL AND "__new_vault_grants"."environment_id" IS NULL)),
	CONSTRAINT "vault_grants_environment_slug_check" CHECK("__new_vault_grants"."environment_slug" IS NULL OR (length("__new_vault_grants"."environment_slug") BETWEEN 1 AND 63 AND "__new_vault_grants"."environment_slug" GLOB '[a-z0-9]*' AND "__new_vault_grants"."environment_slug" NOT GLOB '*[^a-z0-9-]*')),
	CONSTRAINT "vault_grants_role_check" CHECK("__new_vault_grants"."role" IN ('viewer', 'developer', 'maintainer', 'access-manager', 'auditor', 'owner')),
	CONSTRAINT "vault_grants_environment_role_check" CHECK(("__new_vault_grants"."environment_id" IS NULL AND "__new_vault_grants"."environment_slug" IS NULL) OR "__new_vault_grants"."role" IN ('viewer', 'developer', 'auditor'))
);
--> statement-breakpoint
INSERT INTO `__new_vault_grants`("principal", "project_id", "environment_id", "role", "expires_at", "granted_at", "granted_by") SELECT "principal", "project_id", "environment_id", "role", "expires_at", "granted_at", "granted_by" FROM `vault_grants`;--> statement-breakpoint
DROP TABLE `vault_grants`;--> statement-breakpoint
ALTER TABLE `__new_vault_grants` RENAME TO `vault_grants`;--> statement-breakpoint
CREATE UNIQUE INDEX `vault_grants_on_every_project` ON `vault_grants` (`principal`) WHERE "vault_grants"."project_id" IS NULL AND "vault_grants"."environment_id" IS NULL AND "vault_grants"."environment_slug" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `vault_grants_on_project` ON `vault_grants` (`principal`,`project_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `vault_grants_on_environment` ON `vault_grants` (`principal`,`environment_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `vault_grants_on_environment_slug` ON `vault_grants` (`principal`,`environment_slug`);