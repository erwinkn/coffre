-- Roles an Owner makes (0.10): a grant names a role by its id, which the vault's policy defines; which of them an environment may be granted, the vault decides. The checks widen: the release before grants only the roles it ships.
PRAGMA foreign_keys=OFF;--> statement-breakpoint
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
	CONSTRAINT "vault_grants_role_check" CHECK(length("__new_vault_grants"."role") BETWEEN 2 AND 32 AND "__new_vault_grants"."role" GLOB '[a-z]*' AND "__new_vault_grants"."role" NOT GLOB '*[^a-z0-9-]*')
);
--> statement-breakpoint
INSERT INTO `__new_vault_grants`("principal", "project_id", "environment_id", "environment_slug", "role", "expires_at", "granted_at", "granted_by") SELECT "principal", "project_id", "environment_id", "environment_slug", "role", "expires_at", "granted_at", "granted_by" FROM `vault_grants`;--> statement-breakpoint
DROP TABLE `vault_grants`;--> statement-breakpoint
ALTER TABLE `__new_vault_grants` RENAME TO `vault_grants`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE UNIQUE INDEX `vault_grants_on_every_project` ON `vault_grants` (`principal`) WHERE "vault_grants"."project_id" IS NULL AND "vault_grants"."environment_id" IS NULL AND "vault_grants"."environment_slug" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `vault_grants_on_project` ON `vault_grants` (`principal`,`project_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `vault_grants_on_environment` ON `vault_grants` (`principal`,`environment_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `vault_grants_on_environment_slug` ON `vault_grants` (`principal`,`environment_slug`);