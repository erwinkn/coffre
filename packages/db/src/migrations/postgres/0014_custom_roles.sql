-- Roles an Owner makes (0.10): a grant names a role by its id, which the vault's policy defines; which of them an environment may be granted, the vault decides. The checks widen: the release before grants only the roles it ships.
ALTER TABLE "vault_grants" DROP CONSTRAINT "vault_grants_environment_role_check";--> statement-breakpoint
ALTER TABLE "vault_grants" DROP CONSTRAINT "vault_grants_role_check";--> statement-breakpoint
ALTER TABLE "vault_grants" ADD CONSTRAINT "vault_grants_role_check" CHECK ("vault_grants"."role" ~ '^[a-z][a-z0-9-]{1,31}$');