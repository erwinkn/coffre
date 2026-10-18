-- The Contributor role (0.10): use and write, never read. The role checks widen to it, which the release before never grants.
ALTER TABLE "vault_grants" DROP CONSTRAINT "vault_grants_role_check";--> statement-breakpoint
ALTER TABLE "vault_grants" DROP CONSTRAINT "vault_grants_environment_role_check";--> statement-breakpoint
ALTER TABLE "vault_grants" ADD CONSTRAINT "vault_grants_role_check" CHECK ("vault_grants"."role" IN ('viewer', 'contributor', 'developer', 'maintainer', 'access-manager', 'auditor', 'owner'));--> statement-breakpoint
ALTER TABLE "vault_grants" ADD CONSTRAINT "vault_grants_environment_role_check" CHECK (("vault_grants"."environment_id" IS NULL AND "vault_grants"."environment_slug" IS NULL) OR "vault_grants"."role" IN ('viewer', 'contributor', 'developer', 'auditor'));