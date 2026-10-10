ALTER TABLE "vault_members" ADD COLUMN "role" text;--> statement-breakpoint
ALTER TABLE "vault_members" ADD COLUMN "scope" text;--> statement-breakpoint
-- The vault sets a person's instance role and its scope, as it sets the rest of their row.
GRANT UPDATE (role, scope) ON vault_members TO coffre_vault;
