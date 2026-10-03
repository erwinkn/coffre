CREATE TABLE "service_bindings" (
	"id" uuid PRIMARY KEY NOT NULL,
	"auth_mac" "bytea" NOT NULL,
	"principal" text NOT NULL,
	"generation" integer NOT NULL,
	"profile" text NOT NULL,
	"issuer" text NOT NULL,
	"jwks_uri" text NOT NULL,
	"claims" text NOT NULL,
	"label" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoked_by" text,
	CONSTRAINT "service_bindings_principal_check" CHECK ("service_bindings"."principal" LIKE 'token:%'),
	CONSTRAINT "service_bindings_auth_mac_check" CHECK (octet_length("service_bindings"."auth_mac") = 32),
	CONSTRAINT "service_bindings_claims_check" CHECK ("service_bindings"."claims"::jsonb IS NOT NULL)
);
--> statement-breakpoint
ALTER TABLE "service_bindings" ADD CONSTRAINT "service_bindings_principal_fkey" FOREIGN KEY ("principal") REFERENCES "public"."vault_members"("principal") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "service_bindings_principal_idx" ON "service_bindings" USING btree ("principal","issuer");--> statement-breakpoint
CREATE INDEX "audit_log_unbind_idx" ON "audit_log" USING btree ((("metadata")::jsonb ->> 'bindingId')) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" = 'token.unbind' AND "audit_log"."decision" = 'allow';--> statement-breakpoint
-- The app reads and adds bindings, and changes only what the MAC allows to
-- change in place: its label, its last use, and its revocation (with the
-- MAC that covers it). A binding's policy is never updated, nor deleted.
GRANT SELECT, INSERT ON service_bindings TO coffre_app;--> statement-breakpoint
GRANT UPDATE (label, last_used_at, revoked_at, revoked_by, auth_mac) ON service_bindings TO coffre_app;
