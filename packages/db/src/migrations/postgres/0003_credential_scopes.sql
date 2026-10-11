ALTER TABLE "credentials" ADD COLUMN "scope" text;--> statement-breakpoint
ALTER TABLE "service_bindings" ADD COLUMN "scope" text;--> statement-breakpoint
-- The app seals each token and binding of 0.4 with its account's grants, once, as it seals the rest of their rows.
GRANT UPDATE (scope) ON credentials, service_bindings TO coffre_app;
