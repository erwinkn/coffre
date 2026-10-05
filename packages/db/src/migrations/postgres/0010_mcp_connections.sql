CREATE TABLE "mcp_connections" (
	"id" uuid PRIMARY KEY NOT NULL,
	"auth_mac" "bytea" NOT NULL,
	"principal" text NOT NULL,
	"generation" integer NOT NULL,
	"client_id" text NOT NULL,
	"client_name" text NOT NULL,
	"client_host" text,
	"registration" text NOT NULL,
	"scopes" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"code_hash" "bytea",
	"code_challenge" text,
	"code_expires_at" timestamp with time zone,
	"refresh_hash" "bytea",
	"refresh_previous_hash" "bytea",
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"last_used_ip" text,
	"revoked_at" timestamp with time zone,
	"revoked_by" text,
	CONSTRAINT "mcp_connections_code_hash_key" UNIQUE("code_hash"),
	CONSTRAINT "mcp_connections_refresh_hash_key" UNIQUE("refresh_hash"),
	CONSTRAINT "mcp_connections_principal_check" CHECK ("mcp_connections"."principal" LIKE 'user:%'),
	CONSTRAINT "mcp_connections_registration_check" CHECK ("mcp_connections"."registration" IN ('cimd', 'dcr')),
	CONSTRAINT "mcp_connections_auth_mac_check" CHECK (octet_length("mcp_connections"."auth_mac") = 32),
	CONSTRAINT "mcp_connections_code_hash_check" CHECK ("mcp_connections"."code_hash" IS NULL OR octet_length("mcp_connections"."code_hash") = 32),
	CONSTRAINT "mcp_connections_refresh_hash_check" CHECK ("mcp_connections"."refresh_hash" IS NULL OR octet_length("mcp_connections"."refresh_hash") = 32)
);
--> statement-breakpoint
CREATE TABLE "oauth_clients" (
	"id" uuid PRIMARY KEY NOT NULL,
	"auth_mac" "bytea" NOT NULL,
	"name" text NOT NULL,
	"redirect_uris" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_ip" text,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "oauth_clients_auth_mac_check" CHECK (octet_length("oauth_clients"."auth_mac") = 32),
	CONSTRAINT "oauth_clients_redirect_uris_check" CHECK ("oauth_clients"."redirect_uris"::jsonb IS NOT NULL)
);
--> statement-breakpoint
ALTER TABLE "mcp_connections" ADD CONSTRAINT "mcp_connections_principal_fkey" FOREIGN KEY ("principal") REFERENCES "public"."vault_members"("principal") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "mcp_connections_refresh_previous_idx" ON "mcp_connections" USING btree ("refresh_previous_hash");--> statement-breakpoint
CREATE INDEX "mcp_connections_live_idx" ON "mcp_connections" USING btree ("principal","expires_at") WHERE "mcp_connections"."revoked_at" IS NULL;--> statement-breakpoint
-- The app reads and adds registered clients, and only ever revokes one,
-- with the MAC that covers it: a client's redirects never change.
GRANT SELECT, INSERT ON oauth_clients TO coffre_app;--> statement-breakpoint
GRANT UPDATE (revoked_at, auth_mac) ON oauth_clients TO coffre_app;--> statement-breakpoint
-- A connection's person, client, scopes, redirect and lifetime are what was
-- approved: never updated. Its code is redeemed, its refresh token rotated,
-- its use noted and its revocation written, each with the MAC; nothing is
-- deleted.
GRANT SELECT, INSERT ON mcp_connections TO coffre_app;--> statement-breakpoint
GRANT UPDATE (code_challenge, code_expires_at, refresh_hash, refresh_previous_hash, last_used_at, last_used_ip, revoked_at, revoked_by, auth_mac)
    ON mcp_connections TO coffre_app;
