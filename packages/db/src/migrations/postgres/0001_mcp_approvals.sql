CREATE TABLE "mcp_approvals" (
	"id" uuid PRIMARY KEY NOT NULL,
	"connection_id" uuid NOT NULL,
	"tool" text NOT NULL,
	"arguments" text NOT NULL,
	"digest" "bytea" NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"outcome" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"decided_at" timestamp with time zone,
	"reported_at" timestamp with time zone,
	CONSTRAINT "mcp_approvals_status_check" CHECK ("mcp_approvals"."status" IN ('pending', 'approved', 'denied', 'cancelled', 'failed')),
	CONSTRAINT "mcp_approvals_digest_check" CHECK (octet_length("mcp_approvals"."digest") = 32),
	CONSTRAINT "mcp_approvals_arguments_check" CHECK ("mcp_approvals"."arguments"::jsonb IS NOT NULL)
);
--> statement-breakpoint
ALTER TABLE "mcp_approvals" ADD CONSTRAINT "mcp_approvals_connection_fkey" FOREIGN KEY ("connection_id") REFERENCES "public"."mcp_connections"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "mcp_approvals_open_idx" ON "mcp_approvals" USING btree ("connection_id","digest") WHERE "mcp_approvals"."reported_at" IS NULL;--> statement-breakpoint
-- The app asks for approvals and records what became of them: the tool,
-- its arguments, their digest, the connection and the expiry are what the
-- person is shown, and never change. Nothing is deleted.
GRANT SELECT, INSERT ON mcp_approvals TO coffre_app;--> statement-breakpoint
GRANT UPDATE (status, outcome, decided_at, reported_at) ON mcp_approvals TO coffre_app;
