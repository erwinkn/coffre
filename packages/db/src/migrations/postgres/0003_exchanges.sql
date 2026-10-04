CREATE TABLE "consumed_tokens" (
	"hash" "bytea" PRIMARY KEY NOT NULL,
	"consumed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "consumed_tokens_hash_check" CHECK (octet_length("consumed_tokens"."hash") = 32)
);
--> statement-breakpoint
CREATE INDEX "audit_log_exchange_idx" ON "audit_log" USING btree ((("metadata")::jsonb ->> 'credentialId')) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" = 'token.exchange' AND "audit_log"."decision" = 'allow';--> statement-breakpoint
-- The app records each token it exchanges, and reads whether one was; it
-- never changes or deletes a record, so a token stays spent.
GRANT SELECT, INSERT ON consumed_tokens TO coffre_app;
