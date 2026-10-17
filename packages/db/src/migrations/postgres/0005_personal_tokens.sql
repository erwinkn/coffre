-- Personal tokens (0.7). The check widens to their kind: the release before makes none, and refuses one, whose prefix, coffre_pat_, it does not take for a token.
ALTER TABLE "credentials" DROP CONSTRAINT "credentials_kind_check";--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_kind_check" CHECK ("credentials"."kind" IN ('browser', 'cli', 'service', 'personal'));--> statement-breakpoint
-- A token's creation, by the credential's ID: the label a personal token's entries are shown with.
CREATE INDEX "audit_log_token_create_idx" ON "audit_log" USING btree ((("metadata")::jsonb ->> 'targetCredentialId')) WHERE "audit_log"."author" = 'app' AND "audit_log"."action" = 'token.create' AND "audit_log"."decision" = 'allow';
