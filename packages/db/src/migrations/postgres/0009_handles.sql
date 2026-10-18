-- Handles (0.8): the stand-ins a person's app holds, which reach only the credential proxy. The check widens to their kind: the release before makes none, and refuses one, whose prefix, coffre_use_, it does not take for a token.
ALTER TABLE "credentials" DROP CONSTRAINT "credentials_kind_check";--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_kind_check" CHECK ("credentials"."kind" IN ('browser', 'cli', 'service', 'personal', 'handle'));
