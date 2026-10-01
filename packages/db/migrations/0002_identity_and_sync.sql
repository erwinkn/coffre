CREATE TABLE "credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"kind" text NOT NULL,
	"token_hash" "bytea" NOT NULL,
	"token_hint" text NOT NULL,
	"principal_type" text NOT NULL,
	"principal_id" text NOT NULL,
	"identity_id" uuid,
	"label" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_used_at" timestamp with time zone,
	"last_used_ip" text,
	"revoked_at" timestamp with time zone,
	"revoked_by" text,
	CONSTRAINT "credentials_token_hash_key" UNIQUE("token_hash"),
	CONSTRAINT "credentials_kind_check" CHECK ("credentials"."kind" IN ('browser', 'cli', 'service')),
	CONSTRAINT "credentials_kind_matches_principal" CHECK (("credentials"."kind" = 'service') = ("credentials"."principal_type" = 'service')),
	CONSTRAINT "credentials_token_hash_check" CHECK (octet_length("credentials"."token_hash") = 32)
);
--> statement-breakpoint
CREATE TABLE "device_authorizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"device_code_hash" "bytea" NOT NULL,
	"user_code" text NOT NULL,
	"client_label" text,
	"client_ip" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"decided_at" timestamp with time zone,
	"decision" text,
	"principal_type" text,
	"principal_id" text,
	"consumed_at" timestamp with time zone,
	CONSTRAINT "device_authorizations_device_code_hash_key" UNIQUE("device_code_hash"),
	CONSTRAINT "device_authorizations_user_code_key" UNIQUE("user_code"),
	CONSTRAINT "device_authorizations_decision_check" CHECK ("device_authorizations"."decision" IS NULL OR "device_authorizations"."decision" IN ('approved', 'denied')),
	CONSTRAINT "device_authorizations_approval_names_principal" CHECK (("device_authorizations"."decision" = 'approved') = ("device_authorizations"."principal_id" IS NOT NULL))
);
--> statement-breakpoint
CREATE TABLE "identities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider" text NOT NULL,
	"subject" text NOT NULL,
	"principal_type" text NOT NULL,
	"principal_id" text NOT NULL,
	"email" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"last_sign_in_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoked_by" text,
	CONSTRAINT "identities_principal_type_check" CHECK ("identities"."principal_type" = 'user'),
	CONSTRAINT "identities_provider_check" CHECK ("identities"."provider" ~ '^[a-z0-9][a-z0-9-]{0,31}$')
);
--> statement-breakpoint
CREATE TABLE "sync_keys" (
	"sync_id" uuid NOT NULL,
	"key" text NOT NULL,
	"secret_version_id" uuid,
	"pushed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"removed_at" timestamp with time zone,
	CONSTRAINT "sync_keys_pkey" PRIMARY KEY("sync_id","key")
);
--> statement-breakpoint
CREATE TABLE "syncs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_id" uuid NOT NULL,
	"environment_id" uuid NOT NULL,
	"provider" text NOT NULL,
	"config" text NOT NULL,
	"credential_secret_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"paused_at" timestamp with time zone,
	"archived_at" timestamp with time zone,
	"lease_until" timestamp with time zone,
	"last_run_at" timestamp with time zone,
	"last_status" text,
	"last_error" text,
	CONSTRAINT "syncs_config_check" CHECK ("syncs"."config"::jsonb IS NOT NULL),
	CONSTRAINT "syncs_last_status_check" CHECK ("syncs"."last_status" IS NULL OR "syncs"."last_status" IN ('ok', 'partial', 'failed'))
);
--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_principal_fkey" FOREIGN KEY ("principal_type","principal_id") REFERENCES "public"."principals"("principal_type","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_identity_id_fkey" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_authorizations" ADD CONSTRAINT "device_authorizations_principal_fkey" FOREIGN KEY ("principal_type","principal_id") REFERENCES "public"."principals"("principal_type","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identities" ADD CONSTRAINT "identities_principal_fkey" FOREIGN KEY ("principal_type","principal_id") REFERENCES "public"."principals"("principal_type","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sync_keys" ADD CONSTRAINT "sync_keys_sync_id_fkey" FOREIGN KEY ("sync_id") REFERENCES "public"."syncs"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sync_keys" ADD CONSTRAINT "sync_keys_secret_version_id_fkey" FOREIGN KEY ("secret_version_id") REFERENCES "public"."secret_versions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "syncs" ADD CONSTRAINT "syncs_environment_in_project" FOREIGN KEY ("environment_id","project_id") REFERENCES "public"."environments"("id","project_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "syncs" ADD CONSTRAINT "syncs_credential_secret_id_fkey" FOREIGN KEY ("credential_secret_id") REFERENCES "public"."secrets"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "credentials_principal_idx" ON "credentials" USING btree ("principal_type","principal_id") WHERE "credentials"."revoked_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "identities_active_subject" ON "identities" USING btree ("provider","subject") WHERE "identities"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identities_principal_idx" ON "identities" USING btree ("principal_type","principal_id");--> statement-breakpoint
CREATE INDEX "syncs_environment_idx" ON "syncs" USING btree ("environment_id") WHERE "syncs"."archived_at" IS NULL;--> statement-breakpoint

-- The runtime role gets the same shape of access as in 0001: read and insert,
-- UPDATE on named columns only, and never DELETE. A revoked session, a used
-- device code and a removed sync key are all rows that say so, not gaps.
GRANT SELECT, INSERT ON
    identities,
    credentials,
    device_authorizations,
    syncs,
    sync_keys
TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (email, last_sign_in_at, revoked_at, revoked_by) ON identities TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (last_used_at, last_used_ip, revoked_at, revoked_by) ON credentials TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (decided_at, decision, principal_type, principal_id, consumed_at)
    ON device_authorizations TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (config, credential_secret_id, paused_at, archived_at, lease_until,
              last_run_at, last_status, last_error)
    ON syncs TO coffre_app;
--> statement-breakpoint
GRANT UPDATE (secret_version_id, pushed_at, removed_at) ON sync_keys TO coffre_app;
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON identities, credentials, device_authorizations, syncs, sync_keys
    FROM coffre_app;
