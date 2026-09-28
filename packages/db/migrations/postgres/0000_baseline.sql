CREATE TABLE "audit_chain_head" (
	"only_row" boolean PRIMARY KEY DEFAULT true NOT NULL,
	"next_seq" bigint DEFAULT 0 NOT NULL,
	"head_hash" "bytea" NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "audit_chain_head_only_row_check" CHECK ("audit_chain_head"."only_row"),
	CONSTRAINT "audit_chain_head_head_hash_check" CHECK (octet_length("audit_chain_head"."head_hash") = 32)
);
--> statement-breakpoint
CREATE TABLE "audit_checkpoints" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"seq" bigint NOT NULL,
	"head_hash" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"exported_at" timestamp with time zone,
	"export_target" text,
	CONSTRAINT "audit_checkpoints_head_hash_check" CHECK (octet_length("audit_checkpoints"."head_hash") = 32)
);
--> statement-breakpoint
CREATE TABLE "audit_heartbeat" (
	"only_row" boolean PRIMARY KEY DEFAULT true NOT NULL,
	"last_beat_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seq" bigint DEFAULT 0 NOT NULL,
	CONSTRAINT "audit_heartbeat_only_row_check" CHECK ("audit_heartbeat"."only_row")
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"seq" bigint PRIMARY KEY NOT NULL,
	"id" uuid DEFAULT gen_random_uuid() NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_type" text NOT NULL,
	"actor_id" text NOT NULL,
	"action" text NOT NULL,
	"decision" text NOT NULL,
	"project_id" uuid,
	"environment_id" uuid,
	"secret_id" uuid,
	"bundle_id" uuid,
	"request_id" text,
	"source_ip" text,
	"metadata" text DEFAULT '{}' NOT NULL,
	"prev_hash" "bytea" NOT NULL,
	"hash" "bytea" NOT NULL,
	CONSTRAINT "audit_log_id_key" UNIQUE("id"),
	CONSTRAINT "audit_log_actor_type_check" CHECK ("audit_log"."actor_type" IN ('user', 'service', 'system')),
	CONSTRAINT "audit_log_decision_check" CHECK ("audit_log"."decision" IN ('allow', 'deny')),
	CONSTRAINT "audit_log_metadata_check" CHECK ("audit_log"."metadata"::jsonb IS NOT NULL),
	CONSTRAINT "audit_log_prev_hash_check" CHECK (octet_length("audit_log"."prev_hash") = 32),
	CONSTRAINT "audit_log_hash_check" CHECK (octet_length("audit_log"."hash") = 32)
);
--> statement-breakpoint
CREATE TABLE "environments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_id" uuid NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"archived_at" timestamp with time zone,
	CONSTRAINT "environments_project_id_slug_key" UNIQUE("project_id","slug"),
	CONSTRAINT "environments_project_scoped" UNIQUE("id","project_id"),
	CONSTRAINT "environments_slug_check" CHECK ("environments"."slug" ~ '^[a-z0-9][a-z0-9-]{0,62}$')
);
--> statement-breakpoint
CREATE TABLE "grants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"principal_type" text NOT NULL,
	"principal_id" text NOT NULL,
	"environment_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"project_id" uuid,
	"role_id" uuid NOT NULL,
	"expires_at" timestamp with time zone,
	CONSTRAINT "grants_principal_type_check" CHECK ("grants"."principal_type" IN ('user', 'service')),
	CONSTRAINT "grants_exactly_one_scope" CHECK (("grants"."project_id" IS NULL) <> ("grants"."environment_id" IS NULL))
);
--> statement-breakpoint
CREATE TABLE "permissions" (
	"slug" text PRIMARY KEY NOT NULL,
	"description" text NOT NULL,
	"min_scope" text NOT NULL,
	CONSTRAINT "permissions_min_scope_check" CHECK ("permissions"."min_scope" IN ('environment', 'project'))
);
--> statement-breakpoint
CREATE TABLE "principals" (
	"principal_type" text NOT NULL,
	"principal_id" text NOT NULL,
	"instance_role" text DEFAULT 'user' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	CONSTRAINT "principals_pkey" PRIMARY KEY("principal_type","principal_id"),
	CONSTRAINT "principals_principal_type_check" CHECK ("principals"."principal_type" IN ('user', 'service')),
	CONSTRAINT "principals_instance_role_check" CHECK ("principals"."instance_role" IN ('user', 'owner')),
	CONSTRAINT "principals_service_role_check" CHECK ("principals"."principal_type" = 'user' OR "principals"."instance_role" = 'user')
);
--> statement-breakpoint
CREATE TABLE "projects" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"archived_at" timestamp with time zone,
	CONSTRAINT "projects_slug_key" UNIQUE("slug"),
	CONSTRAINT "projects_slug_check" CHECK ("projects"."slug" ~ '^[a-z0-9][a-z0-9-]{0,62}$')
);
--> statement-breakpoint
CREATE TABLE "role_permissions" (
	"role_id" uuid NOT NULL,
	"permission" text NOT NULL,
	CONSTRAINT "role_permissions_pkey" PRIMARY KEY("role_id","permission")
);
--> statement-breakpoint
CREATE TABLE "roles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"is_builtin" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "roles_slug_key" UNIQUE("slug"),
	CONSTRAINT "roles_slug_check" CHECK ("roles"."slug" ~ '^[a-z0-9][a-z0-9-]{0,62}$')
);
--> statement-breakpoint
CREATE TABLE "secret_versions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"secret_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"envelope_version" integer NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"iv" "bytea" NOT NULL,
	"auth_tag" "bytea" NOT NULL,
	"wrapped_dek" "bytea" NOT NULL,
	"kek_provider" text NOT NULL,
	"kek_id" text NOT NULL,
	"kek_version" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	CONSTRAINT "secret_versions_secret_id_version_key" UNIQUE("secret_id","version"),
	CONSTRAINT "secret_versions_version_check" CHECK ("secret_versions"."version" > 0),
	CONSTRAINT "secret_versions_iv_check" CHECK (octet_length("secret_versions"."iv") = 12),
	CONSTRAINT "secret_versions_auth_tag_check" CHECK (octet_length("secret_versions"."auth_tag") = 16)
);
--> statement-breakpoint
CREATE TABLE "secrets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_id" uuid NOT NULL,
	"environment_id" uuid NOT NULL,
	"key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"current_version_id" uuid,
	"archived_at" timestamp with time zone,
	CONSTRAINT "secrets_project_id_environment_id_key_key" UNIQUE("project_id","environment_id","key"),
	CONSTRAINT "secrets_key_check" CHECK ("secrets"."key" ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$')
);
--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_environment_id_fkey" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_secret_id_fkey" FOREIGN KEY ("secret_id") REFERENCES "public"."secrets"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_principal_fkey" FOREIGN KEY ("principal_type","principal_id") REFERENCES "public"."principals"("principal_type","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_environment_id_fkey" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "grants" ADD CONSTRAINT "grants_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_permission_fkey" FOREIGN KEY ("permission") REFERENCES "public"."permissions"("slug") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret_versions" ADD CONSTRAINT "secret_versions_secret_id_fkey" FOREIGN KEY ("secret_id") REFERENCES "public"."secrets"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_current_version_id_secret_versions_id_fk" FOREIGN KEY ("current_version_id") REFERENCES "public"."secret_versions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_environment_id_fkey" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_environment_in_project" FOREIGN KEY ("environment_id","project_id") REFERENCES "public"."environments"("id","project_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_log_occurred_idx" ON "audit_log" USING btree ("occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_log_actor_idx" ON "audit_log" USING btree ("actor_type","actor_id","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_log_secret_idx" ON "audit_log" USING btree ("secret_id","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_log_environment_idx" ON "audit_log" USING btree ("environment_id","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_log_bundle_idx" ON "audit_log" USING btree ("bundle_id") WHERE "audit_log"."bundle_id" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "environments_active_idx" ON "environments" USING btree ("project_id","slug") WHERE "environments"."archived_at" IS NULL;--> statement-breakpoint
CREATE INDEX "grants_lookup_idx" ON "grants" USING btree ("principal_type","principal_id","environment_id");--> statement-breakpoint
CREATE UNIQUE INDEX "grants_environment_unique" ON "grants" USING btree ("principal_type","principal_id","environment_id","role_id") WHERE "grants"."environment_id" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "grants_project_unique" ON "grants" USING btree ("principal_type","principal_id","project_id","role_id") WHERE "grants"."project_id" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "grants_project_lookup_idx" ON "grants" USING btree ("principal_type","principal_id","project_id") WHERE "grants"."project_id" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "projects_active_idx" ON "projects" USING btree ("slug") WHERE "projects"."archived_at" IS NULL;--> statement-breakpoint
CREATE INDEX "secret_versions_secret_idx" ON "secret_versions" USING btree ("secret_id","version" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "secrets_lookup_idx" ON "secrets" USING btree ("project_id","environment_id","key");--> statement-breakpoint
CREATE INDEX "secrets_active_idx" ON "secrets" USING btree ("project_id","environment_id","key") WHERE "secrets"."archived_at" IS NULL;