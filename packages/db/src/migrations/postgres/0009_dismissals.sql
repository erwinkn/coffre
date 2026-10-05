CREATE TABLE "dismissed_keys" (
	"environment_id" uuid NOT NULL,
	"key" text NOT NULL,
	"dismissed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"dismissed_by" text NOT NULL,
	"restored_at" timestamp with time zone,
	"restored_by" text,
	CONSTRAINT "dismissed_keys_pkey" PRIMARY KEY("environment_id","key"),
	CONSTRAINT "dismissed_keys_key_check" CHECK ("dismissed_keys"."key" ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$')
);
--> statement-breakpoint
ALTER TABLE "dismissed_keys" ADD CONSTRAINT "dismissed_keys_environment_id_fkey" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
-- The app dismisses keys and restores them, in place; it deletes none.
GRANT SELECT, INSERT, UPDATE (dismissed_at, dismissed_by, restored_at, restored_by) ON dismissed_keys TO coffre_app;
