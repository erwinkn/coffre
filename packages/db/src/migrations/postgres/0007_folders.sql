CREATE TABLE "project_folders" (
	"project_id" uuid PRIMARY KEY NOT NULL,
	"folder" text,
	"moved_at" timestamp with time zone DEFAULT now() NOT NULL,
	"moved_by" text NOT NULL,
	CONSTRAINT "project_folders_folder_check" CHECK ("project_folders"."folder" IS NULL OR (char_length("project_folders"."folder") BETWEEN 1 AND 64 AND "project_folders"."folder" !~ '[/[:cntrl:]]' AND "project_folders"."folder" = btrim("project_folders"."folder")))
);
--> statement-breakpoint
CREATE TABLE "secret_folders" (
	"secret_id" uuid PRIMARY KEY NOT NULL,
	"folder" text,
	"moved_at" timestamp with time zone DEFAULT now() NOT NULL,
	"moved_by" text NOT NULL,
	CONSTRAINT "secret_folders_folder_check" CHECK ("secret_folders"."folder" IS NULL OR (char_length("secret_folders"."folder") BETWEEN 1 AND 64 AND "secret_folders"."folder" !~ '[/[:cntrl:]]' AND "secret_folders"."folder" = btrim("secret_folders"."folder")))
);
--> statement-breakpoint
ALTER TABLE "project_folders" ADD CONSTRAINT "project_folders_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret_folders" ADD CONSTRAINT "secret_folders_secret_id_fkey" FOREIGN KEY ("secret_id") REFERENCES "public"."secrets"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
-- The app files projects and secrets, and moves them; a row is never deleted:
-- out of every folder is a null folder. The vault decides nothing by folders.
GRANT SELECT, INSERT, UPDATE (folder, moved_at, moved_by) ON project_folders, secret_folders TO coffre_app;
