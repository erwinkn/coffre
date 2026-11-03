-- Passkeys (0.16, T176; docs/design/passkeys.md, section 5; sqlite 0032_passkeys): a person's WebAuthn credentials, a second factor after the provider's sign-in, and the column on each sign-in row that names the passkey behind it. It only adds: the previous release reads none of it. The constraints on the three existing tables are NOT VALID, as 0022's seals were: their columns are null on every row, so there is nothing to scan for, and each takes its table's lock for a moment only; rows written from now on are checked. The app reads and writes passkeys; it updates only what changes in place (the counter, the replay mark, the name, last use, removal and the MAC), never whose a passkey is or its key; nobody deletes one. The vault's logins get nothing: they never read a passkey.
CREATE TABLE "passkeys" (
	"id" uuid PRIMARY KEY NOT NULL,
	"auth_mac" "bytea" NOT NULL,
	"principal" text NOT NULL,
	"generation" integer NOT NULL,
	"user_handle" "bytea" NOT NULL,
	"credential_id" "bytea" NOT NULL,
	"public_key" "bytea" NOT NULL,
	"algorithm" integer NOT NULL,
	"sign_count" bigint DEFAULT 0 NOT NULL,
	"last_challenge_at" timestamp with time zone,
	"transports" text DEFAULT '[]' NOT NULL,
	"aaguid" "bytea",
	"synced" boolean NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"last_used_at" timestamp with time zone,
	"removed_at" timestamp with time zone,
	"removed_by" text,
	CONSTRAINT "passkeys_credential_id_key" UNIQUE("credential_id"),
	CONSTRAINT "passkeys_auth_mac_check" CHECK (octet_length("passkeys"."auth_mac") = 32),
	CONSTRAINT "passkeys_principal_check" CHECK ("passkeys"."principal" LIKE 'user:%'),
	CONSTRAINT "passkeys_user_handle_check" CHECK (octet_length("passkeys"."user_handle") = 16),
	CONSTRAINT "passkeys_credential_id_check" CHECK (octet_length("passkeys"."credential_id") BETWEEN 16 AND 1023),
	CONSTRAINT "passkeys_algorithm_check" CHECK ("passkeys"."algorithm" IN (-8, -7, -257)),
	CONSTRAINT "passkeys_sign_count_check" CHECK ("passkeys"."sign_count" BETWEEN 0 AND 4294967295),
	CONSTRAINT "passkeys_transports_check" CHECK (jsonb_typeof("passkeys"."transports"::jsonb) = 'array'),
	CONSTRAINT "passkeys_aaguid_check" CHECK ("passkeys"."aaguid" IS NULL OR octet_length("passkeys"."aaguid") = 16),
	CONSTRAINT "passkeys_name_check" CHECK (char_length("passkeys"."name") BETWEEN 1 AND 64),
	CONSTRAINT "passkeys_removed_check" CHECK (("passkeys"."removed_at" IS NULL) = ("passkeys"."removed_by" IS NULL))
);
--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "passkey_id" uuid;--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN "confirmed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "device_authorizations" ADD COLUMN "passkey_id" uuid;--> statement-breakpoint
ALTER TABLE "mcp_connections" ADD COLUMN "passkey_id" uuid;--> statement-breakpoint
ALTER TABLE "passkeys" ADD CONSTRAINT "passkeys_principal_fkey" FOREIGN KEY ("principal") REFERENCES "public"."vault_members"("principal") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "passkeys_live_idx" ON "passkeys" USING btree ("principal","generation") WHERE "passkeys"."removed_at" IS NULL;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_passkey_id_fkey" FOREIGN KEY ("passkey_id") REFERENCES "public"."passkeys"("id") ON DELETE restrict ON UPDATE no action NOT VALID;--> statement-breakpoint
ALTER TABLE "device_authorizations" ADD CONSTRAINT "device_authorizations_passkey_id_fkey" FOREIGN KEY ("passkey_id") REFERENCES "public"."passkeys"("id") ON DELETE restrict ON UPDATE no action NOT VALID;--> statement-breakpoint
ALTER TABLE "mcp_connections" ADD CONSTRAINT "mcp_connections_passkey_id_fkey" FOREIGN KEY ("passkey_id") REFERENCES "public"."passkeys"("id") ON DELETE restrict ON UPDATE no action NOT VALID;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_confirmed_check" CHECK ("credentials"."confirmed_at" IS NULL OR "credentials"."passkey_id" IS NOT NULL) NOT VALID;--> statement-breakpoint
ALTER TABLE "device_authorizations" ADD CONSTRAINT "device_authorizations_passkey_check" CHECK ("device_authorizations"."passkey_id" IS NULL OR "device_authorizations"."decision" = 'approved') NOT VALID;--> statement-breakpoint
GRANT SELECT, INSERT ON passkeys TO coffre_app;--> statement-breakpoint
GRANT UPDATE (sign_count, last_challenge_at, name, last_used_at, removed_at, removed_by, auth_mac) ON passkeys TO coffre_app;--> statement-breakpoint
-- A device login names the passkey that approved it when it is decided, as it names its person.
GRANT UPDATE (passkey_id) ON device_authorizations TO coffre_app;--> statement-breakpoint
GRANT SELECT ON passkeys TO coffre_backup;
