CREATE TABLE "log_replays" (
	"upto" bigint PRIMARY KEY NOT NULL,
	"at" bigint NOT NULL,
	"state" text,
	"state_hash" "bytea",
	"verdict" text,
	"mac" "bytea" NOT NULL,
	CONSTRAINT "log_replays_mac_check" CHECK (octet_length("log_replays"."mac") = 32),
	CONSTRAINT "log_replays_state_check" CHECK (("log_replays"."state" IS NULL) = ("log_replays"."state_hash" IS NULL) AND ("log_replays"."state_hash" IS NULL OR octet_length("log_replays"."state_hash") = 32))
);
--> statement-breakpoint
-- The verifier's replay (plan PR 8): the vault keeps it, the backup copies it. The vault also reads, for its row
-- audit, the credentials' and the bindings' columns their objects are made of, and the references' sources: every
-- input row must be the replay's, and it read these only through use_credential and change_input before.
GRANT SELECT, INSERT, DELETE ON log_replays TO coffre_vault;
--> statement-breakpoint
GRANT SELECT ON log_replays TO coffre_backup;
--> statement-breakpoint
GRANT SELECT (id, principal, kind, scope, revoked_at, expires_at, not_after, seal) ON credentials TO coffre_vault;
--> statement-breakpoint
GRANT SELECT (id, seal) ON service_bindings TO coffre_vault;
--> statement-breakpoint
GRANT SELECT (secret_id, source_secret_id, created_seq) ON secret_references TO coffre_vault;
