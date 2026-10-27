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
-- The verifier's kept replays (plan PR 8), written as the rest of 0.15's log is, through a function of the owner's: the
-- vault's login reads log_replays and writes none of it itself (conformance's logins check holds each release to it).
-- One call keeps a row at its pair and forgets what is done with: a row with a verdict replaces the one at its pair, a
-- stretch's never does; then the rows the walk found were not the vault's (p_forged), the stretch it went on from
-- (p_done), and any other older than ten minutes, but never the newest verdict nor the newest replay. Within bounded
-- lock waits: a row a writer holds locked fails the keep rather than hanging the checkpoint job.
CREATE FUNCTION keep_replay(
    p_upto bigint, p_at bigint, p_state text, p_state_hash bytea, p_verdict text, p_mac bytea, p_forged bigint[], p_done bigint[]
) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '5s' SET statement_timeout = '30s' AS $$
DECLARE
    newest_verdict bigint;
    newest_state bigint;
BEGIN
    DELETE FROM public.log_replays
     WHERE upto = ANY (coalesce(p_forged, '{}'::bigint[]) || CASE WHEN p_verdict IS NULL THEN '{}'::bigint[] ELSE ARRAY[p_upto] END);
    INSERT INTO public.log_replays (upto, at, state, state_hash, verdict, mac)
    VALUES (p_upto, p_at, p_state, p_state_hash, p_verdict, p_mac)
    ON CONFLICT (upto) DO NOTHING;
    SELECT max(upto) INTO newest_verdict FROM public.log_replays WHERE verdict IS NOT NULL;
    SELECT max(upto) INTO newest_state FROM public.log_replays WHERE state_hash IS NOT NULL;
    DELETE FROM public.log_replays k
     WHERE k.upto <> p_upto AND k.upto IS DISTINCT FROM newest_verdict AND k.upto IS DISTINCT FROM newest_state
       AND (k.upto = ANY (coalesce(p_done, '{}'::bigint[])) OR (k.upto < p_upto AND k.at < p_at - 600000));
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION keep_replay(bigint, bigint, text, bytea, text, bytea, bigint[], bigint[]) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION keep_replay(bigint, bigint, text, bytea, text, bytea, bigint[], bigint[]) TO coffre_vault;
--> statement-breakpoint
GRANT SELECT ON log_replays TO coffre_vault, coffre_backup;
--> statement-breakpoint
-- For the verifier's row audit, every input row held to the replay: the columns the credentials' and the bindings'
-- objects are made of, and the references' sources, which the vault read only through use_credential and change_input
-- before. Never a token's hash or MAC.
GRANT SELECT (id, principal, kind, scope, revoked_at, expires_at, not_after, seal) ON credentials TO coffre_vault;
--> statement-breakpoint
GRANT SELECT (id, seal) ON service_bindings TO coffre_vault;
--> statement-breakpoint
GRANT SELECT (secret_id, source_secret_id, created_seq) ON secret_references TO coffre_vault;
