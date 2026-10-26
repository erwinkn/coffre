-- Releases (W199): each key the vault released to a principal, and when last, so that its bulk limit counts the keys released within a window from a row per key, not from every read the principal ever made. The database keeps it, from each vault `secret.read` allowed, in the append's own transaction; the release before neither reads it nor knows it is kept, and its appends keep it too.
CREATE TABLE "vault_releases" (
	"principal" text NOT NULL,
	"key" text NOT NULL,
	"released_at" bigint NOT NULL,
	CONSTRAINT "vault_releases_pkey" PRIMARY KEY("principal","key")
);
--> statement-breakpoint
-- Room in each page for the next version of its rows: a read moves its keys' times on in place (a HOT update), so the
-- table and its key stay a row a key, however often each is read, between vacuums.
ALTER TABLE vault_releases SET (fillfactor = 50);--> statement-breakpoint
-- Each key the entry names, as the count read them before: the secret, or each item of a read's list at one place, or, for an entry that names none, which only a forged one is, the entry itself. As the owner, so that no login may write the table: the vault's appends reach it only through the log.
CREATE FUNCTION vault_releases_keep() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO public.vault_releases AS kept (principal, key, released_at)
    SELECT DISTINCT NEW.actor, coalesce(NEW.secret_id::text, CASE jsonb_typeof(one -> 'secretId') WHEN 'string' THEN one ->> 'secretId' END, 'entry:' || NEW.seq), NEW.occurred_at
      FROM (SELECT) AS entry
      LEFT JOIN LATERAL jsonb_path_query(CASE WHEN NEW.secret_id IS NULL THEN NEW.metadata::jsonb END, 'strict $.secrets ? (@.type() == "array")[*]', '{}', true) AS one ON true
    ON CONFLICT (principal, key) DO UPDATE SET released_at = greatest(kept.released_at, excluded.released_at);
    RETURN NULL;
END
$$;--> statement-breakpoint
-- A trigger runs its function whoever may execute it: no login may call it otherwise.
REVOKE ALL ON FUNCTION vault_releases_keep() FROM PUBLIC;--> statement-breakpoint
CREATE TRIGGER audit_log_releases AFTER INSERT ON audit_log FOR EACH ROW
    WHEN (NEW.author = 'vault' AND NEW.action = 'secret.read' AND NEW.decision = 'allow')
    EXECUTE FUNCTION vault_releases_keep();--> statement-breakpoint
-- Then the releases already in the log, in the same transaction: an append waits from the trigger to the commit, and none is missed.
INSERT INTO vault_releases (principal, key, released_at)
SELECT e.actor, coalesce(e.secret_id::text, CASE jsonb_typeof(one -> 'secretId') WHEN 'string' THEN one ->> 'secretId' END, 'entry:' || e.seq), max(e.occurred_at)
  FROM audit_log e
  LEFT JOIN LATERAL jsonb_path_query(CASE WHEN e.secret_id IS NULL THEN e.metadata::jsonb END, 'strict $.secrets ? (@.type() == "array")[*]', '{}', true) AS one ON true
 WHERE e.author = 'vault' AND e.action = 'secret.read' AND e.decision = 'allow'
 GROUP BY 1, 2;--> statement-breakpoint
GRANT SELECT ON vault_releases TO coffre_vault, coffre_backup;
