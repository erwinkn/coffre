-- A deleted project or environment stays, as a tombstone the log's entries
-- name, under a slug no live place can take: `market~deleted-2026-10-05`.
ALTER TABLE "environments" DROP CONSTRAINT "environments_slug_check";--> statement-breakpoint
ALTER TABLE "projects" DROP CONSTRAINT "projects_slug_check";--> statement-breakpoint
ALTER TABLE "environments" ADD CONSTRAINT "environments_slug_check" CHECK ("environments"."slug" ~ '^[a-z0-9][a-z0-9-]{0,62}(~[a-z0-9-]{1,40})?$');--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_slug_check" CHECK ("projects"."slug" ~ '^[a-z0-9][a-z0-9-]{0,62}(~[a-z0-9-]{1,40})?$');--> statement-breakpoint
-- Its versions stay too, and lose what they sealed: the app empties their
-- ciphertext and wrapped data key. That is the one change a version takes,
-- for every login: a value is never rewritten in place, only erased.
CREATE FUNCTION secret_versions_erase_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF octet_length(NEW.ciphertext) <> 0 OR octet_length(NEW.wrapped_dek) <> 0
       OR (NEW.id, NEW.secret_id, NEW.version, NEW.envelope_version, NEW.iv, NEW.auth_tag,
           NEW.kek_provider, NEW.kek_id, NEW.kek_version, NEW.created_at, NEW.created_by)
          IS DISTINCT FROM
          (OLD.id, OLD.secret_id, OLD.version, OLD.envelope_version, OLD.iv, OLD.auth_tag,
           OLD.kek_provider, OLD.kek_id, OLD.kek_version, OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'a secret version is only ever erased' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
--> statement-breakpoint
CREATE TRIGGER secret_versions_erase_only BEFORE UPDATE ON secret_versions
    FOR EACH ROW EXECUTE FUNCTION secret_versions_erase_only();
--> statement-breakpoint
GRANT UPDATE (ciphertext, wrapped_dek) ON secret_versions TO coffre_app;
