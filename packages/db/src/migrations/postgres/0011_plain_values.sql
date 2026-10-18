-- Plain values (0.9): a version of a key marked not secret holds its value in the clear too. Nullable, so the release before writes on as it did.
ALTER TABLE "secret_versions" ADD COLUMN "plaintext" text;--> statement-breakpoint
-- A version is still only ever erased, and an erased one holds no value, in the clear or not.
CREATE OR REPLACE FUNCTION secret_versions_erase_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF octet_length(NEW.ciphertext) <> 0 OR octet_length(NEW.wrapped_dek) <> 0 OR NEW.plaintext IS NOT NULL
       OR (NEW.id, NEW.secret_id, NEW.version, NEW.envelope_version, NEW.iv, NEW.auth_tag,
           NEW.kek_provider, NEW.kek_id, NEW.kek_version, NEW.created_at, NEW.created_by,
           NEW.recipe, NEW.pair_id, NEW.pair_half)
          IS DISTINCT FROM
          (OLD.id, OLD.secret_id, OLD.version, OLD.envelope_version, OLD.iv, OLD.auth_tag,
           OLD.kek_provider, OLD.kek_id, OLD.kek_version, OLD.created_at, OLD.created_by,
           OLD.recipe, OLD.pair_id, OLD.pair_half) THEN
        RAISE EXCEPTION 'a secret version is only ever erased' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;--> statement-breakpoint
GRANT UPDATE (plaintext) ON secret_versions TO coffre_app;
