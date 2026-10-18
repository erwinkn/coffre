-- Sensitive values (0.10): a version never handed back to a person, which the vault's wrap of its data key binds. Defaults to false, so the release before writes on as it did.
ALTER TABLE "secret_versions" ADD COLUMN "sensitive" boolean DEFAULT false NOT NULL;--> statement-breakpoint
-- A version is still only ever erased: its sensitivity with the rest of it.
CREATE OR REPLACE FUNCTION secret_versions_erase_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF octet_length(NEW.ciphertext) <> 0 OR octet_length(NEW.wrapped_dek) <> 0 OR NEW.plaintext IS NOT NULL
       OR (NEW.id, NEW.secret_id, NEW.version, NEW.envelope_version, NEW.iv, NEW.auth_tag,
           NEW.kek_provider, NEW.kek_id, NEW.kek_version, NEW.created_at, NEW.created_by,
           NEW.recipe, NEW.pair_id, NEW.pair_half, NEW.sensitive)
          IS DISTINCT FROM
          (OLD.id, OLD.secret_id, OLD.version, OLD.envelope_version, OLD.iv, OLD.auth_tag,
           OLD.kek_provider, OLD.kek_id, OLD.kek_version, OLD.created_at, OLD.created_by,
           OLD.recipe, OLD.pair_id, OLD.pair_half, OLD.sensitive) THEN
        RAISE EXCEPTION 'a secret version is only ever erased' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
