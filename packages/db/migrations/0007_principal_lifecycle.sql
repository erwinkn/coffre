-- Keep removed principals as inactive tombstones so an in-flight or later
-- project grant cannot silently recreate an identity that was deliberately
-- offboarded. Re-adding the identity through the directory is the explicit
-- operation that activates it again.
ALTER TABLE principals
    ADD COLUMN active boolean NOT NULL DEFAULT true;

-- Every grant must belong to a known directory principal. Service operations
-- take a matching per-principal transaction lock as well; this constraint is
-- the final database-level guard against orphaned grants.
ALTER TABLE grants
    ADD CONSTRAINT grants_principal_fkey
    FOREIGN KEY (principal_type, principal_id)
    REFERENCES principals (principal_type, principal_id)
    ON DELETE RESTRICT;
