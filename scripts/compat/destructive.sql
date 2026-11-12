-- pnpm test:compat's own test, applied nowhere else: a destructive change,
-- the kind the expand/contract rule ships a release late. It renames a
-- column the previous release reads and writes at every sign-in, so that
-- release cannot be conformant on it.
ALTER TABLE credentials RENAME COLUMN token_hint TO token_hint_renamed;
