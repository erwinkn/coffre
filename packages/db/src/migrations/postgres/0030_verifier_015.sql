-- For 0.15's verifier (plan PR 8): its row audit holds every input row to the replay of the log. It reads the columns
-- the credentials' and the bindings' objects are made of, which the vault read only through use_credential and
-- change_input before (the references it reads whole since 0029). Never a token's hash or MAC. It keeps nothing: a
-- walk answers in the call that asked for it.
GRANT SELECT (id, principal, kind, scope, revoked_at, expires_at, not_after, seal) ON credentials TO coffre_vault;
--> statement-breakpoint
GRANT SELECT (id, seal) ON service_bindings TO coffre_vault;
