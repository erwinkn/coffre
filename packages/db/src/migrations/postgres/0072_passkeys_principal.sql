-- 0.16.0, T176: every passkey a person has had, removed ones included, by person: the sign-in callback counts them, and a first passkey and a sign-in the provider alone answers read them under the head, each row held to its MAC (`passkeyHistory`). `passkeys_live_idx` holds only the live ones, so these read the whole table (review r2 of #500).
-- An index only, which 0.15 never reads, on a table 0.16.0 makes and no release before it writes: built while it is still empty.
--> statement-breakpoint
CREATE INDEX "passkeys_principal_idx" ON "passkeys" USING btree ("principal");