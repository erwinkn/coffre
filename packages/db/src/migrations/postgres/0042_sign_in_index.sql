-- The audit pages list the sign-ins through trust bindings (T156): with 0.15's log, a sign-in writes no 0.14 `token.exchange` entry, and its change is the record (D147), so the app reads the changes, as it reads the vault's members and grants. Two indexes over the sign-ins alone, every service's and one's, newest first by when the vault asked (`at`, then the number, which comes after any wait), so that a page reads as many as it shows however many other changes the log holds. Only a sign-in's payload holds a `signIn` object (`SIGNED_IN` in @coffre/server's queries repeats the condition). Additive: the previous release reads nothing here.
--> statement-breakpoint
CREATE INDEX "log_changes_sign_in_idx" ON "log_changes" USING btree ("at","number") WHERE strpos("log_changes"."payload", '"signIn":{') > 0;
--> statement-breakpoint
CREATE INDEX "log_changes_sign_in_actor_idx" ON "log_changes" USING btree ("actor","at","number") WHERE strpos("log_changes"."payload", '"signIn":{') > 0;
--> statement-breakpoint
GRANT SELECT ON log_changes TO coffre_app;
