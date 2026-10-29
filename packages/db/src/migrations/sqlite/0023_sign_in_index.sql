CREATE INDEX `log_changes_sign_in_idx` ON `log_changes` (`at`,`number`) WHERE instr("log_changes"."payload", '"signIn":{') > 0;--> statement-breakpoint
CREATE INDEX `log_changes_sign_in_actor_idx` ON `log_changes` (`actor`,`at`,`number`) WHERE instr("log_changes"."payload", '"signIn":{') > 0;
