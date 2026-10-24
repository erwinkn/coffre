-- Capped alerts (T98): when a service's sign-in was last refused `unknown_key` with an alert, so that the next alerts an hour later at the soonest, whichever process sees it. It only adds.
CREATE TABLE `capped_alerts` (
	`service` text NOT NULL,
	`kind` text NOT NULL,
	`raised_at` integer NOT NULL,
	PRIMARY KEY(`service`, `kind`)
);
