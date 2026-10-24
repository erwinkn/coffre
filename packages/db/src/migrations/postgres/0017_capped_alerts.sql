-- Capped alerts (T98): when a service's sign-in was last refused `unknown_key` with an alert, so that the next alerts an hour later at the soonest, whichever isolate sees it. It only adds: the release before neither reads nor writes it.
CREATE TABLE "capped_alerts" (
	"service" text NOT NULL,
	"kind" text NOT NULL,
	"raised_at" timestamp with time zone NOT NULL,
	CONSTRAINT "capped_alerts_pkey" PRIMARY KEY("service","kind")
);
--> statement-breakpoint
-- The app moves a row's time on, and deletes none.
GRANT SELECT, INSERT, UPDATE (raised_at) ON capped_alerts TO coffre_app;
