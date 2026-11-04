-- 0.16.0, T179 PR 6: a refusal's record (docs/design/two-trips.md, "A refusal's record"; formal/Writing.tla, Refuse). A key write or a member's first add the vault's decision refused on its read is answered as today's path answers it, and recorded by the vault in 0.15's log, in place of the 0.14 deny entry that path writes: two round trips, the read and this record. The record is a row of `log_changes`, so that the checkpoints seal it and retention keeps it as every change, of an object of its own, its request's (`log_object('request', id)`), which no other row's is: no reader that asks an object's newest change takes it (a use, a hold, a member's watermark), and the replay passes over it as the log's own. Its payload starts `{"code":"`, as no other change's does (change-records.ts, `refusedWrite`, `refusedAdd`).
--> statement-breakpoint
-- The record, written once the app has checked the caller's rows (RefusalAfterAuth): its MAC is the Worker's, over every column but its number, its object the request's own. Under the fence shared, as a use: it waits for a change's hold to its COMMIT, the checkpointer's barrier waits for it, and it holds up no use. A retry of the same record (its request id, its payload) answers the number it took, a retry at the same time as it too; another under its request id is refused. Its own: the vault's login reads `log_changes` and writes none of it.
CREATE FUNCTION log_refusal(p_at bigint, p_request text, p_actor text, p_payload text, p_mac bytea) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    op jsonb := p_payload::jsonb;
    target uuid := public.log_object('request', p_request);
    n bigint;
BEGIN
    IF coalesce(op ->> 'op', '') NOT IN ('write.refused', 'add.refused') OR strpos(p_payload, '{"code":"') <> 1
        OR op -> 'ref' ->> 'kind' IS DISTINCT FROM 'request' OR op -> 'ref' ->> 'id' IS DISTINCT FROM p_request THEN
        RAISE EXCEPTION 'a refusal''s record is a write''s or an add''s, of its own request: its code first, its ref the request' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request;
    IF NOT FOUND THEN
        -- Two retries at once both find none: the second's insert waits for the first's, and takes its row once it commits.
        INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
            VALUES (nextval('public.log_number'), p_at, p_request, target, p_actor, p_payload, NULL, p_mac)
            ON CONFLICT (request_id) DO NOTHING
            RETURNING number INTO n;
        IF FOUND THEN
            RETURN n;
        END IF;
        SELECT c.number INTO n FROM public.log_changes c WHERE c.request_id = p_request;
    END IF;
    IF n IS NULL OR NOT EXISTS (SELECT 1 FROM public.log_changes c WHERE c.request_id = p_request AND c.object = target AND c.payload = p_payload) THEN
        RAISE EXCEPTION 'request % names another change', p_request USING ERRCODE = 'unique_violation';
    END IF;
    RETURN n;
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION log_refusal(bigint, text, text, text, bytea) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION log_refusal(bigint, text, text, text, bytea) TO coffre_vault;
--> statement-breakpoint
-- Where the audit pages list them, where 0.14's deny entries stood: a key write's, every one, one member's, one environment's (by the payload's `environmentId`) and one member's there, as its writes (0065); an add's, every one and one member's, on the instance's pages, as its adds. Partial: they hold refusals alone, however long the log grows (R48).
CREATE INDEX "log_changes_refused_write_idx" ON "log_changes" USING btree ("at","number") WHERE (strpos("log_changes"."payload", '{"code":"') = 1 AND strpos("log_changes"."payload", '"op":"write.refused"') > 0);--> statement-breakpoint
CREATE INDEX "log_changes_refused_write_actor_idx" ON "log_changes" USING btree ("actor","at","number") WHERE (strpos("log_changes"."payload", '{"code":"') = 1 AND strpos("log_changes"."payload", '"op":"write.refused"') > 0);--> statement-breakpoint
CREATE INDEX "log_changes_refused_write_environment_idx" ON "log_changes" USING btree (("payload"::jsonb ->> 'environmentId'),"at","number") WHERE (strpos("log_changes"."payload", '{"code":"') = 1 AND strpos("log_changes"."payload", '"op":"write.refused"') > 0);--> statement-breakpoint
CREATE INDEX "log_changes_refused_write_actor_environment_idx" ON "log_changes" USING btree ("actor",("payload"::jsonb ->> 'environmentId'),"at","number") WHERE (strpos("log_changes"."payload", '{"code":"') = 1 AND strpos("log_changes"."payload", '"op":"write.refused"') > 0);--> statement-breakpoint
CREATE INDEX "log_changes_refused_add_idx" ON "log_changes" USING btree ("at","number") WHERE (strpos("log_changes"."payload", '{"code":"') = 1 AND strpos("log_changes"."payload", '"op":"add.refused"') > 0);--> statement-breakpoint
CREATE INDEX "log_changes_refused_add_actor_idx" ON "log_changes" USING btree ("actor","at","number") WHERE (strpos("log_changes"."payload", '{"code":"') = 1 AND strpos("log_changes"."payload", '"op":"add.refused"') > 0);
--> statement-breakpoint
-- Statistics on the conditions' new markers, as 0065's on its own (R69: statistics, not a planner setting).
CREATE STATISTICS "log_changes_refusals_stats" ON (strpos("payload", '{"code":"')), (strpos("payload", '"op":"write.refused"')), (strpos("payload", '"op":"add.refused"')) FROM "log_changes";
