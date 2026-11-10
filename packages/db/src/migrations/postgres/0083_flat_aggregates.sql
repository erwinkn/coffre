-- 0.16.0, T248 (D189): the last of the runtime logins' reads that cost more as history grows (R48), after 0082's, so that 0.16's 5 s `statement_timeout` on them holds at any size. Additive (AGENTS.md, "expand, then contract"): two functions' bodies with their signatures as 0082's, and indexes, which change no answer.
--
-- A rotation of the log's key past the 246th is refused: the fence row, which every use reads, holds every retired key's 4-byte tag, and past 246 of them Postgres moves the array out of the row (its 2,032-byte threshold), so that every use reads a page more; and every keyring reads each rotation (`keyringRows`). Only the vault's login rotates; a key rotated every month takes twenty years to reach it. `ROTATIONS_HELD` in @coffre/vault's log-store.ts, which SQLite's rotation checks.
CREATE OR REPLACE FUNCTION public.log_rotate_number(p_from bytea)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    IF octet_length(p_from) <> 4 THEN RAISE EXCEPTION 'a key''s tag is 4 bytes' USING ERRCODE = 'invalid_parameter_value'; END IF;
    PERFORM pg_advisory_xact_lock(1668244070, 1);
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    IF EXISTS (SELECT 1 FROM public.checkpoint_fence f WHERE f.only_row AND p_from = ANY(f.retired)) THEN RETURN NULL; END IF;
    IF (SELECT cardinality(f.retired) FROM public.checkpoint_fence f WHERE f.only_row) >= 246 THEN
        RAISE EXCEPTION 'the log has rotated its key 246 times, the most its fence row holds: it takes no more rotation' USING ERRCODE = 'program_limit_exceeded';
    END IF;
    RETURN nextval('public.log_number');
END
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.log_rotate(p_number bigint, p_request text, p_at bigint, p_payload text, p_mac bytea, p_from bytea)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    IF p_payload::jsonb ->> 'op' IS DISTINCT FROM 'rotate' OR p_payload::jsonb ->> 'at' IS DISTINCT FROM p_number::text
       OR octet_length(p_from) <> 4 OR octet_length(p_mac) <> 16 OR substring(p_mac FROM 1 FOR 4) = p_from THEN
        RAISE EXCEPTION 'not a rotation: %', p_payload USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The number this transaction's log_rotate_number took, its locks still held (taking them again is a no-op).
    PERFORM pg_advisory_xact_lock(1668244070, 1);
    PERFORM pg_advisory_xact_lock(1668244070, 0);
    IF p_number IS DISTINCT FROM currval('public.log_number') OR EXISTS (SELECT 1 FROM public.checkpoint_fence f WHERE f.only_row AND p_from = ANY(f.retired)) THEN
        RAISE EXCEPTION 'not the rotation this transaction numbered' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF (SELECT cardinality(f.retired) FROM public.checkpoint_fence f WHERE f.only_row) >= 246 THEN
        RAISE EXCEPTION 'the log has rotated its key 246 times, the most its fence row holds: it takes no more rotation' USING ERRCODE = 'program_limit_exceeded';
    END IF;
    INSERT INTO public.log_changes (number, at, request_id, object, actor, payload, seal, mac)
    VALUES (p_number, p_at, p_request, public.log_object('log', 'key'), 'system:vault', p_payload, NULL, p_mac);
    UPDATE public.checkpoint_fence SET retired = array_append(retired, p_from) WHERE only_row;
    -- No fence row (a damaged or partial restore): no key retired, so the whole rotation fails, closed.
    IF NOT FOUND THEN RAISE EXCEPTION 'the log''s fence row is gone' USING ERRCODE = 'object_not_in_prerequisite_state'; END IF;
    RETURN p_number;
END
$function$;
--> statement-breakpoint
-- The rest are indexes built without blocking writes, after the migrations' transaction commits (`online-indexes.ts`).
-- What an audit page shows unless asked for detail (`entriesOf('shown')`): a page back from the newest in one step, past every heartbeat and checkpoint since, which the primary key walked (82 pages 2,000 heartbeats in, 696 at 20,000).
CREATE INDEX CONCURRENTLY "audit_log_shown_idx" ON "audit_log" USING btree ("seq") WHERE action NOT IN ('sign_in', 'sign_out', 'token.create', 'token.revoke', 'device.approve', 'device.deny', 'mcp.token', 'mcp.read', 'account.link', 'account.unlink', 'passkey.check', 'key.wrap', 'key.rewrap', 'reference.create', 'key.intent', 'key.check', 'audit.heartbeat', 'audit.checkpoint', 'key.reseal') AND seq >= 0;--> statement-breakpoint
-- And what it leaves out (`entriesOf('detail')`), whose newest it counts back from where it started (`auditActionCounts`): a page's count of what it hid read every heartbeat it matched, or past every one it did not (355 pages at 40,000 heartbeats; 1,350 for a page of refusals at 20,000).
CREATE INDEX CONCURRENTLY "audit_log_detail_idx" ON "audit_log" USING btree ("seq") WHERE action IN ('sign_in', 'sign_out', 'token.create', 'token.revoke', 'device.approve', 'device.deny', 'mcp.token', 'mcp.read', 'account.link', 'account.unlink', 'passkey.check', 'key.wrap', 'key.rewrap', 'reference.create', 'key.intent', 'key.check', 'audit.heartbeat', 'audit.checkpoint', 'key.reseal') AND seq >= 0;--> statement-breakpoint
-- A member's reads and writes in 0.14's log, by actor (`memberActivity`, an offboarding report's): every entry of the log was read for every report (2,484 pages behind 80,000). 0.15's log records every use and key write since its cutover: these no longer grow.
CREATE INDEX CONCURRENTLY "audit_log_seen_idx" ON "audit_log" USING btree ("actor","seq") WHERE decision = 'allow' AND action IN ('secret.read', 'secret.write');--> statement-breakpoint
-- A key's restores, by key and the version each made (`restoreMade`), which the report follows back from its current version, a step a restore: the lineage of its value, not every restore of the key (an owner putting version 1 back again and again) nor of the instance.
CREATE INDEX CONCURRENTLY "audit_log_restore_idx" ON "audit_log" USING btree ("secret_id",(CASE WHEN jsonb_typeof("metadata"::jsonb -> 'version') = 'number' THEN (CASE WHEN ("metadata"::jsonb ->> 'version')::numeric = trunc(("metadata"::jsonb ->> 'version')::numeric) THEN trunc(("metadata"::jsonb ->> 'version')::numeric) END) END),"seq") WHERE decision = 'allow' AND action = 'secret.restore';--> statement-breakpoint
-- What a member read, by key and version (`readsBy`): each day a skip from one to the next, the newest read of each first, where every read of theirs was read (797 pages at 30,000). Each day's built and attached as 0082's are (`online-indexes.ts`).
CREATE INDEX CONCURRENTLY "log_reads_seen_idx" ON "log_reads" USING btree ("principal",(coalesce("source", "secret")),"version","at") WHERE version IS NOT NULL;--> statement-breakpoint
-- The lowest `at` above a part of a capped window (`lowestAbove`, T169): from one `at` to the next, past the uses sealed at each in a step, where the index by `at` walked every use sealed at the `at` a backlog shares (366 pages 20,000 uses in, 7,069 at 400,000).
CREATE INDEX CONCURRENTLY "log_uses_at_number_idx" ON "log_uses" USING btree ("at","number");