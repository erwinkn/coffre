-- 0.16.0, T245 (D187): no statement on the runtime logins costs more as history grows (R48), so that 0.16's 5 s `statement_timeout` on them (#501 Q5) holds at any size. Additive (AGENTS.md, "expand, then contract"): a table, a function's body with its signature and answer as 0.15's, and four indexes, which change no answer.
--
-- The spent tokens' prune, a stretch of the table a call. 0080 read the whole table each beat to find the records past two hours, one scan of 7.5 million at R44's 1,000 sign-ins a second (0.9 s warm, measured; 2-4 s from a managed disk's cold cache), and longer for a faster rate, which nothing caps. Now each call reads at most `span` of the table's blocks, from where the last one stopped (`spent_tokens_sweep`), by a TID range scan: 16,384 blocks, 128 MB, at most 0.9 s from a disk reading 150 MB/s, whatever the table's size. The sweep goes round the table, 70,000 blocks at 1,000 a second, in five beats: a record lives two hours and up to one round, about 25 minutes, longer, which guards more. A call still forgets `at_most` at most; one that forgot that many goes on from the last block it emptied. Another call under way, the next one skips (SKIP LOCKED) and forgets none.
CREATE TABLE "spent_tokens_sweep" (
	"only_row" boolean PRIMARY KEY DEFAULT true NOT NULL,
	"next_block" bigint DEFAULT 0 NOT NULL,
	CONSTRAINT "spent_tokens_sweep_only_row_check" CHECK ("only_row")
);
--> statement-breakpoint
INSERT INTO "spent_tokens_sweep" DEFAULT VALUES;
--> statement-breakpoint
-- Read by the backup, as every table is (`pnpm test:schema`); written by the prune alone, as its owner.
GRANT SELECT ON "spent_tokens_sweep" TO coffre_backup;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION public.prune_consumed_tokens(at_most integer) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    span constant bigint := 16384;
    blocks bigint := pg_relation_size('public.spent_id_tokens') / current_setting('block_size')::bigint;
    lo bigint;
    hi bigint;
    pruned integer;
    last bigint;
BEGIN
    SELECT s.next_block INTO lo FROM public.spent_tokens_sweep s WHERE s.only_row FOR UPDATE SKIP LOCKED;
    IF NOT FOUND OR blocks = 0 THEN RETURN 0; END IF;
    -- Past the table's end, which a vacuum may have cut short: round again from the start.
    IF lo >= blocks THEN lo := 0; END IF;
    hi := lo + span;
    -- Each record's `ctid` read and the row deleted in one statement, under one snapshot: nothing moves a row between.
    WITH gone AS (
        DELETE FROM public.spent_id_tokens
         WHERE ctid = ANY(ARRAY(
            SELECT c.ctid FROM public.spent_id_tokens c
             WHERE c.ctid >= format('(%s,0)', lo)::tid AND c.ctid < format('(%s,0)', hi)::tid
               AND c.consumed_at < now() - interval '2 hours'
             LIMIT at_most))
        RETURNING (ctid::text::point)[0]::bigint AS block
    )
    SELECT count(*)::integer, max(block) INTO pruned, last FROM gone;
    UPDATE public.spent_tokens_sweep SET next_block = CASE WHEN pruned >= at_most THEN last ELSE hi END WHERE only_row;
    RETURN pruned;
END
$$;
--> statement-breakpoint
-- The rest are indexes built without blocking writes, after the migrations' transaction commits (`online-indexes.ts`): a plain CREATE INDEX would hold each table's inserts for its build, 0.5 s on an audit log of 440,000 entries and 1.3-1.9 s on 1.2 million (measured on the compose Postgres), minutes on a day of uses. coffre runs without them until they are built, slower at scale.
--
-- The first entry an author wrote under a key, or that it wrote none (`firstVaultEntryUnder`, `wroteUnder`): one step of its author's index, where the walk by `seq` read the whole log for a key that never wrote, at every cold start of a vault given a new key, or of an app that lists a previous key it never used, and every older key's entries for a key that wrote most of the log. The key first, and the lookup orders by the key then `seq` through `= ANY` (`keyedBy`): ordered by `seq` alone, Postgres walked `audit_log_app_idx` past 20,000 entries of another key, 557 pages, and Postgres 16 reads an `= ANY` in order only of a leading column. Every entry has one, about 50 B (50 MB at 1.2 million entries, measured).
CREATE INDEX CONCURRENTLY "audit_log_vault_key_idx" ON "audit_log" USING btree ("key_id","seq") WHERE author = 'vault';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_app_key_idx" ON "audit_log" USING btree ("key_id","seq") WHERE author = 'app';--> statement-breakpoint
-- The vault's newest entries (`vaultPage`): one step, where the walk back by `seq` read every app entry since the vault's last, a beat's at most while checkpoints are signed and the whole log since when they stop. The vault's entries only, a few a beat in 0.15.
CREATE INDEX CONCURRENTLY "audit_log_vault_idx" ON "audit_log" USING btree ("seq") WHERE "audit_log"."author" = 'vault';--> statement-breakpoint
-- The app's newest entry (`newestAppEntry`, at each app's cold start): one step, where the walk back by `seq` read every vault entry since the app's last, 3,050 pages past 100,000 of them. The app's entries only, 17 MB at 800,000 (measured).
CREATE INDEX CONCURRENTLY "audit_log_app_idx" ON "audit_log" USING btree ("seq") WHERE "audit_log"."author" = 'app';--> statement-breakpoint
-- Each kind of entry a runtime read asks the newest of (`KINDS` in access-entries.ts), an index of its own with the kind's condition: one step however long the run of other entries since its newest. Postgres walks back any index that yields `seq` order with the rest as a filter whenever its statistics hold the kind common: 140,000 rotations then 20,000 checkpoints, and the newest rotation read 641 pages; 700,000 checkpoints then 100,000 unwraps, and the newest checkpoint 3,731. An index of the kind alone is smaller than any of those and needs no filter, so it is cheaper by Postgres's own estimate, and reads 4 pages. One `(author, action, decision, seq)` for every kind lost to `audit_log_vault_idx` once half the table was not yet vacuumed, and cost every entry 9% more WAL; these cost an entry of another kind nothing.
CREATE INDEX CONCURRENTLY "audit_log_signed_idx" ON "audit_log" USING btree ("seq") WHERE author = 'vault' AND action = 'audit.checkpoint' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_checkpoint_idx" ON "audit_log" USING btree ("seq") WHERE author = 'vault' AND action = 'audit.checkpoint';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_broken_log_idx" ON "audit_log" USING btree ("seq") WHERE author = 'vault' AND action = 'audit.checkpoint' AND decision = 'deny' AND code = 'log_broken';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_policy_idx" ON "audit_log" USING btree ("seq") WHERE author = 'vault' AND action = 'policy.change' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_settings_idx" ON "audit_log" USING btree ("seq") WHERE author = 'vault' AND action = 'settings.change' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_rotation_idx" ON "audit_log" USING btree ("seq") WHERE author = 'vault' AND action = 'key.rotate' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_intent_idx" ON "audit_log" USING btree ("seq") WHERE author = 'vault' AND action = 'key.intent' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_key_check_idx" ON "audit_log" USING btree ("seq") WHERE author = 'vault' AND action = 'key.check' AND decision = 'allow';--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_tamper_idx" ON "audit_log" USING btree ("subject_principal","seq") WHERE author = 'vault' AND action = 'vault.tampered' AND code IN ('mac', 'stale');--> statement-breakpoint
CREATE INDEX CONCURRENTLY "audit_log_moves_idx" ON "audit_log" USING btree ("seq") WHERE author = 'app' AND action IN ('key.reseal', 'key.rotate');--> statement-breakpoint
-- Whether a target is frozen: its newest allowed freeze or lift, one step back by `(target, seq)`. `audit_log_freeze_idx`, keyed `seq DESC NULLS LAST`, serves no `ORDER BY seq DESC` (nulls first), and Postgres walked the app's entries back by `seq` from the newest to the target's newest freeze, at each sign-in of a workload while a freeze stood: 1,024 pages behind 20,000 of the app's other entries, 4 by this one. The old one goes in 0.17.
CREATE INDEX CONCURRENTLY "audit_log_frozen_idx" ON "audit_log" USING btree ((("metadata")::jsonb ->> 'target'),"seq") WHERE "audit_log"."author" = 'app' AND "audit_log"."action" IN ('workload.freeze', 'workload.unfreeze') AND "audit_log"."decision" = 'allow';--> statement-breakpoint
-- A pair's reads by number, which the reads check lists (`listing`): the index by `at` read every read in the window's times, a stall's backlog, for the 10,000 a pair holds at most. Each day's built apart and attached.
CREATE INDEX CONCURRENTLY "log_reads_by_number_idx" ON "log_reads" USING btree ("number");--> statement-breakpoint
-- The checkpointer's window by number (`postgresWindow`): its first 10,001 in one step of each day's index, however far behind it is, where it read every use from the floor and sorted them, 1.4 µs a use (WINDOW_ENTRY_MS), past 5 s at 3.5 million, an hour's backlog at R44's rate, after which no pair was ever signed again. A use's insert writes one entry more, 22.5 B and 149 B of WAL (docs/design/audit-tree.md). Each day's built apart and attached; the days `make_day` makes ahead take theirs, empty, as they are attached.
CREATE INDEX CONCURRENTLY "log_uses_by_number_idx" ON "log_uses" USING btree ("number");
