# Planner defaults (0.15.1, T207)

From 0.15.1 coffre sets no planner setting anywhere: no `jit`, no
`plan_cache_mode`, no `enable_seqscan`, `enable_sort` or
`enable_bitmapscan`, on no function, login or connection. Every statement
plans and runs at the server's own settings. Timeouts (`lock_timeout`,
`statement_timeout`) are not planner settings and stay on the hot login.
`bytea_output = 'hex'` and `TimeZone = 'UTC'` stay on the functions whose
answer is text (below).

Migration [0063](../../packages/db/src/migrations/postgres/0063_planner_defaults.sql)
resets the settings on the functions and rewrites the four whose plans
leaned on them; `coffre migrate` resets what 0.15.0 set on the logins,
where its login may ([deploy.md](../deploy.md#the-database-and-its-keys-for-either-deployment)).

## What the settings were hiding

**One misestimated table.** `use_credential`'s main statement joined the
fence, `log_fence`, a table of exactly one row (its key is `only_row`,
held true by a check):

```sql
LEFT JOIN public.log_fence f ON f.only_row
```

A table nobody has analyzed or vacuumed has no statistics. The planner
then assumes ten pages, 1,180 rows of the fence's width, and gives a bare
boolean filter half of them: 590 rows where there is one. That row count
sits at the bottom of a nested loop, so every join above it is costed 590
times over. Measured on Postgres 16.14, with the fence
unanalyzed and everything else analyzed:

| `use_credential`'s main statement | plan for the call's values (custom) | plan for any values (generic) |
|---|---|---|
| 0060, the fence joined | 37,706 to 42,634 | 42,970 (one form 59,042) |
| 0063, the fence `LIMIT 1` | 65 to 203 | 226 (every form 195 to 301) |

0028's and 0029's statements, with more joins above the same fence, were
estimated at 96,869 and 101,819 on fresh test databases
([0.15-plan.md](0.15-plan.md), "JIT, found on the way"): the "90k-100k".
Past `jit_above_cost` (100,000) Postgres compiles the plan on every
execution, about 130 ms a use. `SET jit = off` hid that.

**The plan cache.** A function's statement is planned for its call's
values its first five times. After that, Postgres keeps one plan for any
values when that plan costs no more than the average custom plan plus a
charge for planning. With the fence misestimated, the generic plan's extra
joins (the three kinds of caller, the cap's count of other keys) were
costed 590 times over too, so the generic plan always lost and
every call planned again. At 1,000 uses a second, before any autoanalyze:

| | plans of the statement | Postgres CPU a use |
|---|---|---|
| 0060, no planner settings | 12,864 for 12,824 calls | 4.4 ms |
| 0060, once analyzed | 240 for 12,883 calls | 1.6 ms |
| 0063, never analyzed | 240 for 12,859 calls | 1.7 ms |

The hot login's `force_generic_plan` hid that. A database without the
fence's statistics is not unusual: a new one, one restored (`pg_restore`
restores no statistics), one upgraded across a major version, and any
small deployment, since a one-row table rarely written may never reach
autovacuum's thresholds.

**The fix** is a query that says what is true:

```sql
LEFT JOIN LATERAL (SELECT y.at_floor, y.retired FROM public.log_fence y WHERE y.only_row LIMIT 1) f ON true
```

`LIMIT 1` bounds the estimate to one row whatever the statistics say, and
changes no answer: there is never a second row. No other table is joined
that way: every other row source of the statement is a unique-key probe, a
`LIMIT 1` probe or an aggregate, each one row however its table is
estimated (checked by resetting each table's statistics in turn; only the
fence moved the plan cache's choice).

## The day queries

`use_covered`, `log_reads_by` and `log_reads_at` each read one day of a
partitioned table by values only the call knows. A plan for any values
cannot prune at plan time: it names, and locks, every day (130 locks a use
at 109 days, [0.15-plan.md](0.15-plan.md), T187). They held
`force_custom_plan`, and the read functions also turned off sorts and bitmap
scans. 0063 plans each of those statements per call with `EXECUTE`, which
prunes to the day and plans the index read newest first, the same plan the
settings forced. Planning a covered use's probe costs about 0.09 ms
(686 calls, 64 ms of planning), as the custom plan did before.

## What stays

- **`bytea_output = 'hex'`** on the functions whose answer is text, and in
  `coffre backup`. The vault reads every seal and MAC in their JSON as hex
  (`bytes`, `packages/vault/src/write.ts`). Postgres writes a bytea in JSON
  in the session's format: on a server, database or login set to
  `escape`, `"\\000\\377A"` where hex is `"\\x00ff41"`. Without the
  setting, such a deployment refuses every use as `tampered`
  (`use.test.ts`, "a use on a server whose bytes are written `escape`").
- **`TimeZone = 'UTC'`** where a function writes a timestamp as text.
- **The hot login's timeouts**, which bound a use (1 s for a lock, 2 s
  for a statement).

## Holding it

- `use.test.ts` and `log-guarantees.sql` hold every function to no planner
  setting, and `runtime-role.test.ts` holds every login to none.
- `use-days.alone.ts` holds a use's locks and buffers the same at a few
  days and at a hundred more.
- Measured at 5, 100 and 365 days attached, at 1,000 uses a second: 1.62,
  1.70 and 1.66 ms of Postgres CPU a use, about 50 buffers, the generic
  plan kept (estimate 222 to 237, far below `jit_above_cost`).
- Tests that weigh a call's buffers (`scripts/matrix-weigh.ts`) let the
  plan cache settle on each statement before they weigh it, since a
  custom plan's planning reads catalog and index pages that count in the
  call's buffers. Their session refuses sequential scans, as before, and
  so turns JIT off for itself: refused scans cost so much that an estimate
  passes `jit_above_cost`, and JIT reads no buffer.
