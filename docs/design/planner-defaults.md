# Planner defaults (0.16.0, T207)

From 0.16.0 coffre sets no planner setting anywhere: no `jit`, no
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

## Arrays a plan cannot see

`use_named_batch` and `use_route` resolve the names asked in one
statement, over two arrays: the names, and the place's layers (the place,
then what it inherits from). Planned for a call's own values, Postgres
counts each array, three names and two layers, say; planned for any
values, it guesses ten of each. So the plan for each call's values always
looked cheaper than the plan for any values, and the cache never kept the
latter: that statement planned on every call (43 plans for 42 calls of
`use_named_batch` in `use-cost.test.ts`, 140 for 137 of `use_route` in
the use tests), and each batch's buffers carried that planning's reads,
which move with the data. CI caught it as a batch's own buffers moving by
7 between 1,000 and 10,000 forks.

0063 reads each array through a scalar subquery,
`unnest((SELECT v_layers))`. Its value is then unknown to both plans,
both count ten, and the cache keeps the plan for any values after five
calls, as 0.15.0's forced generic plans did. The rows and their order are
the same.

## Planning before the fence (T131)

`use_credential` takes a shared advisory lock, the fence, which a
checkpoint's barrier takes exclusively: a barrier waits for every use
holding it, and every later use waits for the barrier. So a session's
first call runs each of its four statements once dry, before the fence,
and only then takes it. 0.15.0's hot login forced generic plans, so that
dry run built the very plans every call after reused: no use planned
under the fence.

At the default `plan_cache_mode = auto`, Postgres makes a custom plan for
each of a statement's first five runs in a session, then a generic one,
which it keeps when it costs no more than the custom ones did. The dry
run's own plan is trivial, since `WHERE NOT dry` folds to false for its
values, but making it still opens every table and index the statement
names and reads their statistics: the cold work, most of a new
connection's first planning (66 to 71 ms under load in T187's
measurements). Measured on an idle fresh session (Postgres 16.14):

| call | `auto` (0.16.0) | `force_generic_plan` (0.15.0) |
|---|---|---|
| first (dry runs, then the call) | 5 plans, 17.3 ms | 4 plans, 16.0 ms |
| second to fifth | 1 plan each, about 1.7 ms, under the fence | none |
| sixth and after | none: the generic plan is kept | none |

A use holds the fence about as long as it runs, a few ms, so four warm
plans of about 1.7 ms are within what a barrier already waits for; the
cold work stays before it. `use.test.ts` (T131) holds the dry run to
having opened the statements' indexes before the fence, and a session
told its plans are made to having opened none.

## 0022, rewritten

0022 made the hot login, with its timeouts and generic plans, and asked a
login without `ADMIN` on the role to have an administrator set them first.
Role settings are the server's, but each database runs 0022 itself: once
a migrate had reset the generic plans, a login without `ADMIN` could no
longer migrate another database of the same server through 0022, and
`coffre setup` no longer sets them. 0022 now gives the timeouts alone. A
database that applied it before keeps its earlier hash in its ledger, which
the migrator accepts for that migration alone (`REWRITTEN` in
[migrate.ts](../../packages/db/src/migrate.ts)); for such a database
nothing changes, since the migration has already run.

0.15.0's conformance requires generic plans on the hot login, so
`pnpm test:compat` gives that release's hot login them in its URL, as
its own database did, and holds it to every other check
([compat-check.sh](../../scripts/compat-check.sh)).

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
- The use matrices hold a refusal of a caller who stands nowhere to
  reading as many blocks of the key's tables for every key, in two ways
  (`scripts/matrix-weigh.ts`):
  - On settled plans (`weigh`): one session that refuses sequential scans,
    to plan a test's tables of a few pages as an instance's grown ones
    are, and forces the plan for any values, which refused scans would
    otherwise keep the cache from settling on (each call would be weighed
    on a plan for its own values: a key never made read 22 blocks where
    every other key read 26), without JIT, which those costs would reach.
  - At each of a new session's first seven calls (`weighInTurn`), at the
    server's own settings: the dry run, the four calls planned for their
    own values, the one that makes the plan for any values, and the first
    on it. Each key's refusal is weighed in a session of its own, and so
    is its twin, the same request for a key its world never made; the
    two must fetch as many blocks of the key's tables at every call.
    Each key of a matrix row lives in a world of its own, whose rows sit
    where its writes put them, so the check holds each key to its own
    world's twin, not to the other worlds. Before them, one call of the
    control below, unweighed, in a session of its own: the first session
    to plan after a batch's rolled-back writes read 1 or 2 more `log_bulk`
    blocks at its first call than every session after it, the same request
    asked again included (75 beside 74 for held, a batch's first key, in
    three runs out of three; 74 again when it was asked after its
    controls). That call carries nothing of the key, so it cannot hide a
    read of the key's, which every weighing would show. The twin changes only the
    key's name, and keeps what the isolate remembered of the key: its id,
    a cover. A read by that id would cost the twin as much as the key, so
    each refusal is also held to a second control (`absentOf`), the twin
    with no id, cover or seal, its caller and place unchanged (Sol's
    review r4). A dry run made to read by the id passed fails against it,
    and passes against the twin alone.

  These are the weighing's own session settings, never a login's or a
  function's.

## The dry run plans for no key

A plan made for a call's own values is made with them, and planning for a
value can read pages by it. Sol's review r2 weighed a session's first
calls at the server's settings and found a named call of a caller who
stands nowhere reading 16 more blocks of the key's tables (`log_bulk`,
`secret_versions`, `environments`) on its first call for a key held than
for one never made. Every statement's own execution read the same: the
gap was the dry run's planning, which bound the key id the isolate passed
before anything had decided the caller may know of it. 0.15.0's generic
plans never planned for a value, so never showed it.

The dry run now binds the nil id, which no key has; the call binds a key
where it reads it, a use by id or a named call of a caller who stands.
Weighed at each of a session's first seven calls, a held key and a key
never made then read the same blocks at every call.
