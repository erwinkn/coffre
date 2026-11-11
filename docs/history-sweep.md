# The history sweep

Rule R48: no statement on the runtime logins (the app's `coffre_runtime`, the
vault's `coffre_vault_runtime` and its hot path's `coffre_vault_hot`) may cost
more as history grows. The runtime logins run under a 5 s `statement_timeout`
(D187, D189), so a read that walks a log is a read that fails once the log is
long enough. The sweep finds such reads by measuring, rather than by reading
the code: it runs the same request paths on a history of one size and on one
ten times longer, and lists every statement that read more at the larger.

```sh
COMPOSE_PROJECT_NAME=coffre_mine COFFRE_POSTGRES_PORT=56432 pnpm sweep:history            # 2,000, then 20,000
COMPOSE_PROJECT_NAME=coffre_mine COFFRE_POSTGRES_PORT=56432 pnpm sweep:history --size 4000 --out ~/sweep
```

It needs a Postgres of its own (it refuses the shared one on :55432): it turns
auto_explain on for its own databases, which logs a plan for every statement,
and reads the server's log through `docker compose logs`. A release that adds
a read, or a shape of history, reruns it. It exits 1 when a statement grows,
or when the two runs did not go the same way to the end (below).

## What it does

[`scripts/history-sweep.sh`](../scripts/history-sweep.sh) runs
[`packages/server/test/history.sweep.ts`](../packages/server/test/history.sweep.ts)
twice through the suite's runner (`scripts/test-suite.sh --files`), each time
on a fresh clone of the migrated template:

1. **auto_explain on the runtime logins, in this database alone.** Before any
   runtime connection opens, `ALTER ROLE … IN DATABASE … SET` loads
   `auto_explain` for the three logins (`session_preload_libraries`), with
   `log_min_duration = 0`, `log_analyze`, `log_buffers` and
   `log_nested_statements`, so each statement a function runs is logged too.
2. **An instance**, through the API: two projects, a fork, keys, a reference,
   members of each kind, a service token, a few reveals sealed and projected.
3. **A history `COFFRE_SWEEP_SIZE` long in each shape** that has hidden a walk
   before, oldest first: another member's reads in 0.14's log, a thousand to an
   `occurred_at`; the vault's findings about one member, 0.14's and 0.15's; the
   access grants and refusals about someone no member row names; 0.15's changes
   of other objects and rotations of the log's key; one member's reads of the
   same four keys at their versions (one through a reference), a thousand a
   day, over a day for each thousand; uses sharing one `at`, unsealed; and,
   newest, the heartbeats an
   ordinary audit page hides. Then the watch and the vault catch up with it, as
   a deployment's do between beats, so that what a beat walks is what came since.
4. **Every request path, three times**: every GET route of the API (from the
   client's route table, its parameters filled), as an Owner and as a viewer;
   the audit page under each filter; each member's page; a sign-in, reveals, a
   key write, an access change, a heartbeat, readiness, the vault's checkpoint,
   the checkpointer's tick and the reads' projection, with and without a key it
   replaced; then an offboarding, and the removed member's report, of a
   member of their own in each round (three of one history). The first round
   warms the plans; a statement in the other two, between the marks
   `/* sweep:<path> */` the file logs, is measured: twice, so that each path
   has a run of each of its statements on a backend that ran it before. Its
   pools hold one connection each, kept until the end
   (`keepTestConnections`), as a request takes turns on one through
   Hyperdrive: a pool that closed one idle for a second, or spread its
   statements over ten, sent a path's next run to a backend new to it.

[`scripts/history-sweep.mjs`](../scripts/history-sweep.mjs) then reads both
logs. A statement is its path and its text with its literals left out, and
each list of parameters one (an `IN` as long as a page's rows is one
statement however long; each run's database is another, and Postgres's query
identifier hashes its tables' OIDs): by path, so that a statement many paths run, a member's access say, is
measured in each, and one path's walk is not hidden under another's larger,
flat run of it (review r2 of #559). Its cost is the most pages (shared
buffers hit or read) one run of it read in its path, and how many times it
ran there. It **grows** when the larger run read at least twice the
pages and eight more, or ran it at least twice as often. A flat statement gains
an index level at most, a page for each index it steps down, and its rows; the
rule is growth, not a budget of pages (R70). The cost tests use the same rule
([`packages/server/test/db/growth.ts`](../packages/server/test/db/growth.ts)).

A statement too slow at the larger size leaves no plan behind if something
cancels it, so a sweep that only compared plans would read it as one that did
not grow. So the sweep also fails when either run's runner failed (its exit
status is kept), when a path answered otherwise at the two sizes (each path's
outcome, by a name the same at both, is printed as `sweep outcomes`), when a
statement the smaller run completed is missing from the larger's log, or when
either log holds a statement the server cancelled (review r1 of #559).

Two things it does not count. A statement's first run on a backend reads the
catalog to plan a function's statements (`prune_bulk`'s first call, 1,295
pages on an empty database as on a grown one, 18 after, or anywhere between,
by what the catalog's caches held): only its later runs count. A path whose
runs of a statement at either size were all first runs on their backends
is not compared, and fails the sweep (`COLD`), since its pages there are the
catalog's as much as its own (review r3 of #559). And rows of 0.15's log carry no MAC of the
vault's, so the checkpointer refuses at the first: it runs its reads first,
which is what is measured, but a backlog it would drain stays where it is
(`lowestAbove` and the checkpointer's window have tests of their own that
drain one, in `packages/vault/test/log-store.test.ts`).

## What it found (T248)

The first sweep, 2,000 and 20,000 entries of each shape, on #556's head:

| Statement | 2,000 | 20,000 | Fix |
|---|---|---|---|
| A member's activity in 0.14's log (`memberActivity`), on every member page | 265 | 2,484 | A sequential scan, for its `OR` with every restore: now a probe of `audit_log_seen_idx` for each of the member's names, then a probe of each version they saw and of its key's current one, the same value when the ciphertext is (T252: a walk back of each restore of a restore before) |
| Every member's findings (`tamperedMembers`), the members list's | 151 | 1,454 | A skip of `audit_log_tamper_idx` from one member reported to the next, then a probe each |
| An ordinary audit page, past the heartbeats since | 82 | 696 | `audit_log_shown_idx`, the entries a page shows |
| An audit page's count of what it hides (`auditActionCounts`) | 99 | 336 | The newest `HIDDEN_COUNTED` of its stretch at most, and `hiddenMore` |
| A member's reads by key and version (`readsBy`), an offboarding report's | 66 | 494 | `log_read_newest`, a row for each key and version the member read (T252: each day the member read on before, a day at a time) |
| The keyring's rotations (`rotations`, `keyringRows`) | 56 | 452 | No more than `ROTATIONS_HELD` (246) rotations in a log's life |
| The window a proof or the projector reads (`entries`), past uses sharing an `at` | 70 | 396 | Its first entries by number, `log_uses_by_number_idx` (T245), its bounds read first and given as values, so that it plans its own days alone |

Two of an offboarding report's reads still grew after it, with what one
member did rather than with the instance: `readsBy` probed each day the
member read on (a member who read every day for a year is 365 probes, and a
read projected keeps every day unless `retainDays` says otherwise), and the
restores its activity followed back were one step each of a chain an owner
made (restore version 6 back, then the version that made, and on: 7 from 6,
8 from 7, …). T252 reads `log_read_newest` instead, each member's newest
read of each key and version, which a trigger writes with the reads
(`formal/Reads.tla`), and finds a value carried forward by its ciphertext,
whose IV and tag a restore copies and every new value draws afresh.

And the checkpointer's `lowestAbove`, which a forged backlog does not reach,
by its own test (7,069 pages past 390,000 uses sharing one `at`): a walk of
`log_uses_at_number_idx` from one `at` to the next.

Flat once a backlog is walked (each a batch of a bounded walk, which the first
sweep measured before the watch caught up): the heartbeat's and the
verification's walks of the log, their counts of a stretch (`COUNTED_AT_ONCE`,
T245) and the vault's releases' prune.

## The audit pages of a place, of a reader's places and of refusals (T254)

Found after the first sweep, by review (#559) and by W367's 240,000-entry
shape: a page with a place (`?path=`), a reader's page of their places, and
`?decision=deny` walked back past everything the page hides about the place,
or every shown entry about another place. Each now reads streams of indexes
of its own, merged by `seq`, an entry two streams hold listed once
(`placeStreams` in `packages/server/src/db/queries.ts`). Pages read, 4,000
and 40,000 entries in (`holdsFlat`, `packages/server/test/history-aggregates.test.ts`):

| Page | Before | After |
|---|---|---|
| A project's, behind its own `mcp.read` and others' writes | 157 → 1,555 | flat |
| An environment's, or a key's | 304 → 3,023 | flat |
| A reader of some places, on `/audit` | 148 → 1,471 | flat |
| `?decision=deny` | 35 → 334 | flat |
| W367's shape: 22 shown entries, then 240,000 others' reads and heartbeats | 7,802 pages at 240,000 | 7 |

What a page lists is unchanged: `packages/server/test/audit-place-pages.test.ts`
holds every place, scope, decision and detail filter to its condition over
the whole log, a page at a time to the end, on both engines.

### Still growing (T255)

None of these grows in the sweep's shapes; each is a filter the API takes:

- **A key's page behind 0.14's reads of several other keys** (228 → 2,219
  pages): such a read names its keys only in its metadata, so a key's page
  reads every one at its environment. 0.16 writes none once its vault serves
  0.15's uses (every Workers and Node vault), so these stop growing at the
  upgrade; `holdsFlat` holds the page flat with their number fixed.
- **An environment left out of a reader's scope inside a project they read**
  (`within.except`): the project's streams read past its entries.
- **A member's page at a place** (actor and place together): one stream per
  member, past their entries elsewhere.
- **A place's or a reader's page of one decision**: its streams read past
  the other decision's entries. Flat in the sweep, by the planner's choice.
- **Detail with `?decision=deny`**, and **a reader of more than 100 places**
  (past 200 streams, the page walks the log once, as before).

### What the indexes cost a write (T256)

Eight partial indexes (Postgres 0085, SQLite 0044): the shown entries about a
project, an environment and a key, by the place's uuid as 16 bytes
(`uuid_send`, `placeKey`); those naming each besides, by `also`'s text
(`besideKey`: nothing holds `also` to name uuids, and a cast that failed in an
index would fail the insert); 0.14's reads of several keys by environment;
and refusals by decision. Each is partial, so an insert pays for those whose
condition it meets. Measured on a copy of `audit_log` with every index, 200,000
entries deep, single-row inserts, pgbench at 4 clients (own Postgres 16.14,
`placeKey` as 16 bytes; T254's pull request has the method and the text-key
variant):

| One audit insert | Without | With T254's indexes |
|---|---|---|
| A shown write at a key | 1,658 B WAL, 221 µs | 2,037 B (+23%), 247 µs (+11%) |
| A refusal at a key | 1,487 B, 216 µs | 1,943 B (+31%), 243 µs (+13%) |
| A read through a reference (`also`) | 2,256 B, 238 µs | 3,119 B (+38%), 279 µs (+17%) |
| A detail entry (a heartbeat, `mcp.read`) | 1,328 B, 189 µs | +0 B, 202 µs (+7%) |

A use's insert (`log_uses`, `log_reads`) gains no index. But a request pays
more than its inserts: Postgres plans every statement anew, and weighs every
index of `audit_log` for each time a statement reads it. The vault's snapshot
reads it several times over, twice a request, and planned in 2.7 ms each
before T254. Measured on one request at a time, 2,000 entries in
(`pg_stat_statements`):

| One request | Postgres planning | Postgres CPU |
|---|---|---|
| A key's write (`POST /secrets`) | 9.1 → 12.4 ms (+36%) | 15.2 → 19.0 ms (+25%) |
| A key's reveal | 6.7 → 10.0 ms (+50%) | 10.5 → 14.1 ms (+34%) |

About 0.4 ms a request for each index, keyed by an expression or by a
column alike (the place's three plain on their columns plan as long), and
none of it execution (1.4 ms a write, 0.8 a reveal, before and after). The
older `audit_log_{project,environment,secret}_idx` and the three of `also`
still key every entry about a place, detail included, beside the new ones;
T256 (0.17) drops them or narrows them to the entries the new ones leave out,
which takes back most of the WAL above and part of the planning. T257 (0.17)
plans the snapshot's statements once, so that the planning stops growing with
each index `audit_log` gains.
