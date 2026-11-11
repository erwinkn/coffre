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
   Its reveals come in behind Access, a way in, so they are 0.15's uses, on the
   hot path's login; a caller who came in no way reads as 0.14's do, through
   the vault's unwrap, and the hot path's reads went unmeasured (review r4 of
   #559). The sweep counts the hot path's statements and fails when a reveal,
   or the instance's, ran none.
3. **A history `COFFRE_SWEEP_SIZE` long in each shape** that has hidden a walk
   before, oldest first: another member's reads in 0.14's log, a thousand to an
   `occurred_at`; the vault's findings about one member, 0.14's and 0.15's; the
   access grants and refusals about someone no member row names; 0.15's changes
   of other objects and rotations of the log's key; one member's reads of the
   same four keys at their versions (one through a reference), a thousand a
   day, over a day for each thousand; uses sharing one `at`, unsealed; someone
   who only ever signed in, and an MCP client's reads of the `shop` project,
   which their own pages hide; and, newest, the scheduler's heartbeats, which
   an ordinary audit page and the scheduler's own hide. Then the watch and the vault catch up with it, as
   a deployment's do between beats, so that what a beat walks is what came since.
4. **Every request path, three times**: every GET route of the API (from the
   client's route table, its parameters filled), as an Owner and as a viewer;
   the audit page under each filter, and the pages of the signer, the
   scheduler and `shop`, each behind entries of its own it leaves out; each
   member's page; a sign-in, reveals, a
   key write, an access change, a heartbeat, readiness, the vault's checkpoint,
   the checkpointer's tick and the reads' projection, with and without a key it
   replaced; then an offboarding, and the removed member's report, of a
   member of their own in each round (three of one history). The first round
   warms the plans; a statement in the other two, between the marks
   `/* sweep:<path> */` the file logs, is measured: twice, so that each path
   has a run of each of its statements on a backend that ran it before. Its
   pools, the hot path's included, hold one connection each, kept until the end
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
([`packages/server/test/db/growth.ts`](../packages/server/test/db/growth.ts)),
on Postgres: only that run holds a read to its growth. Their SQLite run reads
plans, which name no rows, so it refuses a log read whole (a `SCAN`) and passes
a walk of an index's range however long (a `SEARCH`).

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
| A member's activity in 0.14's log (`memberActivity`), on every member page | 265 | 2,484 | A sequential scan, for its `OR` with every restore: now a probe of `audit_log_seen_idx` for each of the member's names, then the restores its current values come from, walked back from each key's current version (T252 replaces the walk) |
| Every member's findings (`tamperedMembers`), the members list's | 151 | 1,454 | A skip of `audit_log_tamper_idx` from one member reported to the next, then a probe each |
| An ordinary audit page, past the heartbeats since | 82 | 696 | `audit_log_shown_idx`, the entries a page shows |
| An audit page's count of what it hides (`auditActionCounts`) | 99 | 336 | The newest `HIDDEN_COUNTED` of its stretch at most, and `hiddenMore` |
| A member's reads by key and version (`readsBy`), an offboarding report's | 66 | 494 | Open: T252's (below) |
| The keyring's rotations (`rotations`, `keyringRows`) | 56 | 452 | No more than `ROTATIONS_HELD` (246) rotations in a log's life |
| The window a proof or the projector reads (`entries`), past uses sharing an `at` | 70 | 396 | Its first entries by number, `log_uses_by_number_idx` (T245), its bounds read first and given as values, so that it plans its own days alone |

Two of an offboarding report's reads still grow, and are T252's. `readsBy`
grows with what the member did: it reads every read of theirs, a day at a
time. The walk back from each key's current version to the restores its
value came from grows with the key's history, whoever made it: it reads
every entry naming the key at each step, so that everyone's writes and
reveals of a key the member once read add to it, after they left too. A restore copies the old version's ciphertext and rewraps only its key,
so two versions hold one value exactly when their ciphertexts match: T252
replaces the walk with a probe of each version seen, and `readsBy` with the
newest read of each key and version, which a trigger keeps as reads are
written.

Review r1 of #559 (Fable) found two more the sweep had no history for: an
audit page filtered to someone, or to a place, behind entries of its own the
page leaves out. A filter's page walked its own index (`audit_log_actor_idx`,
the project's, the environment's) past each of them: the scheduler's page past
its heartbeats, 199 pages 4,000 in and 1,955 at 40,000; a member's past their
sign-ins, 165 and 1,628; a project's past its MCP reads, 132 and 1,303. An
actor's page is now a step of `audit_log_shown_actor_idx`, `(actor, seq)`
over what pages show, and flat, under a place too (a member's page under
`market`, behind their sign-ins: 3 pages then 4 at 4,000 and 40,000). A place's
still walks, past the entries of its own it hides or past everyone else's it
shows, and is in the sweep as `?path=shop`: T254's. A place is matched by its
columns and by the references and lists in an entry's metadata, which no index
of the same kind covers.

The sweep after those fixes found one of their own: `audit_log_shown_idx` took
a place's page too. Postgres walked it back past every place's entries shown
since the place's newest: `?path=market` read 8 pages at 2,000 and 2,267 at
20,000, where main reads the place's own indexes (`audit_log_project_idx` and
`audit_log_also_project_idx`, as a bitmap) in 9. A place's page with no actor
now writes main's own condition, `action NOT IN (…)` (`shownOffIndex`), which
implies no index's condition, since `KINDS.shown` adds `seq >= 0` to it. Review
r2 (Fable) found the first fence, `action || '' NOT IN (…)`, worse than main
where few entries are shown: an expression hides the column's statistics, so
Postgres priced the page as if most entries were shown and walked the primary
key back. In a log led by heartbeats, one entry in ten shown, a place's page
read 5 pages at 24,000 and 7,812 at 240,000 under it; under main's condition it
reads 5 and 6, the same in five runs with fresh statistics
(`history-aggregates.test.ts`, "a project's audit page in a log of
heartbeats"). It also fenced an actor's page under a place off its index (158
pages then 1,538); the fence is now for pages with no actor alone. Where half
the log is shown, past about 200,000 entries, main's plan is itself a walk
back of the primary key (7,802 pages at 240,000): T254's. The fence is
Postgres's alone: on SQLite main's condition brings back a SCAN of the whole
log, where the plain condition searches `audit_log_shown_idx` back from the
newest, the better plan there.

`?path=shop` (a place behind its own MCP reads) reads 522 pages at 2,000 and
5,022 at 20,000, a walk back of the primary key past every entry since the
place's newest shown one. That is main's plan: the same shape rebuilt on a
scratch database plans the same walk under main's condition and indexes, 403
pages and 4,010 at 12,000 and 120,000 entries. With `shown`'s own condition it
walked `audit_log_shown_idx` in half that (207 and 2,044), but past every other
place's entries too, `?path=market`'s 2,267 above.

Every page of a reader of one place (a project's auditor or admin) is a place's
page, the place their access (`within`). The sweep asks every page as an
auditor of `market`, and two walk back the primary key past everyone's entries
since market's newest, as on main, T254's: a small limit makes the walk look
cheap (`?limit=5`: 517 pages at 2,000, 5,016 at 20,000), and a page with no
action condition takes it once the log is long enough (`?detail=1`: market's
own indexes at 2,000, 8 pages, then the walk at 20,000, 5,023). Both send
main's SQL. The auditor's other pages, its actors' among them, are flat.

And the checkpointer's `lowestAbove`: a walk of `log_uses_at_number_idx` from
one `at` to the next. The sweep measures it on the first window only (once
that window is full, below), since the checkpointer refuses the forged
backlog before draining it. Its own test drains one: 7,069 pages past 390,000
uses sharing one `at`.

Flat once a backlog is walked (each a batch of a bounded walk, which the first
sweep measured before the watch caught up): the heartbeat's and the
verification's walks of the log, and the vault's releases' prune.

Bounded, not flat, and still listed as growing: the count of the log's prefix
that the checkpoint, the heartbeat and the verification take (`missingEntry`,
`count(*) … seq BETWEEN`), which counts at most `COUNTED_AT_ONCE` (1,000,000) entries
at once (T245), so the whole log until it is that long: 42 pages at 2,000, 241
at 20,000; and the window a proof or the projector
reads, up to `WINDOW_MAX` entries (91 and 196 pages), with `lowestAbove`'s walk
(3 pages) once the window is full.
