# The growth sweep

Rule R48: no statement on the runtime logins (the app's `coffre_runtime`, the
vault's `coffre_vault_runtime` and its hot path's `coffre_vault_hot`) may cost
more as history grows. 0.16 puts those logins under a 5 s
`statement_timeout`, so a read that walks a log is a read that fails once the
log is long enough. The sweep finds such reads by measuring, rather than by
reading the code: it runs the same request paths on a history of one size and
on one ten times longer, and lists every statement that read more at the
larger.

```sh
COMPOSE_PROJECT_NAME=coffre_mine COFFRE_POSTGRES_PORT=56432 pnpm sweep:growth            # 2,000, then 20,000
COMPOSE_PROJECT_NAME=coffre_mine COFFRE_POSTGRES_PORT=56432 pnpm sweep:growth --size 4000 --out ~/sweep
```

It needs a Postgres of its own (it refuses the shared one on :55432): it turns
auto_explain on for its own databases, which logs a plan for every statement,
and reads the server's log through `docker compose logs`. `pnpm validate` runs
it on a Postgres of its step's, with `--full` and on a diff to the migrations, to
source the sweep runs or to its own files (`scripts/affected.mjs`); `pnpm test`
never does.

## The list of known growers

Until 0.16's redesign is done, some statements still grow.
[`scripts/growth-sweep-known.txt`](../scripts/growth-sweep-known.txt) lists
them, a line for each statement of each request path: the statement's id (the
first 12 hex digits of the SHA-256 of its text, literals left out), then the
path. A comment above each statement's lines gives its text and, written in
by hand, where the code asks it (`#   from <file>:<line>`): most statements
leave the database layer from a queue, whose stack no longer names the code
that asked them. The sweep exits 1 when a statement grows that the list
does not name, or that only the larger run ran (`NEW`: a branch the history's
size took, a window past its limit or a prune, whatever its pages); one it
names is printed, marked `(known)`, and passes. So:

- a change that makes a statement grow fails the sweep, the statement marked
  `NOT KNOWN`;
- a change that fixes one deletes its lines: the sweep prints `FLAT` for each
  line whose statement grew no more, and passes;
- `--write-known` rewrites the list with what grew in that run, keeping the
  comments of each statement it already listed, and refuses to when the run
  failed or cannot be compared (a `GONE`, `COLD`, `CANCELLED`, unparsed plan
  or changed answer): such a run measured only part of the paths; a new one's reads
  `from ?` until someone fills it in. A statement whose plan flips between
  runs, growing in one and flat in the next (two today, their lines say
  which), drops out of a list written from a flat run: put its lines back.

The list is a burn-down: once it is empty, every runtime statement is flat in
history, and the timeout goes on.

## What it does

[`scripts/growth-sweep.sh`](../scripts/growth-sweep.sh) runs
[`packages/server/test/growth.sweep.ts`](../packages/server/test/growth.sweep.ts)
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
   hot path's login. The sweep counts the hot path's statements and fails when
   a reveal, or the instance's, ran none.
3. **A history `COFFRE_SWEEP_SIZE` long in each shape** that has hidden a walk
   before, oldest first: another member's reads in 0.14's log, a thousand to an
   `occurred_at`; the vault's findings about one member, 0.14's and 0.15's; the
   access grants and refusals about someone no member row names; 0.15's changes
   of other objects and rotations of the log's key; one member's reads of the
   same four keys at their versions (one through a reference), a thousand a
   day, over a day for each thousand; uses, spread between the
   checkpointer's floor and its next barrier; someone who only ever signed
   in, and an MCP client's reads of the `shop` project, which their own pages
   hide; and, newest, the scheduler's heartbeats, which an ordinary audit
   page and the scheduler's own hide. Then the watch and the
   vault catch up with it, as a deployment's do between beats, so that what a
   beat walks is what came since, and the checkpointer seals 0.15's log to its
   head, as a deployment's does every 500 ms, so that its tick and the trees'
   check read what came since the newest checkpoint, not the whole history.
4. **Settled.** `VACUUM (ANALYZE)` of every table, then autovacuum off for each:
   no dead row, no missing statistic, and no autovacuum run in the middle of
   the measured rounds, which flipped plans and buffer counts by a few pages
   from run to run in the cost tests before (T200, T209, T225).
5. **Every request path, three times**: every GET route of the API (from the
   client's route table, its parameters filled, and the query a route needs:
   a real CLI sign-in's code, `?from=start` for the reads' check), as an Owner
   and as a viewer;
   the audit page under each filter, as an Owner, a viewer and an auditor of
   one project; each member's page; a sign-in, reveals, a key write, an access
   change, a heartbeat, readiness, the vault's checkpoint, the checkpointer's
   tick and the reads' projection, with and without a key it replaced; then
   an offboarding, and the removed member's report, of a member of their own
   in each round. The first round warms the plans; a statement in the other
   two, between the marks `/* sweep:<path> */` the file logs, is measured:
   twice, so that each path has a run of each of its statements on a backend
   that ran it before. Its pools hold one connection each, kept until the end
   (`keepTestConnections`), as a request takes turns on one through
   Hyperdrive.

   Not measured: the optional plugins' routes (workload bindings and lookups,
   enrollments, freezes, MCP's authorizations, approvals and apps), which the
   test deployment does not add, so that they answer 404 or 501 before any
   read; and the writes the list above does not name (tokens, bindings, roles,
   settings, environments and projects), which run in the instance's seed
   alone. The sweep holds each GET route an Owner asks to a 2xx, but those
   plugins' to the status `UNREACHED` names, fails when the client's route
   table has a GET route its pattern does not read, and fails when any path
   throws: a route that stopped short would answer the same at both sizes,
   its reads unmeasured.

[`scripts/growth-sweep.mjs`](../scripts/growth-sweep.mjs) then reads both
logs. A statement is its path and its text with its literals left out, and
each list of parameters one (an `IN` as long as a page's rows is one
statement however long, and so is a run of `UNION ALL` arms alike, one a row).
By path, so that a statement many paths run, a
member's access say, is measured in each, and one path's walk is not hidden
under another's larger, flat run of it. Its cost is the most pages (shared
buffers hit or read) one run of it read in its path, and how many times it
ran there. It **grows** when the larger run read at least twice the pages and
eight more, or ran it at least twice as often. A flat statement gains an
index level at most, a page for each index it steps down, and its rows; the
rule is growth, not a budget of pages, so the sweep compares the two sizes
and never an absolute count.

A statement too slow at the larger size leaves no plan behind if something
cancels it, so a sweep that only compared plans would read it as one that did
not grow. So the sweep also fails, known list or not, when either run's
runner failed, when a path answered otherwise at the two sizes (each path's
outcome is in the run's `<size>.outcomes.json`), when a statement the smaller run
completed is missing from the larger's log (`GONE`), when either log holds a
statement the server cancelled, or a plan it cannot parse.

A statement's first run on a backend reads the catalog to plan a function's
statements (`prune_bulk`'s first call reads 1,295 pages on an empty database
as on a grown one, 18 after): only its later runs count. A path whose runs of
a statement at either size were all first runs on their backends is not
compared, and fails the sweep (`COLD`).

The seeded rows of 0.15's log carry the vault's MAC, as a deployment's do, or
the checkpointer would refuse the first and leave them all as a backlog above
its newest checkpoint, which its tick and the trees' check would read whole
(91 to 196 pages, and 62 to 389, until T288). A run that leaves any seeded
row unsealed fails before it measures. A backlog to drain has tests of its
own, in `packages/vault/test/log-store.test.ts`. Uses sharing one `at` are
T248's case, a todo test there (it runs, but its failure does not fail the
suite), and no test holds the trees' check to its pages over a large backlog
of uses.
