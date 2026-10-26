# The simple hot path: Postgres only (0.15, W201)

An experiment, not a decision. Written by W201 on 2026-10-26, on a draft
PR marked DO NOT MERGE. It answers one question: can 0.15's hot path stay
plain Postgres (no Durable Object, no cache) and still meet R44? R44 asks
for:

- 1,000+ `/use` a second on Workers;
- hundreds of them concurrent, one principal included;
- no instance-wide step held across a round trip;
- overload refused fast;
- a cost per request that stays flat as the log grows (R48).

**Follow-up (W208):** [`hot-path-one.md`](hot-path-one.md) makes a use one
round trip and drops the revision: `seq`'s read and append become one
plpgsql call under the same shared lock, with every number taken under it.

It is measured against today (0.14, "v0") and against W194's shards
(`docs/design/hot-path.md` on [PR #350](https://github.com/erwinkn/coffre/pull/350), "v5"), on the same rig, the same day.

- **Prototype:** [`experiments/lanes/src/simple.ts`](../../experiments/lanes/src/simple.ts),
  with its SQL in [`experiments/lanes/schema.sql`](../../experiments/lanes/schema.sql).
- **Benches:** [`experiments/lanes/bench-simple.ts`](../../experiments/lanes/bench-simple.ts)
  runs from Node, through a relay that adds a round trip; the Worker's
  `/simple/…` routes run on Cloudflare.
- **Model:** [`formal/HotPath.tla`](../../formal/HotPath.tla), checked by
  [`scripts/formal-hotpath.sh`](../../scripts/formal-hotpath.sh).

## In short

- **A use is two statements.** One read (standing and the revision, in one
  snapshot) and one append (the entry, under a fence), each committed on
  its own. No lock is held across a round trip. One audit entry per use;
  the app writes none.
- **Revocation is a revision fence.** Every change raises one number, the
  revision, and commits before it answers. An append writes nothing if the
  revision moved since its read. So a use that reads after a revoke's
  answer is refused, and a use that read before it and appends after it is
  refused too.
- **Two ways to give an entry its place.**
  - `head` is the brief's design: the head row is locked by the append
    statement alone, and the chain link is a plain hash computed in SQL.
  - `seq` has no head: the read takes the entry's number from a sequence,
    the MAC covers that number, and a checkpoint signs the entries every
    second.
  - **`seq` is the one to build.** It scales with Postgres's CPU.
  - `head` also serializes every use behind one commit flush. Where a flush
    takes 1 ms (network storage, as managed databases have), it tops out
    near 650 uses a second.
  - And `head` rewrites one row a thousand times a second. While a backup
    holds a snapshot open, those dead versions pile up: a use went from
    5 ms to 571 ms within 90 s. `seq` did not move.
- **Measured.**
  - **Locally,** on a Postgres held to Equisafe's size (2 vCPU, 2 GB),
    `seq` serves 2,000 uses a second clean in three runs (1,981–2,008
    served): p50 5.5 ms at a 2 ms round trip, 0.4–0.7 ms of Postgres CPU
    per use. At 2,500 it is saturated.
  - **On Workers,** it serves 1,000 a second for 5 minutes, with 2 edge
    errors in about 300,000 requests, from 100 principals or from one.
  - **What limits it on Workers** is Hyperdrive's pool, by Little's law:
    connections ÷ (2 statements × the round trip from Hyperdrive to
    Postgres).
- **What it costs against shards.**
  - **Worker CPU:** 2.9 ms p50 and 8.1 ms p99 per use (the `pg` client),
    against shards' 0.7 and 1.9.
  - **Latency:** two Postgres round trips per use instead of one Durable
    Object call. Equal near the database; worse far from it.
  - **Availability:** the hot path fails when Postgres does, as it does
    today.
  - **Integrity:** someone with write access to the database but not the
    vault's key can delete an entry younger than about 6 seconds, or undo
    a change that young, without trace. They cannot forge, alter, reorder
    or replay one. Today they can only cut the newest entries. This holds
    only if the newest checkpoint is also anchored outside the database
    (the audit watch's anchor); otherwise it is weaker than today.
  - **Overload is not refused fast** on Workers: Hyperdrive queues instead
    (below). Shards had a version of this too.
- **One thing it gains** over shards: nothing new to run, to model, to
  migrate, or to keep consistent with Postgres. And no partial log order:
  every entry has one place, (revision, number).

## Today, and why it can't scale

A cold `/use` on 0.14 holds the instance's one audit head across about seven
round trips: two in the vault's decision, five in the app's own
`credential.use` entry. At 20 ms a round trip, the whole instance tops out
near 5 uses a second (W194, measured: 5.4). Measured again here on
Cloudflare, at 5 a second from one principal, it served 0.8 a second, p50
16.7 s, with 93 timeouts out of 150.

## The design

### A use

```
Worker   authenticate the caller (CPU only)
read     SELECT standing, revision, nextval('audit_seq') …     one round trip, no lock
Worker   decide (decide.ts), open the key, MAC the entry over (number, revision, what it says)
append   SELECT append_use(number, revision, …, mac)           one round trip
           pg_advisory_xact_lock_shared(fence)                 shared with every other use
           revision still the one read, number above the floor?
           INSERT the entry; COMMIT                            the shared lock goes with it
Worker   only now release the value
```

The read is today's decision read in one statement: member row (MAC'd over
its grants), grants, credential, the newest access entry it names,
environment, secret and its wrapped key, and the revision. The append is a
plpgsql function, so it is one statement and one round trip. A use whose
fence fails reads and appends once more, then answers 503 `changing` with
`Retry-After`. Denials are appended too, as today.

### A change

```
read     SELECT revision, nextval('audit_seq')                 one round trip
Vault    MAC the entry and seal the member row at revision + 1
change   SELECT change_grant(…)                                one round trip
           pg_advisory_xact_lock(fence)                        exclusive: waits for the uses in their append
           revision still the one read? else nothing, and read again
           the grant, the member row, the entry; revision := revision + 1; COMMIT
answer
```

The exclusive lock waits only for appends already holding the shared lock,
each a few hundred microseconds. Postgres queues a waiting exclusive lock
ahead of later shared ones, so a burst of uses cannot starve a change. A
change never holds anything across a round trip either.

**What must be a change.** The fence protects only what is written through
it. Every input a decision reads must change through a statement shaped
like `change_grant`: under the exclusive lock, with the revision raised and
an entry written. Those inputs are member rows and their status, grants
and roles, the policy, places (projects, environments, their deletion),
secrets and their versions and natures, and credentials (revocation,
expiry). A writer that updates one of them directly reopens the hole the
fence closes: a use that read before it would still be allowed after it.
The prototype has grants and credential revocation as fenced changes (both
measured below). 0.15's spec must list every writer, and a trigger like
W194's can refuse a write that did not come through the change function.

**Isolation.** The fence relies on READ COMMITTED:
- **`seq`:** each statement of the volatile `append_use` takes a fresh
  snapshot, so its check, made after the lock's statement, sees every
  change committed before the lock was granted.
- **`head`:** the head's lock re-reads the locked row.

Run either inside REPEATABLE READ, or inside a transaction that spans the
read and the append, and the check goes stale without a sound.
[`fence.ts`](../../experiments/lanes/fence.ts) shows both cases on
Postgres, each with the wrong way next to it.

### The log's order

Every entry carries (revision, number), and the log's order is exactly
that: first by revision, then by number. Example:

| entry | revision | number | |
|---|---|---|---|
| svc-a uses STRIPE_KEY | 811 | 4,001 | |
| svc-b uses DFNS_KEY | 811 | 4,003 | took its number later, appended first: still 811 |
| Ada revokes svc-b's grant | 812 | 4,002 | took its number before svc-b, committed after |
| svc-b uses DFNS_KEY | 812 | 4,004 | denied |

Every use is ordered against every change by revision. That is the order
that matters ("was this use allowed under the grants of the time?"), and it
is total. Among uses of one revision, the number orders them by when they
read.

### Checkpoints

Every second, the vault (on Workers, a Durable Object's alarm; on Node, a
timer) runs `close_checkpoint`. Under the exclusive lock, for one
statement, it raises the floor to the number the sequence had reached 5
ticks earlier. After that, no append at or below the floor can commit:
each append checks the floor under its shared lock. Then, outside any
lock, it reads the entries between the last floor and the new one, checks
each MAC, and signs a hash over all of them (numbers and MACs), chained to
the previous checkpoint.

The 5-tick lag means a use slower than 5 s between its read and its append
is refused and reads again. On Cloudflare a 1-tick lag refused 0.7–4.5% of
uses in the first runs, because the rig's slowest round trips run past 1 s;
with 5 ticks, none.

The checkpointer keeps no state of its own that matters. It starts from
the last checkpoint row, so one that restarts carries on from what was
signed. A floor that was closed but never signed (a crash between the two)
gets signed by the next tick. An entry that fails its MAC stops the
checkpoint: nothing is signed over it, and the operator is alerted.
[`verify-simple.ts`](../../experiments/lanes/verify-simple.ts) checks the
log from the database alone:
- each checkpoint starts where the one before ended;
- its hash is the entries it covers, chained to the one before;
- its signature is the vault's;
- every entry carries its MAC.

Each part was checked:
- **Every local run** verified from the tables after the run.
- **A floor closed by hand,** then a fresh checkpointer: it signed up to
  that floor.
- **One sealed entry deleted:** caught ("1,043 entries, signed 1,044";
  hash).
- **A checkpoint row deleted from the middle:** caught (the tiling breaks).

Cost at 1,000 uses a second, with the checkpointer connected to Postgres
directly (a production one would be a Durable Object's alarm going through
Hyperdrive, which adds three round trips a tick and changes nothing else):
- **Per checkpoint:** ~990 entries, 3.0 ms of database time p50 (16 ms max),
  4 ms to verify and sign (about 4 µs an entry).
- **On the database:** 3 statements a second, against 2,000 for the uses.
- **Verified:** all 299,085 entries of the 5-minute Cloudflare run.

## Integrity, plainly

An attacker with write access to the database but not the vault's key. Two
things to separate:
- **Integrity:** whether the log shows what happened.
- **Authorisation:** whether a use is allowed. Someone who can write the
  `grants` table can already allow uses. The fence state (the revision, the
  floor, the sequence) is authorisation state like `grants`: tampering with
  it changes what is allowed or refused, and the log's checks must catch
  that afterwards.

| | Today (0.14: MAC chained over the hash before) | `seq` | `head` |
|---|---|---|---|
| Forge an entry | no | no | no |
| Alter an entry | no | no | no |
| Reorder entries | no | no: the MAC covers the number | **yes, until the next checkpoint**: the MAC covers what an entry says, not its place, and the link is a plain hash they can recompute |
| Replay an entry at another number | no | no | yes, until the next checkpoint |
| Delete the newest entries | yes, until the next checkpoint or the anchor sees it | yes, until sealed | yes, until the next checkpoint |
| Delete an entry from the middle | no: the next entry's MAC breaks | **yes, until sealed** (~6 s): a deleted number looks like a gap, and gaps happen (a refused fence, a dropped connection) | yes, until the next checkpoint |
| Undo a revocation: delete its entry, put back the member row and grant from before | only with every entry after it (a cut tail), within the anchor's window | **yes, until sealed**: one entry and two rows | yes, until the next checkpoint |
| Lower the revision or the floor, set the sequence back | n/a | an append the fence would refuse goes in. A reused number collides with its entry (primary key) or fills a gap in a sealed window, which the verifier catches (the checkpointer starts from its last row, not from the floor). An append let through a lowered revision shows afterwards as an entry at a revision older than a change numbered before it | the same for the revision |
| Delete checkpoint rows | the same exposure | from the middle: caught (tiling). **The newest ones: not caught inside the database** | the same |
| Anything under a checkpoint the anchor holds | detected | detected | detected |

The last two rows are why the newest checkpoint must also live outside the
database. That is the audit watch's anchor (R39, R40): today it anchors
the chain's head; with `seq` it must anchor the newest checkpoint, as
often as checkpoints are made, or an attacker deletes the newest
checkpoints along with their entries. With that anchor, "sealed" means
sealed. Without it, `seq` is weaker than today, where the chained MAC
alone catches a deletion from the middle.

So, with the anchor, `seq` moves one thing from "no" to "yes, for about
6 seconds": deleting one entry (or undoing one change) while keeping the
ones after it. Example: at 14:02:01.300 svc-b reads DFNS_KEY. At 14:02:03
an attacker deletes that one entry and keeps the 2,000 after it. The
checkpoint at 14:02:07 signs the window without it, and nothing ever shows
it. Today, the same attacker could delete it only by deleting everything
after it too, which the next checkpoint or the anchor would see.

The window is the lag (5 ticks of 1 s), plus one tick, plus however late
the alarm fires: about 6 s on time.

It is configurable: a checkpoint every 0.5 s with a 2-tick lag gives
about 1.5 s, at twice the checkpoint statements (still ~6 a second).

Keeping a MAC chained over the previous entry, as today, costs a round
trip that serializes. The `cas` variant measures that: the read returns
the head, the append moves it only if nobody else did, and retries
otherwise. Contention collapses it:

| round trip | offered | served | why |
|---|---|---|---|
| 2 ms | 500/s | 272/s | 4,523 refused after 6 tries; 8.4 statements a use |
| 2 ms | 1,000/s | 6/s | retries saturate the pool |
| 20 ms | 500/s | 4/s | |

That is the "1/(2 × RTT)" limit of any single chain W194 measured. It
cannot reach 1,000 a second.

## Measurements

### Setup

- **Postgres:** 16.14 in Docker, **held to Equisafe's size with `--cpus=2
  --memory=2g`**, on this machine's NVMe (fdatasync 24 µs).
  `shared_buffers` 512 MB, `synchronous_commit` on.
- **Slower disks:** emulated with `commit_delay = 1000` µs and
  `commit_siblings = 0`. Every commit then waits 1 ms before its flush,
  which concurrent commits share (group commit), as on network storage.
  Slightly pessimistic: the flush's leader always pays the whole delay.
- **Postgres CPU:** read from its container's cgroup. "Per use" divides it
  by every use attempted, including those that then timed out, so past
  saturation it reads low against what was served.
- **The rig's own CPU:** the load generator stayed under 32% of a core and
  the relay under 20% in every run, so neither limits what is measured.
- **Statements:** from `pg_stat_statements`.
- **Local load:** an open loop (Poisson arrivals) from Node, through a pool
  of 40 connections (Equisafe's Hyperdrive), to a relay that delays each
  packet by half the round trip. A use waits at most 250 ms for a
  connection, then answers 503.
- **Each run:** 100 principals, a revocation of svc-0 halfway, and a
  checkpoint every second.
- **Cloudflare:** a Worker in Warsaw (WAW), Hyperdrive with caching off,
  then a Cloudflare Tunnel to the same container. Load from this machine
  with W194's `load.mjs`.
- **The rig's network:** 35–40 ms from the Worker per statement p50, but
  each Worker connection gets either that path or a ~220 ms one (p90).
  The tail below is that, not the design. It also got slower during the
  afternoon: by 16:00 most connections were on the slow path.
- **Repeats:** each local headline row was run three times (the ranges
  below). Each Cloudflare row is one run.

**"Named"** means the hot path's statements are prepared once per
connection. Coffre sends unnamed statements today, which Postgres parses
and plans at every call. Hyperdrive supports named ones.

### Local, 2 vCPU / 2 GB, pool 40

Round trip 2 ms (a Hyperdrive pool next to its database):

| variant | disk flush | offered | served | p50 | p99 | Postgres CPU per use | |
|---|---|---|---|---|---|---|---|
| seq | 25 µs | 1,000/s | 1,000/s | 5.1 ms | 7.7 ms | 0.89 ms | unnamed |
| seq | 25 µs | 2,000/s | 1,929/s | 377 ms | 475 ms | 1.0 ms | unnamed: CPU saturated |
| **seq, named** | 25 µs | **2,000/s** | **1,981–2,008/s** | **5.4–5.6 ms** | **38–111 ms** | **0.40–0.71 ms** | 3 runs; 80–144% of one core |
| seq, named | 25 µs | 2,500/s | 1,793/s | 236 ms | 536 ms | 0.76 ms | Postgres at 187% of a core: saturated |
| seq, named | 25 µs | 3,000/s | 993–1,121/s | 444 ms | 605 ms | 0.67 ms | 198–200%: saturated, then collapses (no admission control) |
| seq, named, pool 80 | 25 µs | 2,500–3,000/s | 1,122–1,410/s | 352–449 ms | 623–637 ms | | a bigger pool does not help: Postgres is the limit |
| seq, named | 1 ms | 2,000/s | 1,998/s | 6.1 ms | 100 ms | 0.59 ms | the flush does not matter |
| head, named | 25 µs | 1,000/s | 993/s | 5.0 ms | 9.7 ms | 0.48 ms | |
| head, named | 25 µs | 2,000/s | 1,628/s | 433 ms | 539 ms | — | the head: one lock holder at a time |
| head | 1 ms | 1,000/s | 662–689/s | 520–525 ms | 808–904 ms | — | 3 runs. **Every use waits its turn for one flush** |
| head | 1 ms | 2,000/s | 645/s | 537 ms | 739 ms | — | |
| cas | 25 µs | 500/s | 272/s | 12 ms | 37 ms | 2.6 ms | |

Round trip 20 ms (W194's local setting): both variants serve 500/s at p50
42 ms, and cap at ~915/s at 1,000/s offered. That cap is the pool:
40 ÷ (2 × 21 ms) ≈ 950. Postgres was under half a core.

**Revocation.** Every run revoked svc-0 halfway, on a pool of its own (as
a separate Hyperdrive config would be), and was checked twice:
- **Uses sent after the answer:** 0 of them allowed, in every row (between
  46 and 498 uses each).
- **The log, for the case that count cannot see** (a use that read before
  the revocation and appended after it): no allowed svc-0 entry at an older
  revision was written after the revocation's entry. Each row checks it
  with `written_at`, stamped inside the lock. 0 such entries in every run,
  including those with 4–19 svc-0 uses in flight while the revocation ran.

A revocation took 22–278 ms under load. Revoking svc-0's credential
instead of its grant, through the same fenced change, held the same way
(0 allowed, 0 written late).

That case is also tested on its own, deterministically.
[`fence.ts`](../../experiments/lanes/fence.ts) starts an append while a
change holds the lock, waits until Postgres shows the append waiting on
that lock, then commits the change:

| append | after the change committed |
|---|---|
| `head`, the revision in another table (the brief's example) | **wrote its entry** |
| `head`, the revision in the head row (`APPEND_HEAD`) | wrote nothing |
| `seq`, the check in the lock's own statement | **wrote its entry** |
| `seq`, `append_use` (the check in a statement after the lock's) | wrote nothing |

### Cloudflare

| run | offered | served | client p50 / p99 | Worker p50 / p99 | failed | Postgres CPU |
|---|---|---|---|---|---|---|
| v0 (today), 1 principal | 5/s | 0.8/s | 16.7 s / 20 s | 16.6 s / 19.9 s | 110 of 150 (93 client timeouts, 17 lock timeouts) | 1% |
| simple seq, named, pool 40 | 1,000/s | 633/s | 7.3 s / 13.9 s | 1.5 s / 2.3 s | 3,075 (client timeouts) | 65% |
| simple seq, named, pool 40, 1 principal | 1,000/s | 626/s | 6.9 s / 13.3 s | 1.4 s / 2.2 s | 3,144 | 30% |
| simple seq, named, **pool 100** | 1,000/s | all | 102 ms / 8.4 s | 75 ms / 6.8 s | 0 | 48% |
| simple seq, unnamed, pool 100 | 1,000/s | all | 103 ms / 1.8 s | 76 ms / 1.5 s | 0 | 96% |
| simple head, named, pool 100 | 1,000/s | all | 100 ms / 2.8 s | 74 ms / 2.7 s | 0 | 54% |
| simple seq, named, pool 100 | 1,500/s | 1,325/s | 112 ms / 7.8 s | 83 ms / 7.4 s | 0 | 138% |
| **simple seq, named, pool 100, 5 min** | **1,000/s** | **989/s** | **101 ms / 2.2 s** | **74 ms / 2.2 s** | **2 edge 502s** (of ~300,000) | 57% |
| simple seq, named, pool 40, at 16:00 | 400/s | 202/s | 5.6 s / 9.0 s | 1.5 s / 2.2 s | 6,308 | 14% |
| v5 shards (W194's), same day | 1,000/s | 996/s | 59 ms / 1.0 s | 34 ms / 228 ms | 0 | 18% |

**Worker CPU** (Cloudflare's analytics):
- **Simple path,** over 4.5 minutes of the 5-minute run (270,875 requests;
  the analytics window started after the run did): 2.9 ms p50
  and 8.1 ms p99. Most of it is the `pg` client: connecting to Hyperdrive,
  two statements, parsing their answers. Still to profile.
- **Shards,** for comparison: 0.7 ms p50 and 1.9 ms p99. Their Workers
  open no connection, and each shard call adds about 0.6 ms in the Durable
  Object.
- **Against the limits:** both are under R27's targets (10 ms p50, 20 ms
  p99). The simple path's p99 sits near the Free plan's 10 ms limit.

"All" means every request answered 200 or its expected 403. Served-per-second
figures are averaged over the run plus its drain, so they read a little under
the offered rate.

**What limits it: Hyperdrive's pool.** Hyperdrive pools in transaction
mode: an autocommitted statement holds an origin connection for its own
round trip and no longer, so a use's two statements hold one twice. With
the pool full, Little's law, solved for what was served, gives the mean
time a statement held an origin connection (t = 40 ÷ (2 × served)):
- **At 14:55,** 633 a second: t ≈ 32 ms.
- **At 16:00,** on the slower network, 202 a second: t ≈ 99 ms.

Postgres sat at 14–65% of one core both times. The statement times the
Worker measured (mean 684–729 ms at pool 40) are mostly the wait in
Hyperdrive's queue, so they cannot give t directly. The 38 ms / 220 ms
split comes from runs below saturation, and includes the Worker's own
round trip to Hyperdrive, which holds no origin connection. With 100
connections the same code served 1,000 and 1,500 a second.

One more thing the slow network showed: 190 appends failed with a
duplicate number (23505) at 16:00. The likeliest cause is that Hyperdrive
replayed an append whose answer it lost after the commit. The primary key
on the number made the replay fail rather than write twice, and the use
answered 500 without a value. It was audited, which is the safe side, but
production should recognise its own entry and answer with the value.

**Revocation on Cloudflare,** one principal at 1,000 a second, revoked at
30 s:

| | took | uses after the answer | allowed |
|---|---|---|---|
| simple, change on the uses' pool (40) | **8.3 s** | 21,546 | 0 |
| simple, change on a pool of its own (5) | 334 ms | 29,479 | 0 |
| v5 shards, K = 8 | 527 ms | 29,599 | 0 |

The first row is a finding: a change must not share the uses' Hyperdrive
config, or it queues behind them exactly when it matters most.

### Statements and work per use

- **Per use:** 2 statements, 2 round trips. Today a cold use is 17.
- **Server time:** read 0.08 ms (10 shared buffers), append 0.05 ms (4
  buffers, 2 WAL records). The rest of Postgres's 0.4 ms (named) or 0.9 ms
  (unnamed) is protocol, parsing, planning and commit.
- **Flat as the log grows (R48):** seeded with 10 million entries
  before the run, against an empty log, at 1,000 a second:

  | | log | read: ms, buffers | append: ms, buffers | p50 / p99 | Postgres CPU per use |
  |---|---|---|---|---|---|
  | seq | empty | 0.080, 10.0 | 0.049, 4.1 | 5.2 / 6.9 ms | 0.36 ms |
  | seq | 10M entries | 0.078, 10.0 | 0.047, 3.3 | 5.1 / 6.7 ms | 0.35 ms |
  | head | empty | 0.076, 10.5 | 0.205, 14.8 | 5.0 / 8.8 ms | 0.48 ms |
  | head | 10M entries | 0.079, 14.4 | 0.357, 22.2 | 4.9 / 21.8 ms | 0.48 ms |

  The checkpoint reads only its window: about 740 buffers for about 1,000
  entries, the same at either size.
- **A snapshot held open,** as a backup's `pg_dump` holds one: a
  REPEATABLE READ transaction open for the whole 90 s run, at 1,000 a
  second:

  | | first fifth p50 | last fifth p50 | append: ms, buffers | read: buffers | served |
  |---|---|---|---|---|---|
  | seq | 5.1 ms | 5.2 ms | 0.050, 4.4 | 10.3 | 996/s |
  | head | 5.2 ms | **563–571 ms** | **31–94, 855–1,882** | **562** | **624–642/s** |

  Three runs each for `head`; the ranges are theirs.

  `head` rewrites one row a thousand times a second. While any snapshot
  older than those versions is open, Postgres can prune none of them, so
  every lock and read of the head walks a longer chain of dead versions:
  the cost of a use grows with the backup's age. `seq` writes no row twice.
  Today's 0.14 head has the same exposure, at its own (low) rate.

## Equisafe's size

Equisafe runs a 2 vCPU / 2 GB managed Postgres behind Hyperdrive with 40
connections. Its Workers run in Europe, near the database. At 1,000 uses
a second:

- **Pool:** 40 ÷ (2 statements × t). Hyperdrive's pool sits next to its
  origin, so t is Paris to Paris, a few milliseconds: the pool allows
  4,000–10,000 uses a second. It is not the limit there, but it is the first
  thing to check: at t = 20 ms it allows 1,000, and at 32 ms (this rig)
  625.
- **CPU:** 1,000 uses a second (2,000 statements) took 0.35–0.71 vCPU
  here with named statements, and 0.9–1.0 unnamed (AMD EPYC 9454P, on a
  shared host). How much slower a managed instance's vCPU is was not
  measured, so here is the range. Named statements, of 2 vCPU:

  | if its vCPU is | 1× | 1.5× | 2× | 3× slower |
  |---|---|---|---|---|
  | named | 0.35–0.7 | 0.5–1.1 | 0.7–1.4 | 1.1–2.1 |
  | unnamed | 0.9–1.0 | 1.4–1.5 | 1.8–2.0 | saturated |

  **With named statements it fits, with room for the rest of the app,
  unless its vCPUs are about 3× slower.** Unnamed, it fits only on fast
  vCPUs. Past saturation, goodput collapses. Measuring a use on the same
  instance class (in a throwaway project) would settle it.
- **Disk:** `seq` does not care. Its commits flush in groups. `head` would
  cap near 650 a second on a 1 ms flush.
- **Memory:** the hot path touches the decision tables and the log's
  newest pages; 2 GB holds them.
- **Storage:** an entry is about 344 bytes with its indexes: 30 GB a day at
  a sustained 1,000 a second. Retention is the real cost, as with shards.
- **Changes:** a second Hyperdrive config for changes, of a few
  connections, so a revocation never waits behind uses.

## Overload

R44 asks that overload be refused fast, with `Retry-After`. Postgres-only
does not get there by itself:

- **On Workers,** a full Hyperdrive pool queues statements instead of
  refusing them: 730 ms each at 1,000 a second on 40 connections, and
  client timeouts beyond. No 503 came back. The Worker can answer 503 on a
  deadline of its own, but the queued statements still run.
- **Locally,** with a 250 ms limit on waiting for a connection, overload is
  refused in 250–600 ms, not milliseconds. Past saturation, goodput
  collapses: at 3,000 a second offered, against a capacity between 2,000
  and 2,500, 993–1,121 were served. Postgres stayed saturated on uses
  that then timed out.

The fix is admission control in front of the pool: a bound on uses in
flight, refusing at once above it, sized from Little's law
(pool × 1/(2t)). On Workers that bound cannot be global without a shared
counter: a Durable Object, or Postgres itself. W194's shards had the same
gap (a per-isolate bound; Cloudflare's own queue in front of a hot shard).
This is the one R44 point neither design meets as prototyped.

## The model

`formal/HotPath.tla` models uses (read; the append's snapshot, its lock,
its check, its commit, each a step), changes (read; one statement under the
exclusive lock, which may also fail and roll back; the answer) and, for
`seq`, the checkpointer (close the floor under the lock; read and sign
later). Two scenarios, `HotPathHead` and `HotPathSeq`: two uses, each
retried once, against a revoke and then a grant again.

Invariants:
- **`FenceHolds`:** every use's entry was committed at the revision its
  decision read.
- **`NothingAllowedAfterAnswer`:** no allowed use commits after a change
  that revoked it has answered.
- **`EveryReleaseAudited`:** a value leaves only with its entry.
- **`LogConsistent`:** `head`'s log in number order is a valid history.
- **`CheckpointsHold`:** what a checkpoint signed stays exactly the entries
  under its floor.
- **`NumbersUnique`.**

Both scenarios hold: `HotPathHead` 19k states, `HotPathSeq` 25M states in
111 s on 8 workers. Each protection, removed, must fail, and does (16 of
16):

| protection removed | breaks |
|---|---|
| the append checks the revision | `FenceHolds`, `NothingAllowedAfterAnswer`, `LogConsistent` |
| **it checks the revision as committed when it holds its lock** | `FenceHolds`, `NothingAllowedAfterAnswer` |
| a change takes the lock exclusively | `NothingAllowedAfterAnswer` |
| a change answers only once committed (with a change that can fail after locking) | `NothingAllowedAfterAnswer` |
| a value leaves only after its entry commits | `EveryReleaseAudited` |
| `seq`: the checkpoint raises its floor under the exclusive lock | `CheckpointsHold` |
| `seq`: the append refuses a number at or below the floor | `CheckpointsHold` |

The second row is a trap in the brief's own example. As written, `WITH h AS
(SELECT … FROM audit_chain_head FOR UPDATE) INSERT … WHERE (SELECT n FROM
revision) = $rev_read` is wrong under READ COMMITTED. The statement takes
its snapshot when it starts. If it then waits for the head, the lock
re-reads the head row when granted, but not the `revision` table, which it
still sees as of before the wait. TLC's counterexample:

1. A use reads revision 0.
2. Its append starts.
3. Ada's revoke takes the head, raises the revision to 1, commits and
   answers.
4. The append gets the head, still sees revision 0, and commits an allowed
   use after the revocation.

Reproduced on Postgres 16 ([`fence.ts`](../../experiments/lanes/fence.ts)): with the
revision in another table the waiting append wrote its entry; with the
revision in the head row (`WHERE h.revision = $rev`) it wrote nothing.
`head` keeps the revision in the head row for that reason. `seq` checks it
in a statement after the one that takes the lock: a volatile function's
statements each take a new snapshot.

What the model does not cover:
- **Any number of uses and changes:** a proof would.
- **Liveness:** a use is answered within k + 1 tries if at most k changes
  come in its window.
- **A crash between the append's commit and the Worker's answer:** this
  loses an answer, not an entry.
- **A checkpointer that crashes between closing and signing:** tested on
  Postgres, not modelled.
- **The lag:** the model closes up to the previous tick's number; the
  prototype waits 5 ticks. Safety does not depend on it, so the ~6 s window
  is arithmetic, not checked.
- **One grant stands for every decision input.** Each kind of input is safe
  only if its writer is a fenced change (above).
- **One principal.** With an instance-wide revision, "no allowed use after
  a change answered" is stronger than the per-principal promise, and the
  model checks the stronger one.

## Recommendation for 0.15

**Build `seq`, not shards,** for 0.15, and keep shards as the plan for when
one Postgres is not enough. It meets R44's throughput on Workers at
Equisafe's size, with:

1. **Named statements** on the hot path (`prepared.ts` sends unnamed ones
   today). Postgres CPU halves.
2. **Changes on a Hyperdrive config of their own.**
3. **Every write to a decision input as a fenced change,** listed in the
   spec and enforced by a trigger.
4. **The newest checkpoint anchored outside the database** (the audit
   watch), each time one is made. Without it, the integrity trade above
   is worse than stated.
5. **An append that recognises its own replay** (a duplicate number whose
   row is its own) and answers with the value.
6. **Admission control** in front of the pool, which is still to design
   (below).
7. **Hyperdrive's pool sized from Little's law,** with the database's
   region in mind.
8. **One measurement on Equisafe's instance class** (a throwaway project)
   before committing to the CPU estimate.

The prototype's path and its model are about 680 lines (`simple.ts`, its
SQL, `HotPath.tla`). The shard and its models are about 1,740, plus their
migration, Node's in-process variant, and storage that Postgres's backups
do not see.

Shards are better at three things, and they are why shards stay the
fallback:
- **Latency far from the database:** one Durable Object call, no
  Postgres round trip.
- **Serving while Postgres is down.**
- **Instances beyond one Postgres's CPU.** That ceiling is ~2,000 uses a
  second on 2 vCPU here, and it scales with vCPUs.

## Decisions for Erwin

1. **Is a 6-second window acceptable,** in which someone with database
   write access (but no key) can delete a single use's entry, or undo a
   single change, without trace? Today they can only cut the newest
   entries, which the anchor sees. This assumes the newest checkpoint is
   anchored outside the database. Smaller windows cost checkpoint statements: 1.5 s costs about 6 a
   second. Or keep today's chained MAC and accept ~1/(2 × RTT) uses a
   second (measured: 272/s at 2 ms, 4/s at 20 ms).
2. **Log order by (revision, number).** Every use is placed exactly
   against every change. Two uses at one revision are ordered by when
   their read took its number, not when they committed. Example: svc-b's
   use numbered 4,003 committed before svc-a's 4,001.
3. **One instance-wide revision.** Any change, even a grant in another
   project, sends the uses in flight at that moment (about two round trips'
   worth) back for one more try. Measured: 4–15 retries per change at
   1,000 a second and a 2 ms round trip. Per-project revisions would
   narrow it, at the price of a fence per place.
4. **Admission control:** a bound on uses in flight, refused at once
   above it. Per isolate (cheap, not global), or a shared counter (a
   Durable Object, back on the hot path)?
5. **Retention:** 30 GB a day at a sustained 1,000 uses a second, as with
   shards.

## Reproducing

All throwaway, synthetic, and deleted after: the container `w201-pg`, the
Worker `coffre-w201-lanes`, its loader, KV namespace, two Hyperdrive
configs, the tunnel, its DNS record, the Access app and two service
tokens.

```
node experiments/lanes/fence.ts --url $DB
node experiments/lanes/seed.ts --url $DB --principals 100 --simple seq [--history 10000000]
node experiments/lanes/relay.mjs --listen 127.0.0.1:30202 --to 127.0.0.1:30201 --rtt 2
node experiments/lanes/bench-simple.ts --url $RELAY --admin $DB --variant seq --named --rate 2000 \
  --seconds 20 --principals 100 --pool 40 --queue-ms 250 --cgroup <container>/cpu.stat --revoke-at 10 [--revoke-kind credential]
node experiments/lanes/verify-simple.ts --url $DB --variant seq
node experiments/lanes/load.mjs --base https://<worker> --path /simple/seq/use --query '&named=1' --rate 1000 --seconds 300 --principals 100
node experiments/lanes/checkpointer.ts --url $DB --variant seq --every 1000 --seconds 305
scripts/formal-hotpath.sh --workers 8
```

