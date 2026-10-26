# One call per use (0.15, W208)

An experiment, not a decision. Written by W208 on 2026-10-26, on a draft PR
marked DO NOT MERGE. It follows W201's
[`hot-path-simple.md`](hot-path-simple.md), whose `seq` variant is two
statements per use: a read that takes a number, then an append fenced by an
instance-wide revision. This one asks: can a use be **one** round trip, with
**no revision at all**?

- **Prototype:** [`experiments/lanes/src/one.ts`](../../experiments/lanes/src/one.ts),
  its SQL in [`experiments/lanes/schema-one.sql`](../../experiments/lanes/schema-one.sql).
- **Benches:** W201's rig, unchanged where it could be:
  [`bench-simple.ts`](../../experiments/lanes/bench-simple.ts) (`--variant one`)
  locally, and the Worker's `/simple/one/…` routes on Cloudflare.
- **Checks:** [`verify-one.ts`](../../experiments/lanes/verify-one.ts) (checkpoints,
  MACs, and a replay of every decision),
  [`fence-one.ts`](../../experiments/lanes/fence-one.ts) (why it must be a
  function), [`size-one.ts`](../../experiments/lanes/size-one.ts) (bytes per use).
- **Model:** [`formal/HotPathOne.tla`](../../formal/HotPathOne.tla), checked by
  [`scripts/formal-hotpath.sh`](../../scripts/formal-hotpath.sh).

Every number below is labelled **measured** (with where) or **reasoned**.

## In short

- **A use is one call.** The Worker MACs the request, then calls
  `use_credential` once. That plpgsql function takes an advisory lock
  *shared*, then, in one statement, reads everything the decision needs and
  inserts the use's entry, numbered from a sequence. It commits, which lets
  the lock go. The Worker then decides, opens the key and releases the value.
- **A change** takes the same lock *exclusive*, writes, inserts its entry
  from the same sequence, commits, then answers.
- **No revision.** Uses and changes never overlap (shared against
  exclusive), each takes its number under the lock, and the lock is let go
  only once the commit is visible. So the number alone puts every use before
  or after every change. Nothing is ever fenced out, nothing retries, there is
  no `changing` 503. TLC checks this, and fails without each of the pieces.
- **The log stores the request, not the outcome.** A denial is logged like
  an allowance. The outcome is a function of the changes numbered before the
  entry and of the entry's time, so a replay recomputes it. Every benchmark
  run below was replayed: **every live decision agreed with the replay**
  (measured: 3.2M uses across the local runs and 922k on Cloudflare, 0
  disagreements).
- **Measured, locally** (2 vCPU / 2 GB Postgres, pool 40, 2 ms round trip,
  same day as a `seq` rerun):
  - at 1,000/s for 5 min: p50 **2.6 ms** against `seq`'s 5.2 ms, p99 6.1
    against 9.2; 1 statement and 1 round trip against 2 and 2;
  - served without loss (under 1% refused, 20 s steps): `one` 4,000/s
    (5,000/s before review r1 added one row read per use), `seq` 3,000/s.
    Postgres CPU per use at the top: 0.37–0.38 ms against 0.52 ms, so about
    **1.3–1.6×** the uses on the same 2 vCPU;
  - Postgres CPU per use about the same at 1,000/s (0.30–0.35 ms against
    0.36), and it stays flat as load rises, where `seq`'s does not (0.52–0.64
    ms at 2,500–3,000/s).
- **Measured, on Cloudflare** (Worker in WAW, Hyperdrive, same evening as a
  `seq` rerun):
  - at 1,000/s for 5 min, pool 100: Worker p50 **37 ms** against `seq`'s 70,
    p99 828 ms against 2.5 s; Worker CPU 1.9 ms against 2.3 at p50;
  - at Equisafe's pool of 40: **~1,040/s** served against `seq`'s ~500/s. One
    round trip doubles what a pool serves.
- **Overload:**
  - **Locally,** past the ceiling (8,000/s offered to `one`, 5,000/s to
    `seq`, 1.6–1.7× each): with a cap and a deadline, `one` served 4,991/s
    before review r1 and 4,554/s after it, at p50 3.8 ms, and refused the rest
    at once (503, `Retry-After`). Without them, `seq` collapsed to 243/s.
  - **On Workers,** a deadline carried into Postgres keeps goodput at the pool's
    ceiling, because calls held too long do nothing. But a per-isolate cap
    does not refuse fast: Cloudflare spread the load over at least ~150
    isolates. A bound shared by all isolates is still open.
- **About flat to 10M entries** (R48), with a log partitioned by day: 14.6–15.5
  buffers per use and p50 2.6 ms at 10k, 1M and 10M. Retention is `DETACH` and
  `DROP` of a day: 3 ms and 26–52 ms for a day of 1M entries, under load, with
  no effect on uses.
- **Bytes per use:** 341 as prototyped, **158** in a slim row (141 with a
  16-byte MAC). At 1,000/s, that is 29, 13.6 and 12.2 GB a day (measured at
  1M rows, heap and index).
- **Fewer rows:** a repeat of an allowed use, with no change since, can ride
  on that use's entry ("covers"). At 80% repeats, 0.215 entries per use and a
  fifth of the WAL locally, with a member's revocation and the replay
  unchanged (secret and environment changes are not yet covers-aware). On
  Workers, 0.63 entries per use, because covers are per isolate.

## The design

### A use

```
Worker   authenticate the caller (CPU only)
Worker   MAC (principal, credential, request id, time, what it asks for)
call     SELECT use_credential(principal, credential, request id, time, payload, mac, deadline)
           pg_advisory_xact_lock_shared(208)                    shared with every other use
           past its deadline, or its time below the floor? write nothing, answer null
           one statement: INSERT the entry (nextval) and read     one snapshot, taken after the lock
             member, grants, the member's newest change, credential,
             environment, secret and its wrapped key
           COMMIT                                                  the lock goes with it
Worker   decide (decide()), open the key, release the value
```

The entry has no outcome: it is the request. Example: svc-b asks for
DFNS_KEY at 14:02:01.300 with request id `r-81`. The entry is (number 4,003,
time 14:02:01.300, svc-b, its credential, `r-81`, DFNS_KEY, MAC). Whether it was
allowed is a question for the changes numbered below 4,003.

The value leaves only once the call has returned, which is after the commit
(the driver resolves on `ReadyForQuery`, which Postgres sends after the
commit, and `synchronous_commit` is on, so the commit is on disk first). A
Worker that dies between the commit and its answer leaves an entry whose
value never left: the log claims a little more than happened, never less.

### A change

```
read     the member and its grants (no lock)
Vault    seal the member's next state; MAC the entry
call     SELECT change_member(principal, request id, time, payload, seal before, seal after, mac)
           pg_advisory_xact_lock(208)                           exclusive: waits for the uses in flight
           the member's seal is still the one read? else nothing, read again
           apply the payload, as logged; INSERT the entry (nextval); COMMIT
answer   (W209: once its entry is sealed and witnessed)
```

The exclusive lock waits only for uses already holding it shared, each a
fraction of a millisecond of server time. Postgres queues an exclusive
request ahead of later shared ones, so uses cannot starve a change. The
change's payload is what the function applies (`grant`, `revoke`, credential
`revoke`, `restore`): the log says exactly what was done. The function
returns the entry's number, which a change waits to see sealed (rule R51).

### Why a function and not one statement

A statement takes its snapshot when it starts, before it waits for anything.
Written as one statement, `WITH l AS (SELECT pg_advisory_xact_lock_shared(…))
INSERT … SELECT … FROM l`, a use that waits behind a revoke still reads the
grant as of before the wait. Inside a volatile plpgsql function, each
statement takes a fresh snapshot, so the statement after the lock sees every
change committed before the lock was granted.

[`fence-one.ts`](../../experiments/lanes/fence-one.ts) shows it on Postgres 16,
deterministically. A change holds the lock, a use for svc-0 starts and waits
(seen in `pg_locks`), the change revokes svc-0 and commits, the use goes on
(measured):

| the use, written as | its number | what it read | the replay says |
|---|---|---|---|
| one statement (bare CTE) | after the revoke's | the grant: **allowed**, value released | refused |
| `use_credential` (function) | after the revoke's | no grant: refused | refused |

The first row is a use the log says was refused and that released the value.

### No revision: why the number orders everything

The claim: if a use's number is below a change's, the use saw nothing of the
change, and if above, it saw all of it. Four things make it true:

1. **Uses hold the lock shared and changes exclusive,** so a change never
   holds it while a use does.
2. **Each takes its number under the lock** (`nextval` inside the function's
   statement, not passed in).
3. **The lock goes only once the commit is visible.** It is a transaction
   lock: Postgres makes a commit visible (`ProcArrayEndTransaction`) before
   it releases the transaction's locks. A session lock unlocked inside the
   function would go before the commit.
4. **The sequence hands numbers out in order across sessions** (`CACHE 1`,
   the default; a per-session cache would not).

So between any use and any change, one held the lock entirely before the
other: the first one's number is smaller, and its commit was visible before
the second took its snapshot. Example: Ada revokes svc-b while svc-b's use is
in flight.

| | number | the use saw the revoke? |
|---|---|---|
| svc-b's use got the lock first | 4,003 < revoke's 4,004 | no: allowed, and committed before the revoke could start |
| the revoke got it first | revoke's 4,004 < use's 4,005 | yes: refused |

There is no third case, so nothing is ever fenced out and retried. W201's
`seq` needed the revision because its use took its number in a read, one
round trip before its append.

**What the model says** (formal/HotPathOne.tla, measured with TLC): two uses, a
change that revokes then grants again and may fail after locking, a
checkpointer, and one Postgres crash. It holds (1.19M states). Each protection
removed breaks it:

| protection removed | breaks |
|---|---|
| a use takes the lock shared | `TotalOrder`, `NothingAllowedAfterAnswer` |
| its reads are a statement after the lock (else: a bare CTE) | `TotalOrder`, `ReplayAgrees`, `NothingAllowedAfterAnswer` |
| a use takes its number under the lock | `TotalOrder`, `CheckpointsHold` |
| a change takes the lock exclusive | `TotalOrder`, `NothingAllowedAfterAnswer` |
| a change takes its number under the lock | `TotalOrder` |
| the lock goes with the commit, not before it | `TotalOrder`, `NothingAllowedAfterAnswer` |
| a change answers only once committed | `NothingAllowedAfterAnswer` |
| a value leaves only after its entry commits | `DurableBeforeRelease` |
| `synchronous_commit` on | `DurableBeforeRelease`, `NothingAllowedAfterAnswer` (a crash loses an answered revoke) |
| the checkpointer closes under the lock exclusive | `CheckpointsHold` |

- `TotalOrder`: every use saw exactly the changes numbered before it.
- `ReplayAgrees`: the decision recomputed from the log is the live one.
- `NothingAllowedAfterAnswer`: no use allowed on a state from before a
  change commits after that change answered ("no use after a confirmed
  revoke").
- `DurableBeforeRelease`: a value leaves only with its entry flushed.

**What it does not cover:**
- **Scale:** two uses (three with covers), one principal, credential and
  secret, one isolate. Any number of uses would need a proof.
- **Liveness.**
- **No clocks, deadlines, floors, request ids, replays, partitions, seals or
  expiry.** Those are argued above and tested on Postgres (`fence-one.ts`),
  not modelled.
- **Tampering** by someone with database write access (below).
- **One grant stands for every decision input,** so every writer of one must
  be a change like `change_member` (W201's point, unchanged).
- **`ReplayAgrees` adds nothing to `TotalOrder` in the model:** an entry's
  decision is built from what it saw. The independent check of live against
  replay is `verify-one.ts`, on the real runs.
- **Covers:** the cover is invalidated by any change (one principal), and
  the check and the read are one step. In the code they are one statement
  under the shared lock, which no change can commit through.

### The outcome, recomputed

`decide(view, request, time)` is a pure function. Live, the view is what
`use_credential` read. In a replay, it is the state built from the change
entries alone, in number order, starting from the seed's (environment,
secret, members, grants, credentials, each a change entry). Expiry is decided
at the entry's time, which the MAC covers, so a credential expiring
mid-run is refused the same way live and in the replay.

[`verify-one.ts`](../../experiments/lanes/verify-one.ts) does it from the
tables alone, then holds each replayed decision to the live answer the bench
recorded. Measured, every local run: all agree, deny reasons included
(`forbidden` after the revoke, `expired` after svc-1's credential expired
mid-run). The 5-minute run: 300,274 uses, 300,274 agree.

### The member's seal: what it protects, without a revision

W201 sealed a member row "at revision + 1": the vault's MAC over the member,
its grants and the revision of its newest access change, checked against the
newest `access.*` entry naming it. **It protects against rollback**: someone
with database write access but no key puts back the member row and grant
from before a revoke. Both are validly MAC'd (they were once current), so a
plain MAC accepts them.

In `one` it matters more, because the outcome is not stored: after such a
rollback, uses would be allowed live while the replay of the log says
refused, and nothing would ever show the difference.

Without a revision, `one` keeps it with no counter: the change entry carries
the seal it leaves (`seal`, under the entry's MAC), and a use is refused
(`stale`) unless the member row's seal is the one its newest change wrote.
Example: grant (seal S1), revoke (S0), and an attacker puts back the S1 row
and grant. The newest change for svc-b says S0, the row says S1: refused.
Putting back an identical state (S1 after grant, revoke, grant) is not a
rollback, and passes. To undo the revoke unseen, the attacker must also
delete its entry before it is sealed, which W209's rule (a change answers
only once sealed and witnessed) closes.

The lookup is one index probe on the changes partition, which only changes
grow (measured: flat to 10M uses). The prototype seals only the member and its
grants; credentials, secrets and environments need the same treatment
(reasoned).

### Replays

A call whose answer is lost may be sent again (W201 saw 190 such appends on a
slow network), by Hyperdrive or by the Worker retrying the request. A request
carries its id and its time from the start, and a retry reuses both
(`UseInput.at`, `change(…, request)`). A use's entry is unique on (time,
request id), both under its MAC, so a retry within the deadline fails on that
index, writes nothing and answers 503 `replayed`; a retry after it answers
503 `late` and writes nothing either. Both leave the first entry standing.
This binds callers of `one.use` and `one.change`; the prototype's Worker
route mints a new request id per HTTP request, so there an HTTP retry is a
new use. It must not decide again: on today's state, after a revoke, it could
allow a use the log puts before the revoke. A change's replay finds its entry
under the lock and returns its number; a request id names one change, and
another payload under it is refused. `fence-one.ts` checks both, retrying
through `one.use` and `one.change`, and a retry after the deadline (measured:
one entry each). The verifier rejects two entries with one request id, so a
copied entry is caught. A replay or a failed call uses up a number, so the
numbers have gaps, and a gap is not a deletion: only checkpoints prove
completeness.

(`ON CONFLICT DO NOTHING` would answer the replay without an error, but its
speculative insertion doubled a use's buffers and WAL records, measured
12 → 24 and 2 → 4. The plain unique index costs nothing extra.)

### Deadlines, the floor of `at`, and one index per use row

Every use carries a deadline, at most 3 s after its time, set when the
request arrives. The call does nothing if it gets its lock later (and a
missing or longer deadline is answered the same way: 503 `late`). So a call
Hyperdrive held while the Worker gave up does no work when it finally runs.

The checkpointer needs to find the uses numbered after its last barrier
without an index on the number. Each barrier, under the lock exclusive,
raises a floor, `fence.at_floor`, to its own clock less 3 s, and never lowers
it. A use whose time is below the floor writes nothing (`late`). So every use
numbered after a barrier has a time at or above that barrier's floor, by
what the rows say. The checkpointer reads its window through the (time,
request id) index from there.

- **Clocks:** the Worker stamps the time; Postgres stamps the floor. Skew
  between them, or Postgres's clock stepping back, can only refuse uses
  (`late`), never let one be written below the floor where a checkpoint
  would miss it. `fence-one.ts` checks it: a floor set ahead of the clock,
  then a use whose deadline still passes: `late`, no entry (measured).
- **No floor row** (the schema makes it): every use is refused, so a
  database without one cannot log uses where no checkpoint looks (tested).
- **Cost:** the use reads one more row (the floor), and the barrier writes
  it, once a tick.

So a use row has **one index**, the replay's, and no index on its number.

A first version had a BRIN index on the number. At 10M entries the seeded
days' BRIN ranges were not summarised, the checkpointer scanned all of them
(11.8 s a tick), and R48 failed (measured). A second version bounded the
window by the barrier's clock and the 3 s deadline alone; review r1 found it
missed a use if Postgres's clock stepped back. The floor holds whatever the
clocks do.

### Checkpoints: no lag

The checkpointer (W201's flat hash, kept so the load compares; W209 replaces
it with Merkle checkpoints) closes its window with a barrier: the lock
exclusive for one statement that raises the floor of `at` and reads the
sequence's last value. With every number taken under the lock, nothing at or
below that value can still commit. W201 needed a 5-tick lag and a number
check in every append. `one` needs neither: an entry is sealed by the next
tick.

The barrier waits for the uses in flight, and new uses queue behind it while
it waits. Its mean server time, lock wait included, is load-dependent
(measured, `pg_stat_statements`, `matrix4.log`): 0.21 ms at 1,000/s, 0.38 ms
at 4,000/s, 12.5 ms in the capped overload run, and 40 ms at 5,000/s (past
the ceiling), where the uses it waits for are themselves waiting for CPU.
That stall comes once a tick.

### The log's tables

`entries` is partitioned by kind:

- **`entries_changes`:** kept for good. Decisions read the member's newest
  change, and a replay starts from them.
- **`entries_uses`:** partitioned by day of the request's time. Retention
  drops a day whole.

A day's partition is made ahead, apart, then attached. Measured at 10M
entries: `CREATE TABLE … PARTITION OF` took the parent ACCESS EXCLUSIVE, queued
behind a reader for 10.7 s, and every use queued behind it. `ATTACH PARTITION`
takes SHARE UPDATE EXCLUSIVE, which inserts don't wait for: 12 ms, no effect
on uses.

**Why days by request time, not by number:** a replay must find its first
entry. A replay across midnight would get a number in the next day's range
and miss a per-day index on the number. The request's time is the replay's
own, so the replay lands in the same day.

A unique index on a partitioned table must include the partition key, so a
use's number is unique by the sequence alone (the verifier checks it).

### Admission control

- **Per isolate:** a counter of uses with a call in flight. Above the cap, a
  use is refused at once (503, `Retry-After: 1`), without a connection.
- **The deadline**, above: the Worker answers 503 at its deadline, and the
  call it leaves behind does nothing when Hyperdrive finally runs it.
- **On the vault login:** `lock_timeout = 1s` and `statement_timeout = 2s`,
  so a statement that does reach Postgres cannot run on long after its Worker
  gave up.

Per isolate is not global: N isolates admit N × cap. A global bound needs a
shared counter (a Durable Object, back on the hot path). Locally the bench is
one isolate.

### Fewer rows: covers

An agent that reads the same secret 50 times a minute should not cost 50
rows. Three ways were weighed:

| | how | verdict |
|---|---|---|
| **a. covers** (built) | after an allowed use writes entry #k, the isolate passes k with the next uses of the same credential and secret, for a window. In the statement that reads (one snapshot, under the same shared lock), the call writes nothing if no change to the member was numbered after k. The first use after any change to the member is a fresh entry | **built and measured** |
| b. a per-tick counter row | one row per (credential, secret, tick), its count updated by every use | **rejected (reasoned):** every use of a hot key updates one row, one at a time under its row lock, which R44 forbids; and an update writes a whole new row version, so WAL does not shrink |
| c. a shared dedup table | covers kept in Postgres, so every isolate shares them | **not built:** a cover row would have to be MAC'd (else a database writer could make uses skip logging), written by a second statement after the first use, and read by every use. Worth it only if per-isolate covers prove too weak on Workers (below) |

What a cover keeps:

- **Append before release:** a repeat's value leaves only after its cover's
  entry is on disk.
- **No serialization:** a repeat is a read-only transaction; no row is
  written, so there is no lock to wait on and no WAL.
- **Revocation:** a repeat on a cover from before a change to the member is
  impossible, so a use after a confirmed revoke is a fresh entry, refused,
  and provably so. TLC holds `RepeatsAreTheirCover` (96.5M states) and breaks
  it without the change check or without the shared lock.
- **Scope, as built:** "a change to the member" means what `change_member`
  writes: the member, its grants, its credentials. A secret rotated, moved or
  deleted, or an environment deleted, writes no change entry for the member,
  so a cover would not see it. Before covers ship, every other decision input
  must be a change the cover check can see (its own number, compared the same
  way).
- **Expiry:** a cover ends at the credential's expiry, so the first use after
  it is a fresh, logged refusal.

What the log can no longer say: how many times, and exactly when, a
credential read a secret within a cover. It still says the first time, and
that every later read in the window saw the same grants.

Measured locally, 100 credentials on one secret, a 60 s window, 20% of uses
sent without a cover (as distinct reads would be):

| | entries per use | WAL records per use | Postgres CPU per use | ceiling |
|---|---|---|---|---|
| no covers | 1 | 2.0 | 0.30–0.35 ms | ~5,000/s |
| 80% repeats | **0.215** | **0.4** | 0.32 ms | 5,750/s at 6,000 offered |

The CPU barely moves: a repeat still reads everything, and Postgres's cost
per call is mostly protocol and plpgsql, not the insert. The win is rows,
bytes and WAL.

**How it scales with the window (R52 keeps the bulk cap's window a
parameter; the cover window is one too, `--cover-ms`):** covers are per
isolate, in memory: one
entry per (isolate, credential, secret) per window. A 1-day window holds as
many as there are distinct keys an isolate saw that day, and costs nothing in
Postgres. A cover never outlives a change or an expiry, so a long window
loses nothing to revocation.

**The bulk cap** (1,000 distinct keys per principal per 15 min, configurable
as `bulkLimit: { count, windowMinutes }`): the prototype does not implement
it. Covers do not change what it must count: every distinct key still writes
at least one entry per isolate per window. But counting from the log would
scan history (R48), so the cap still needs its own table (`vault_releases`,
latest read per principal and key). Its size grows with distinct keys read in
`windowMinutes`, up to a day, and with a count of 10 it refuses the 11th
distinct key the same way (reasoned; not measured here).

### Row size

What one use costs on disk, measured at 1M rows (heap and index), and in WAL
over 20,000 more, one per transaction, commit records included
([`size-one.ts`](../../experiments/lanes/size-one.ts); `size-one.txt`):

| row | heap | index | total | WAL | at 1,000/s |
|---|---|---|---|---|---|
| as prototyped: text ids, JSON payload, `kind`, `written_at` | 273 B | 68 B | **341 B** | 441 B | 29 GB/day |
| slim: number, time, request id (random bigint), credential (uuid), secret (uuid), MAC (32 B) | 126 B | 32 B | **158 B** | 260 B | 13.6 GB/day |
| slim, MAC truncated to 16 B | 109 B | 32 B | **141 B** | 244 B | 12.2 GB/day |
| slim, 80% repeats on covers | | | **~34 B** | ~56 B | 2.9 GB/day |

The slim row drops:

- **`kind`:** the partition says it.
- **The principal:** the credential's, which never changes. The replay maps
  it from the credential's `credential.issue` change.
- **The environment:** the secret's.
- **`written_at`:** only the benches use it.

A 64-bit random request id need only be unique within its millisecond: at
5,000 uses a second, about 5 share one, so a collision is about one in 10^18
per millisecond. A collision would answer one use 503 `replayed`, and its
retry, with a new id, would pass. Of a
row's 158 B, about 24 B is the tuple header and 32 B the MAC; the rest is
three bigints and two uuids. The prototype keeps its readable columns; the
slim row is measured, not wired through (reasoned: the decision, the replay
and the verifier need nothing it drops).

## Measurements

### Setup

W201's rig: Postgres 16.14 in Docker, held to Equisafe's size (2 vCPU via a
CPU quota, 2 GB), `synchronous_commit` on, a pool of 40, a relay adding a
2 ms round trip, an open loop (Poisson arrivals), 100 principals, a
revocation halfway, a checkpoint every second. `seq` was rerun the same
evening on the same container. Two differences from W201: `max_wal_size` is
8 GB (fewer Postgres checkpoints in a run), and the uses' login has
`lock_timeout` 1 s and `statement_timeout` 2 s.

One artifact of the rig: Docker's CPU quota freezes Postgres for the rest of a
100 ms period once it has used its 200 ms. The ~100–250 ms p99 at high load,
for both variants, comes from that; a VM with 2 vCPUs would queue instead.

Every number below comes from a run kept in this thread's storage
(`w208-raw/`): `main-seq-1000.txt` and `main3-one-1000.txt` (the 5-minute
runs), `cap-*.txt` and `cap3-*.txt` (ceilings), `matrix2.log`, `matrix3.log`,
`matrix4.log` and `rev4-seq-own.txt` (overload, revocation, R48, covers), and
`cf-matrix1.txt` and `cf-matrix2.txt` (Cloudflare). The `one` runs before
review r1 (`main3`, `cap3`, `matrix3`) ran without the floor of `at`. The
runs after it (`matrix4.log`) add it: one more row read per use (below).

### Local, 1,000/s for 5 minutes

| | served | p50 | p99 | statements and round trips per use | Postgres CPU per use | server time per use | buffers per use | revoke | live = replay |
|---|---|---|---|---|---|---|---|---|---|
| `seq` (W201) | 994/s | 5.2 ms | 9.2 ms | 2 | 0.36 ms | 0.14 ms | 13.7 | 22.8 ms, 0 allowed after | n/a (stores outcomes); checkpoints verified |
| **`one`** | 991/s | **2.6 ms** | **6.1 ms** | **1** | 0.30–0.35 ms | 0.26 ms | 12.0 | 22.9 ms, 0 allowed after | **300,274 of 300,274** |

`one` spends more time in Postgres per call (plpgsql and building the JSON
answer, ~0.15 ms of its 0.26) but saves a whole protocol round trip and a
commit, so its total Postgres CPU per use is about the same. Returning a row
instead of JSON would trim it (reasoned).

### Local, ceilings and overload

| | offered | served | p50 | p99 | refused, and how fast |
|---|---|---|---|---|---|
| `seq` | 2,500/s | 2,493/s | 5.7 ms | 110 ms | 0 |
| `seq` | 3,000/s | 2,993/s | 6.1 ms | 438 ms | 264 (0.4%) after waiting 250 ms for a connection |
| `one` | 4,000/s | 3,991/s | 2.9 ms | 196 ms | 0 |
| `one` | 5,000/s | 4,967/s | 3.3 ms | 225 ms | 121 (0.1%) after 250 ms |

After review r1 (the floor of `at`, one more row read per use;
`matrix4.log`):

| | offered | served | p50 | p99 | refused |
|---|---|---|---|---|---|
| `one` | 4,000/s | 3,980/s | 2.9 ms | 212 ms | 1 |
| `one` | 5,000/s | 4,678/s | 226 ms | 267 ms | 4,607 (9%) after 250 ms |
| `one`, cap 48 + deadline | 8,000/s | 4,554/s | 3.8 ms | 50 ms | 102,879, at once |

**Ceiling, defined as** the highest rate offered in 20 s steps that is served
with under 1% refused: `seq` 3,000/s (at 0.52 ms of Postgres CPU per use);
`one` 5,000/s before review r1 (0.37 ms) and 4,000/s after it (0.38 ms).
Neither was stepped beyond without admission control. On CPU alone, 2 vCPU
would carry ~3,800 and ~5,000–5,400 uses a second: **about 1.3–1.6×**.
| `seq`, no admission | **5,000/s (1.7×)** | **243/s** | 487 ms | 619 ms | 142,777, after 250–566 ms |
| `seq`, cap 48 + deadline | 5,000/s | 4,249/s | 7.2 ms | 36 ms | 21,893, **at once** |
| `one`, no admission | **8,000/s (1.6×)** | 5,230/s | 243 ms | 292 ms | 80,336, after 250 ms |
| **`one`, cap 48 + deadline** | 8,000/s | **4,991/s** | **3.8 ms** | **46 ms** | 88,966, **at once** |

- **Admission control matters most under overload,** for either design.
  Without it, `seq` collapses: its reads crowd its appends out of the pool's
  queue, and the uses that time out have already spent their read.
- **One statement makes `one` collapse-proof without it too:** there is no
  half-done use to waste. But its latency is the queue's (~250 ms), not the
  database's.
- **`seq` near its ceiling is metastable.** At 2,400/s with a revocation, it
  fell into a 450 ms queue in 4 of 5 runs: 527/s and 2,046/s served
  (`matrix2.log`, own pool and shared), 885/s (`matrix3.log`, own pool),
  1,632/s (`rev4-seq-own.txt`, which started clean and tipped at the
  revocation), and 2,392/s once, clean (`matrix3.log`, shared). `one` at
  3,800/s, ~76% of its ceiling, held in all 4 runs (`matrix2.log`,
  `matrix3.log`).

### Local, revocation under load

On a pool of its own, as a separate Hyperdrive config would be, or on the
uses' pool:

| | load | own pool | uses' pool |
|---|---|---|---|
| `one` | 3,800/s | 25.5 ms, 22.5 ms | 6.4 ms, 7.5 ms |
| `seq` | 2,400/s | 162 ms, 119 ms (in collapsing runs) | 7.1 ms, 7.1 ms |

Two runs each, `matrix2.log` then `matrix3.log`.

0 uses allowed after the answer in every run, and 0 entries numbered before
the revoke and written after it. Locally the pool is never the bottleneck, so
its own pool saves nothing here; on Cloudflare it does (below).

### Local, flat as the log grows (R48)

1,000/s for 30 s, on a log seeded with 10k, 1M or 10M uses over 10 days
(`matrix3.log` before review r1; `r1-r48-10k.txt`, `r1-r48-1m.txt`,
`matrix4.log` after it):

| log | use: server time, buffers (before r1) | after r1 | p50 / p99 after r1 | checkpoint db time p50 / max |
|---|---|---|---|---|
| 10k | 0.42 ms, 13.7 | 0.43 ms, 14.7 | 2.6 / 32 ms | 4.9 / 11 ms |
| 1M | 0.34 ms, 13.4 | 0.50 ms, 14.6 | 2.6 / 77 ms | 5.3 / 12 ms |
| 10M | 0.50 ms, 13.9 | 0.64 ms, 15.5 | 2.6 / 110 ms | 4.5 / 19 ms |

The checkpoint column is from the runs after r1.

- **Buffers:** the floor adds about one buffer per use. The 10M run after r1
  reads about one more again, which the runs before r1 did not. It was not
  investigated; one guess is autovacuum on the freshly seeded partitions
  invalidating cached plans.
- **Server time** varies between runs on this shared host (0.34–0.64 ms) with
  no trend in size; p50 latency is 2.6 ms at every size.
- **No statement reads history:** the use reads its member's newest change
  (an index probe) and inserts into today's partition; the checkpointer reads
  its window from the floor.

Retention under load, at 10M: a day's partition made in 12 ms; the oldest day
(1M entries) detached in 3 ms and dropped in 26–52 ms; uses in the 5 s after
it: p50 2.6 ms, max 12–25 ms.

### Cloudflare

Run on the code before review r1 (81a39ebb: no floor of `at`, which adds one
row read per use). Same rig as W201: a Worker in Warsaw (WAW), Hyperdrive with caching off, a
Cloudflare Tunnel (connectors in Helsinki and dme05) to the same container,
load from this machine with `load.mjs`, the checkpointer beside each run. As
for W201, each Worker connection gets one of two network paths to Postgres:
~31 ms or ~222 ms per statement (measured with `/rtt`). The tail of every row
is that path, not the design. One run each.

**Hyperdrive pool 40 (Equisafe's size), 22:13–22:32 UTC:**

| run | offered | served | Worker p50 / p99 | failed | live = replay |
|---|---|---|---|---|---|
| `seq` | 1,000/s | 501/s | 987 ms / 1.9 s | 5,963 client timeouts, 141 errors | |
| **`one`** | 1,000/s | **932/s** | **38 ms** / 2.8 s | 633 `late` (did nothing) | 58,853 of 58,853 |
| `one` | 1,500/s | 1,043/s | 463 ms / 554 ms | 8,615 `late` | 81,381 of 81,381 |
| `seq` | 2,000/s | 559/s | 1.2 s / 1.6 s | 11,111 client timeouts | |
| `one`, no cap | 2,500/s | 1,085/s | 461 ms / 551 ms | 13,592 `late` | 136,228 of 136,228 |
| `one`, cap 8 per isolate, deadline 1.5 s | 2,500/s | 1,133/s | 973 ms / 1.2 s | 68,901 `overloaded`, 10,976 `deadline` | 69,998 of 69,998 |
| `one`, covers (60 s) | 1,000/s | 935/s | 37 ms / 2.8 s | 965 `late` | 36,596 of 36,596 |

- **The pool is the ceiling, as for W201.** By Little's law, ~40 ÷ t uses a
  second for `one` and 40 ÷ 2t for `seq`. Measured: `one` ~1,040/s, `seq`
  ~500/s: one round trip doubles what a pool serves.
- **Past the ceiling, `one` holds its goodput:** a call Hyperdrive held past
  its deadline does nothing when it runs (`late`), so the database does no
  wasted work. `seq` collapses and its clients time out.
- **A per-isolate cap does not bound the whole.** Cloudflare spread this
  load over many isolates: the covers run made 14,817 covers for 100 keys in
  60 s, which is at least ~150 isolates' worth (an isolate that saw fewer
  keys makes fewer covers, so the count is a lower bound). A cap of 8 each still admitted ~1,000 calls at once, and
  the Worker waited ~1 s in Hyperdrive's queue. Fast refusal on Workers needs
  a bound that all isolates share. That is not measured here; it is the open
  part of R44.
- **Covers are per isolate, and so diluted:** 0.63 entries per use on Workers,
  against 0.215 locally. A shared cover table would recover the local figure.
  It would need a MAC on each cover row and one more statement per cover
  (above).
- **12 entries with no answer** (the capped run): calls the Worker had given
  up on at its deadline, which still committed in time by Postgres's clock.
  The log claims a little more than happened, never less.

**Hyperdrive pool 100, 1,000/s for 5 minutes, 22:33–22:43 UTC:**

| | served | client p50 / p99 | Worker p50 / p99 | Worker CPU p50 / p99 | statements | failed | Postgres | live = replay |
|---|---|---|---|---|---|---|---|---|
| `seq` | 997/s | 94 ms / 2.5 s | 70 ms / 2.5 s | 2.27 / 5.35 ms | 2 | 0 | 51% of a core | |
| **`one`** | 994/s | **61 ms / 878 ms** | **37 ms / 828 ms** | **1.87 / 4.65 ms** | **1** | 60 dropped connections (Hyperdrive), 320 `late` | 46% | 299,927 of 299,927 |

Worker CPU is Cloudflare's analytics over 4.5 minutes of each run (~271k
requests each). Both sit under R27's 10 ms p50 and 20 ms p99. The 60 dropped
connections are Hyperdrive's ("Connection terminated unexpectedly"); 29 of
those calls had committed (entries with no answer), which is the safe side.

**Revocation under load, one principal at 1,000/s, revoked at 30 s:**

| | pool | change on a config of its own (5 connections) | change on the uses' config |
|---|---|---|---|
| `one` | 40, near its ceiling | 933 ms | 101 ms |
| `one` | 100 | 892 ms | 91 ms |
| `seq` | 40, 2× over its ceiling | 14.9 s | 12.9 s |
| `seq` | 100 | 869 ms | 103 ms |

0 uses allowed after the answer, in every run (~29,000 each).

- **This reverses W201's finding:** below saturation, the config of its own
  was the slow one. Every change on it took ~0.9 s, the same for both
  designs. An idle 5-connection config most likely pays a cold origin
  connection through the tunnel (Access, TLS) on the change's first
  statement. This was not isolated further.
- **Past saturation, both were slow (`seq`, 12.9–14.9 s).** Here both configs
  go through one tunnel, so a separate config cannot skip the uses' queue on
  this rig.
- **For 0.15 (reasoned):** keep changes on a config of their own, as W201
  measured at 8.3 s against 334 ms on its run. But keep it warm, or route a
  change to the uses' config when that one is not saturated.

## What it removes from the open decisions

W201 left five decisions. With `one`:

1. **The ~6 s window** in which a database writer could delete one entry: now
   **one tick** (~1 s). There is no lag, because the barrier closes every
   number handed out so far. For changes, W209 closes it to zero (a change
   answers once sealed).
2. **Log order by (revision, number):** **gone.** The number alone orders
   uses against changes.
3. **One instance-wide revision,** and the retries every change caused:
   **gone.** A change makes no use in flight retry; it waits for them, for a
   fraction of a millisecond.
4. **How to build admission control:** **half answered.** A deadline carried
   into Postgres, plus timeouts on the login, keeps goodput at the ceiling, on
   Workers too (measured). A per-isolate cap refuses fast locally, but not on
   Workers, where ~150 isolates share the pool. The shared bound is still
   open (decision 4 below).
5. **Retention:** **days partitioned by request time, dropped whole,** 158 B
   per use slim (13.6 GB/day at 1,000/s), and covers on top.

## What changes for integrity

Against W201's `seq`, for someone with database write access but no key:

- **The MAC does not cover the number** (the vault calls before it knows
  it). Until a checkpoint seals it, two entries' numbers can be swapped, or an
  entry copied under a new number:
  - Any two unsealed entries can be swapped: the window is the unsealed one
    (a tick, or longer if the checkpointer stalls), not a bound on time.
  - A copy is caught by the unique (time, request id) index, and by the
    verifier's check.
  - A swap across a revoke moves a use to the other side of it. That is
    inside the ~1-tick window R51 accepts for uses.
  - Once sealed, nothing moves: W209's leaves hash the whole entry.
- **Rollback of decision inputs:** refused by the seal check (above) for the
  member and its grants only. Rolling back a credential's `revoked`, a
  secret's wrapped key or an environment's `deleted` changes the live
  decision with nothing to see it: the outcome is not stored, so no replay
  disagrees. **Open until every decision input is sealed to its newest
  change.**
- **Unchanged from W201:** everything a database writer could already do,
  such as change a grant directly. That is authorisation state, and the
  replay catches it afterwards only if the row is sealed to the log.

## Decisions for Erwin

1. **Drop the revision (R50 says "revision fence").** `one` needs none, by
   the argument and the model above: uses and changes never overlap, so the
   number orders them. The cost: every use takes one advisory lock shared, and
   every change waits for the uses in flight. Recommended.
2. **The log stores requests, not outcomes.** "Was this allowed?" is
   answered by a replay, which is deterministic and checked here against every
   live decision. The catch: a database writer who rolls back a decision
   input (a grant, a credential) makes live and replay disagree unseen,
   unless that input is sealed to its newest change. So every decision input
   needs a seal like the member's.
3. **Covers.** Fewer rows for less detail: the log keeps the first read in a
   window, not each one. Per isolate, as built: 0.215 entries per use locally,
   0.63 on Workers (~150 isolates). A shared, MAC'd cover table would recover
   the local figure, at one more statement per cover.
4. **A shared admission bound on Workers.** Per-isolate caps did not refuse
   fast at 2.5× the pool's ceiling. The options: a counter in a Durable Object
   (one more hop per use), or a small per-isolate cap derived from the pool and
   a measured isolate count. The deadline already keeps goodput at the ceiling.
5. **The slim row** (158 B, or 141 with a 16-byte MAC): worth wiring through.
   A 16-byte MAC keeps 128 bits against forgery, which is what HMAC
   truncation guidance allows.
6. **A use must carry a deadline ≤ 3 s.** It bounds overload work; a request
   with a longer one, or with a time below the barrier's floor, gets no entry
   and a 503 `late`.

## Reproducing

All throwaway and deleted after: the container `w208-pg` (its own compose
project, port 30208), the Worker `coffre-w208-lanes`, its loader, KV
namespace, two Hyperdrive configs, the tunnel, its DNS record, the Access app
and two service tokens.

```
node experiments/lanes/fence-one.ts --url $DB
node experiments/lanes/size-one.ts --url $DB
node experiments/lanes/seed-one.ts --url $DB --principals 100 --expire-after 155 [--history 10000000]
node experiments/lanes/relay.mjs --listen 127.0.0.1:30209 --to 127.0.0.1:30208 --rtt 2
node experiments/lanes/bench-simple.ts --url $VAULT_VIA_RELAY --admin $DB --variant one --named --rate 1000 --seconds 300 \
  --principals 100 --pool 40 --queue-ms 250 --cgroup <container>/cpu.stat --revoke-at 150 --outcomes run.jsonl \
  [--cap 48 --deadline-ms 250] [--cover-ms 60000 --distinct 0.2] [--control-shared] [--maintain-at 15]
node experiments/lanes/verify-one.ts --url $DB --outcomes run.jsonl
node experiments/lanes/load.mjs --base https://<worker> --path /simple/one/use --query '&named=1[&cap=8&deadline=1500][&cover=60000]' \
  --rate 1000 --seconds 300 --principals 100 --outcomes run.jsonl
node experiments/lanes/checkpointer.ts --url $DB --variant one --every 1000 --seconds 305
scripts/formal-hotpath.sh --workers 8
```
