# The audit trees (0.15, plan PR 6)

0.15's log seals its entries into signed Merkle trees: W209's design (#365)
in W212's two-tree shape (#368), built for shipping. This page covers what
the code does, the numbers behind each choice, and what it catches. The
experiments' docs on those PRs keep the full studies. Their prototypes live
in `experiments/merkle/` on those branches, not on `main`.

- **Pure code:** `@coffre/core/merkle` (`packages/core/src/audit/`): the
  RFC 9162 tree, C2SP tiles, C2SP signed checkpoints, the head pair, the
  leaf encoding, a witness's rule, and the verifier's walk.
- **The checkpointer:** `packages/vault/src/checkpointer.ts`, behind a
  storage seam (`CheckpointStore`), with the signer's memory and witnesses.
- **Tests:** `packages/core/test/audit-tree.test.ts` (the tree, against
  the RFC's recursion and Go's vectors) and
  `packages/vault/test/audit-tree.test.ts` (the checkpointer against W209's
  attacks and the pair's rules).
- **Go's check:** `scripts/audit-tree-go.sh`.

**Status.** PR 6a (#370) shipped the trees and the checkpointer behind its
seam. PR 6b wires them to the database and the runtimes ("Where it runs",
below): the store over migration 0022, the checkpointer on Node and in its
Durable Object, and the witnesses. The change path (plan PR 4) calls
`sealThrough` through the seam 6b leaves it. Since plan PR 10, every
deployment runs it: the vault's process on Node (`keepCheckpointer`), the
`CoffreCheckpointer` object the vault starts on Workers.

## In short

- **Two growing RFC 9162 trees** (Certificate Transparency's), one per
  retention class: `changes`, kept for good, and `uses`, dropped by day. Each
  is a standard log with its own origin and key, so Go's `tlog` or any C2SP
  witness reads either one alone.
- **One pair.** A tick signs both heads with the same `upto`, `at` and `floor`. The
  signer remembers both in one record, before the database has either. One
  statement writes both, and opening, every tick and every witness check
  both as one value. No state anywhere holds one head without the other.
- **Checked by Go.** Go's `golang.org/x/mod/sumdb` ran against a split log
  the checkpointer sealed (70,003 uses and 420 changes, 141 pairs). It
  opened every note, rebuilt every tile byte for byte, and gave the same
  proofs. Through uses-tree cuts that keep one tile per level below them,
  `TileHashReader` still proves everything above the cut. W212 could not run
  this check; it passes.
- **The signer's memory stays in core** (R54). It costs 0.6 ms of wall time
  a tick at p50 on Node, as an fsynced file, and one write of about 0.5 KB a tick
  on Workers.
- **Level-0 tiles stay, for both trees.** Dropping them for the uses tree
  would save 25% of a use's storage and 17% of the log's WAL. It would also
  put a second source of truth for the tree's bottom level into every reader
  and into retention's cut. Revisit through the seam if storage bites
  (below).

## The shape: two trees, one pair

W212 chose two trees by numbers. Against one tree, a tick costs about 2 KB
more WAL (under 0.5% of the log's) and 0.2 to 0.6 ms more signer CPU. What
the split gains is retention: no daily rebuild of the dropped window (10.4
minutes of CPU a day at 1,000/s), no digest of the kept changes, and a
change stays provable for good (25 hashes a year in, at one change a
second). W212's review r1 rated the pair's atomicity a P1. The code holds
it with these rules (`packages/core/src/audit/pair.ts`, `checkpointer.ts`):

| rule | in the code |
|---|---|
| two logs, two origins, two keys | `pairSigners(origin, seed)`: `<origin>/changes` and `<origin>/uses`, Ed25519 keys derived from one seed by HKDF |
| one tick signs both, at one `upto`, `at` and `floor` | `signPair`; `openPair` refuses two notes whose `upto`, `at` or `floor` differ |
| one memory record | `encodePair`: one JSON record holding both notes; `remember` before `write` |
| one write | `CheckpointStore.write(row, tiles)`: both trees' tiles and the pair's row, one statement |
| `open()` takes the pair as one value | the newest row must open as a pair; the memory must be equal, a prefix in both trees, or re-derived to both heads, else refused |
| each tick checks the row | `close` returns the newest row; anything but the signer's pair, note for note, refuses the tick |
| witnesses get the pair | `witnessPair`: both notes in one request, each tree's consistency checked, a fork of either refused whole |
| the verifier merges both trees by number | `verifyLog`: one walk in number order, each entry to its tree, both heads required at every row |

**Example.** A tick seals numbers 41 to 49: uses 41 to 48 and the change
49, with no 45 (an aborted append). It signs `changes` at 17 leaves and
`uses` at 3,000, both `upto 49`. If a crash hits after the signer
remembered that pair but before the write, the next start finds the memory
ahead of the database. It re-seals 41 to 49 from the entries and must
reach both heads exactly. If a writer deleted use 44 in between, the uses
head differs and the checkpointer refuses to start.

## A leaf

A leaf is the whole entry: its tree, its number, then every column of its
row in order, its MAC included (`leaf.ts`). The number is sealed with the
entry, so a sealed entry cannot be renumbered. The tree is sealed too, so an
entry moved from one tree to the other is no longer its leaf.

```
"coffre.audit.leaf.v1" \n tree \n number (8 bytes, big-endian) column count (4)
then each column: tag (1) length (4) bytes
  tag 0 null, 1 bytes, 2 text (UTF-8), 3 integer (decimal text)
```

Every column is tagged and length-prefixed, so no two rows encode alike.
`test/vectors/audit-tree.json` pins the bytes. Which columns each table
contributes is 6b's, once migration 0022 fixes the rows.

## Tiles

Go's and C2SP's layout: height 8, each tile up to 256 hashes of one level, a
partial tile only growing (`tiles.ts`). A proof reads about one tile per 8
levels.

- **Partitioned by leaf range.** `tileLeaves(t)` is the range of leaves a
  tile stands for. Retention drops a whole range of uses-tree tiles as a
  table instead of deleting rows: 1.16 s and 294 KB of WAL, against 13.8 s
  and 3 GB for a `DELETE` (W212). 6b lays the tables out.
- **Below a retention cut, one tile per level.** `keptAbove(tile, cut)`:
  proofs of leaves at or above the cut, and consistency from sizes at or
  above it, read only tiles that reach past it. So only the tile holding the
  cut stays at each level, instead of #365's 10.8 MB a day kept for good.
  The TypeScript test checks this exhaustively on a 1,500-leaf tree, for
  cuts on and around tile edges, and sampled on 300,000 leaves. Go's check
  covers it too (below).

## The checkpointer behind its seam

The rest of the vault sees `tick()` (the window in, a signed pair out),
`sealThrough(number)` and `prove(number)`. The trees' shape, tiles and pair
stay behind them. The database is behind `CheckpointStore`:

- `close(after, from)`: the barrier (`close_one`), then the window (its uses
  read from `from`, the newest pair's floor) and the newest
  row in the next statement, a snapshot taken after the barrier's lock: every
  number at or below `upto` has ended, so the entries above `after` up to it
  are final;
- `write(row, tiles)`: the pair and both trees' tiles, one statement;
- `newest()`, `entries()`, `tiles()`, `pairs()`, `pair()` and `locate()`:
  the reads.

**A tick** checks the window, then signs, remembers, writes and publishes.
The window must hold numbers that increase, all inside it, each in a tree,
each with a MAC that holds, and none more than 10 minutes older than the
signer's pair. A replay of a use whose day retention dropped is caught that
way, because no lookup can match it. Any failure refuses the tick and
alerts. The newest row must be the signer's pair, note for note, so a row
deleted or replaced under a running signer shows within a tick.

**Each pair signs its floor.** A checkpoint note carries three extension
lines: `upto N` (every number at or below it is final), `at T` (when it was
signed) and `floor F`. The floor is the lowest `at` a use may still be
written with once that tick's barrier ran. Its row in the database is
unsigned, so a writer could lower it and let in a late use below it, which a
window read from the floor would miss (`HotPathOne.tla`'s
BarrierChecksFloor). So each pair signs the floor its barrier left, and the
signer reads windows from the newest pair's floor, moving it only when a
pair carrying a new one is written. Every barrier must find the floor
exactly where this process's last barrier left it. Found lower, a late use
may have got in below it; found higher, the writer's value would be signed,
and so kept. Either way the tick is refused and alerted, and so is every
tick after it until the checkpointer is reopened (review r10), even if a
later barrier lands the row back on the expected value. After a restart the
first barrier may find it higher honestly, since barriers whose pairs went
unsigned (quiet ticks, a crash) raised it, but never lower than the newest
pair's. Open, witnesses and the verifier refuse a floor that comes down
between pairs, as they do for `at`, the verifier among pairs held outside
too.

**The pair's `at` never comes down, and never runs far ahead.** Retention's
freshness step (plan PR 7) rests on the first half. A replay of a dropped
use must never become fresh again when a clock steps back, so `open()` and
witnesses refuse a newer pair signed earlier than the one they hold, and
the verifier reports one. The
second half is Fable's review. One tick on a signer clock an hour ahead
would sign a time that makes every honest entry read as a replay for that
hour. So a tick signs the signer's clock, held to at most 10 minutes past
the newest entry in its window:

```
at = max(last at, min(now, newest entry's at + 10 min))
```

A clock ahead moves the time one bound at most, so sealing never stops on
it. A signer that stalled past the bound on a quiet log still seals when it
resumes (review r6). A window holding only gaps keeps the last time. The
genesis pair seals nothing and carries `at 0`, so no clock is trusted
before the first entry holds it.

**A failed tick** leaves its pair pending. The trees grow on a copy, so the
signer stays at the pair the database holds. The next tick finishes the
pending pair before anything else: it remembers the pair again, then
adopts it if the database holds it (a write that committed, then threw),
or writes it as it was if the database is still at the signer's pair. It
never signs another pair for that place, even if an entry of it was
deleted since: the pair goes in as signed, and the verifier reports the
loss. A database at neither pair is refused until the checkpointer is
reopened. #365's "broken until reopened" state is gone.

**A change** waits for its seal (R51). `sealThrough` ticks at once unless a
pair already covers it. A pair covering the number is not enough: an entry
deleted before its tick leaves a gap the pair calls final. So the change is
proved in the pair, and its answer carries that proof; if the entry is not
there, the change is refused and alerted. Then it waits for every witness
to hold a pair that covers it, for at most 2 s. Each witness has a pump that always sends the
newest pair, one at a time, each try bounded by 2 s, so a witness that
never answers fails its try instead of stopping its pump. A witness that
refuses is asked again every
100 ms until the deadline, and never after it. A silent witness lets the
change answer `witnessed: false`, alerted. With no witness, `witnessed` is
`null`. 6b records unwitnessed answers where the plugin's alerts read them.

**A proof** is checked against the signed head before it is handed out, and
must be for the entry asked. A database that changed the entry, or
answered for another, makes `prove` throw instead of returning a proof that
fails later.

**Notes are read as strictly as Go's `note.Open`.** That means canonical
base64, at most 100 signature lines, and no control characters. The first
line by the log's key decides: if it does not verify, the whole note is
spoiled, whatever follows; later lines by that key are ignored, as Go
does. So a
tree's note the database holds opens here only if Go's `note.Open`, given
that tree's key, would open it too. (Given both trees' keys at once, Go
also refuses a bad line by the other key; each note here is opened with its
own key alone.)

**Witnesses** (R40's plugin) implement `Witness.publish(notes, proofs)`.
`localWitness` runs `witnessPair` in process, as the witness's Durable Object
will. The R2 archive under a bucket lock protects against a compromised
Worker or database, not against the Cloudflare account: an account admin
can remove the lock rule, as W209's cleanup showed (R54).

## What it catches

Each row is a test in `packages/vault/test/audit-tree.test.ts`, after
W209's attack table (#365).

| a database writer | caught by | how |
|---|---|---|
| deletes a sealed entry | the verifier; `prove` | the next pair's head differs; a proof of an entry after it throws |
| cuts the tail (rows and entries) | a pair held outside; the signer at its next start | "the database ends up to …"; "lost entries the signer sealed" |
| rolls back and gets a second history signed by a signer without memory | the witness; the signer with memory | "split view"; refuses to start |
| crashes the signer between memory and write | the next start | rewrites the remembered pair; with an entry of it deleted, refuses |
| deletes every row | the signer | refuses to start a new log over a remembered one; a remembered genesis is written back as it was |
| deletes a change and renumbers a use into its place before the tick | `sealThrough` | the number's proof is from the uses tree: refused, alerted (KindInMac) |
| moves an entry to the other tree before its tick | the tick | its MAC, which covers its tree, fails (KindInMac) |
| forges a pair at the newest row's place | the signer | refuses to start |
| deletes or replaces the newest row under a running signer | the next tick, with no traffic | "the database's newest checkpoint is …" |
| deletes a change's entry before its tick | `sealThrough` | the change is refused, alerted, never answered as sealed |
| holds a fork both as a row and as a pair held outside, below where a walk starts | the verifier | each such pair must be a prefix of the start, row or not |
| forges an entry, replays an old one, or duplicates a number | the tick | refuses to sign; a change waiting on it fails with the alarm |
| stores notes of two ticks as one row or memory record | `open()`, the verifier | "not a pair" |
| moves an entry from one tree to the other | the verifier | both heads differ |
| restores the memory from a backup | `open()` | accepted, alerted, if a prefix in both trees, by a consistency proof between the signed roots; else refused |
| plants a remembered root in a tile the newest head never reads | `open()` | the consistency proof binds both roots, so planted tiles cannot pass |

**What it does not catch, as designed:** an entry deleted or reordered
before its tick, a window of about 500 ms (R51: uses do not wait, changes
do). A signer whose memory is gone takes the database's word for the
newest pair. It says so (an alert), and only a witness catches what
happened before.

## Checked by Go

`scripts/audit-tree-go.sh` runs `packages/core/test/go`, which uses Go's
`golang.org/x/mod/sumdb/tlog` and `sumdb/note` (v0.41.0, Go 1.27.3) and
shares no code with ours. Run on 2026-10-27:

- **Vectors.** Go builds a 70,001-leaf tree from known leaves. Its heads at
  15 sizes, 45 inclusion proofs, 42 consistency proofs and all 277 tiles are
  pinned in `test/vectors/audit-tree.json`. The TypeScript tests hold the
  code to them on every run, so CI keeps the byte equality without Go.
- **A split log.** The checkpointer sealed 70,003 uses and 420 changes, in
  141 pairs.
  - Every note opens with `note.Open` under its own origin's key, and every
    pair shares `upto`, `at` and `floor`. A uses note renamed to the changes origin
    fails.
  - `tlog.TileHashReader` gives the signed head from our tiles.
  - Go rebuilds every tile from the leaf hashes and gets ours byte for
    byte, with nothing more and nothing less (3 changes tiles, 277 uses
    tiles).
  - 102 inclusion and 277 consistency proofs per tree equal Go's
    `ProveRecord` and `ProveTree`, and every head but the empty ones and
    the newest (which have nothing to prove) passes `CheckTree`. A
    proof with one byte flipped fails.
- **Cuts.** Uses-tree cuts at 40,000, 65,536, 65,537 and 70,002 keep only
  the tiles `keptAbove` keeps, from 121 down to 3 of 277. Go's
  `TileHashReader`, which checks each tile it loads against the signed head,
  still proves, with our bytes, up to 42 sampled leaves above each cut (one
  at 70,002, where only one is left) and
  consistency from each sampled size: the cut, the cut plus one, and every
  tick's head at or above it. Leaf 0 is no longer provable. (Every leaf and
  every size above a cut is the TypeScript test's, on the 1,500-leaf tree.)
- **It fails when it should.** A flipped byte in one tile, or one pair's
  uses note swapped for the next pair's, stops it.

## Numbers

**A tick** at R44's 1,000 entries a second and a 500 ms tick: 500 entries,
one in a hundred a change. Measured with `packages/vault/scripts/audit-tree-bench.ts`,
in Node on this host. The p99s include garbage collection.

| signer's memory | checkpointer CPU, p50 / p99 | tick wall time over the in-memory store, p50 / p99 | memory write, p50 / p99 |
|---|---|---|---|
| in a variable | 4.6 / 41–46 ms | 4.4–4.7 / 23–26 ms | 0 |
| a file, fsynced before the write (Node) | 5.0–5.2 / 74–80 ms | 5.1–5.3 / 41–42 ms | 0.6 / 2.8–7.5 ms |

That is about 9 µs an entry: the MAC check, the leaf hash, the tree, and
two Ed25519 signatures. At two ticks a second, the memory costs about 0.1%
of a core on Node. The wall time leaves out the database: `close_one` and
the write are 6b's to measure (W212 measured the write at 1.46 ms p50). On
Workers the memory is one write of about 0.5 KB to the Durable
Object's storage a tick, 172,800 a day. **R54: the memory stays in core.**

**A tick on Postgres (6b).** Measured with
`packages/vault/scripts/checkpoint-bench.ts` on a Postgres 16 of this
worker's own (2 vCPU, 2 GB, W212's rig).
- **The load:** a loader appends 1,000 entries a second, one in a hundred a
  change, each under the fence's lock shared as `use_credential` takes it,
  so `close_one` waits for appends in flight.
- **The checkpointer:** it ticks every 500 ms through the vault's login,
  its memory an fsynced file.
- **The runs:** two of 60 s each, 120 ticks of about 500 entries; the
  first tenth of each run is left out.

| per tick | p50 | p99 |
|---|---|---|
| barrier and window (`close_one`, then the read) | 3.6 ms | 6.4–6.7 ms |
| write (`write_checkpoint`) | 2.5 ms | 5.2–5.6 ms |
| tick, wall | 13.1–13.5 ms | 32–39 ms |
| checkpointer CPU | 9.2–9.4 ms | 59–74 ms (garbage collection) |

Postgres's CPU (`docker stats`, two samples a run) was 22.6% of a core for
the loader alone and 26.5% with the checkpointer too: the checkpointer
costs about four points of a core at R44's rate. The loader's appends are
bare inserts, not `use_credential`'s whole statement, which adds nothing to
the checkpointer's share.

**A tick in the Durable Object (6b).** Measured with
`packages/vault/scripts/checkpoint-bench-workers.ts`.
- **The setup:** the object runs in workerd, as `wrangler dev` runs it, and
  ticks on its alarm through Hyperdrive's local connection to the same
  Postgres. Each pair goes to the witness's object and the R2 archive.
- **The load:** the same loader, at 1,000 entries a second.
- **The sample:** 111 ticks of 530 entries p50.

| per tick | p50 | p99 |
|---|---|---|
| barrier and window | 5 ms | 10 ms |
| write | 3 ms | 8 ms |
| tick, wall in the object | 28 ms | 56 ms |

workerd's clock moves only on I/O, so these are I/O times; the CPU is
V8's, as in Node's 9 ms. A run on Cloudflare itself was not made. Executor's
Cloudflare API runs code that may not fetch from GitHub, so the bundle could
not be uploaded from there, and this host holds no Cloudflare token for
`wrangler deploy`. Nothing was created; the account was checked afterwards.

**Level-0 tiles for the uses tree.** Plan PR 6 asked for this decision by
numbers. Measured with `packages/vault/scripts/audit-tree-level0.mjs` on a
Postgres 16 of this worker's own (2 vCPU, 2 GB), with W211's slim use row:

| | with level-0 tiles | without |
|---|---|---|
| a use's row and index | 141 B (109 + 31.5) | 141 B |
| the uses tree on disk, per use | 57 B (41 B compacted, W212) | 9.6 B |
| the uses tree's WAL, a tick of 495 uses | 31.3 KB | 5.0 KB |
| the log's WAL a tick (rows at 244 B a use, plus the tree) | 152 KB | 126 KB |
| a proof's leaf level (8 KB tiles) | one tile: 0.21 ms p50, 0.35 ms p99 | 256 uses read back: 0.59 ms p50, 0.89 ms p99 (by the window's `at` range; a number index would add 22.5 B and 149 B of WAL a use) |

**The call: keep them.**

- **For dropping:** 47.5 B a use, 25% of a use's storage, and 17% of the
  log's WAL. At R44's sustained 1,000 uses a second that is about 4.1 GB of
  level-0 tiles a day, 120 GB held at a 30-day retention.
- **Against dropping:**
  - **Every level-0 read would rebuild tiles from use rows.** All readers
    go through the store's `tiles()`, so the rebuild has one home there.
    But it runs on every tick's consistency proofs for witnesses, on
    `open()`, on the tile API that Go and C2SP clients read, and on the
    verifier's start. Each costs 0.59 ms instead of 0.21. The use table
    has no index on number (W211), so each rebuild reads a window by `at`,
    which ties the store's tree reads to the hot path's barrier.
  - **Retention would get a new step.** The tile holding each cut would
    have to be written out before its day's uses are dropped.
  - **The saving does not grow without limit.** Level-0 tiles go with
    their day's partition, so it is bounded by retention times rate.
- **How to reverse it:** if storage bites, the store can synthesize the
  uses tree's level-0 tiles behind `CheckpointStore.tiles` without touching
  the checkpointer or the verifier.

## Decisions

| decision | numbers | by |
|---|---|---|
| two trees, one per retention class, moving as one pair | +2 KB WAL and +0.2–0.6 ms signer CPU a tick; no 10.4 min/day rebuild | W212, R54 |
| tiles partitioned by leaf range; one tile per level below a cut | drop 1.16 s / 294 KB WAL vs 13.8 s / 3 GB; ~1 tile a level vs 10.8 MB a day | W212; checked by Go here |
| the 32-bit power-of-two bug fixed (`n & (n - 1)` past 2^32 leaves) | day 50 at 1,000/s | W212; regression tests in `audit-tree.test.ts` |
| the signer's memory in core | +0.6 ms wall a tick (Node, fsynced); 2 DO writes a second | R54, measured here |
| level-0 tiles kept for the uses tree | saving 47.5 B a use (25%) and 17% of WAL, against a second source of truth for level 0 | this PR, by the numbers above |
| a failed tick leaves its pair pending, finished by the next tick (copy, then commit) | removes #365's "broken until reopened" state; never two pairs for one place | this PR, review r1 |
| the leaf: tagged, length-prefixed columns, its tree and number in it | injective; pinned by vectors | this PR, after `audit/chain.ts`'s encoding |
| a 500 ms tick; a change waits for its seal and at most 2 s for witnesses | sealed within ~530 ms p99 (W209) | R51, R54 |
| the window read as rows, the newest pair read with the barrier | 6.0 → 3.6 ms p50 a tick; three statements a tick | 6b, measured |
| leaf tiles in ranges of 2^24 leaves, made ahead by the write | ~5 ranges a day at 1,000/s; a range is 512 MB | 6b |
| the entry MAC covers the tree and every column but the number (KindInMac) | 16 B (R53): the key's 4-byte tag, then 12 B of HMAC | 6b, after Seal.tla; the tag D162 |
| the log's origin from the signing key; no deployment option | — | 6b |
| witnesses are vault config, opted into, fed by the checkpointer | the plugin's capability where the pairs are signed (R40) | 6b |
| a refusal that stands is alerted once; alarms kept where the plugin reads them | — | 6b |
| a tile read names its tiles as constants | planning 8.7 → 0.4 ms at 150 ranges | 6b, Fable's review |
| the object's memory synced before the database write | one storage round trip a tick | 6b, Fable's review |

## Where it runs (6b)

**The store.** `packages/vault/src/log-store.ts` is `CheckpointStore` over
migration 0022's tables (Postgres) and 0018's (SQLite), through the vault's
own login, which reads `log_*` and writes them only through 0022's
functions.

- **A tick is three statements.**
  1. `close_one()`, the barrier, with the newest pair read in the same
     statement. Only the checkpointer writes that row, so a snapshot from
     before the barrier's lock holds it.
  2. The window, in the next statement, a snapshot taken after the lock:
     changes by number, uses through their one index `(at, request_id)`
     from the floor the newest pair signed, kept by number. It comes back
     as rows: built as JSON, it took 6.0 ms p50 at 1,000/s; as rows,
     3.6 ms.
  3. `write_checkpoint(…)`: both trees' tiles and the pair, one call
     (PairWrittenTogether). A tile only grows, and a second pair at one
     place fails.
- **A tile read names its tiles as constants** (`(level = 0 AND leaf =
  256) OR …`), so Postgres prunes the leaf ranges as it plans. As an array,
  every range was planned: 8.7 ms at 150 ranges, a month at 1,000 uses a
  second, against 0.4 ms (Fable's review). It runs for every witness's
  proof each tick and every change's proof.
- **No read scans history (R48).** Each read of uses is bounded by `at`
  on both sides: from the floor of the pair it starts after, to the slack
  past the floor of the pair that seals where it ends (review r3). Only a
  read past the newest pair, the head, is open-ended.
- **`locate` finds an old use** through the uses' one index. Without its
  time, it reads between its window's floor and the sealing barrier's floor
  plus `deadline_max()` and 60 s (63 s in all); a caller that knows the
  use's `at` (`prove(number, { at })`) finds it in one probe. Its index is where
  its leaf sits among the window's leaves, in the uses tree's level-0 tiles
  (a tick's worth: two or three tiles at 1,000/s). A use whose leaf is not
  there was changed since its tick, and `locate` says so.
  - **The bound is a rule, not an assumption** (review r2): `use_credential`
    answers `ahead` and writes nothing for an `at` more than 60 s past
    Postgres's clock (#372).
  - **The cost, measured** (plan PR 8, T119; 1M uses at 1,000/s, a pair
    every 500 uses, hot cache): counting the window's uses before it by
    `at`, as PR 6 did, read about 63,500 index entries twice, 9.6 ms and
    1,397 buffers a proof. Now: 3.7 ms and 303 buffers without the use's
    time (one pass), 0.4 ms and 17 buffers with it, plus the tiles.
    Changes are found, and counted, by their key.
- **Leaf tiles go in ranges of 2^24 leaves** (`TILE_RANGE`, about 4.7 hours
  at 1,000 uses a second, 512 MB of tiles). `make_tiles` makes each range,
  and the next one, before a tile lands in it. Retention (PR 7) drops whole
  ranges below a cut, and deletes the few upper tiles that end at or below
  it.
- **SQLite** has one writer: the barrier only moves the floor, every
  number committed is final, and the write is the same statements in one
  transaction.

**The entries.** `packages/vault/src/log-entry.ts` turns a row of either
table into its leaf: every column in the table's order but the number,
with the MAC last. The MAC (`entryMac`) is 16 bytes (R53): the tag of the
key that made it, four bytes, then HMAC-SHA256 under a key derived from
the vault's signing seed, cut to twelve (D162). The tag is public, one per
key (HKDF of the seed under a label of its own, `coffre.log.tag.v1`), and
names the key, so that once the signing key rotates (T168) the database
can refuse a replaced key's entries and a reader knows which key to check
one under ("A rotation", below); it vouches for nothing by itself. The HMAC covers the tree and
every column but the number and the MAC (`macData`, KindInMac). The
change path (PR 4) and the use path (PR 5) compute it when they write an
entry; the checkpointer checks it before it seals anything.

**The log's origin** is derived from the vault's signing key:
`coffre.log/<the first 8 bytes of SHA-256 of the changes key, hex>`. Each
tree's origin is that plus `/changes` or `/uses`. A rotation of the key
keeps the trees and moves them to the new key's origin (below).

**A rotation** (T168, W277; the spec: [`formal/Rotation.tla`](../../formal/Rotation.tla),
[formal.md](../formal.md#rotationtla)). A deployment moves to a new
signing key, a new local KEK or a new `signingKey` beside a key service,
and keeps the old one configured (`previousKeks`, `previousSigningKeys`).
The vault's signing keys are then `[new, …previous]`, and the log's rule is
R41's: a replaced key vouches only for what came before the rotation.
- **The boundary is an entry.** At its first start under the new key, the
  checkpointer finds the log under another (the `to` of the newest
  rotation entry, else the key of its head) and writes the rotation: a
  change of the log's own object `log_object('log', 'key')`, its payload
  naming both keys by origin and its own number, its MAC the new key's.
  One transaction: `log_rotate_number` takes the barrier's locks (the
  issue lock, then the fence, both exclusive), reads `retired` again under
  them (a start that rotated first leaves nothing to do) and takes the
  number; the vault MACs the entry naming it; `log_rotate` writes it at
  that number and adds the old key's tag to `log_fence.retired`
  (migration 0050). An entry's MAC covers every column but its number,
  which a database writer can change: a rotation counts only at the
  number it names (`rotationOf`), so one moved up extends nothing. Then
  the checkpointer ticks, so that the rotation is sealed under the new key
  within a tick.
- **Old isolates write nothing past it.** A use whose MAC names a retired
  key is `superseded` (the app answers 503, `Retry-After`; a newer isolate
  answers the retry), in `use_credential`'s own statement, on the fence row
  it reads already: no extra read on the hot path. A change under one is
  refused by a trigger on `log_changes`, whoever writes it. Each check runs
  under the lock the rotation takes exclusive, in the statement that takes
  the number, so no entry under the old key lands past the rotation.
  Without this an old isolate's entry past the boundary would hold every
  tick from then on, and every change would fail at its seal.
- **The signer carries its memory across.** It opens its memory, and the
  database's newest pair, under any key it holds; a pair under a replaced
  key only below that key's rotation, and never at or above a pair it
  remembers under its own. It seals an entry under a replaced key only
  below its rotation, from the boundary it wrote or read at its open,
  never from the database again. Its first pair under the new key extends
  the old key's trees, and is the one it remembers from then on. With its
  memory lost at that moment, it takes the database's newest pair, under
  the old key, alarmed as any lost memory is, and rotates as above.
- **The verifier** takes a newest pair under a replaced key while the log
  moves on from it: below its rotation, and not above the pair held outside
  under the current key. Above the newest pair, a replaced key's entries
  count below its own rotation, whatever key that pair is under (a backlog
  sealed in parts leaves a pair under the new key below the rotation), or,
  with no rotation yet, while the newest pair is under it. The key a pair
  is under is the one its signatures hold under, never a name its notes
  carry. It reads the rotations, in its own snapshot, whenever the vault
  holds a replaced key.
- **The other readers** hold to the same rule, through one keyring
  (`keyring.ts`): the reads' projector, `coffre verify log`'s check of the
  reads, and the vault's `vouch`, which the audit pages ask of the rows
  they show. A replaced key vouches for a pair, an entry, a read or the
  cursor numbered below its rotation; one no rotation retired yet, while
  the newest pair is under it; otherwise for nothing. Each reads the
  rotations and the newest pair in one statement, and keeps no bound
  between calls (a restore brings the rotation back at another number).
  The projector lists every read and moves its cursor under the current
  key; what it listed before keeps the old key's MAC, which holds below
  the rotation, so no row is MAC'd again.
- **A replaced key never comes back.** A checkpointer whose own key a
  rotation retired refuses to open, and the trigger refuses its entries.
- **Witnesses.** The witness's object takes `previous`, the log's keys
  under each replaced key: the pair it holds may be under one, and the
  first pair under the new key it cosigns must extend it.
- **The window.** Until the rotation is sealed, someone who holds the old
  key and writes the database can delete the rotation entry and sign over
  its place with the old key, and no check sees it: R51's window, normally
  the moment between the rotation and the tick right after it. What the
  old key forged before the rotation verifies like the rest, as under
  0.14 ([keys.md](../keys.md)).
- **Seals.** A use checks an object's seal under every key the vault holds,
  the replaced ones included, whatever the change's number: one who holds
  the old key and writes the database can still seal a row the use takes,
  though its change entry is refused by every tick and named by every
  check (BoundaryChecked). Holding seals to the boundary too needs each
  input's change number in the use's row; not done here (T168's scope is
  the log).

**Nothing it awaits is unbounded** (T169). On W278's Cloudflare bench, one
tick waited 25 minutes on a connection that never answered, until a
redeploy reset the object. Every seal waited behind it, sign-in and
readiness with them, and each new vault isolate's first uses waited on the
cutover's seal. Now:
- **A tick runs at most `TICK_BOUND_MS`** (10 s). Past it the checkpointer
  *stalls*: it is closed for good behind its `Fence`, which refuses every
  call it makes to its store and every write to its memory from then on.
  Its host opens another: on Workers the next alarm, its connection cut
  first (`HyperdrivePool.destroy`); on Node a tick later. What the stalled
  one had sent may still land. A memory write the host waits for. A
  database write is refused where a row holds its place, and a barrier
  raises the floor no higher than the next one does (below). Seal.tla's
  `Fenced` (`SealStall`) shows the fence necessary: without it, the stalled
  tick writes a pair the new signer does not hold, an alarm with no
  attacker.
- **A change waits at most `SEAL_WAIT_MS`** (5 s) for its ticks and its
  proof, then the witnesses' 2 s. Past it, or once the checkpointer stalled
  or its database does not answer, it is `Unsealed`: committed and in
  force, and its message carries core's `UNSEALED`, which is all Workers'
  RPC carries. The app answers 503 with Retry-After, and the next tick
  seals it. On Workers the vault asks the object for at most 8 s, and 2 s
  for anything else.
- **The open, the next days of uses, and the upkeep after a tick** are
  bounded too: 10 s, 10 s and 60 s.
- **A use waits on no checkpointer.** An isolate's uses start the object
  behind them (`#behind` in `cloudflare.ts`), and its first ones take the
  cutover as sealed once a pair the vault's key signed covers its number,
  as the newest checkpoint row shows: no seal asked, unless the cutover is
  that new.
- **Readiness asks `sealing()`**: open, its last tick ended well within
  `SEALING_STALE_MS` (5 s), no failure standing (`sealingOf`). On Workers
  the object answers from its own state and clock, in at most 2 s, or the
  answer is no; `/readyz` gives the vault 3 s. Red within seconds of a
  stall, green again once a tick seals.
- **A tick seals at most `WINDOW_MAX` (10,000) entries** of its barrier's
  window, read by number, the next tick at once while more remains, the
  upkeep once it has caught up. After a stall the backlog is hundreds of
  thousands of uses; sealed whole, a tick would run past its bound and
  stall again, for good. A part ends at its last entry and signs as its
  floor the lowest `at` of the uses left above it, if below the barrier's
  (HotPathOne's `ChunkFloor`), found by a probe of the uses' index; its
  time is its newest entry's, so the rest of the backlog is no replay.
  Every pair still has its uses within 63 s of its floor (`CeilingHolds`),
  by the `ahead` rule and the deadline on Postgres's clock. Measured
  (`packages/vault/scripts/chunk-bench.ts`, Postgres 16.14 on Debian, a
  20 ms round trip added each statement): 240,000 uses drain in 24 ticks,
  7.4 s, each tick at most 403 ms (its window read 89 ms, the probe
  2 ms); 1,000,000 in 100 ticks, 56 s, the first and slowest 1.6 s. The
  window read sorts what is left by number (the uses have no index by
  number), so it grows with the backlog: an hour's at 1,000 a second
  takes some 5 s a tick. So a tick's bound grows with its window
  (`WINDOW_ENTRY_MS`, 10 µs a number the barrier's window spans, some
  seven times the measured sort): a drain of millions goes on, and a
  read that takes that long for a few entries is still a stall
  (review by Fable).
- **The first barrier after an open is held to its ceiling too**: the
  barriers whose pairs went unsigned left the floor at most at their own
  clock less the deadline. An upkeep whose checkpointer was closed under
  it raises no alarm; on Node it runs beside the ticks, and on Workers
  readiness counts the bounded upkeep after a good tick as its time.
- **A late barrier is no alarm.** A barrier sent by a checkpointer given
  up on may run in the database after the next one has opened and ticked,
  raising the floor past where that one's last barrier left it. The next
  barrier takes a floor above its last one when it is no higher than its
  own clock less the use deadline (`floor.ceiling`, read after
  `close_one`): exactly what a late barrier leaves, and what this barrier
  raises it to anyway. Higher, a writer raised it, and the tick refuses.
  HotPathOne's `BarrierAcceptsLate` (`HotPathOneStallLive`) shows the rule
  necessary for checkpoints to go on. It leaves open what it always left
  open: a writer who lowers the floor and puts it back before the next
  barrier reads it lets uses in unsealed, and a late barrier can put it
  back too (`HotPathOneStall`, EXPECTED).

**On Node** (`packages/vault/src/checkpointer-node.ts`):
- `runCheckpointer({ database, signingKeys, memory, witnesses })` ticks every
  500 ms, a tick after the last ends. A tick that throws is an alarm, kept
  once; `stop()` closes the checkpointer, so a handle kept after it never
  ticks beside a runner started over the same file.
- The memory is a file, written whole, synced, renamed over the last, and
  the directory synced (`fileMemory`).
- Alarms are appended to `<memory>.alarms`, one JSON line each.
- The vault's process runs it (`localVault`, `serveVault`), through
  `keepCheckpointer`, opened before the vault serves. An open refused (a
  log it cannot take, as after a restore; the database out of reach) is an
  alarm, kept once, and tried again every 10 s, each try making the next
  days of uses first: uses go on, and a change's seal fails with why. One
  vault process per database: two would each sign, and the floor's check
  refuses the second's ticks.

**On Workers** (`packages/vault/src/checkpointer-workers.ts`): one Durable
Object, `export const CoffreCheckpointer = checkpointer()` beside `vault(…)`,
configured by the same `vault(env => …)`.
- **The vault starts it**, from each isolate's first call, before that call
  goes on (`start` in `cloudflare.ts`): its alarm set, then its open. An
  object that refuses to open is started all the same, and each alarm
  tries again, making the next days of uses meanwhile; one out of reach is
  tried again by a call 10 s later.
- **Its memory is its storage**, synced before `remember` returns
  (RememberFirst). The output gate holds a Response and a new connection
  until a write is durable, but not a query on a connection already open,
  as the database write is. So `sync()` makes RememberFirst hold without
  leaning on the gate (Fable's review).
- **It ticks on its alarm** every 500 ms, holding one Hyperdrive connection
  that closes when idle. A failed tick drops the connection and the
  checkpointer, and the next alarm opens both again under `open()`'s rules.
  The old checkpointer is closed first, fenced, its connection cut, with
  nothing else delivered meanwhile. A change still waiting on it can tick
  it no more, so two never sign at once (review r3).
- **A refused open and a tick that throws are alarms**, kept once while
  they stand (Fable's review). A refused open is the gravest of states:
  entries the signer sealed lost, another pair at its place, time run
  back. A write that fails may be a tamper signal: a tile changed under
  the signer. A refused open is never thrown inside the gate, which would
  reset the object; the object stays up and says why.
- **Asked with `fetch`**, as the anchor and the gates are:
  - `startCheckpointer(env.CHECKPOINTER)` starts it;
  - `durableSealThrough(env.CHECKPOINTER)` is the change path's seam;
  - `checkpointerStatus` returns its last ticks and their timings;
  - `checkpointerAlarms` returns its alarms, kept 30 days in its storage.
- **Its workerd test** runs it, the witness's object and an R2 archive
  in workerd itself (`packages/vault/test/checkpointer-workers.test.ts`).

**Witnesses** (`packages/vault/src/witness-workers.ts`): a deployment opts
in by listing them in its vault config (`witnesses: […]`). They are R40's
optional capability, wired where the pairs are signed, in the vault.
- **`durableWitness(env.WITNESS)`** is a Durable Object of its own,
  `witness(env => ({ name, key, log, previous }))`. It cosigns a pair only if both
  trees extend the one it holds. Its client sends each tree's proof from
  the sizes the object holds; on a 409 it learns those sizes and sends
  again. It passes the try's abort signal to the object's request.
  A pair it holds that no longer opens (its settings now name other keys,
  a record damaged) is refused, never forgotten into a fresh witness: a
  new witness is a new name (Fable's review). After a rotation of the
  vault's signing key, `previous` names the log's keys under the replaced
  one: the pair it holds opens under them, and only a pair under `log`
  that extends it is cosigned (T168).
- **`r2Archive(env.ARCHIVE)`** puts each pair it is sent under
  `audit/<upto>.json` without overwriting. The pump sends the newest pair,
  so one a slow put skipped over is not kept; the next, which extends it,
  is. A put over an object already there, answered with null or, under a
  bucket lock, with an error, is the same pair sent again, which is fine,
  or another, which is refused. Under a bucket lock, a Worker or a database
  writer cannot overwrite or delete what it holds; an account admin can
  lift the lock (R54).

**Unwitnessed changes are recorded** as alarms: on Node in the alarms file,
on Workers in the object's storage. A refused tick, a memory found behind
the database and a change answered unwitnessed all land there, and a
refusal that stands is alerted once, not every tick. R40's plugin and
PR 8's surfaces read them from there.

**The change path's seam** is `SealThrough`: `runCheckpointer(…).sealThrough`
on Node, `durableSealThrough(…)` on Workers. `sealThroughDouble` in
`packages/vault/test/audit-tree.ts` stands in for it in PR 4's tests.

## Not here yet

- **PR 4, the change path:** a change waits on `SealThrough` and answers
  with what it returns (R51).
- **PR 7, retention:** days and tile ranges made ahead and dropped (with
  `make_day`, `make_tiles`), the freshness step, and the cut named in the
  uses tree's coordinates.
- **PR 8, the verifier's surfaces:** built (`packages/vault/src/verifier.ts`;
  0.15-plan.md, "As built: PR 8"): a page's check from the newest pair.
  No walk of the whole log on a request (D145): `verifyLog` from the first
  entry, through the retention cut, is what an offline scan will run.

## The spec, and where the code holds it

Plan PR 1 (W211) models the pair in `formal/Seal.tla`, and TLC shows each
protection necessary. The names below are the spec's; each row names where
the code holds it and the tests that break it.

| protection (`Seal.tla`) | in the code | tests (`packages/vault/test/audit-tree.test.ts`) |
|---|---|---|
| NumberUnderLock, CloseLocks | `CheckpointStore.close`: the barrier (`close_one`) | 6b, over migration 0022 |
| BarrierChecksFloor (`HotPathOne.tla`) | `tick`: the floor `close_one` found must be exactly where this process's last barrier left it (after a restart, no lower than the newest pair's), else every tick refuses until reopened; each pair signs its floor, and windows are read from the newest pair's | "BarrierChecksFloor: …", "review r9–r10, BarrierChecksFloor: …" |
| BarrierAcceptsLate (`HotPathOne.tla`, T169) | `tick`: a floor above the last barrier's no higher than `floor.ceiling` is a late barrier's | "T169: a tick whose barrier never answers…"; stall.test.ts |
| ChunkFloor, CeilingHolds (`HotPathOne.tla`, T169) | `tick`: a part of the window ends at its last entry and signs `max(floor held, min(barrier's floor, lowest at left above))`; its time its newest entry's | "T169: a backlog far past the window…" and the clock stepping back, log-store.test.ts |
| Fenced (T169) | `Fence`: every store call and memory write of a checkpointer closed or stalled refused; `close` waits for its memory writes in flight | "T169: …", stall.test.ts, log-hosts.test.ts and workers-stall.test.ts |
| RememberFirst | `tick`: `memory.remember` before `store.write` | (e) |
| SignerMemory | `open()`: memory equal, a prefix in both trees, or re-derived; else refused | (b), (c), (g), (j), "a memory restored…" |
| RowChecked, PairChecked | `tick`: the newest pair, each tree's own newest note, byte for byte | (m), "PairChecked: …", "review r1: a row replaced…" |
| PairWrittenTogether | `CheckpointStore.write`: both notes and both trees' tiles, one statement | the store's contract; 6b's stores hold it |
| PairRemembered | `encodePair`: one memory record for both notes | "the pair is one value…" |
| KindInMac | `authentic` covers the tree; `sealThrough` proves a change in the changes tree | "KindInMac: …", "review r2, KindInMac: …" |
| MacChecked | `tick` refuses an entry whose MAC fails | "nothing is sealed over a forged entry…" |
| WaitForSeal | `sealThrough`: sealed, proved, then witnessed or 2 s | "a change answers once sealed…", "review r1: a change whose entry…" |
| Witness | `witnessPair`, the pumps | (c), "a change waits for the witness…" |
| RequestIdChecked | the verifier's `check` (verifier.ts): each request once in a walk, and the unique indexes that refuse a copy further apart still there | verifier.test.ts, "a page's check names a forged entry…" |
| PairVerified | `verifyLog`: a row whose notes do not open as one pair is a problem | "the pair is one value…" |
| invariants KindKept, PairConsistent, AnsweredChangeKept | the rows above together | as above |

**Where this PR is stricter than the spec.** The spec lets `open()` repair
a half-written pair: rows of the two trees at different `upto`s, checked
each against the one remembered pair. This code refuses them instead. With
PairWrittenTogether, only a database writer can leave a pair half written.
Refusing is the safe side of the same rule and costs no liveness to an
honest crash.
