# Merkle checkpoints for 0.15's audit log (W209)

An experiment, not a decision. Written by W209 on 2026-10-26, on a draft PR
marked DO NOT MERGE. It answers one question: once 0.15's hot path gives up
the chain between entries (W201, [`hot-path-simple.md`](https://github.com/erwinkn/coffre/blob/b4453ebc7a0a/docs/design/hot-path-simple.md);
W208's one-call `use()`), what keeps the audit log honest, and how fast?

The setting, in one paragraph. A use appends one entry in one statement. The
entry gets its number from a Postgres sequence and carries a MAC over
everything except that number (the vault computes the MAC before the INSERT
picks the number). Nothing links one entry to the next. So someone with
write access to the database, but not the vault's keys, cannot forge or alter
an entry. They can delete one: numbers have gaps anyway (an aborted append
leaves one), so a missing number proves nothing. Something has to seal the
entries, quickly and in a way that no database writer can undo.

- **Prototype:** [`experiments/merkle/`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/). The
  tree, tiles and proofs are in `src/tree.ts` and `src/tiles.ts`; the signed
  checkpoints in `src/note.ts`; the log, checkpointer and proofs in
  `src/log.ts`; the verifier in `src/verify.ts`; retention in
  `src/retention.ts`; the change rule in `src/change.ts`; witnesses in
  `src/witness.ts`; and the SQL in `schema.sql`.
- **Independent check:** [`experiments/merkle/go/verify.go`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/go/verify.go),
  Go's `golang.org/x/mod/sumdb/tlog` and `sumdb/note`.
- **Cloudflare:** [`experiments/merkle/worker/`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/worker/)
  holds a Durable Object witness, an R2 archive under a bucket lock, and the
  receipt CPU probe. It ran on Erwin's personal account and has been deleted.
- **Model:** [`formal/Seal.tla`](../../formal/Seal.tla), checked by
  [`scripts/formal.sh`](../../scripts/formal.sh).

## In short

- **Two growing RFC 9162 trees** (Certificate Transparency's), one per
  retention class, decided by numbers (W212, "Tree shape, by numbers"):
  changes, kept forever, and uses, pruned by day. Each is byte for byte the
  tree #365 built, stored as Go/C2SP tiles. (#365 itself has one tree for
  both; the code below is that.) Checkpoints are C2SP signed notes with Ed25519
  signatures. Go's sumdb code, which shares no line with ours, verifies our
  signatures, tiles, inclusion proofs and consistency proofs, and produces
  byte-identical proofs from our tiles.
- **Sealing needs no lag.** The append takes its number under the fence's
  shared lock, so the checkpointer's barrier (that lock held exclusive just
  long enough to read the sequence) seals everything up to the sequence's
  last value, with nothing left in flight. The window is one tick plus a few
  milliseconds. Measured at 1,000 appends/s:

  | tick | sealed after (p50 / p99 / max) | Postgres CPU |
  |---|---|---|
  | 1 s | 1,017 / 1,031 / 1,031 ms | unchanged (12.8% vs 12.9% of a core) |
  | 500 ms | 507 / 526 / 526 ms | unchanged (13.0%) |
  | 250 ms | 254 / 269 / 272 ms | unchanged (12.9%) |

- **Something outside the database must hold the newest signed head.**
  Without it, a database writer can cut the log's tail, and can get a second,
  different history signed by a checkpointer that restarts from the
  database: a split view. With it, both are caught. The cheapest such thing
  is the checkpointer's own memory (its Durable Object's storage). It costs
  nothing extra and should be core, not a plugin. External witnesses (a
  Durable Object witness, an R2 archive under a lock) stay optional, as R40
  has it, and add third-party verifiability.
- **TLA+ found a real bug, and settles the core/plugin split.** The
  checkpointer must record a head outside the database before writing it to
  the database. Otherwise a crash between the two, followed by a rollback,
  gets a split view signed even with the anchor in place. Fixed and modelled
  (RememberFirst). The model also shows a witness alone cannot replace the
  signer's memory.
- **A change answers once sealed** (R51, approved by Erwin during the
  experiment): +5 ms p50 / +53 ms p99 with no witness, +63 / +518 ms with
  the Cloudflare witness. This closes the "undo a change" window entirely.
  Uses keep a one-tick window.
- **Receipts** cost ~24 µs of Workers CPU each for the Ed25519 signature;
  batching saves about 18 µs of that, which is not worth coalescing requests. Recommendation: none for uses (nobody would check them); a change's
  answer carries its inclusion proof instead.
- **Key ratcheting** buys too little here to be worth a holder for its
  state. Below is why.
- **Retention** works with the tree in both layouts. A day is dropped only
  below a freshly sealed head. The retention entry is a kept-forever change
  that commits to the changes below the cut. Retention drew a review finding
  in each of rounds 3 to 9, all fixed, the last fix unreviewed. It is the
  least settled part (see that section).

## The tree

### The shape

Decided by numbers in "Tree shape, by numbers" below (W212). In short:
**two growing trees, one per retention class**. Changes go in one, kept
forever; uses go in the other, dropped by day. Each tree is the one this
section describes, byte for byte. A chain of per-window roots loses on
proofs: an entry from 09:00, proved against the head at 17:00, needs 57,600
links.

### Byte for byte

- A leaf hashes as `SHA-256(0x00 || data)`, a node as
  `SHA-256(0x01 || left || right)`, and a tree of n leaves splits at the
  largest power of two below n (RFC 9162 §2.1).
- **Leaf data is the whole entry, in order:** number, at, principal,
  credential, kind, request_id, payload, seal, MAC. Its number is sealed
  with it, so entries cannot be renumbered once sealed. Anyone holding the
  public key can check rows against the tree, without the MAC key. The MAC
  then matters only until an entry is sealed.
- **The leaf index is the entry's position, not its number.** Numbers have
  gaps; positions do not. Sealed entries go into the tree in number order.
- **A checkpoint is a [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint)
  inside a [signed note](https://c2sp.org/signed-note):**

  ```
  coffre.example/audit                           origin
  60497                                          tree size
  4Ht6…=                                         head, base64
  upto 2000000009183                             every number at or below it is final
  at 1793048700000                               when it was signed

  — coffre.example/audit Az3g…                   key ID and Ed25519 signature
  ```

  `upto` is an extension line. It says every number at or below it is final:
  either in the tree, or never to appear. That is what turns a gap from
  "maybe deleted" into "never was".
- **Tiles** follow [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and Go's
  `tlog.Tile`. Each tile has height 8, holding up to 256 hashes of one tree
  level, and a partial tile only grows. One table, `audit_tiles(level, idx,
  hashes)`, stores them. A proof reads one tile per 8 levels, in a single
  statement.

**Checked by an independent implementation.**
[`go/verify.go`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/go/verify.go) ran against our
proof server over a log of 70,003 leaves (70,001 uses and two day entries)
that spanned three days. It:

- opened every checkpoint with `note.Open`;
- loaded our tiles through `tlog.TileHashReader`, which checks every tile
  against the signed head, then recomputed the head (`tlog.TreeHash`);
- checked 100 inclusion proofs with `tlog.CheckRecord` and 5 consistency
  proofs with `tlog.CheckTree`;
- recomputed each proof with `tlog.ProveRecord` and `tlog.ProveTree` from
  our tiles, and got the same bytes;
- rejected every proof with one flipped byte.

What this proves: the bytes of the tree, the tiles, the proofs and the notes
are RFC 9162's and C2SP's. It does not check how an entry becomes a leaf.
The leaf Go proves comes from the same proof server, and Go only checks it
names its number. That binding, `leafData`, is checked by the TypeScript
tests and by the verifier, which rebuilds every leaf from the rows.

### What the database holds

Laid out as W208's: one `audit` table, `PARTITION BY LIST (kind)`. Changes
live in `audit_changes`, forever; uses live in `audit_uses`, partitioned by
day. Nothing in Postgres keeps numbers unique across partitions, so the
verifier checks that, and also that request IDs are unique (see Replays,
below).

## Tree shape, by numbers (W212)

Erwin approved #365's recommendations except the tree shape: "validate that
shape against other options with actual quantitative arguments". This
section does that, numbers first, then taste.

**Decision (recommended): two growing RFC 9162 trees, split by retention
class.** One tree holds changes and is never pruned. The other holds uses
and is pruned from the left, a day at a time. Each is #365's tree, tiles and
C2SP checkpoint, unchanged. A tick seals both and signs both heads with the
same `upto`, and the two heads are kept, written and checked as one pair
("What `split` needs to stay one log", below). Measured against #365's single tree, a tick of the split
writes 7 to 8% more bytes and WAL (2 KB, under 0.5% of what the whole log
writes a tick) and costs 0.2 to 0.6 ms more signer CPU (a second
signature). Storage, proof sizes and walk cost are the same. It wins
on retention:

- no daily rebuild of the dropped day before dropping it (10 minutes of CPU
  a day at 1,000/s);
- no digest of the kept changes in the retention entry;
- a change stays provable forever: 25 hashes after a year at one change a
  second, growing as log₂ of the number of changes (29 after ten years).

That is the part of #365 that drew a review finding in each of rounds 3 to 9.

### The shapes compared

All of them use #365's hashing and its sealing (one barrier, one read and
one write a tick); only the trees differ. The code is in
[`experiments/merkle/shapes/`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/shapes/).

| | shape | prior art |
|---|---|---|
| **one** | one growing tree of every entry (#365) | CT (RFC 9162), Trillian, Go's sumdb, Sigsum, Rekor v2 (Tessera tiles) |
| **split** | one growing tree per retention class: changes (forever) and uses (pruned by day) | CT's temporal sharding: logs split by *when their entries may be deleted* (each shard holds certificates expiring in one period, and is retired whole) |
| **day** | a tree per `at` day; each closed day's root a leaf of a top tree, the open day's head beside it in the checkpoint | CT/Sunlight shards per year, Rekor's frozen shards, with a top tree over them |
| **tick** | a tree per tick (≈500 entries), rebuilt from its entries when needed; each tick's root a leaf of a top tree | AWS QLDB's journal blocks under one digest tree |
| **chain** | a tree per tick; each checkpoint names the previous one's hash | SQL Server Ledger blocks, AWS CloudTrail hourly digests, W201's flat hash per checkpoint |
| **mmr** | a Merkle Mountain Range: every node in append order, the root its peaks bagged | Peter Todd's MMR (proposed for OpenTimestamps), Grin |

Two of these collapse into others:

- **An MMR is the RFC 9162 tree.** RFC 9162's head of n leaves is the
  perfect subtrees of n's binary digits, bagged right to left: a mountain
  range. Hashed with the same node hash, both give the same root at every
  size (`shapes.test.ts`, 1,100 sizes). So they have the same proofs, hash
  for hash. Grin hashes a node's position into it, which changes the bytes,
  not the sizes. What an MMR adds is storage: it keeps every node, where
  tiles keep one level in eight.
- **Shards by period** (CT's per-year logs, Rekor's frozen shards) are `day`
  without the top tree: each period a separate log, with its own origin.
  Witnesses and monitors are configured per log, so a daily log would mean
  configuring every witness every day. A yearly shard does not help a
  retention measured in weeks.

### Sealing a tick

Measured with [`shapes/bench.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/shapes/bench.ts)
on a Postgres 16 of W212's own, limited to 2 vCPU and 2 GB. Each tick seals
500 leaves, one change in a thousand. Every shape writes its rows and signed
heads in one statement, as #365 does. The figures are means over 20,000
ticks (10M leaves), with a CHECKPOINT every 600 ticks to stand for
Postgres's 5-minute checkpoints at a 500 ms tick, so full-page writes count.
The entries' own append and the sealing read are the same in every shape and
are left out. For scale, #365's whole log, with entries and tiles, writes
**443 KB of WAL a tick** at 1,000 appends a second (`shapes/midnight.ts`).

| per tick | one | split | day | tick | chain | mmr |
|---|---|---|---|---|---|---|
| rows written | 4.95 | 6.35 | 4.95 | 2.00 | 1.00 | 5.90 |
| bytes written | 24.4 KB | 26.3 KB | 24.5 KB | 4.4 KB | 0.3 KB | 36.3 KB |
| WAL, mean (p50) | 39.2 (32.1) KB | 38.3 (33.6) KB | 36.6 (31.0) KB | 5.7 (5.6) KB | 0.5 (0.5) KB | 45.9 (42.2) KB |
| write statement, p50 / p99 | 1.39 / 2.99 ms | 1.46 / 3.06 ms | 1.36 / 2.78 ms | 0.57 / 1.16 ms | 0.35 / 0.65 ms | 1.71 / 2.97 ms |
| signer CPU (tree + signatures), p50 | 1.27 ms | 1.50 ms | 1.22 ms | 1.01 ms | 0.81 ms | 0.76 ms |
| flat as the log grows (R48): WAL at 0 → 10M → 1 day → 1 year, synthetic start states (below) | 27.9 → 27.9 → 27.9 → 27.7 KB | 29.6 → 30.1 → 29.8 → 29.9 KB | 27.8 → 27.8 → 27.8 → 29.0 KB | 4.9 → 5.0 → 4.9 → 4.9 KB | 0.5 KB throughout | 40.7 → 40.9 → 40.8 → 40.9 KB |

- **Every shape writes the same a tick at any size.** The last row's runs
  (600 ticks each) start from logs of 0, 10M, 86.4M and 31.5B leaves. These
  are synthetic start states: the shape's right edge is set up in memory at
  that size (`shapeAt`), and the tile tables start empty. So they measure
  what a tick writes at that size: its rows, bytes and WAL. They do not
  measure a 1.3 TB tile store's index depth, cache pressure or vacuum
  state. The 10M rows of the table, and #365's `history.ts`, do
  materialize 10M leaves (seal p50 2.2 → 2.3 ms from 70,000 to 10M). A tick
  touches the tree's right edge, one tile per level, and the levels above
  1 only when a tile below them fills.
- **The tree is under a tenth of the log's write load** in `one`, `split`
  and `day`: 30 to 40 KB of the 443 KB. `tick` and `chain` write less
  because they store no leaf-level hashes, not because of their shape (see
  "Leaf-level tiles", below). The MMR writes 46% more than `one`, because
  it keeps every node.
- **The split's second tree costs, a tick:**
  - 1.4 more rows;
  - 7 to 8% more bytes and WAL;
  - 0.2 to 0.6 ms more signer CPU, mostly a second Ed25519 signature.

  Three interleaved repeats of 600 ticks each, `one` then `split`, give
  this WAL:

  | | from an empty log | from a year |
  |---|---|---|
  | one | 27.5 KB, identical in all three | 27.7 KB, identical |
  | split | 29.5–29.7 KB | 29.9–30.2 KB |

  So the split writes +2.1 KB a tick, under 0.5% of the log's 443 KB. The
  table's 20,000-tick means are one run each, with vacuum and checkpoints
  in them. Those put `split` below `one`, which is noise, not a result.
- Not in the table, common to all: verifying 500 MACs and hashing 500 leaves
  costs about 2.3 ms of signer CPU (3.3 µs and 1.1 µs an entry).

### Storage and retention

| | one | split | day | tick | chain | mmr |
|---|---|---|---|---|---|---|
| tree storage per entry, on disk (10M leaves, compacted) | 41.1 B | 41.1 B | 41.1 B | 0.08 B | 0 | 81.8 B |
| signed heads per entry | 0.71 B | 1.41 B | 0.83 B | 0.83 B | 0.83 B | 0.71 B |
| retention can delete | level-0 tiles below the cut | the uses tree below the cut, every level | the day's whole tree | (nothing stored per entry) | nothing: every link stays for the chain to verify | node chunks below the cut |
| retention must keep, a day of 86.4M entries | higher-level tiles: 10.8 MB a day, forever (as #365 does; 1 tile per level would do, below) | the changes tree (32 B a change, kept as a feature); 1 tile per level of the uses tree | 32 B (the day's root) | one root per tick: 5.5 MB a day (1 tile per level would do) | 172,800 links: 72 MB a day, forever | the peaks |
| deleting a day's tiles | 13.8 s, 3.0 GB of WAL (DELETE; measured at 10M leaves, × 8.64) | the same | 1.16 s, 294 KB of WAL: DROP of a table holding a day's 2.9 GB of tiles | — | — | 26 s, 6.0 GB |
| checked before dropping (round 9), beyond the freshness step every shape keeps | the window below the cut rebuilt from its entries: **10.4 min of CPU a day** (7.2 µs an entry, read, hashed, into the tree) | **nothing**: retention names the cut alone and never touches the changes | nothing, if changes are in a tree of their own; otherwise as `one` | as `one` | as `one` | as `one` |
| digest of kept changes in the retention entry | yes, and the verifier re-reads every cut's changes on every walk, so its cost grows with history | none | as `split` or `one` | yes | yes | yes |
| a change from a dropped day, proved later | not from the tree (its siblings' hashes are gone): its retention entry's inclusion, plus the cut's kept changes, all of them, to rebuild the digest | **25 hashes** a year in, at one change a second (log₂ of the changes), as before the drop | as `split` or `one` | as `one` | as `one` | as `one` |
| uses of the next day below a cut ("stragglers", `at` days) | 275 p50, 306 max at each midnight | the same | **none**: a day's tree holds exactly its partition | as `one` | as `one` | as `one` |

- **The deletes are a layout choice, not a shape.** `one` and `split`
  delete a prefix of a tree, so their tiles can be partitioned by leaf range
  and dropped whole, as `day` does: from 13.8 s and 3 GB of WAL a day to
  1.2 s and 0.3 MB.
  Worth doing in either.
- **One tile per level is enough below a cut.** Proofs of entries above a
  cut, and consistency proofs from heads above it, read only the tile that
  holds the cut at each level. Every tile wholly below it can go, at every
  level. `shapes.test.ts` checks this exhaustively on a tree of 1,500 leaves
  cut on and around tile edges (every leaf above the cut, consistency from
  every size above it), and sampled on 300,000 leaves. That turns #365's 10.8 MB a day kept forever
  into five tiles, in any shape. Not yet checked against Go's
  `TileHashReader`, which also reads each tile's parent to check it. The
  parents of those tiles hold the cut too, so they would be kept.
- **The verifier's cost in `one` grows with history.** #365's verifier loops
  over every retention entry ever written, and reads every change kept below
  each cut, on every walk, incremental ones included. At 1,000 changes a
  day, a year's walk starts with about 2.6 s of re-reading before it reaches
  its own entries; at one change a second, about 4 minutes. That is against
  R25. `split` walks each tree from its own last verified head.
- **Stragglers** were measured on #365's own `at`-day log
  ([`shapes/midnight.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/shapes/midnight.ts)):
  1,000 appends a second, days 5 s long, 34 midnights. Each midnight's cut
  falls on the first tick past the day's last number, so about half a tick
  of the next day lies below it. With a use held to R53's 3 s deadline, the
  bound is 3.5 s of uses: 3,500. Measured, that is 3 in a million of a
  day's uses, unprotected for one day; at the bound, 40 in a million.

### Proofs, a year in

A year at 1,000 a second is 31.5 billion entries. Proof sizes come from RFC
9162's recursion, and every time is a real verification of a proof that size
([`shapes/proofs.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/shapes/proofs.ts),
`shapes/sparse.ts`). The proofs are against the newest head. Changes in
`split` are one a second, the heavy case.

| | one (= mmr) | split | day | tick | chain |
|---|---|---|---|---|---|
| inclusion, entry 1 min old | 28 hashes, 896 B, 82 µs | use 29; change 16 | 21 | 26 | 129: 10.8 KB, 0.5 ms |
| inclusion, 1 day old | 32, 1.0 KB, 77 µs | use 32; change 25 | 32 | 35 | 172,809 links: 15 MB, 0.65 s |
| inclusion, 1 year old | 35, 1.1 KB, 69 µs | use 35; change 25 | 36 | 35 | 63M links: 5.6 GB, ~3 min |
| consistency, heads 1 tick apart | 23 hashes, 76 µs | a tick of 500 uses: 28, 97 µs; of 499 uses and a change: 28 + 19 = 47, 169 µs | 16 (custom) | 18 | 1 link, 88 B |
| consistency, 1 day apart | 21, 62 µs | 41 (both trees), 162 µs | 31 (custom) | 17 | 172,800 links: 15 MB, 0.5 s |
| consistency, 1 year apart | 34, 81 µs | 35 (the changes tree was empty a year back), 71 µs | 29 (custom: the old open day to its end, its place in the top tree), 72 µs | 26 | 63M links: 5.6 GB, 181 s (all walked) |
| one proof is | one RFC 9162 path | one RFC 9162 path, in its tree | two paths (day, top), or one for today | two paths (tick, top) | a path and every link since |

Proof lengths move by a few hashes with the sizes' binary digits (`one`'s 23
against the uses tree's 28 for one tick is that, not a cost of splitting).
Every tree shape verifies anything in under a quarter of a millisecond. The
chain does not: its proofs grow with age. That rules it out on R48 alone.

### Walks, witnesses, the ecosystem

| | one | split | day | tick | chain | mmr |
|---|---|---|---|---|---|---|
| full walk, tree part per entry (10M; ±0.15 µs between runs) | 2.49 µs | 2.62 µs | 2.44 µs | 2.57 µs | 2.49 µs | 2.37 µs |
| walk all changes, alone | no: the tree mixes them with uses, all walked | **yes**: a year at one change a second is 31.5M entries, against 31.5B | no | no | no | no |
| a witness stores | the newest note (229 B) | two notes | the newest note | the newest note | the newest note | the newest note |
| a witness checks, per tick | signature (138 µs) + 23-hash consistency (75 µs) | two signatures; consistency of 28 hashes (110 µs), or 47 (200 µs) on a tick with a change | the top tree; **the open day only with a witness of our own** | as `one`, on the top tree | one link, and it **must see every link** (a missed one needs all since) | as `one` |
| Go's `sumdb/tlog`, C2SP witnesses | yes (#365's Go check) | yes: each tree is #365's bytes | the top tree only | the top tree; an entry's proof is two `CheckRecord`s | no | only hashed as RFC 9162, when it is `one` |

- **Walks cost the same in every shape.** A tree costs about one node hash
  per leaf, however it is cut up. Every shape also hashes the leaf, at
  1.1 µs, and checks the MAC, at 3.3 µs. With the database read, #365's
  walk is 7.2 µs an entry.
- **`split` can audit what changed without walking the uses.** That is
  three orders of magnitude less to walk for the entries that matter most.
  It is cheap enough for a routine full walk of every change ever made.

### What each would change in #365, and in the model

| | lines and moving parts vs #365 (estimated by file, not ported) | TLA+ (`formal/Seal.tla`) | round 9's retention fix |
|---|---|---|---|
| one | — | — | needed (rebuild below the cut before dropping) |
| split | about even in lines. Added: a second edge, head and note in the checkpointer, kept as one pair (below); pair checks in `open()` and at each tick; a `tree` column on tiles and checkpoints; two origins for witnesses. Removed: the window rebuild, `keptBetween` and the kept-changes digest in retention and in the verifier | none for today's invariants, by the reduction below, provided the pair rules hold; the pair belongs in the model when the port starts. A retention model, when written, is smaller: changes are never pruned | **not needed**: no sealed change is ever below a cut. The freshness step (#365's step 2) stays, as in every shape |
| day | +~120: day trees, a top tree, closing a day once its 3 s deadline has passed, a checkpoint format of our own, a witness of our own | the witness's check splits in two, and a standard one checks only the top | needed for changes, unless they are split out too |
| tick | +~60: a tree per tick, a top tree, proofs in two parts | as is | needed |
| chain | −120 (no tiles), but proofs walk links, and the witness pump must send every head, not the newest | publication must keep every head (today it keeps the newest only) | needed |
| mmr | +~80: a node array instead of tiles, its own proofs; non-standard if position-hashed | as is | needed |

### What `split` needs to stay one log (review r1)

Two trees are only as strong as #365's one tree if the two heads behave as
one head everywhere the model and the code use "the head". Built as two
independent logs, a crash between writing one tree's checkpoint and the
other's would leave them at different `upto`s. A restart that repaired each
tree on its own could then sign a uses head for a window whose changes head
is already out: a fork of one tree that the other tree's witness never
sees. So the two heads form a **pair**, under these rules:

1. **Two logs, two origins.** `coffre.example/audit/changes` and
   `coffre.example/audit/uses`, two Ed25519 keys derived from the vault's
   signing secret. Each checkpoint is a standard C2SP one. Both carry the
   same `upto` and `at` lines. The bench signs them this way since review r1.
2. **One tick signs both.** Both notes go to the signer's memory in **one
   write**, one record holding the two, before the database has either
   (RememberFirst).
3. **One statement writes both.** It writes both trees' tiles and both
   checkpoint rows, as `shapes/bench.ts` does. No database state holds one
   without the other.
4. **`open()` takes the pair as one value.**
   - The database's newest rows must be a pair at one `upto`. Two rows at
     different `upto`s are refused.
   - #365's rules apply to the pair: equal, a prefix of it, or re-derived.
     A re-derivation rebuilds both trees from the same window of entries,
     and must give both remembered heads, or it refuses.
5. **Each tick checks both rows.** The database's newest pair must be the
   pair the signer holds (RowChecked).
6. **Witnesses get the pair.**
   - The pump sends both notes in one publication: one request to a witness
     of our own, or each note to the standard witness of its origin.
   - A change answers (R51) once a pair at or above its `upto` is
     witnessed on both logs. With no witness, it answers once that pair is
     sealed.
7. **The verifier walks both trees from one start `upto` and merges them by
   number.** Numbers and request IDs must be unique across both trees. Each
   leaf's `kind` must match its tree: the kind is in the MAC and the leaf, so
   an entry moved between trees fails. Pairs must share their `upto`.

**Why the model needs no change for today's invariants, under rules 2 to
5.** Every action `formal/Seal.tla` takes on the head acts on the pair as one
value: signing, remembering, writing, comparing at `open()` and at each tick.
The pair is a function of the sealed sequence the model already tracks: its
two projections by kind, at one `upto`. So each model state maps to exactly
one state of the split. Each invariant stated over heads (Complete,
SealedDeletionDetected, SplitViewDetected, AnsweredChangeKept, NoFalseAlarm)
holds for pairs if it holds for heads.

Two things this argument does not cover:
- **Standard witnesses see one log each.** A fork of one tree is a fork of
  that log, which its own witness refuses. That is what each needs to
  check.
- **A reader that pairs notes itself.** Notes from different ticks carry
  different `upto`s, and rule 7 rejects them.

Putting the pair into `Seal.tla` explicitly, with a crash between the two
notes, is the first step of the port (R45). It is an argument here, not a
TLC run.

### Retention with `split`, step by step (review r1)

The freshness step stays, and the cut is named in the uses tree's own
coordinates:

1. **Seal a pair at least two freshness bounds after the day's cut**
   (#365's step 2, unchanged). Append an `audit.retention.begin` change and
   wait for its seal. From then on, the signer refuses any entry stamped
   before the cut, less its bound. This is what keeps copies of dropped uses
   out, since no lookup can match them once their originals are gone.
2. **Append the `audit.retention` change.** It holds `{day, prev: {upto,
   usesSize}, cut: {upto, usesSize}}`. The cut is the first pair at or above
   the day's highest number. `usesSize` is read from that pair's signed
   uses note, not from a row, and is the uses tree's size, not the log's.
   The change is sealed in the changes tree, which is never pruned.
3. **Drop the day's uses partition**, after the entry. A crash between the
   two is finished by a retry, as in #365.
4. **Delete the uses tree's tiles below the cut**, by uses-tree leaf index
   (`cut.usesSize`), at every level, except the tile holding the cut at each
   level.

**What the verifier does.**
- It walks the changes tree from genesis, or from its last verified changes
  head. Every retention entry is on that walk, and each must chain from the
  one before, be sealed, and sit above its own cut.
- It walks the uses tree from the newest cut's `usesSize`. It starts from
  the kept edge tiles, checked against that pair's signed uses head.

**What goes, against #365.** Step 1 (rebuilding the window below the cut
from its entries) and step 3's digest of the kept changes. Both existed so
that a sealed change could not be lost across retention. In `split`, no
change ever lies below a cut.

**What stays.** The freshness step and its bound. The stragglers: up to
half a tick of the next day's uses at each midnight, below the cut and
unprotected until their own day goes, as in #365.

### The decision, numbers then taste

**Numbers.**

- `chain` is out: proofs and witness catch-up grow with age, 5.6 GB a year.
- `mmr` is `one` with twice the storage.
- `tick` and `day` match `one` on cost and proofs. They lose standard
  verification: an entry's proof comes in two parts, and `day`'s open day
  is invisible to a standard witness. That is the one protection #365 found
  against the Cloudflare account itself.
- That leaves `one` and `split`. A tick of `split` costs 7 to 8% more
  bytes and WAL (2 KB) and 0.2 to 0.6 ms more signer CPU. A proof or a walk
  costs the same in both. `split` drops what `one` needs for
  retention:
  - the 10-minute daily rebuild;
  - the kept-changes digest;
  - a verifier cost that grows with history.

  It also keeps every change provable forever (25 hashes a year in, at one
  change a second). The only measured gap in
  favour of `day` is the stragglers: 275 uses at each midnight, against a
  non-standard checkpoint.

**Taste.** Each tree has one retention rule: the changes tree never shrinks,
and the uses tree only loses its left end. That is CT's lesson about
sharding by when entries can be deleted, taken at its smallest: two classes,
two logs, both standard. Every format stays C2SP and RFC 9162, and every
verifier and witness that reads #365's tree reads both. The second tree is a
constant: one more signature, one more origin, one more row a tick.

**Also worth taking, in either shape** (separate decisions, numbers above):

- **Below a cut, keep one tile per level**, not every level above 0.
- **Partition tiles by leaf range**, so retention drops a table instead of
  deleting a day's rows: 13.8 s and 3 GB of WAL a day, down to 1.2 s and
  0.3 MB.
- **Optionally, store no leaf-level tiles for the uses tree** (`one-0` in
  the bench). The level-0 tile is rebuilt from its 256 entries when a proof
  or a tile request needs it.
  - Gains: 41 B an entry, about 16% of the log's storage beside a 213 B
    entry row, and 85% of the tree's WAL (5.6 KB a tick instead of 39 KB).
  - Costs: a proof's leaf-level read goes from one tile (0.56 ms p50) to 256
    entries (2.1 ms p50).
  - The bytes served are the same.

  Only if storage matters more than proof latency, which is rare: R51's
  change proofs come from the changes tree, which keeps its tiles.

**Fixed on the way.** #365's `tree.ts` tested "is n a power of two" with
`n & (n - 1)`. JavaScript's bitwise operators work on 32 bits, so past 2³²
leaves the tree split wrongly. At 1,000 a second that is day 50. Now it uses
plain arithmetic, with a regression test that fails on the old code
(`test/tree.test.ts`).

**Not measured.**

- Go's code against a split log, and against a tile set cut to one tile per
  level. The split's trees are #365's bytes, so Go's check of #365 covers
  their format, not a run.
- The split ported into #365's checkpointer, verifier and attack suite. The
  line counts above are estimates by file.
- The stragglers on Workers: their clocks and Hyperdrive's latency would
  move the count, not its bound.

## Sealing

```
use      SELECT append_entry(…)                     one statement
           pg_advisory_xact_lock_shared(fence)
           n := nextval('audit_number')             under the lock
           INSERT …; COMMIT                          the lock goes with it

tick     SELECT * FROM seal_window(last upto)       one statement
           pg_advisory_lock(fence)                  exclusive: waits for appends in flight
           upto := pg_sequence_last_value(…)        every number ≤ upto has ended
           pg_advisory_unlock(fence)                held for microseconds, not for the read
           RETURN the entries in (last upto, upto]
         verify each MAC; hash leaves; extend the tree; sign
         remember the head outside the database     (RememberFirst)
         write tiles + checkpoint                    one statement
         hand the head to the witnesses              not awaited by the next tick
```

**Why no lag works.** An append takes its number only after it holds the
shared lock, and keeps the lock until it commits or aborts. When the
barrier holds the lock exclusively, every number up to the sequence's last
value belongs to an append that has ended. Every later append will take a
larger one. Example: appends A and B hold the lock with numbers 41 and 42;
the barrier waits for both, reads 42, and lets go; C then takes 43. The
window (40, 42] is final.

W201's two-statement use took its number in the read, a round trip before
the append, so it needed a 5-tick lag and a floor check in the append. W208
reached the same conclusion independently.

The sequence must have `CACHE 1`. The barrier releases the lock before it
reads the window, so the appends' wait is the lock grant alone. Holding a
transaction-level lock across the read would stall them for the read too.

**Measured** (`bench.ts`, Postgres 16 limited to 2 vCPU / 2 GB, open-loop
appends from a separate process, 30 s each, the checkpointer connected
directly):

| tick | entries / checkpoint | statements/s | DB time: seal / write (p50) | checkpointer CPU (MAC + tree + sign, p50) | sealed after (p99) |
|---|---|---|---|---|---|
| none | — | — | — | — | — |
| 1 s | 1,003 | 1.9 | 3.9 / 1.5 ms | 18.7 ms | 1,031 ms |
| 500 ms | 501 | 3.9 | 2.2 / 1.1 ms | 6.5 ms | 526 ms |
| 250 ms | 250 | 7.9 | 1.3 / 0.8 ms | 3.5 ms | 269 ms |

- **"Sealed after"** runs from when the oldest entry's row was written,
  inside its statement, a moment before its commit, to the commit of the
  checkpoint that seals it. It is the worst case of each tick.
- **Postgres CPU** was 12.9% of a core without checkpoints and 12.8–13.0%
  with them: below noise. The appends' p99 moved within noise too
  (2.1 → 1.3–4.4 ms).
- **The checkpointer's CPU** is about 10 µs per entry when warm (micro-bench:
  3.5 µs HMAC, 3 µs leaf hash, 2 µs tree, 0.15 ms per signature). That is
  1–2% of one core at 1,000 entries/s. On Workers it would run in the
  checkpointer's Durable Object.
- **The append here is the integrity part only.** W208's real `use()` adds
  the reads and the decision to the same statement, and the checkpointer's
  share does not change.

**R48, flat as the log grows.** A tree of 10 million leaves (39,217 tiles,
324 MB), against one of 70,000:

| | 70,000 leaves | 10,000,000 leaves |
|---|---|---|
| inclusion proof (largest of 300 random) | 17 hashes, 544 B, 4 tiles, 1.1 ms p50 | 24 hashes, 768 B, 5 tiles, 1.5 ms p50 |
| consistency proof | 18 hashes | 25 hashes |
| checkpoint at 1,000/s, 500 ms tick | seal 2.2 / write 1.1 ms p50, sealed after p99 526 ms | seal 2.3 / write 1.2 ms p50, sealed after p99 530 ms, 4 tiles written |

A checkpoint touches only the tiles at the tree's right edge, one per level.
A proof reads one tile per 8 levels. The first 10-million-leaf run, right
after loading 324 MB of tiles, showed append p99 at 663 ms and seal p99 at
79 ms. That was Postgres writing out what had just been loaded: after a
`CHECKPOINT` and `VACUUM ANALYZE`, the numbers above. Proof p99s run 13–68 ms
at either size, against ~1.5 ms p50: cold tiles read from disk.

## Proofs: the API

```
GET /audit/checkpoint[?size=N]          the newest signed checkpoint (of at most N leaves)
GET /audit/proof?number=N[&size=S]      { index, size, leaf, proof[], checkpoint }
GET /audit/consistency?from=M&to=N      { proof[] }
GET /audit/tile/8/<L>/<N>[.p/<W>]       tile bytes, as Go's sumdb and C2SP serve them
```

- **Size:** 32·⌈log₂ n⌉ bytes. That is 768 B at 10 million entries, 1 KB at
  a billion.
- **Cost:** two statements.
  1. Locate the entry, its leaf index and the newest checkpoint. The index
     is the first index of its checkpoint's window, plus the entries of that
     window numbered before it: at most one window's worth of index entries,
     never history.
  2. Read the tiles the proof needs.
- **Access:** tiles and proofs reveal nothing about content. Every leaf
  holds a keyed MAC, so a leaf hash cannot be guessed from what it might
  say. The entries themselves stay behind today's access rules.

## Anchors, witnesses, and what a database writer can hide

### The attacks, run

[`attacks.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/attacks.ts) runs each scenario on a
fresh log of 8 checkpoints (all as expected):

| | database alone | with a head held outside | signer that remembers its head |
|---|---|---|---|
| (a) delete one sealed entry from the middle | **caught**: the checkpoint after it no longer matches | caught | caught |
| (a′) delete an entry not sealed yet | not caught: the window | not caught | not caught |
| (b) delete the newest 3 checkpoints and every entry after | **not caught**: a consistent, shorter log | **caught**: "the database ends at 125 leaves; a head held outside seals 200" | **caught** at its next start: "lost entries the signer sealed" |
| (c) split view: roll back, drop one entry, let a checkpointer restart from the database and seal again | **not caught**: reader A holds the old head, reader B the new one, and only comparing them would show it | **caught**: the witness refuses ("154 leaves at 155 does not extend 150 at 150") | **caught**: it refuses to sign |
| (d) slip a forged entry into the window | caught: the checkpointer seals nothing over a failed MAC | | |
| (e) crash after remembering a head, before writing it | — | — | rewrites it at restart; the log verifies |
| (e′) same crash, then one entry of that window deleted | — | — | **caught**: refuses |
| (f) copy an unsealed entry under a fresh number (a replay: the MAC still holds), both then sealed | **caught**: "request r2121 logged twice" | | |
| (g) every checkpoint row deleted | **caught**: no genesis to start from | | **caught**: "the database holds no checkpoint; the signer signed 200 leaves" |
| (h) a sealed change deleted, a forged retention entry naming what is left as kept | **caught**, with or without the MAC key: the cuts must chain from genesis, and a retention entry must lie above its cut and be sealed | | |
| (i) a sealed entry deleted, with every checkpoint up to the one after it | **caught**: the walk starts at genesis, not at the first row left | | |
| (j) an equal-size fork signed by a stateless signer, then the signer with memory restarts | | | **caught**: "does not extend the one the signer remembers" |
| (k) a change sealed by a background tick, the witness slower than the deadline | | the change answers `witnessed: false` at the deadline | |
| (l) a forged entry in the window, then a change waits for its seal | | | the change fails with the MAC alarm instead of waiting forever |
| (m) the newest row and its entries deleted under a running signer, no traffic after | | | **caught** at the next tick: "the database's newest checkpoint is 0, the signer's head is at 20" |
| (n) a replay of an entry sealed before the head an incremental check starts from | **caught**: "request … logged twice: at 4, below the start, and again after it" | | |
| (o) a forked head below where the walk starts, held outside; then its row deleted too | | **caught**: against the row at its place, else by a consistency proof to the start | |
| (p) a garbage checkpoint row; a malformed retention entry | **a failing verdict**, not a crash | | |
| (q) a witness that refuses once, then recovers, while a change waits | | the change answers witnessed: the witness is asked again within the deadline | |
| (r) no witness set up | | | the change answers `witnessed: null`, never "witnessed" |
| (s) a use copied before its day is dropped, replayed after the retention cut: after a tick with the rows between deleted; slipped into the retention entry's own tick on a log quiet since the day closed; after the signer restarts with its memory; or with the cut row's note swapped during retention | the verifier warns only (rows are the writer's) | | **the signer refuses to seal it**: "older than the signer's head: a replay" (the request-ID lookup cannot: the original is gone). With the note swapped, retention refuses to drop the day |
| (t) a witness that always refuses, after the change has answered | | asked 4 times until the answer (300 ms), 0 after | |
| (u) remembering a head fails once | | | the next tick's head holds |
| (v) writing a head fails, then putting the tree back fails too | | | the checkpointer refuses every tick until reopened; reopened, the log holds |
| (v′) the same, the tree read back of the right length but wrong hashes | | | refuses until reopened: the reloaded tree must give the held head |

Rows (f) to (v′) came from six review rounds: (g) to (l), (n) to (r),
(s) to (u), (v), (v′) and (s)'s later variants are the reviewer's own
reproductions, each of which got through the version before. Round six
confirmed the retention argument below, across restarts and without
witnesses, and found two slips in its code, both fixed:
- retention trusted the cut row's note without checking it was that row's;
- a retention attempt refused as too early, then retried, logged its
  forcing entry's request ID twice.

Retention now also refuses a checkpointer that keeps no memory. Round nine,
the last (run by agreement with the coordinator, with no round 10), found
the deepest one. Retention committed to whichever changes remained below
the cut, so a sealed change deleted just before it was blessed, in both
layouts. Now retention first rebuilds the window below the cut and requires
the signed head. It also writes its entry before dropping the partition, so
a crash between the two is finished by a retry. That fix is not reviewed;
see "Least settled". Round seven
found that retaining an ended day with no uses (a quiet `at` day) wrote a
cut that did not advance, which then failed verification forever. Now a day
with no uses just loses its empty partition, with no entry, and a cut that
does not pass the last one is refused before anything is dropped. Round
eight found the same layout's sharper case: a tick that seals one day's end
together with the next day's start puts some of the next day's uses below
the first day's cut, and the first retention counted them as kept, so
dropping the next day broke verification. Now a retention entry commits
only to the changes below its cut. Every use below a cut is droppable,
whichever day holds it, and a day whose uses all lie below the last cut just
loses its partition. Retention also goes in day order, and an `at` day only
once it has ended on the clock. Round five
found that the signer's freshness bound, measured from its newest head,
freezes on a quiet log, so a replay slipped into the retention entry's own
tick passed. Now retention drops a day only after sealing a head at least
two bounds after the cut (it appends an `audit.retention.begin` change and
waits for its seal), so every later replay of a dropped use is too old for
the signer.

Round four found:
- round three's freshness rule measured age against checkpoint rows, which
  the writer can delete. The signer now enforces it against its own head;
  the verifier keeps the row check as a warning;
- a failed tree reload let the next tick sign on a corrupted tree; the
  checkpointer now refuses until reopened.

Round three found:
- a forked head below the start passed if a tile was deleted too: a missing
  tile is now an excuse only below a real retention cut;
- a dropped use could be replayed after its cut (fixed in round four, below);
- the witness retries outlived the change that waited on them;
- a failed `remember` left the in-memory tree ahead of the database.

Round two found:
- incremental checks missed replays of entries sealed before their start;
  they now look up each walked request ID below the start, one indexed
  query per chunk;
- heads held outside, below the start, went unchecked;
- the verifier could be crashed by rows it could not parse; it now always
  returns a verdict;
- a witness that failed once was not asked again while a change waited.

Round one found:
- the signer signed a fresh genesis, and overwrote its memory with it,
  before comparing that memory with an empty checkpoint table;
- the verifier started at whatever checkpoint row came first, and trusted
  any retention entry it found;
- `sealThrough` reported `witnessed` when another tick had sealed the change;
- a database ahead of the memory was accepted at equal size.

Round one's fixes:
- the memory is read first;
- the verifier starts only from the genesis head, from a retention cut
  named by a sealed, chained retention entry, or from a head the caller
  verified before;
- a change waits for every witness to hold a head that covers it;
- the database's head and the memory must be one history.

**What a verification costs.** A full one walks every entry from genesis or
the newest retention cut: 15 µs an entry in Node. Routine checks pass the
last head they verified as `from` and walk only what came after (R25).

Against the real anchors on Cloudflare
([`anchor-check.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/anchor-check.ts)), with the
log the benchmark left (88 checkpoints, 60,497 entries):

- **It verified** against the R2 archive's newest head and the witness's
  head, in 911 ms (15 µs an entry).
- **R2 refused to overwrite and to delete** an archived head: "The object
  is locked by the bucket policy (10069)". This held for the Worker's own
  binding, with no precondition.
- **Rolled back 3 checkpoints, one entry deleted:**
  - the database alone verifies;
  - against the archive's newest head: caught.
- **A stateless signer then sealed again and published:**
  - the Durable Object witness **refused** ("split view: 60499 leaves at
    60500 does not extend 60497 at 60497");
  - the R2 archive, which checks nothing but signatures, **stored** the
    forked head. The verifier caught it against the archive's 8 newest
    heads: "no checkpoint in the database at 59896, where a head held
    outside is: a second history".

### What each anchor gives

| | signer's memory (checkpointer DO storage) | DO witness | R2 archive under a bucket lock | W201 / R40's audit-watch DO anchor |
|---|---|---|---|---|
| holds | its last head | the newest head it cosigned, served with its cosignature | every head, immutable for the lock's term | the chain head |
| checks consistency | yes, at each start (re-seals from entries) | yes, at each head | no, the verifier does later | n/a |
| catches a tail cut | at the signer's next tick | at verification | at verification | yes |
| catches a split view | prevents it | refuses at publication | at verification | no (it holds no signed tree) |
| survives the vault's own DO being reset | no | yes | yes | no |
| third parties can check | no | yes (cosignature) | yes (public reads possible) | no |
| who can defeat it | whoever can reset the DO (Cloudflare account) | the same, for that witness | **any account admin**: lock rules can be removed (below) | the same |
| cost at a 500 ms tick | one storage write per tick | one DO request per tick | one Class A op per head: archive every minute or so, not every tick | |
| publish round trip (measured, from this host) | n/a | p50 ~210 ms | p50 ~210 ms (in parallel) | |

**R2's bucket lock is not S3's compliance mode.** A lock rule (`Age`, 900 s
here) stops overwrites and deletes from every binding and token, but an
account admin can remove the rule and then delete. W209's cleanup did
exactly that (below). So the archive protects against a compromised Worker
or database, not against the Cloudflare account. A witness run by someone
else, a transparency-dev or Sigsum witness, is what protects against the
account.

### Does this need the anchor mandatory? (R40)

**The signer's memory, yes. External witnesses, no.**

- **Without anything outside the database,** the checkpointer starts from
  the database's newest row. A writer can then cut the tail, get a second
  history signed (c), or undo a sealed change by deleting its entry along
  with every checkpoint since. W201's `seq` design had exactly this
  property ("the checkpointer keeps no state of its own that matters").
- **The fix is the checkpointer's own memory of its last head**, in the same
  Durable Object that runs the ticks (on Node, a file beside the vault),
  written before the database (RememberFirst). It costs one storage write
  per tick and needs no plugin, so it belongs in core. On Node the file is
  synced before the database write (file, rename, directory), so it holds
  through a power loss, not just a process crash.
- **R40's plugin keeps what it has:** alerts, readiness gating, re-anchoring
  and "accept loss". It also gains external witnesses: cosigning (the DO
  witness stores and serves the cosigned head, and a change's answer
  carries every cosignature it got in time), third-party verification, and
  surviving a reset of the vault's DO.
- **The core checkpointer must refuse to sign** when the database is behind
  or beside its memory, and say so where an operator sees it. It also checks
  at every tick that the database's newest checkpoint row is its own head
  (folded into the sealing statement, at no extra round trip), so a deleted
  row shows within a tick, even with no traffic. Without the plugin, that
  refusal is the only alarm.

## Changes answer once sealed (the rule)

W208 pointed out the sharpest case of the window. A writer rolls a member
row back and deletes that member's newest change entry before it is
sealed. The revoke the admin saw succeed is silently undone, and nothing in
the log can ever show it. The fix, approved by Erwin as a rule during this
experiment: **a change answers only once its entry is sealed and, where
witnesses are configured, witnessed.** The change asks the checkpointer to
seal now (on Workers, one call to its DO) instead of waiting for the next
tick. It answers with the signed head and the entry's inclusion proof,
which the admin's client checks and can keep. Uses keep the one-tick window.

Measured ([`change-bench.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/change-bench.ts), 40
changes under 1,000 uses/s, 500 ms tick, 2 s witness deadline; every
answer's proof verified). The first three rows were re-run after the review
fixes; the first run gave the same within noise (DO witness 68 / 600 ms):

| witness | commit | seal (+ witness) | total, p50 / p99 | witnessed |
|---|---|---|---|---|
| none (R40 without the plugin) | 1 / 2 ms | 5 / 53 ms | **7 / 58 ms** | n/a |
| Cloudflare DO witness, from this host | 1 / 2 ms | 63 / 518 ms | **65 / 531 ms** | 40 of 40 |
| slow witness (answers after 3 s) | 1 / 1 ms | 2,004 / 2,077 ms | 2,008 / 2,082 ms | 0 of 20: "no answer within 2000 ms" |
| unreachable (connection refused) | 1 / 2 ms | 2,006 / 2,071 ms | 2,009 / 2,077 ms | 0 of 20: "no answer within 2000 ms (last: unreachable: fetch failed)"; asked again every 100 ms until the deadline (after review r2; before, it answered in 7 / 82 ms, unwitnessed, without retrying) |
| unreachable (no route; packets dropped) | 1 / 1 ms | 2,004 / 2,078 ms | 2,006 / 2,083 ms | 0 of 20: "no answer within 2000 ms" |

The first version waited for witnesses inside the serialized tick, so a
slow witness held the next tick back, and a change's p99 came out at 3.9 s
against a 2 s deadline. The checkpointer now gives each witness a pump that
always sends the newest head, so a slow witness delays only its own
acknowledgement.

**When the witness is slow or unreachable**, two options:

- **(A) Answer after the deadline, marked unwitnessed** (`witnessed: false`,
  shown in the UI, alerted), while the checkpointer keeps publishing. A
  witness that fails is asked again every 100 ms until the deadline, so a
  dropped request costs a retry, not an unwitnessed change. Nothing retries
  after the answer. The regular ticker never waits for witnesses, so a
  refusing one cannot set its pace. With no witness set up, `witnessed` is
  null.
  *Recommended.* The change has committed and is in force either way: the
  revocation already stops uses. A 503 would tell the admin it failed when
  it didn't, and invite a retry of a change that already happened. And the
  entry is sealed in the database and in the signer's memory: undoing it
  now means deleting a sealed entry and resetting the checkpointer's
  Durable Object, not just writing to the database.
- **(B) 503 after the deadline.** This is honest about integrity, but
  misleads about the change itself. It would only be right if a change
  could stay pending until witnessed, which the fence does not allow.

**Without a witness** (R40), a change waits for its seal alone, about
+5 ms. The model shows what that leaves. AnsweredChangeKept fails without an
anchor: the writer deletes the sealed change together with the newest
checkpoint rows. It holds once the signer's memory is core, which is the
recommendation above.

## Receipts

A receipt is the vault's signed promise for a use's entry: this leaf, at
this number, sealed by this deadline (CT's SCT, Rekor v1's SET). Measured on
Workers ([`worker/index.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/worker/index.ts), CPU
time from `wrangler tail`, each request making 1,000 receipts, 6 requests
per row):

| per 1,000 receipts | CPU (median) | per receipt |
|---|---|---|
| the leaf only (`leafData`'s layout, SHA-256) | 12.5 ms | ~12.5 µs |
| + HMAC (not publicly verifiable) | 16.5 ms | +4 µs |
| + Ed25519 (WebCrypto) | 36 ms | **+23.5 µs** |
| batched: 1,024 leaves, one signature, 1,024 paths | 18.5 ms | ~18 µs, the leaf included |

So a receipt per use costs about 1% of the 2.9 ms a use already costs on
Workers (W201). Batching halves that, to about 0.6%, but it means holding
requests in an isolate to fill a batch, which is not worth 18 µs. (A first
run of this probe hashed a shorter, made-up leaf. The figures above are from
the corrected probe, 8 requests per row.)

**What it closes in practice: little, for uses.** A receipt makes deleting
that entry detectable by whoever holds it and checks inclusion after the
deadline. The holder of a `/use` receipt is the app, and apps will not
check. A sampler that checked 1% would catch a targeted deletion 1% of the
time. The window it narrows is already one tick. Changes, where it matters,
now get something stronger: the inclusion proof itself, in the answer.

**Recommendation: no receipts for uses in 0.15.** They could come later for
people's reveals through the CLI, which can keep and check them, if Erwin
wants a user to hold proof that Coffre logged their access.

## Key ratcheting (forward-secure MACs): too little to be worth it here

Schneier and Kelsey's scheme evolves the MAC key after each entry or epoch
(`K_{i+1} = H(K_i)`) and erases the old one. Someone who steals today's key
then cannot forge yesterday's entries. That needs a sound place for the
ratchet's state, and Coffre on Workers has none:

- **The key comes from config.** Every isolate can derive `K_i` from the
  base key and i, so the base key still exists and nothing is forward
  secure.
- **Real erasure needs one mutable holder** that every `use()` would ask
  for the current key: the checkpointer's DO, back on the hot path (R44).
- **The database is no holder:** a ratchet stored there, wrapped by a key
  that still exists, buys nothing.
- **Today the keys live together.** Whoever steals the MAC key has, in
  practice, stolen the vault's config, and with it the key-encryption key.
  Forging log entries is the least of it. (The prototype's MAC, signing and
  witness keys are separate values. If a deployment ever kept the MAC key
  apart, a MAC-only theft would be the case ratcheting protects.)
- **The tree already gives most of what ratcheting was for.** Sealed,
  anchored heads fix the past. A stolen MAC key can forge entries only for
  the unsealed window, about one tick; a stolen signing key cannot rewrite
  heads that the signer's memory and the witnesses hold.
- **What ratcheting would add** is protection, after a MAC-only theft, for
  the entries written in the tick before it. That is under a second of
  entries, and it would put a DO call back on the hot path.

Not prototyped, for those reasons.

## Retention and days

Changes are kept forever, uses are dropped by day. Both of W208's options
are prototyped ([`retention.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/src/retention.ts),
[`test/retention.test.ts`](https://github.com/erwinkn/coffre/blob/b6645a9895e5/experiments/merkle/test/retention.test.ts)):

- **`number` days.** Day d holds the numbers [d·10¹², (d+1)·10¹²). At
  midnight the checkpointer's barrier moves the sequence there, under the
  lock. So a day is exactly a run of numbers, and its extent is recorded in
  a signed `audit.day` change entry: {first, last, firstLeaf, lastLeaf}.
  Verifiers read the extent from the entry rather than infer it from
  numbers, and retention reads it from there, not from an unsigned column.
  Rules:
  - the sequence only ever moves forward, and a day's entry is written once
    (a clock stepped back, or a day closed twice, does nothing);
  - retention takes the one day entry, and requires it sealed and
    MAC-valid;
  - a missed midnight just makes a long day;
  - 10¹² numbers a day allow 11 million appends a second and 25,000 years
    of days.
- **`at` days** (W208's current layout). Day d holds the uses whose `at`
  (the Worker's clock) falls in it. Near midnight the numbers interleave
  with the next day's.
  - The cut is the first checkpoint at or above the day's highest number.
  - A few next-day uses below it (stragglers) stay until their own day
    goes, unprotected meanwhile (step 3).
  - An append whose `at` falls in an already dropped day fails for want of
    a partition, so days must be dropped well after any clock skew (they
    will be: retention is weeks).

In both, retention runs in six steps. These are #365's, for one tree of
both kinds. With the two trees W212 recommends, step 1 and step 3's digest
go: no sealed change is ever below a cut, and the retention entry names the
cut alone.

In both, retention runs in six steps:

1. Check that what lies below the cut is exactly what was sealed there:
   rebuild the window since the last cut from the entries, on top of the
   last cut's edge, and require the signed cut head. Otherwise a sealed
   change deleted just before retention would be blessed by it (review r9,
   not yet reviewed itself).
2. Seal a head at least two freshness bounds (20 minutes) after the day's
   cut: append an `audit.retention.begin` change (a request ID of its own
   per attempt) and wait for its seal. The checkpointer must keep its
   memory, and the cut row's note must be that row's.
   From then on the signer refuses any entry stamped before the cut, so a
   copy of a dropped use can never be sealed (see Replays, below).
3. Append a kept-forever `audit.retention` change: {cut, the changes below
   the cut since the last cut, as a count and the RFC 9162 head of their
   leaves}. Below a cut, only changes are protected. A use still there
   (with `at` days, at most a tick's worth of the next day at each
   midnight) can be deleted unseen until its own day goes. Its copies stay
   out all the same: the fresh head of step 2 is past its stamp.
4. Drop the day's uses partition, after the entry, so a crash between the
   two is finished by a retry. A day with no uses only loses its empty
   partition: no cut, no entry. A cut must pass the last one, or nothing is
   dropped.
5. Delete the level-0 tiles below the cut.
6. Keep the higher levels: one hash per 256 leaves, 10 MB a day at a
   sustained 1,000/s. (W212: one tile per level, the one holding the cut,
   is all proofs above it read.)

**What a verifier keeps after a drop:**

- **The heads.** Its witnesses' heads, and the archive's for the lock term.
- **What it checks:**
  - every retention entry's digest against the changes below its cut;
  - everything from the newest cut on, by walking.
- **What still works:**
  - proofs of entries above the cut (the tiles they read are kept);
  - consistency between heads above the cut.
- **What fails, as it should:**
  - deleting a kept change below the cut fails its retention entry's digest;
  - deleting the retention entry itself moves the walk below the cut, where
    leaves are gone.

**The bulk cap.** `bulkLimit` is the deployment's choice (R52):
`{ count, windowMinutes }`, default 1,000 keys per principal per 15 minutes,
any window up to a day. Nothing here fixes either number. The cap counts from
a table of its own that keeps up to a day of keys (W199), not from the audit
log, so dropping days of uses weeks later never touches it. If it ever
counted from the log instead, retention would have to keep at least the
configured window (at most a day) plus a tick.

**Which layout:** the two prototypes disagree. See "Least settled", below.

## Replays and reorders in the window

The MAC does not cover the number (W208). So before sealing, a writer can
also do two things:

- **Copy an entry under a fresh number.** The copy has a valid MAC. Once
  both are sealed, the verifier flags the duplicate request ID, including
  against entries below an incremental check's start (one indexed lookup
  per chunk). A copy of a use whose day was dropped has no original left to
  match. So the signer refuses to seal any entry more than 10 minutes older
  than its own head (`FRESH_MS`). The MAC covers `at`, so a copy keeps its old
  time, and the signer's head is its own, checked against its memory, not a
  row a writer can delete. The verifier repeats the check against the rows,
  as a warning only.
  - **The bound's assumptions:** a use stamps `at` and takes its number
    within one statement's timeout (W208's one-statement append: seconds),
    and the Workers' clocks agree with the signer's to well under 10 minutes
    (NTP: milliseconds).
  - **Why it covers every dropped use:** retention seals a head at least two
    bounds after a day's cut before dropping it, and every dropped entry was
    stamped before that cut was signed. Copies of uses that were not dropped
    still have their originals, which the request-ID lookup finds.
  - **What breaks it:** a stamp held back longer, say a request suspended
    for ten minutes between stamping and appending. The signer then refuses
    the window and raises the alarm: a false alarm, never a silent pass. The append
  therefore has to be **idempotent by request ID**: a unique index on
  `request_id` within each partition, with `ON CONFLICT` returning the
  existing number. Otherwise an honest transport replay (Hyperdrive
  retrying a statement whose reply was lost; W201 saw 190) would read as an
  attack. Found by the model and passed to W208.
- **Swap two unsealed entries' numbers.** Swapping a use and a revoke makes
  the sealed log say the use came first. The MAC'd `at` bounds how far an
  entry can move in time, but not within a tick. The model shows this
  (UnsealedReorderDetected is expected to fail). It is the same one-tick
  window as deletion.

## Least settled, and open findings

Nine review rounds ran, each "needs attention". Every finding they made is
fixed, each with a regression case. What is still open:

- **Retention is the least settled part.** It drew a P2 in every round from
  3 to 9, a different defect each time, all fixed. The core (tree, sealing,
  signer memory, verifier walk, R51 change rule) drew none after round 5.
  Round 9's fix (rebuild the window below the cut before dropping; entry
  before drop) is not reviewed. Round 9 confirmed, for both layouts, that
  no copy of a dropped use can be sealed and that honest in-order retention
  leaves a log that verifies.
- **The day layout: the two prototypes disagree.** Erwin decides.
  - **W208 (#366) partitions uses by `at`, on purpose.** Uses are unique on
    (at, request_id), so a replayed statement lands in the same partition as
    its original and the append is idempotent. That unique index is the use
    rows' only index, and W208's checkpointer reads its window from an `at`
    floor raised under the barrier (`greatest(floor, clock - 3 s)`), which
    leans on R53's hard 3 s use deadline.
  - **W209 recommends `number` days.** Days are exact runs of numbers, cut
    at the barrier and recorded in signed day entries. Retention then has no
    stragglers, and every `at`-specific review finding (rounds 7 and 8) came
    from days interleaving at midnight. The checkpointer reads its window by
    number, which needs an index on number.
  - **W208 adopting `number` days** would need idempotency outside the
    partition key. A replay takes a fresh number and may land in the next
    day's partition at the midnight jump, so a per-partition unique index on
    request_id misses it. That means a small request-ID table kept for a
    day: one more index write per use, measured against R44. Its
    checkpointer would also need the number index.
  - **W209 adopting `at` days** is what the prototype already supports, with
    rounds 7 to 9's fixes: changes-only digests, ordered retention of ended
    days, the window check. It would also mean taking W208's `at`-floor
    sealing. That replaces "every number ≤ upto is final" with "every entry
    with `at` ≤ the floor is final", and the bound then depends on the 3 s
    deadline being enforced inside Postgres, not just in the Worker. A
    window's leaves are still sealed in number order.
- **R53, as it lands on this design.**
  - The hard 3 s use deadline is what the signer's freshness bound assumes
    (stamp to number well under 10 minutes).
  - The 16-byte MAC only shortens leaves. A 128-bit MAC still makes a leaf
    hash unguessable from its content.
  - Per-isolate covers that skip repeat uses are the dedup option analysed
    below: a repeat has no leaf, and a receipt for it would name the first
    entry.
- **Open P3s.**
  - Go's cross-check covers the bytes, not how an entry becomes a leaf.
  - TLA+ does not model retention, freshness or tile edits.
  - The verifier's row-based freshness check is a warning; the signer
    enforces it.
  - A full retention pass hashes the whole day once, in memory, in this
    prototype; a real one would stream it in chunks.

## Fewer rows: what aggregation would mean for the tree

W208 is comparing two ways to log fewer use rows. Neither is built here;
this is what each means for the tree.

**(a) Dedup.** Only the first use of (credential, secret, version) in a
window is logged; repeats log nothing.

- **Leaves:** fewer, and nothing else changes. The first-use entry is an
  ordinary leaf, sealed as now.
- **Proofs and receipts:** a repeat has no leaf. Its receipt can only point
  at the first entry, and proves "a use of this key was logged in this
  window", not that this request was.
- **Deletion:** deleting that one first entry before it is sealed now hides
  every repeat in its window. The window and its length are unchanged, but
  one deletion hides more.
- **Retention and the verifier:** unchanged, with fewer rows. The verifier
  cannot check how many uses there were, because nothing records them.

**(b) A counter row per tick, upserted until its checkpoint seals it, then
immutable.**

- **Leaves:** a sealed counter row is a leaf like any other, its count
  included. After sealing, the count is fixed and provable.
- **The MAC:** the Worker cannot MAC a count it does not know. So until
  sealing, either:
  - the MAC covers only (key, window) and the count is unauthenticated, so
    a writer can change it within the window, just as they can delete an
    entry now; or
  - every upsert recomputes the MAC in SQL, which needs the key in the
    database.
- **The fence:** an upsert must not land in a row the checkpointer has
  already read. The window id has to be bumped by the barrier, under the
  exclusive lock, and checked by the upsert under the shared lock, or a
  late increment changes a sealed leaf, which the verifier reports as
  tampering.
- **Contention: the real cost.** Every use of the same key in the same tick
  updates one row and holds its lock until commit. That is W201's `head`
  problem, per key: uses of one hot key serialize behind one commit flush,
  near 650/s on network storage (W201, measured). R44 asks for hundreds of
  concurrent uses from one principal, and that principal's hot key would be
  exactly this row.
- **Receipts and retention:** a receipt can say "counted in row N", but not
  that its own increment is in the count. Retention is unchanged (rows sit
  in day partitions).

From the tree's side, (a) composes cleanly and (b) does not: it needs
mutable-until-sealed rows, a fence on them, and a hot row per key.

## The model (R45)

[`formal/Seal.tla`](../../formal/Seal.tla) models the following:

- **Appends** take the lock, then the number, then commit, or abort and
  leave a gap. One append is a change, answered to an admin.
- **Ticks** check the database's newest checkpoint row against the head
  they hold, take the barrier, seal, sign, remember, write, and queue the
  head for the witness. Publication runs behind the tick and sends only the
  newest head.
- **Crashes** can fall between any of those steps. A crash loses the
  witness queue and the head held in memory. A restart (`open()`) follows
  the code's rules:
  - **no rows at all:** refuse if the memory holds a head beyond genesis,
    otherwise start at genesis;
  - **memory ahead of the database:** re-derive from the entries, then
    write the row or refuse;
  - **same place:** the two heads must be equal;
  - **database ahead:** the remembered head must be a prefix of it.
- **An attacker** may delete any entry or any checkpoint row, forge an
  entry, replay one under any number handed out (live ones included: there
  is no unique key on numbers), or swap two numbers.
- **A ghost set** of every head shown to a reader: written to the database
  or published.

The alarm is the code's verifier:
- a walk from genesis, where every row and the witness's head must equal
  the entries at or below its place;
- no database ending before the witness's head;
- no duplicate numbers or request IDs;
- the signer's and the witness's refusals, and a failed MAC at sealing.

Protections, each a constant:
- **NumberUnderLock, CloseLocks:** the append and the barrier.
- **SignerMemory:** the head kept outside the database, read at restart.
- **Witness:** an external head, consistency-checked at publication.
- **RememberFirst:** memory written before the database.
- **RowChecked:** each tick compares the database's newest row with the
  head the signer holds.
- **MacChecked:** no entry sealed over a failed MAC.
- **RequestIdChecked:** a verifier check; removing it is removing the
  protection.
- **WaitForSeal:** R51.

`scripts/formal.sh --workers 4 --shard seal`, about 2 minutes:

| scenario | distinct states | time |
|---|---|---|
| **Seal**: memory and witness | 8,986,394 | 37 s |
| **SealCore**: memory only (R40 without the plugin) | 4,742,654 | 20 s |
| **SealPlugin**: witness only, no signer memory | 10,432,858 | 40 s |

Seal and SealCore hold every invariant. SealPlugin holds Complete,
AnsweredChangeKept, NoForgerySealed, NoUndetectedReplay and NoFalseAlarm.

Invariants:
- **Complete:** no honest entry commits under a signed head.
- **SealedDeletionDetected**
- **SplitViewDetected**
- **NoForgerySealed**
- **NoUndetectedReplay**
- **AnsweredChangeKept**
- **NoFalseAlarm:** honest runs with crashes never alarm.

The deletion, split-view, answered-change and replay invariants are stated
over heads shown to someone, from the next tick after an attack on. Before
the signer acts again, nobody outside the database has looked.

Each protection removed, TLC fails as required:

| removed | breaks | TLC's counterexample |
|---|---|---|
| NumberUnderLock | Complete | number 1 taken before the lock; the tick seals up to 1 without it; then 1 commits |
| CloseLocks | Complete | the tick reads the sequence while an append holding number 1 is in flight |
| RememberFirst | SealedDeletionDetected, SplitViewDetected | head h1 holding entry 1 is written, not yet remembered; the attacker deletes entry and row; crash; the restart sees memory equal to the database (genesis) and signs a second head for the same place |
| MacChecked | NoForgerySealed | a forged entry at an aborted append's gap gets sealed |
| RequestIdChecked | NoUndetectedReplay | an entry replayed into a gap, both MACs valid, both sealed and written |
| WaitForSeal | AnsweredChangeKept | a change answered while the signer is down; the attacker deletes it |
| SignerMemory (Seal) | SealedDeletionDetected | h1 written and queued; crash drops the queue; entry and row deleted; the stateless restart opens on genesis |
| SignerMemory (SealCore) | SealedDeletionDetected, SplitViewDetected, AnsweredChangeKept | the same shape, then a second head for the same place |
| RowChecked (SealCore) | SealedDeletionDetected | h1 written; entry and row deleted; no new traffic, so the next tick writes nothing and nothing ever alarms |
| Witness (SealPlugin) | AnsweredChangeKept | written, the change's entry deleted, answered, crash, row deleted, stateless restart |

Expected to fail, as documented:
- **The window (Seal):** UnsealedDeletionDetected and
  UnsealedReorderDetected.
- **A witness without signer memory (SealPlugin):** SealedDeletionDetected
  and SplitViewDetected. h1 is written, a crash drops its queued
  publication, the attacker deletes the entry and the row, and the
  stateless restart signs a second head, which the witness (still at
  genesis) accepts.

**What the model settles for the design:** a witness cannot stand in for
the signer's memory, because the head is written to the database before it
is published. The signer's memory is what closes the hole across a restart.
That is why it belongs in core. The witness adds what the model does not
exercise: surviving the loss of that memory, and a head third parties can
check.

Not modelled:
- several checkpointers at once (one DO is assumed);
- tile edits (the tree is abstracted to its leaves; an edit changes the
  head, by the code's argument, not TLC's);
- the attacker moving the sequence;
- retention.

## Prior art

- **[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) (CT 2.0)** and
  **Trillian:** the tree, signed tree heads, inclusion and consistency
  proofs, and the SCT, a promise to include an entry within the maximum
  merge delay (24 h in CT). Our "sealed after" is a merge delay of one tick.
- **Go's checksum database and C2SP** (tlog-tiles, tlog-checkpoint,
  signed-note): the tile layout and the checkpoint format used here
  unchanged. **Witnesses** (transparency-dev, Sigsum, the armored witness)
  cosign a checkpoint only once they've checked it extends the last one
  they saw. That is our DO witness.
- **Sigstore Rekor:** v1 returned a signed entry timestamp, a promise; the
  tile-based v2 answers with an inclusion proof once the entry is
  integrated. Our change rule makes the same choice, for the same reason.
- **SQL Server / Azure SQL Ledger:** a Merkle tree per block of
  transactions, blocks chained, and "database digests" (the latest block
  hash) uploaded automatically to immutable Azure Blob storage. That is the
  per-window shape with an external anchor, and the closest analogue to the
  R2 archive.
- **AWS CloudTrail digest files:** an hourly signed digest of the hour's log
  files, each naming the previous digest's signature, kept in S3 (with
  Object Lock if configured). It is W201's flat-hash-per-checkpoint shape,
  with an hour's window.
- **Crosby and Wallach, "Efficient Data Structures for Tamper-Evident
  Logging" (USENIX Security 2009):** history trees with logarithmic
  membership and incremental proofs against an untrusted logger. Their
  point: auditors must compare what they were shown (gossip), or a
  forking logger goes unseen. That is case (c) above.
- **Schneier and Kelsey, "Secure Audit Logs to Support Computer Forensics"
  (1999):** forward-secure MACs by key evolution and erasure, for a logging
  machine that may later be compromised. See "Key ratcheting".

## Measured or reasoned

- **Measured:**
  - the window and checkpoint costs at 1,000/s;
  - Postgres CPU with and without checkpoints;
  - proof sizes and times at 70,000 and 10 million leaves;
  - change latency with no, healthy, slow, refused and blackholed witnesses;
  - receipt CPU on Workers;
  - the R2 lock refusing overwrite and delete;
  - every attack scenario, locally and against Cloudflare;
  - Go's cross-check.
- **Reasoned, not measured:**
  - the checkpointer running in a Durable Object through Hyperdrive. It
    adds two round trips a tick and changes nothing else; witness round
    trips from inside Cloudflare should be well under the ~210 ms measured
    from this host;
  - W208's full `use()` statement in place of the bare append;
  - the attacker editing tiles (an edit changes the head, so a proof
    against a signed head fails: denial of service, not forgery).

## Decisions for Erwin

1. **The tick, which is the window.** 500 ms is recommended: entries sealed
   within ~530 ms p99, 4 statements a second, no measurable Postgres cost.
   250 ms halves the window for 8 statements a second. Example at 500 ms:
   svc-b reads DFNS_KEY at 14:02:01.30; an attacker who deletes that entry
   must do it before ~14:02:01.83. W201's design gave them ~6 s, today's
   chain until the next checkpoint.
2. **The signer's memory in core, external witnesses as R40's plugin.**
   Recommended. The alternative, everything outside the database optional,
   leaves tail cuts, split views and undoing sealed changes uncaught for
   instances without the plugin.
3. **A slow or unreachable witness** (the approved change rule): answer
   after a 2 s deadline, marked unwitnessed and alerted (recommended), or
   503.
4. **Receipts:** none for uses (recommended); maybe later for people's
   reveals through the CLI.
5. **Tree shape** (W212, by numbers): two growing RFC 9162 trees with C2SP
   formats, one for changes (kept forever) and one for uses (pruned by day)
   (recommended), over #365's single tree, a tree per day or tick, a chain,
   or an MMR. Also, in either shape: keep one tile per level below a cut,
   and partition tiles by leaf range so retention drops instead of deletes.
6. **Day layout:** W208 chose `at` days, for replay idempotency; W209
   recommends `number` days, for exact retention. What each would need to
   adopt the other's is in "Least settled".
7. **External witnesses, if any:** the R2 archive protects against a
   compromised Worker or database, not against the Cloudflare account (lock
   rules can be removed). Protecting against the account needs a witness
   run by someone else.

## Cleanup

Everything was on Erwin's personal Cloudflare account and is gone. Each
deletion was verified by listing through the API: no Worker, R2 bucket or
Durable Object namespace named w209 remains.

**Resources** (cost: within the plan's included usage, a few thousand
requests):
- the Worker `coffre-w209-anchor`, deleted with its Durable Object witness;
- the R2 bucket `coffre-w209-anchor`: its 88 archived heads deleted, then
  the bucket itself.

**The lock-rule test, which is where R2's guarantee ends.**
1. A fresh head was archived under the 900 s lock rule.
2. The Worker's delete was refused ("locked by the bucket policy").
3. The rule was removed through the account API.
4. The same delete then succeeded at once, well inside the 900 s.

Locally: a Postgres 16 container of W209's own (compose project `w209`, port
56209), its volume and `~/scratch/w209`, deleted after the last run.
