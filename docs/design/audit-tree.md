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

**Status.** Nothing calls this code yet, and 0.14 behaviour does not
change. PR 6b wires it: the Postgres and SQLite stores over migration 0022's
tables, the Workers checkpointer's Durable Object, the Node interval, and a
change waiting for its seal. 6b comes after plan PRs 2 (the schema) and 4
(the change path).

## In short

- **Two growing RFC 9162 trees** (Certificate Transparency's), one per
  retention class: `changes`, kept for good, and `uses`, dropped by day. Each
  is a standard log with its own origin and key, so Go's `tlog` or any C2SP
  witness reads either one alone.
- **One pair.** A tick signs both heads with the same `upto` and `at`. The
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
  a tick at p50 on Node, as an fsynced file, and one 488-byte write a tick
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
| one tick signs both, at one `upto` and `at` | `signPair`; `openPair` refuses two notes whose `upto` or `at` differ |
| one memory record | `encodePair`: one JSON record holding both notes; `remember` before `write` |
| one write | `CheckpointStore.write(row, tiles)`: both trees' tiles and the pair's row, one statement |
| `open()` takes the pair as one value | the newest row must open as a pair; the memory must be equal, a prefix in both trees, or re-derived to both heads, else refused |
| each tick checks the row | `close` returns the newest row's `upto`; any other than the signer's refuses the tick |
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

- `close(after)`: the barrier and the window, one statement (`close_one`):
  every number at or below `upto` has ended, the entries above `after`, and
  the newest row's `upto`;
- `write(row, tiles)`: the pair and both trees' tiles, one statement;
- `newest()`, `entries()`, `tiles()`, `pairs()`, `pair()` and `locate()`:
  the reads.

**A tick** checks the window, then signs, remembers, writes and publishes.
The window must hold numbers that increase, all inside it, each in a tree,
each with a MAC that holds, and none more than 10 minutes older than the
signer's pair. A replay of a use whose day retention dropped is caught that
way, because no lookup can match it. Any failure refuses the tick and
alerts. The trees grow on a copy, kept only once the write succeeds. So a
failed memory or write leaves the signer at the pair the database holds,
and #365's "broken until reopened" state is gone by construction.

**A change** waits for its seal (R51). `sealThrough` ticks at once unless a
pair already covers it, then waits for every witness to hold a pair that
covers it, for at most 2 s. Each witness has a pump that always sends the
newest pair, one at a time. A witness that refuses is asked again every
100 ms until the deadline, and never after it. A silent witness lets the
change answer `witnessed: false`, alerted. With no witness, `witnessed` is
`null`. 6b records unwitnessed answers where the plugin's alerts read them.

**A proof** is checked against the signed head before it is handed out. A
database that changed the entry makes `prove` throw instead of returning a
proof that fails later.

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
| deletes every row | the signer | refuses to start a new log over a remembered one |
| forges a pair at the newest row's place | the signer | refuses to start |
| deletes the newest row under a running signer | the next tick, with no traffic | "the database's newest checkpoint is …" |
| forges an entry, replays an old one, or duplicates a number | the tick | refuses to sign; a change waiting on it fails with the alarm |
| stores notes of two ticks as one row or memory record | `open()`, the verifier | "not a pair" |
| moves an entry from one tree to the other | the verifier | both heads differ |
| restores the memory from a backup | `open()` | accepted if a prefix in both trees, else refused |

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
    pair shares `upto` and `at`. A uses note renamed to the changes origin
    fails.
  - `tlog.TileHashReader` gives the signed head from our tiles.
  - Go rebuilds every tile from the leaf hashes and gets ours byte for
    byte, with nothing more and nothing less (3 changes tiles, 277 uses
    tiles).
  - 102 inclusion and 277 consistency proofs per tree equal Go's
    `ProveRecord` and `ProveTree`, and every head passes `CheckTree`. A
    proof with one byte flipped fails.
- **Cuts.** Uses-tree cuts at 40,000, 65,536, 65,537 and 70,002 keep only
  the tiles `keptAbove` keeps, from 121 down to 3 of 277. Go's
  `TileHashReader`, which checks each tile it loads against the signed head,
  still proves every sampled leaf above each cut and every size above it,
  with our bytes. Leaf 0 is no longer provable.
- **It fails when it should.** A flipped byte in one tile, or one pair's
  uses note swapped for the next pair's, stops it.

## Numbers

**A tick** at R44's 1,000 entries a second and a 500 ms tick: 500 entries,
one in a hundred a change. Measured with `packages/vault/scripts/audit-tree-bench.ts`,
in Node on this host. The p99s include garbage collection.

| signer's memory | checkpointer CPU, p50 / p99 | tick wall time, p50 / p99 | memory write, p50 / p99 |
|---|---|---|---|
| in a variable | 4.6 / 41–46 ms | 4.4–4.7 / 23–26 ms | 0 |
| a file, fsynced before the write (Node) | 5.0–5.2 / 74–80 ms | 5.1–5.3 / 41–42 ms | 0.6 / 2.8–7.5 ms |

That is about 9 µs an entry: the MAC check, the leaf hash, the tree, and
two Ed25519 signatures. At two ticks a second, the memory costs about 0.1%
of a core on Node. On Workers it is one 488-byte write to the Durable
Object's storage a tick, 172,800 a day. **R54: the memory stays in core.**

**Level-0 tiles for the uses tree.** Plan PR 6 asked for this decision by
numbers. Measured with `packages/vault/scripts/audit-tree-level0.mjs` on a
Postgres 16 of this worker's own (2 vCPU, 2 GB), with W211's slim use row:

| | with level-0 tiles | without |
|---|---|---|
| a use's row and index | 141 B (109 + 31.5) | 141 B |
| the uses tree on disk, per use | 57 B (41 B compacted, W212) | 9.6 B |
| the uses tree's WAL, a tick of 495 uses | 31.3 KB | 5.0 KB |
| the log's WAL a tick (rows at 244 B a use, plus the tree) | 152 KB | 126 KB |
| a proof's leaf level | one tile: 0.18 ms p50, 0.29 ms p99 | 256 uses read back: 0.68 ms p50, 1.0 ms p99 (by the window's `at` range; a number index would add 22.5 B and 149 B of WAL a use) |

**The call: keep them.**

- **For dropping:** 47.5 B a use, 25% of a use's storage, and 17% of the
  log's WAL.
- **Against dropping:**
  - **Every reader of level 0 would rebuild it from use rows.** That means
    `open()`'s edge, every tick's consistency proofs for witnesses, the
    tile API that Go and C2SP clients read, and the verifier's start. The
    use table has no index on number (W211), so each rebuild reads a
    window by `at`, which ties the tree to the hot path's barrier.
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
| a failed tick leaves the trees as they were (copy, then commit) | removes #365's "broken until reopened" state | this PR |
| the leaf: tagged, length-prefixed columns, its tree and number in it | injective; pinned by vectors | this PR, after `audit/chain.ts`'s encoding |
| a 500 ms tick; a change waits for its seal and at most 2 s for witnesses | sealed within ~530 ms p99 (W209) | R51, R54 |

## Not here yet

- **6b, the wiring:** `close_one`, the tiles tables and their leaf-range
  partitions, the checkpointer's Durable Object and its storage as the
  memory, a synced file and an interval on Node, a change waiting on
  `sealThrough`, and the witness plugin's Durable Object and R2 archive.
- **PR 7, retention:** the freshness step, the cut named in the uses
  tree's coordinates, and dropping tile partitions below it.
- **PR 8, the verifier's surfaces:** MACs and request IDs through
  `verifyLog`'s `check`, starting from a retention cut, and the UI and CLI.
- **The pair in the model:** plan PR 1 puts the pair into `Seal.tla`, with
  a write of one head without the other failing an invariant. This PR
  follows that spec where they differ.
