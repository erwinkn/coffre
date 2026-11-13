# The audit trees

The vault's log, `log_changes` and `log_uses`, is sealed into two signed Merkle trees. A database
writer without the vault's key cannot delete, move, reorder or forge a sealed entry without a check
naming it. This page says how the trees are built, how the checkpointer seals them, where it runs,
and what each check catches.

- **Pure code:** `@coffre/core/merkle` (`packages/core/src/audit/`): the RFC 9162 tree, C2SP tiles,
  C2SP signed checkpoints, the head pair, the leaf encoding, a witness's rule, and the verifier's
  walk.
- **The checkpointer:** `packages/vault/src/checkpointer.ts`, behind a storage seam
  (`CheckpointStore`, over Postgres in `packages/vault/src/log-store.ts`), with the signer's memory
  and witnesses. The vault's process runs it on Node (`keepCheckpointer`); on Workers it is the
  `CoffreCheckpointer` Durable Object, which the vault starts.
- **Tests:** `packages/core/test/audit-tree.test.ts` (the tree, against the RFC's recursion and Go's
  vectors) and `packages/vault/test/audit-tree.test.ts` (the checkpointer against a database writer,
  and the pair's rules).
- **Go's check:** `scripts/audit-tree-go.sh`.

## In short

- **Two growing RFC 9162 trees** (Certificate Transparency's), one per retention class: `changes`,
  kept for good, and `uses`, dropped by day. Each is a standard log with its own origin and key, so
  Go's `tlog` or any C2SP witness reads either one alone.
- **One pair.** A tick signs both heads with the same `upto`, `at` and `floor`. The signer remembers
  both in one record, before the database has either. One statement writes both, and opening, every
  tick and every witness check take both as one value. No state anywhere holds one head without the
  other.
- **The signer's memory lives outside the database**: an fsynced file on Node, the Durable Object's
  storage on Workers. A database rolled back or cut under it is caught at its next start.
- **Level-0 tiles are stored for both trees** ("Numbers" says why).

## The shape: two trees, one pair

Two trees, because uses are dropped by day and changes are not. With one tree, retention would
rebuild the dropped window every day (10.4 minutes of CPU a day at 1,000 uses a second) and keep a
digest of the changes inside it. With two, a change stays provable for good and the uses tree drops
whole tile ranges. The split costs about 2 KB more WAL a tick (under 0.5% of the log's) and 0.2 to
0.6 ms more signer CPU. Its risk is the two heads drifting apart, which these rules close
(`packages/core/src/audit/pair.ts`, `checkpointer.ts`):

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

**Example.** A tick seals numbers 41 to 49: uses 41 to 48 and the change 49, with no 45 (an aborted
append). It signs `changes` at 17 leaves and `uses` at 3,000, both `upto 49`. If a crash hits after
the signer remembered that pair but before the write, the next start finds the memory ahead of the
database. It re-seals 41 to 49 from the entries and must reach both heads exactly. If a writer
deleted use 44 in between, the uses head differs and the checkpointer refuses to start.

## A leaf

A leaf is the whole entry: its tree, its number, then every column of its row in order, its MAC
included (`leaf.ts`). The number is sealed with the entry, so a sealed entry cannot be renumbered.
The tree is sealed too, so an entry moved from one tree to the other is no longer its leaf.

```
"coffre.audit.leaf.v1" \n tree \n number (8 bytes, big-endian) column count (4)
then each column: tag (1) length (4) bytes
  tag 0 null, 1 bytes, 2 text (UTF-8), 3 integer (decimal text)
```

Every column is tagged and length-prefixed, so no two rows encode alike.
`packages/core/test/vectors/audit-tree.json` pins the bytes. Which columns each table gives is
`log-entry.ts`'s ("The entries", below).

## Tiles

Go's and C2SP's layout: height 8, each tile up to 256 hashes of one level, a partial tile only
growing (`tiles.ts`). A proof reads about one tile per 8 levels.

- **Partitioned by leaf range.** `tileLeaves(t)` is the range of leaves a tile stands for. Retention
  drops a whole range of uses-tree tiles as a table instead of deleting rows: 1.16 s and 294 KB of
  WAL, against 13.8 s and 3 GB for a `DELETE`.
- **Below a retention cut, one tile per level.** `keptAbove(tile, cut)`: proofs of leaves at or
  above the cut, and consistency from sizes at or above it, read only tiles that reach past it. So
  only the tile holding the cut stays at each level. The TypeScript test checks this exhaustively on
  a 1,500-leaf tree, for cuts on and around tile edges, and sampled on 300,000 leaves; Go's check
  covers it too.

## The checkpointer behind its seam

The rest of the vault sees `tick()` (the window in, a signed pair out), `sealThrough(number)` and
`prove(number)`. The trees' shape, tiles and pair stay behind them. The database is behind
`CheckpointStore`:

- `close(after, from)`: the barrier (`close_one`), then the window (its uses read from `from`, the
  newest pair's floor) and the newest row in the next statement, a snapshot taken after the
  barrier's lock: every number at or below `upto` has ended, so the entries above `after` up to it
  are final;
- `write(row, tiles)`: the pair and both trees' tiles, one statement;
- `newest()`, `entries()`, `tiles()`, `pairs()`, `pair()` and `locate()`: the reads.

**A tick** checks the window, then signs, remembers, writes and publishes. The window must hold
numbers that increase, all inside it, each in a tree, each with a MAC that holds, and none more than
10 minutes older than the signer's pair (`FRESH_MS`). A replay of a use whose day retention dropped
is caught that way, since no lookup can match it. Any failure refuses the tick and alerts. The
newest row must be the signer's pair, note for note, so a row deleted or replaced under a running
signer shows within a tick.

**Each pair signs its floor.** A checkpoint note carries three extension lines: `upto N` (every
number at or below it is final), `at T` (when it was signed) and `floor F`, the lowest `at` a use
may still be written with once that tick's barrier ran. The floor's row in the database is
unsigned, so a writer could lower it and let in a late use below it, which a window read from the
floor would miss. So each pair signs the floor its barrier left, and the signer reads windows from
the newest pair's floor. Every barrier must find the floor exactly where this process's last
barrier left it. Lower, a late use may have got in; higher, the writer's value would be signed.
Either way the tick is refused and alerted, and so is every tick after it until the checkpointer is
reopened, even if a later barrier lands the row back on the expected value. After a restart the
first barrier may find it higher honestly (barriers whose pairs went unsigned raised it), never
lower than the newest pair's. Open, witnesses and the verifier refuse a floor that comes down
between pairs, as they do for `at`.

**The pair's `at` never comes down, and never runs far ahead.** Retention's freshness rule needs the
first half: a replay of a dropped use must never become fresh again when a clock steps back, so
`open()` and witnesses refuse a newer pair signed earlier than the one they hold, and the verifier
reports one. The second half: one tick on a signer clock an hour ahead would make every honest entry
read as a replay for that hour. So a tick signs its clock, held to at most 10 minutes past the
newest entry in its window:

```
at = max(last at, min(now, newest entry's at + 10 min))
```

A clock ahead moves the time one bound at most, so sealing never stops on it. A signer that stalled
past the bound on a quiet log still seals when it resumes. A window holding only gaps keeps the
last time. The genesis pair seals nothing and carries `at 0`, so no clock is trusted before the
first entry holds it.

**A failed tick** leaves its pair pending. The trees grow on a copy, so the signer stays at the pair
the database holds. The next tick finishes the pending pair before anything else: it remembers it
again, then adopts it if the database holds it (a write that committed, then threw), or writes it as
it was if the database is still at the signer's pair. It never signs another pair for that place,
even if an entry of it was deleted since: the pair goes in as signed, and the verifier reports the
loss. A database at neither pair is refused until the checkpointer is reopened.

**A change** waits for its seal; a use does not. `sealThrough` ticks at once unless a pair already
covers the change, or the running tick will (its barrier came after the change committed); the
change then waits for that tick alone. A pair covering the number is not enough: an entry deleted
before its tick leaves a gap the pair calls final. So the change is proved in the pair, and its
answer carries that proof; if the entry is not there, the change is refused and alerted. The proof
comes from the tick that sealed it: the checkpointer keeps its last pairs that sealed a change, 4 MiB
of them at most, each with the changes it placed and the changes tree's tiles that tick wrote, and
checks the proof against that pair's root before handing it out. A change sealed outside that memory
is proved from the database (`locate`, then its tiles), two round trips more. A checkpointer closed
or stalled answers no change, and one whose last tick was refused none while the refusal stands.

Then the change waits for every witness to hold a pair that covers it, for at most 2 s
(`WITNESS_DEADLINE_MS`). Each witness has a pump that sends the newest pair, one at a time, each try
bounded by 2 s, so a witness that never answers fails its try instead of stopping its pump. A
witness that refuses is asked again every 100 ms until the deadline. A silent witness lets the
change answer `witnessed: false`, alerted. With no witness, `witnessed` is `null`.

**A proof** is checked against the signed head before it is handed out, and must be for the entry
asked. A database that changed the entry, or answered for another, makes `prove` throw instead of
returning a proof that fails later.

**Notes are read as strictly as Go's `note.Open`**: canonical base64, at most 100 signature lines,
no control characters. The first line by the log's key decides: if it does not verify, the whole
note is spoiled; later lines by that key are ignored, as Go does. So a note the database holds
opens here only if Go's `note.Open`, given that tree's key, would open it too.

**Witnesses** implement `Witness.publish(notes, proofs, signal)`. `localWitness` runs `witnessPair`
in process, as the witness's Durable Object does. The R2 archive under a bucket lock protects
against a compromised Worker or database, not against the Cloudflare account: an account admin can
remove the lock rule.

## What it catches

Each row is a test in `packages/vault/test/audit-tree.test.ts`.

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

**What it does not catch, by design:** an entry deleted or reordered before its tick, a window of
about 500 ms (uses do not wait for their seal; changes do). A signer whose memory is gone takes the
database's word for the newest pair. It says so (an alert), and only a witness catches what happened
before.

## Checked by Go

`scripts/audit-tree-go.sh` runs `packages/core/test/go`, which uses Go's `golang.org/x/mod/sumdb/tlog`
and `sumdb/note` and shares no code with ours. On a split log the checkpointer sealed, every note
opens with `note.Open` under its own origin's key, Go rebuilds every tile byte for byte, its proofs
equal ours, and through uses-tree cuts that keep only what `keptAbove` keeps, `TileHashReader` still
proves every sampled leaf and size above the cut. A flipped tile byte or a swapped note stops it. Go's
heads, proofs and tiles for a 70,001-leaf tree are pinned in
`packages/core/test/vectors/audit-tree.json`, so CI holds the TypeScript to them without Go.

## Numbers

Measured at 1,000 entries a second, one in a hundred a change, and a 500 ms tick (about 500 entries).
Scripts: `packages/vault/scripts/audit-tree-bench.ts` (in memory),
`packages/vault/scripts/checkpoint-bench.ts` (Postgres 16, 2 vCPU, 2 GB),
`packages/vault/scripts/checkpoint-bench-workers.ts` (the Durable Object in workerd, through
Hyperdrive's local connection).

| per tick | p50 | p99 |
|---|---|---|
| checkpointer CPU, in memory | 4.6 ms | 41–46 ms (garbage collection) |
| the signer's memory, an fsynced file (Node) | 0.6 ms | 2.8–7.5 ms |
| Postgres: barrier and window | 3.6 ms | 6.4–6.7 ms |
| Postgres: write (`write_checkpoint`) | 2.5 ms | 5.2–5.6 ms |
| Postgres: tick, wall | 13.1–13.5 ms | 32–39 ms |
| Durable Object: tick, wall | 28 ms | 56 ms |

That is about 9 µs an entry: the MAC check, the leaf hash, the tree and two Ed25519 signatures. The
checkpointer costs Postgres about four points of a core at that rate. On Workers the memory is one
write of about 0.5 KB a tick to the object's storage, 172,800 a day.

**Level-0 tiles for the uses tree** are kept, measured with
`packages/vault/scripts/audit-tree-level0.mjs`:

| | with level-0 tiles | without |
|---|---|---|
| the uses tree on disk, per use | 57 B | 9.6 B |
| the log's WAL a tick | 152 KB | 126 KB |
| a proof's leaf level | one tile: 0.21 ms p50 | 256 uses read back: 0.59 ms p50 |

Dropping them would save 47.5 B a use, 25% of a use's storage and 17% of the log's WAL (about
4.1 GB a day at 1,000 uses a second). They stay because every level-0 read would otherwise rebuild
tiles from use rows: every tick's consistency proofs for witnesses, `open()`, the tile API Go and
C2SP clients read, and the verifier's start would each cost the rebuild, and retention would have to
write out the tile holding each cut before dropping its day. The saving is bounded anyway (level-0
tiles go with their day's partition). If storage bites, the store can synthesize the uses tree's
level-0 tiles behind `CheckpointStore.tiles` without touching the checkpointer or the verifier.

## Where it runs

**The store.** `packages/vault/src/log-store.ts` is `CheckpointStore` over Postgres, through the
vault's own login, which reads `log_*` and writes them only through the log's SQL functions.

- **A tick is three statements.**
  1. `close_one()`, the barrier, with the newest pair read in the same statement. Only the
     checkpointer writes that row, so a snapshot from before the barrier's lock holds it.
  2. The window, in the next statement, a snapshot taken after the lock: changes by number, uses
     from the floor the newest pair signed through `(at, request_id)` (by number through
     `log_uses_by_number_idx` when a backlog is read in parts, below). It comes back as rows, not
     JSON: 3.6 ms p50 instead of 6.0.
  3. `write_checkpoint(…)`: both trees' tiles and the pair, one call. A tile only grows, and a
     second pair at one place fails.
- **A tile read names its tiles as constants** (`(level = 0 AND leaf = 256) OR …`, `tileKeys`), so
  Postgres prunes the leaf ranges as it plans: 0.4 ms at 150 ranges, a month at 1,000 uses a second,
  against 8.7 ms as an array. It runs for every witness's proof each tick and every change's proof.
- **No read scans history.** Each read of uses is bounded by `at` on both sides: from the floor of
  the pair it starts after, to the slack past the floor of the pair that seals where it ends. Only a
  read past the newest pair is open-ended.
- **`locate` finds an old use** through `(at, request_id)`. Without its time, it reads between its
  window's floor and the sealing barrier's floor plus `deadline_max()` (3 s) and 60 s; a caller that
  knows the use's `at` (`prove(number, { at })`) finds it in one probe. The bound is a rule, not an
  assumption: `use_credential` answers `ahead` and writes nothing for an `at` more than 60 s past
  Postgres's clock. A use whose leaf is not where its window puts it was changed since its tick, and
  `locate` says so.
- **Leaf tiles go in ranges of 2^24 leaves** (`TILE_RANGE`, about 4.7 hours at 1,000 uses a second,
  512 MB of tiles). `make_tiles` makes each range, and the next one, before a tile lands in it.
  Retention drops whole ranges below a cut, and deletes the few upper tiles that end at or below it.

**The entries.** `packages/vault/src/log-entry.ts` turns a row of either table into its leaf: every
column in the table's order but the number, with the MAC last. The MAC (`entryMac`) is 16 bytes: the
4-byte tag of the key that made it, then HMAC-SHA256 under a key derived from the vault's signing
seed, cut to 12. The tag is public, one per key (HKDF of the seed under `coffre.log.tag.v1`): it
names the key, so that after a rotation the database can refuse a replaced key's entries and a
reader knows which key to check one under; it vouches for nothing by itself. The HMAC covers the
tree and every column but the number and the MAC (`macData`, KindInMac). The change path and the
use path compute it when they write an entry; the checkpointer checks it before it seals anything.

**The log's origin** is derived from the vault's signing key (`logOrigin`): `coffre.log/<the first
8 bytes of SHA-256 of the changes key, hex>`. Each tree's origin is that plus `/changes` or `/uses`.
There is no deployment option for it. A rotation keeps the trees and moves them to the new key's
origin.

**A rotation** (the spec: [`formal/Rotation.tla`](../../formal/Rotation.tla),
[formal.md](../formal.md#rotationtla)). A deployment moves to a new signing key, a new local KEK or a
new `signingKey` beside a key service, and keeps the old one configured (`previousKeks`,
`previousSigningKeys`). The vault's signing keys are then `[new, …previous]`, and the rule is: a
replaced key vouches only for what came before the rotation.

- **The boundary is an entry.** At its first start under the new key, the checkpointer finds the log
  under another key and writes the rotation: a change of the log's own object
  `log_object('log', 'key')`, its payload naming both keys by origin and its own number, its MAC the
  new key's. One transaction: `log_rotate_number` takes the barrier's locks (the issue lock, then the
  fence, both exclusive), reads `retired` again under them (a start that rotated first leaves
  nothing to do) and takes the number; the vault MACs the entry naming it; `log_rotate` writes it at
  that number and adds the old key's tag to `checkpoint_fence.retired`. Then the checkpointer ticks,
  so the rotation is sealed under the new key within a tick.
- **A rotation counts only where it says it is.** An entry's MAC covers every column but its number,
  which a database writer can change, so a rotation counts only at the number its payload names
  (`rotationOf`): one moved up extends nothing. And it counts only where the key whose MAC it
  carries vouches at that number (`chainOf`, `rotations.ts`; ChainRule): a rotation into the current
  key counts anywhere, one into a key it replaced only below that key's own bound. So a rotation
  planted into the old key past its own counts for nothing, `retired` emptied or not, and the
  checkpointer writes no second boundary. With three keys, someone who holds A and B moves A's bound
  only below B's own rotation, where B vouches anyway (`formal/Keyring.tla`).
- **Old isolates write nothing past it.** A use whose MAC names a retired key is `superseded` (the
  app answers 503 with `Retry-After`; a newer isolate answers the retry), in `use_credential`'s own
  statement, on the fence row it reads already: no extra read on the hot path. A change under one is
  refused by a trigger on `log_changes`, whoever writes it. Each check runs under the lock the
  rotation takes exclusive, in the statement that takes the number, so no entry under the old key
  lands past the rotation. Without this, an old isolate's entry past the boundary would refuse every
  tick from then on.
- **The signer carries its memory across.** It opens its memory, and the database's newest pair,
  under any key it holds; a pair under a replaced key only below that key's rotation, and never at
  or above a pair it remembers under its own. It seals an entry under a replaced key only below its
  rotation, from the boundary it wrote or read at its open. Its first pair under the new key extends
  the old key's trees. With its memory lost at that moment, it takes the database's newest pair,
  alarmed as any lost memory is, and rotates as above.
- **The verifier** takes a newest pair under a replaced key while the log moves on from it: below
  its rotation, and not at or above the pair held outside under the current key. Above the newest
  pair, a replaced key's entries count below its own rotation, whatever key that pair is under, or,
  with no rotation yet, while the newest pair is under it. The key a pair is under is the one its
  signatures hold under, never a name its notes carry.
- **The other readers** hold to the same rule, through one keyring
  (`keyring.ts`): the reads' projector, `coffre verify log`'s check of the
  reads, the vault's `vouch`, which the audit pages ask of the rows
  they show, and retention, whose cut, the first pair past a day's end, is
  under the old key for every day that ends before the rotation. A replaced key vouches for a pair, an entry, a read or the
  cursor numbered below its rotation; one no rotation retired yet, while
  the newest pair is under it; otherwise for nothing. A cursor is
  numbered by both its numbers: the range it stands in starts at `pair`,
  at or below `through`, and one with `pair` past `through` is refused
  whatever its MAC (under the old key, `through` below the rotation and
  `pair` past it would skip every use between them). Each reads the
  rotations and the newest pair in one statement, and keeps no bound
  between calls (a restore brings the rotation back at another number).
  The projector lists every read and moves its cursor under the current
  key; what it listed before keeps the old key's MAC, which holds below
  the rotation, so no row is MAC'd again.
- **A replaced key never comes back.** A checkpointer whose own key a rotation retired refuses to
  open, and the trigger refuses its entries.
- **Witnesses.** The witness's object takes `previous`, the log's keys under each replaced key: the
  pair it holds may be under one, and the first pair under the new key it cosigns must extend it.
- **The window.** Until the rotation is sealed, someone who holds the old key and writes the
  database can delete the rotation entry and sign over its place with the old key, and no check
  sees it: the same window as any entry before its tick. What the old key forged before the
  rotation verifies like the rest ([keys.md](../keys.md)).
- **Below the rotation.** What the old key vouches for there, it vouches
  for to whoever holds it: the leak's reach before the rotation, kept. The
  projector takes a cursor under the old key below the rotation, and walks
  a range it has yet to list held to the pair that starts it, not to the
  newest: someone who holds the old key and writes the database can move
  that cursor among numbers below the rotation (a stretch listed again, or
  skipped, which the check of the reads names), or replace such a pair,
  with uses of her own, which `coffre verify log`'s walk names (it chains
  every pair to the newest). Nothing at or past the rotation, so long as
  the database's newest pair is the vault's: a reader holds no pair
  outside, and the projector keeps the bound it read at a run's start for
  the whole run. So one who holds the old key, deletes the rotation and
  signs the newest pair again under it, takes these readers back to before
  the rotation (the old key pending, vouching on) until a check against a
  pair held outside names it: the verifier's, at or past the signer's
  pair under the new key, its very place included (AnchorKeyHeld), and the signer's next start. A rotation landing mid-run
  leaves the projector on the old bound for that run alone; the old key's
  writes past it are refused (`superseded`), so only such a forger has
  any there.
- **Seals.** A use checks an object's seal under every key the vault holds, the replaced ones
  included, whatever the change's number: one who holds the old key and writes the database can
  still seal a row a use takes, though its change entry is refused by every tick and named by every
  check (BoundaryChecked). Holding seals to the boundary too would need each input's change number
  in the use's row: a known limit.

**Nothing it awaits is unbounded.** A connection that never answers would otherwise hold every seal
behind it, and sign-in and readiness with them.

- **A tick runs at most `TICK_BOUND_MS`** (10 s). Past it the checkpointer *stalls*: it is closed
  for good behind its `Fence`, which refuses every call it makes to its store and every write to its
  memory from then on. Its host opens another: on Workers at the next alarm, its connection cut first
  (`HyperdrivePool.destroy`); on Node a tick later. What the stalled one had sent may still land: a
  database write is refused where a row holds its place, and a late barrier is handled below.
  Without the fence, the stalled tick writes a pair the new signer does not hold, an alarm with no
  attacker (`formal/Seal.tla`'s `Fenced`).
- **A change waits at most `SEAL_WAIT_MS`** (5 s) for its ticks and its proof, then the witnesses'
  2 s. Past it, or once the checkpointer stalled or its database does not answer, it is `Unsealed`:
  committed and in force, its message carrying core's `UNSEALED`. The app answers 503 with
  `Retry-After`, and the next tick seals it. On Workers the vault asks the object for at most 8 s
  for a seal, 2 s for anything else.
- **The open, the next days of uses, and the upkeep after a tick** are bounded too: 10 s, 10 s and
  60 s.
- **A use waits on no checkpointer.** An isolate's uses start the object behind them (`#behind` in
  `cloudflare.ts`) and go on.
- **Readiness asks `sealing()`**: open, its last tick ended well within `SEALING_STALE_MS` (5 s), no
  failure standing (`sealingOf`). On Workers the object answers from its own state and clock, in at
  most 2 s, or the answer is no; `/readyz` gives the vault 3 s. Red within seconds of a stall, green
  again once a tick seals.
- **A tick seals at most `WINDOW_MAX` (10,000) entries** of its barrier's window, read by number, the
  next tick at once while more remains. After a stall the backlog is hundreds of thousands of uses;
  sealed whole, a tick would run past its bound and stall again, for good. A part ends at its last
  entry and signs as its floor the lowest `at` of the uses left above it, if below the barrier's
  (`HotPathOne.tla`'s `ChunkFloor`); its time is its newest entry's, so the rest of the backlog is no
  replay. Every pair still has its uses within 63 s of its floor (`CeilingHolds`), by the `ahead`
  rule and the deadline. With `log_uses_by_number_idx`, the first 10,001 of a backlog of 3.5 million
  read in 3.8 ms (`packages/vault/scripts/chunk-bench.ts`). A tick's bound still grows by
  `WINDOW_ENTRY_MS` (10 µs) per number its window spans, for a database whose index is still being
  built online, which reads by sorting: a drain of millions goes on, and a read that slow for a few
  entries is still a stall.
- **The first barrier after an open is held to its ceiling too**: the barriers whose pairs went
  unsigned left the floor at most at their own clock less the deadline. An upkeep whose checkpointer
  was closed under it raises no alarm.
- **A late barrier is no alarm.** A barrier sent by a checkpointer given up on may run in the
  database after the next one has opened and ticked, raising the floor past where that one's last
  barrier left it. The next barrier takes a floor above its last one when it is no higher than its
  own clock less the use deadline (`floor.ceiling`, read after `close_one`): exactly what a late
  barrier leaves. Higher, a writer raised it, and the tick refuses (`BarrierAcceptsLate`). What
  stays open: a writer who lowers the floor and puts it back before the next barrier reads it lets
  uses in unsealed, and a late barrier can put it back too (`HotPathOneStall`, expected to fail).

**On Node** (`packages/vault/src/checkpointer-node.ts`):

- `runCheckpointer({ database, signingKeys, memory, witnesses })` ticks every 500 ms, a tick after
  the last ends. A tick that throws is an alarm, kept once; `stop()` closes the checkpointer, so a
  handle kept after it never ticks beside a runner started over the same file.
- The memory is a file, written whole, synced, renamed over the last, and the directory synced
  (`fileMemory`). Alarms are appended to `<memory>.alarms`, one JSON line each.
- The vault's process runs it (`localVault`, `serveVault`) through `keepCheckpointer`, opened before
  the vault serves. An open refused (a log it cannot take, as after a restore; the database out of
  reach) is an alarm, kept once, and tried again every 10 s, each try making the next days of uses
  first: uses go on, and a change's seal fails with why. One vault process per database: two would
  each sign, and the floor's check refuses the second's ticks.

**On Workers** (`packages/vault/src/checkpointer-workers.ts`): one Durable Object,
`export const CoffreCheckpointer = checkpointer()` beside `vault(…)`, configured by the same
`vault(env => …)`.

- **The vault starts it** from each isolate's first call (`start` in `cloudflare.ts`). An object
  that refuses to open is started all the same and tries again at each alarm, making the next days
  of uses meanwhile; one out of reach is tried again by a call 10 s later.
- **Its memory is its storage**, synced before `remember` returns (RememberFirst): the output gate
  does not hold a query on a connection already open, as the database write is, so the code does not
  lean on it.
- **It ticks on its alarm** every 500 ms, on one Hyperdrive connection that closes when idle. A
  failed tick drops the connection and the checkpointer; the next alarm opens both again under
  `open()`'s rules, the old one closed and fenced first, so two never sign at once.
- **A refused open and a tick that throws are alarms**, kept once while they stand. A refused open
  (entries the signer sealed lost, another pair at its place, time run back) is never thrown inside
  the gate, which would reset the object: the object stays up and says why.
- **Asked with `fetch`**: `startCheckpointer`, `durableSealThrough` (the change path's seam),
  `checkpointerStatus` (its last ticks and their timings) and `checkpointerAlarms` (kept 30 days).
  `packages/vault/test/checkpointer-workers.test.ts` runs it, a witness and an R2 archive in workerd.

**Witnesses** (`packages/vault/src/witness-workers.ts`) are optional: a deployment opts in by listing
them in its vault config (`witnesses: […]`), and the vault feeds them where the pairs are signed.

- **`durableWitness(env.WITNESS)`** is a Durable Object of its own,
  `witness(env => ({ name, key, log, previous }))`. It cosigns a pair only if both trees extend the
  one it holds. Its client sends each tree's proof from the sizes the object holds; on a 409 it
  learns those sizes and sends again. A pair it holds that no longer opens (its settings now name
  other keys, a record damaged) is refused, never forgotten into a fresh witness: a new witness is a
  new name. After a rotation, `previous` names the log's keys under the replaced one.
- **`r2Archive(env.ARCHIVE)`** puts each pair it is sent under `audit/<upto>.json` without
  overwriting. The pump sends the newest pair, so one a slow put skipped over is not kept; the next,
  which extends it, is. A put over an object already there is the same pair sent again, which is
  fine, or another, which is refused. Under a bucket lock, a Worker or a database writer cannot
  overwrite or delete what it holds; an account admin can lift the lock.

**Alarms.** A refused tick, a memory found behind the database and a change answered unwitnessed
land in the alarms: on Node in the alarms file, on Workers in the object's storage. A refusal that
stands is alerted once, not every tick.

**The change path's seam** is `SealThrough`: `runCheckpointer(…).sealThrough` on Node,
`durableSealThrough(…)` on Workers. `sealThroughDouble` in `packages/vault/test/audit-tree.ts` stands
in for it in tests.

## The spec, and where the code holds it

`formal/Seal.tla` models the pair, and TLC shows each protection necessary. The names below are the
spec's (`HotPathOne.tla`'s where marked). The tests are in `packages/vault/test/audit-tree.test.ts`,
and for the bounds in `stall.test.ts`, `log-hosts.test.ts`, `workers-stall.test.ts` and
`log-store.test.ts`.

| protection | in the code |
|---|---|
| NumberUnderLock, CloseLocks | `CheckpointStore.close`: the barrier (`close_one`) |
| BarrierChecksFloor (HotPathOne) | `tick`: the floor `close_one` found must be exactly where this process's last barrier left it (after a restart, no lower than the newest pair's), else every tick refuses until reopened; each pair signs its floor, and windows are read from the newest pair's |
| BarrierAcceptsLate (HotPathOne) | `tick`: a floor above the last barrier's no higher than `floor.ceiling` is a late barrier's |
| ChunkFloor, CeilingHolds (HotPathOne) | `tick`: a part of the window ends at its last entry and signs `max(floor held, min(barrier's floor, lowest at left above))`; its time its newest entry's |
| Fenced | `Fence`: every store call and memory write of a checkpointer closed or stalled refused; `close` waits for its memory writes in flight |
| RememberFirst | `tick`: `memory.remember` before `store.write` |
| SignerMemory | `open()`: memory equal, a prefix in both trees, or re-derived; else refused |
| RowChecked, PairChecked | `tick`: the newest pair, each tree's own newest note, byte for byte |
| PairWrittenTogether | `CheckpointStore.write`: both notes and both trees' tiles, one statement |
| PairRemembered | `encodePair`: one memory record for both notes |
| KindInMac | `authentic` covers the tree; `sealThrough` proves a change in the changes tree |
| MacChecked | `tick` refuses an entry whose MAC fails |
| WaitForSeal | `sealThrough`: sealed, proved, then witnessed or 2 s |
| Witness | `witnessPair`, the pumps |
| RequestIdChecked | the verifier's `check` (`verifier.ts`): each request once in a walk, and the unique indexes that refuse a copy further apart |
| PairVerified | `verifyLog`: a row whose notes do not open as one pair is a problem |
| invariants KindKept, PairConsistent, AnsweredChangeKept | the rows above together |

**Where the code is stricter than the spec.** The spec lets `open()` repair a half-written pair:
rows of the two trees at different `upto`s, checked each against the one remembered pair. The code
refuses them instead. With PairWrittenTogether, only a database writer can leave a pair half
written, so refusing costs an honest crash nothing.
