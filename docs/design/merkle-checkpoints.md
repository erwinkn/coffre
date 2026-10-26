# Merkle checkpoints for 0.15's audit log (W209)

An experiment, not a decision. Written by W209 on 2026-10-26, on a draft PR
marked DO NOT MERGE. It answers one question: once 0.15's hot path gives up
the chain between entries (W201, [`hot-path-simple.md`](hot-path-simple.md);
W208's one-call `use()`), what keeps the audit log honest, and how fast?

The setting, in one paragraph. A use appends one entry in one statement. The
entry gets its number from a Postgres sequence and carries a MAC over
everything except that number (the vault computes the MAC before the INSERT
picks the number). Nothing links one entry to the next. So someone with
write access to the database, but not the vault's keys, cannot forge or alter
an entry. They can delete one: numbers have gaps anyway (an aborted append
leaves one), so a missing number proves nothing. Something has to seal the
entries, quickly and in a way that no database writer can undo.

- **Prototype:** [`experiments/merkle/`](../../experiments/merkle/). The
  tree, tiles and proofs are in `src/tree.ts` and `src/tiles.ts`; the signed
  checkpoints in `src/note.ts`; the log, checkpointer and proofs in
  `src/log.ts`; the verifier in `src/verify.ts`; retention in
  `src/retention.ts`; the change rule in `src/change.ts`; witnesses in
  `src/witness.ts`; and the SQL in `schema.sql`.
- **Independent check:** [`experiments/merkle/go/verify.go`](../../experiments/merkle/go/verify.go),
  Go's `golang.org/x/mod/sumdb/tlog` and `sumdb/note`.
- **Cloudflare:** [`experiments/merkle/worker/`](../../experiments/merkle/worker/)
  holds a Durable Object witness, an R2 archive under a bucket lock, and the
  receipt CPU probe. It ran on Erwin's personal account and has been deleted.
- **Model:** [`formal/Seal.tla`](../../formal/Seal.tla), checked by
  [`scripts/formal-seal.sh`](../../scripts/formal-seal.sh).

## In short

- **One growing RFC 9162 tree** (Certificate Transparency's), byte for byte,
  stored as Go/C2SP tiles. Checkpoints are C2SP signed notes with Ed25519
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
- **Retention** works with the tree in both layouts. The retention entry is a
  kept-forever change that commits to what stays below the cut.

## The tree

### The shape: one growing tree, not a tree per window

Two shapes were on the table:

- **One growing log tree** (CT, Trillian, Go's sumdb, Sigstore Rekor). Every
  checkpoint signs the head of the whole tree so far. A consistency proof
  shows a later head extends an earlier one, which replaces the chain.
- **A tree per window, roots chained** (SQL Server Ledger's blocks, or W201's
  flat hash per checkpoint). Each checkpoint signs its window's root and the
  previous checkpoint's hash.

The growing tree wins, for four reasons:

1. **Proofs stay O(log n) against the newest head (R48).** In the chained
   shape, proving an entry from 09:00 against the head at 17:00 needs every
   checkpoint between them: at one per 500 ms, that is 57,600 links. The
   growing tree needs log₂(n) hashes, 24 at ten million entries.
2. **A witness needs only the newest head.** It checks a consistency proof
   from the head it holds to the new one, and keeps nothing else. A chain
   witness must see every link or trust the gaps.
3. **The ecosystem already exists.** Go's sumdb clients, transparency-dev
   witnesses, Sigsum and Sigstore's tooling all read RFC 6962/9162 trees,
   C2SP checkpoints and tiles, so we write no verifier for others.
4. **Same storage.** Tiles hold about one hash per leaf either way.

What the growing tree costs: a day of uses is not a clean prefix of it,
because changes are kept forever and sit among the leaves. That's the
"Retention" section below.

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
[`go/verify.go`](../../experiments/merkle/go/verify.go) ran against our
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

[`attacks.ts`](../../experiments/merkle/attacks.ts) runs each scenario on a
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
| (s) a use copied before its day is dropped, replayed after the retention cut, the checkpoint rows between deleted | the verifier warns only (rows are the writer's) | | **the signer refuses to seal it**: "older than the signer's head: a replay" (the request-ID lookup cannot: the original is gone) |
| (t) a witness that always refuses, after the change has answered | | asked 4 times until the answer (300 ms), 0 after | |
| (u) remembering a head fails once | | | the next tick's head holds |
| (v) writing a head fails, then putting the tree back fails too | | | the checkpointer refuses every tick until reopened; reopened, the log holds |

Rows (f) to (v) came from four review rounds: (g) to (l), (n) to (r),
(s) to (u) and (v) are the reviewer's own reproductions, each of which got
through the version before. Round four found:
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
([`anchor-check.ts`](../../experiments/merkle/anchor-check.ts)), with the
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

Measured ([`change-bench.ts`](../../experiments/merkle/change-bench.ts), 40
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
Workers ([`worker/index.ts`](../../experiments/merkle/worker/index.ts), CPU
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
are prototyped ([`retention.ts`](../../experiments/merkle/src/retention.ts),
[`test/retention.test.ts`](../../experiments/merkle/test/retention.test.ts)):

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
  - A few next-day uses below it (stragglers) stay, and are covered by the
    digest.
  - An append whose `at` falls in an already dropped day fails for want of
    a partition, so days must be dropped well after any clock skew (they
    will be: retention is weeks).

In both, retention runs in four steps:

1. Drop the day's uses partition once it is sealed.
2. Append a kept-forever `audit.retention` change: {cut, the entries still
   below the cut since the last cut, as a count and the RFC 9162 head of
   their leaves}.
3. Delete the level-0 tiles below the cut.
4. Keep the higher levels: one hash per 256 leaves, 10 MB a day at a
   sustained 1,000/s.

**What a verifier keeps after a drop:**

- **The heads.** Its witnesses' heads, and the archive's for the lock term.
- **What it checks:**
  - every retention entry's digest against what stays below its cut
    (changes, stragglers);
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

**Which layout:** `number` days are exact and simpler to verify. `at` days
work with the digest rule, at the cost of stragglers and the
dropped-partition caveat. Either fits the tree; W208 picks the one that
suits `use()`.

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

`scripts/formal-seal.sh --workers 8`, about 2 minutes:

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
5. **Tree shape:** one growing RFC 9162 tree with C2SP formats
   (recommended), not a tree per window.
6. **Day layout:** `number` days (exact, recorded in signed day entries) or
   `at` days (W208's current layout, with the retention digest). W208's
   call, under the hot path's constraints.
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
