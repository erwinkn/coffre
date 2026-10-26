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
- **TLA+ found a real bug.** The checkpointer must record a head outside the
  database before writing it to the database. Otherwise a crash between the
  two, followed by a rollback, gets a split view signed even with the anchor
  in place. Fixed and modelled (RememberFirst).
- **A change answers once sealed** (Erwin approved this as a rule during the
  experiment): +5 ms p50 / +54 ms p99 with no witness, +66 / +587 ms with
  the Cloudflare witness. This closes the "undo a change" window entirely.
  Uses keep a one-tick window.
- **Receipts** cost ~25 µs of Workers CPU each (Ed25519); batching does not
  help. Recommendation: none for uses (nobody would check them); a change's
  answer carries its inclusion proof instead.
- **Key ratcheting** buys nothing here. Below is why.
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

**Proved by an independent implementation.**
[`go/verify.go`](../../experiments/merkle/go/verify.go) ran against our
proof server over a 70,001-entry log that spanned three days. It:

- opened every checkpoint with `note.Open`;
- loaded our tiles through `tlog.TileHashReader`, which checks every tile
  against the signed head, then recomputed the head (`tlog.TreeHash`);
- checked 100 inclusion proofs with `tlog.CheckRecord` and 5 consistency
  proofs with `tlog.CheckTree`;
- recomputed each proof with `tlog.ProveRecord` and `tlog.ProveTree` from
  our tiles, and got the same bytes;
- rejected every proof with one flipped byte.

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

- **"Sealed after"** runs from the oldest entry's commit to the commit of
  the checkpoint that seals it, so it is the worst case of each tick.
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
| inclusion proof | 17 hashes, 544 B, 4 tiles, 1.08 ms p50 | 24 hashes, 768 B, 5 tiles, 1.49 ms p50 |
| consistency proof | 18 hashes | 25 hashes |
| checkpoint at 1,000/s, 500 ms tick | seal 2.2 / write 1.1 ms p50, sealed after p99 526 ms | seal 2.3 / write 1.2 ms p50, sealed after p99 530 ms, 4 tiles written |

A checkpoint touches only the tiles at the tree's right edge, one per level.
A proof reads one tile per 8 levels. The first 10-million-leaf run, right
after loading 324 MB of tiles, showed append p99 at 663 ms and seal p99 at
79 ms. That was Postgres writing out what had just been loaded: after a
`CHECKPOINT` and `VACUUM ANALYZE`, the numbers above. The proof p99 at
10 million (68 ms, against 1.5 ms p50) is cold tiles read from disk.

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
| holds | its last head | the newest head it cosigned | every head, immutable for the lock's term | the chain head |
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
  per tick and needs no plugin, so it belongs in core.
- **R40's plugin keeps what it has:** alerts, readiness gating, re-anchoring
  and "accept loss". It also gains external witnesses (cosigning,
  third-party verification, surviving a reset of the vault's DO).
- **The core checkpointer must refuse to sign** when the database is behind
  or beside its memory, and say so where an operator sees it. Without the
  plugin, that refusal is the only alarm.

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
answer's proof verified):

| witness | commit | seal (+ witness) | total, p50 / p99 | witnessed |
|---|---|---|---|---|
| none (R40 without the plugin) | 1 / 2 ms | 5 / 54 ms | **7 / 58 ms** | n/a |
| Cloudflare DO witness, from this host | 1 / 5 ms | 66 / 587 ms | **68 / 600 ms** | 40 of 40 |
| slow witness (answers after 3 s) | 1 / 20 ms | 2,004 / 2,086 ms | 2,006 / 2,092 ms | 0 of 20: "no answer within 2000 ms" |
| unreachable (connection refused) | 1 / 2 ms | 5 / 77 ms | 7 / 82 ms | 0 of 20: "unreachable" |
| unreachable (no route; packets dropped) | 1 / 1 ms | 2,004 / 2,078 ms | 2,006 / 2,083 ms | 0 of 20: "no answer within 2000 ms" |

The first version waited for witnesses inside the serialized tick, so a
slow witness held the next tick back, and a change's p99 came out at 3.9 s
against a 2 s deadline. The checkpointer now gives each witness a pump that
always sends the newest head, so a slow witness delays only its own
acknowledgement.

**When the witness is slow or unreachable**, two options:

- **(A) Answer after the deadline, marked unwitnessed** (`witnessed: false`,
  shown in the UI, alerted), while the checkpointer keeps publishing.
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
| leaf only (JSON + SHA-256) | 11.5–13 ms | ~12 µs |
| + HMAC (not publicly verifiable) | 19 ms | +7.5 µs |
| + Ed25519 (WebCrypto) | 36.5–60 ms | **+25–45 µs** |
| batched: 1,024 leaves, one signature, 1,024 paths | 37.5 ms | ~37 µs: no better |

So a receipt per use costs about 1% of the 2.9 ms a use already costs on
Workers (W201), and batching does not pay.

**What it closes in practice: little, for uses.** A receipt makes deleting
that entry detectable by whoever holds it and checks inclusion after the
deadline. The holder of a `/use` receipt is the app, and apps will not
check. A sampler that checked 1% would catch a targeted deletion 1% of the
time. The window it narrows is already one tick. Changes, where it matters,
now get something stronger: the inclusion proof itself, in the answer.

**Recommendation: no receipts for uses in 0.15.** They could come later for
people's reveals through the CLI, which can keep and check them, if Erwin
wants a user to hold proof that Coffre logged their access.

## Key ratcheting (forward-secure MACs): not worth it here

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
- **Whoever steals the MAC key has stolen the vault's config,** and with it
  the key-encryption key. Forging log entries is the least of it.
- **The tree already gives the property ratcheting was for.** Sealed,
  anchored heads fix the past. A stolen MAC key can forge entries only
  inside the one-tick window, and a stolen signing key cannot rewrite heads
  that the signer's memory and the witnesses hold.

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
  - the sequence only ever moves forward (a clock stepped back, or a day
    closed twice, does nothing);
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

**Which layout:** `number` days are exact and simpler to verify. `at` days
work with the digest rule, at the cost of stragglers and the
dropped-partition caveat. Either fits the tree; W208 picks the one that
suits `use()`.

## Replays and reorders in the window

The MAC does not cover the number (W208). So before sealing, a writer can
also do two things:

- **Copy an entry under a fresh number.** The copy has a valid MAC. Once
  both are sealed, the verifier flags the duplicate request ID. The append
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

- appends that take the lock, the number and commit, or abort and leave a
  gap; one append is a change, answered to an admin;
- ticks that take the barrier, seal, sign, remember and write;
- crashes between those steps;
- an attacker who may delete entries or the newest checkpoint rows, forge
  an entry at a gap, replay an entry under a free number, or swap two
  numbers;
- a ghost set of every head ever shown to a reader.

`scripts/formal-seal.sh --workers 8`, about 47 s:

| scenario | bounds | distinct states | time |
|---|---|---|---|
| Seal | 3 appends (1 change), 3 ticks, 1 crash, 2 attacks | 917,570 | 5 s |
| SealDeep | 4 ticks, 2 crashes, 3 attacks | 7,883,882 | 32 s |

Invariants, all holding:

- **Complete:** no honest entry commits under a signed head.
- **SealedDeletionDetected**
- **SplitViewDetected**
- **NoForgerySealed**
- **NoUndetectedReplay**
- **AnsweredChangeKept:** an answered change missing from the database
  raises the alarm.
- **NoFalseAlarm:** an honest run with crashes never alarms.

Each protection removed, TLC fails as required:

| removed | breaks | TLC's counterexample |
|---|---|---|
| NumberUnderLock | Complete | number 1 taken before the lock; the tick seals up to 1 without it; then 1 commits under the seal |
| CloseLocks | Complete | the tick reads the sequence while an append holding number 1 is in flight |
| Anchored | SealedDeletionDetected | entry 1 sealed; the attacker deletes it and the newest checkpoint row: a consistent shorter log |
| Anchored | SplitViewDetected | the same, then the stateless signer seals the window again: two signed heads, a clean database |
| RememberFirst | SealedDeletionDetected, SplitViewDetected | the head is written to the database, then the checkpointer crashes before recording it outside; the attacker deletes the entry and the row; the restarted signer signs a second head |
| MacChecked | NoForgerySealed | a forged entry at an aborted append's gap gets sealed |
| RequestIdChecked | NoUndetectedReplay | an entry copied into a gap; both copies sealed |
| WaitForSeal | AnsweredChangeKept | a change answered at commit, deleted before any tick |
| Anchored, with WaitForSeal on (R40 without the plugin) | AnsweredChangeKept | the change is sealed into the database's checkpoint and answered; the attacker deletes it and the newest checkpoint row |

The design leaves two things open on purpose, both TLC failures as
expected: **UnsealedDeletionDetected** and **UnsealedReorderDetected**,
the one-tick window.

Not modelled:

- several checkpointers at once (one DO is assumed);
- tile edits (the tree is abstracted to its leaves; an edit changes the
  head, by the code's argument, not TLC's);
- the attacker moving the sequence.

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

CLEANUP_LINE
