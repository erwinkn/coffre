# The hot path at proxy scale (0.15)

A design for coffre's hot paths, `/use`, signing, reveals and CI sign-in,
at the scale of a proxy that every secret-bearing request of an app goes
through: 1,000 requests a second sustained on Cloudflare Workers, a few
hundred of them from one principal, with no queue that grows and no
error. Node is supported second. Written by W194 on 2026-10-26 as an
experiment (draft PR, not merged, not released): a prototype under
`experiments/lanes/`, measured on a personal Cloudflare account, and a
TLA+ model under `formal/Shards*.tla`. Nothing here ships until Erwin
decides the open questions at the end.

"Today" means 0.14.2. Every number below is measured unless it says
"estimated"; the measurements, their setup and their raw output are in
[Measurements](#measurements).

## In short

- **Today one lock orders the whole instance.** A cold `/use` holds the
  audit log's head for about seven round trips to Postgres (two in the
  vault's decision, five in the app's own `credential.use` entry), and the
  caller's member row for three to five. At 20 ms a round trip, the
  instance tops out at **5.4 cold uses a second**, one principal or fifty;
  past that, latency climbs to 9–12 s and connections run out. That is
  Equisafe's incident: about 8 a second from one DFNS job.
- **W185's rework (0.15 as planned) moves that ceiling to about 20 a
  second at 20 ms,** and only once the app's entry is folded into the
  vault's: one global head held across two round trips caps any instance
  at about 1/(2 × RTT).
- **The design: shards.** A fixed set of Durable Objects (64 by default).
  Each is the single writer of three things for the principals it serves:
  their standing (member row, grants, credentials) read once from Postgres
  and kept in memory, the keys it has opened for them, and its own lane of
  the audit log. A warm `/use` is one call to one shard and **no Postgres
  round trip at all**.
- **Changes fence the shards, then commit.** Every change a use decides
  on (a revocation, a removal, a policy edit, a credential revoked, a
  value written) takes one revision number, fences every shard at it,
  commits, and only then answers. A fenced shard answers only from
  standing read at that revision or later. So "revoke returned ⇒ the next
  use is refused" holds by construction, on every shard, with no cache
  TTL anywhere.
- **Audit before return, without Postgres in the way.** A shard seals each
  use's entry from the head it holds and writes it to its own storage
  before the answer leaves (Cloudflare's output gate makes that write
  durable first). Behind it, the shard copies its lane to Postgres in
  batches, each one statement with a compare-and-swap on the lane's head.
  Postgres stays where everything is read, verified and backed up.
- **Tamper evidence per lane, tied together by the revision.** Each lane
  is a hash chain with a MAC per entry, as today's log is. Every entry
  names the revision it was decided at, so every use is ordered exactly
  against every change; uses on two different shards are not ordered
  against each other. A vault-signed checkpoint signs all lane heads
  together.
- **Overload is refused at once.** A shard that cannot keep up answers 503
  with `Retry-After` in milliseconds instead of queueing; nothing holds a
  database connection while it waits.
- **Node runs the same shards in one process,** with Postgres as their
  storage (group commit, sub-millisecond round trips); a standby takes
  over through a lease.

## What a cold `/use` costs today

Here is one cold `/use` on 0.14.2, step by step, at 20 ms a round trip
(each line one statement, so one round trip; locks in brackets):

```
app    resolvePath, valuesIn                                    2 round trips
vault  versions                                                 1
vault  BEGIN; SET lock_timeout                                  2
vault  member row FOR NO KEY UPDATE                [member ▮]   1
vault  snapshot, head FOR UPDATE SKIP LOCKED       [head ▮]     1
vault  append (INSERT + head UPDATE)                            1
vault  COMMIT                                      [both free]  1
app    BEGIN; head FOR UPDATE                      [head ▮]     2
app    policyStill; credentialStill; underHead                  3
app    append; COMMIT                              [head free]  2
                                                                ── 17 statements
```

The head is the instance's one audit-chain head: every append anywhere
waits for it. It is held for about 2 round trips in the vault's
transaction and 5 in the app's, so about 140 ms in all at 20 ms a round
trip, which caps the whole instance at about 7 cold uses a second
(measured: 5.4). The member row serializes one principal's reads behind
each other on top of that. W187 found Equisafe's 15 s failures to be lock
waits on that row; the waiters behind it are queued for the head.

## The design

### Where state lives, and who writes it

| State | Truth | Written by | Read on a warm `/use` |
|---|---|---|---|
| Members, grants, roles, policy, places, secrets (wrapped), credentials, bindings | Postgres | the vault, as today, in a change (below) | no: the shard keeps what it read |
| The revision: one number that every change raises | Postgres, one row | each change, under that row's lock | no |
| A principal's standing (member row, grants, credentials, the revision it was read at) | a copy in its shard's memory | the shard, from one Postgres statement | yes, from memory |
| Opened data keys | the shard's memory | the shard, opening each once | yes, from memory |
| A use's audit entry | the shard's lane: its own storage first, then Postgres | the shard, single writer | written before the answer |
| Changes' audit entries | the control lane, in Postgres | each change, under the revision's lock | no |
| Checkpoints | the control lane | the vault, every few seconds | no |

A principal belongs to one shard, by a hash of its name. A hot principal
(the DFNS job) can be spread over K shards (K = 8 measured clean at 1,000
a second): each request goes to one of them, all K are fenced by every change like every other shard, and the
bulk cap's counter stays with the principal's home shard (below).

### A warm `/use`

```
app Worker   authenticate the caller (signature, DPoP proof: CPU only)
             → shard(principal).use({ credential, place, key, request })
shard        standing in memory, read at revision ≥ floor?        yes
             decide: credential live, member active and sealed, grant, nature
             key opened already?                                  yes
             seal the entry from the lane's head, write it to storage
             ← the value (the output gate releases it once the write is durable)
app Worker   inject the value, call upstream
```

No Postgres. One Durable Object call: about 3–5 ms from a Worker in the
same region. The shard's own work is a few map lookups, one HMAC, one
SHA-256 and one SQLite insert.

A cold `/use` adds one Postgres statement: the standing read (member,
grants, credentials, the newest access entry, the secret's wrapped key,
and the revision, all at once). After that, the shard keeps it until a
change fences it.

### A change, and why a revocation cannot be outrun

Every change any use decides on goes through one function:

```
BEGIN
SELECT value FROM revision FOR UPDATE           -- R := value + 1; changes queue here, uses never do
fence every shard at R                          -- each persists floor := max(floor, R), then acks
the change itself, and its control-lane entry
UPDATE revision SET value = R
COMMIT                                          -- then, and only then, answer
```

A shard fenced at R answers only from standing read at revision R or
later. Standing at R exists only once the change has committed. So:

- A use that reaches a shard after the fence, and before the commit,
  reads standing at R − 1, which is below the floor: the shard answers
  503 `changing`, and the client retries. That is the only window where a
  change costs anything, and it lasts one fence and one commit (10–40 ms
  measured).
- A use after the commit reads standing at R, which has the change.
- A use that arrives after the revocation answered finds every shard
  fenced at R (the fences finished before the commit), so none of them
  answers from older standing.

Example, Ada revokes `svc-dfns`'s grant on `market/prod` while it calls
`/use` 1,000 times a second over 4 shards: each shard is fenced in about
10 ms; for those few milliseconds, calls on it answer 503 `changing`; the
change commits; Ada's request returns. Every call made after that is
refused 403. Measured on the prototype: of 1,076 calls made after the
answer, none was allowed.

Three things make it hold when things go wrong:

- **A fence is durable.** The shard writes its floor to its storage
  before acknowledging. A shard that restarts between a fence and the
  commit would otherwise come back with no floor and read the old
  standing. (The TLA+ model finds that interleaving when the protection
  is removed.)
- **A change that rolls back lifts its fence**, by an `unfence` sent to
  every shard. If that message is lost, a shard stuck below its floor
  probes `SELECT value FROM revision FOR UPDATE NOWAIT`: if it gets the
  row, no change is in flight, so the fencing change will never commit,
  and the floor comes down. Exact, and no clock involved.
- **Fences are idempotent and ordered** (floor only goes up), so retried
  or duplicated fences change nothing.

What a change costs: one round trip to each of the 64 shards, in
parallel (10–40 ms measured), on top of today's change transaction.
Changes are human or CI actions: a few a minute. Each one also makes
every shard read the standing of its active principals again, one
statement each, on their next use.

### The audit log as lanes

Each shard writes its own lane: a hash chain exactly like today's log,
one entry per use, its MAC covering the lane, its number, the previous
hash and everything it says, including the **revision** the use was
decided at. Changes, checkpoints and key rotations go in the control
lane, which is today's chain carried on.

Durable before return: the shard writes the entry to its own SQLite
storage, synchronously, before it answers. Cloudflare's output gate holds
the answer until that write is durable, so a value never leaves without
its entry, and a shard that dies a microsecond later still has it.

Copied to Postgres behind: every 200 ms while entries wait, the shard
copies its unflushed tail to Postgres in one statement that inserts the
entries and moves the lane's head there only if Postgres's head is where
the shard last left it (`UPDATE … WHERE next_seq = $flushed`). Two live
instances of one shard (Cloudflare allows it briefly) cannot fork the
lane: only one of them can commit to the shard's storage, and Postgres's
compare-and-swap refuses the other. A Postgres head behind what the shard
copied before is a rewound database, which the shard reports and stops
on.

What the log promises, compared with today:

| | Today | Lanes |
|---|---|---|
| Order of uses against changes | total | total: a use at revision r came after change r committed and before change r+1 did |
| Order of uses among themselves | total | per lane, so per principal (unless spread over K shards); none between lanes |
| Each entry authenticated | MAC over seq, prev hash, fields | the same, per lane, plus the revision |
| Deleting an entry in the middle | breaks the next entry's MAC | the same, in its lane |
| Cutting the newest entries | seen by the next checkpoint or the anchor | the same; and the shard's own copy keeps them |
| Verification | from the last checkpoint, O(entries since) | the same, per lane, lanes in parallel |

The checkpoint signs `{ revision, control head, every lane's head }`
together, every 5 s: so within 5 s any two entries are ordered by the
checkpoints around them, and a lane cut short shows against the last
checkpoint as today's log does.

### Overload

A shard counts what it is doing. When a call would wait behind more than
its budget (100 ms of queued work, or 2,000 calls), it answers 503 with
`Retry-After: 1` at once. Measured: under a 4,000 a second burst on 64
shards, the budget never tripped (one failure in 114,000 calls). Nothing
on the hot path waits on a database lock, so nothing holds a connection
while it waits.

What did trip was Cloudflare's own limit on one object: one principal at
1,000 a second on one shard got 57,498 "Durable Object is overloaded"
errors, Cloudflare's answer when an object's queue is too long, and slow
(seconds). A shard's own budget only sees calls once they reach it, so
the real defence is upstream: the app Worker counts its calls in flight
to each shard and refuses above a bound, and a hot principal is spread
over K shards before it gets there.

### Hot principals

One Durable Object handles roughly 1,000 simple calls a second. A
principal with more traffic than a shard can take is spread over K
shards, chosen per principal in the configuration (`fan: 4`) or when a
shard sees it dominate its traffic. Each of the K is fenced by every
change, as every shard is. The bulk cap (R28: 1,000 distinct keys per
principal per 15 minutes) stays exact: a shard asks the principal's home
shard only when the principal opens a key it has not opened in the
window, which for a proxy job is once per key.

### Node

The same shard code runs in-process: one vault process holds every
shard. Its storage is Postgres itself, written by group commit per shard
(round trips are sub-millisecond on a local network, so a batch per
millisecond is plenty). A standby process takes over through a Postgres
advisory-lock lease, starting with empty memory, which is safe because
standing is always read again. Several active vault processes would need
shards leased between them and requests routed to the owner; that is
left out until a deployment needs it (one vault process serves far more
than a Node app's traffic).

### What else shards change

- **Sign-in (CI OIDC, `token.exchange`).** The principal's shard verifies
  the token, spends its `jti` in its own storage (single writer, so
  single use holds without a database lock), issues the credential and
  writes the entry. The credential row goes to Postgres with the next
  flush; until then only that shard knows it, which is where it is used.
- **Reveals.** A reveal of 7 keys is one shard call: 7 decisions, 7 keys
  opened once and kept, one entry per environment, as today.
- **Signing.** The app Worker signs, as today; the private key comes from
  the shard as any value does. Signing CPU stays in stateless Workers.

## Capacity model

Little's law: what is in flight is the arrival rate times the time each
one takes (L = λ × W). It says where each design runs out.

**Today, one cold `/use`** holds the audit head for about 7 round trips.
At 20 ms a round trip that is W ≈ 140 ms of head per use, and only one
use holds it at a time, so λ ≤ 1 / 0.14 s ≈ 7 a second for the whole
instance (measured 5.4). The pool fills first in practice: 17 statements
per use × 20 ms = 340 ms of connection per use, so 20 connections serve
at most 20 / 0.34 s ≈ 59 uses a second even with no lock at all.

**Any design that puts Postgres statements on the hot path** is capped
by the pool: with C origin connections, s statements per request and a
round trip of t, λ ≤ C / (s × t). Measured on this experiment's setup
(C = 20, t ≈ 35–85 ms through a tunnel): one statement per request
topped out near 800 a second, two near 400. At Equisafe's 40 connections
and a few milliseconds a round trip the cap is higher, but it is there,
and every queued request holds a connection while it waits. Hence the
first rule of this design: **no Postgres statement on a warm request.**

**With shards, per hot path:**

| Path | Postgres round trips | Statements | DO calls | Worker CPU | Shard CPU |
|---|---|---|---|---|---|
| warm `/use` | 0 | 0 (its entry is flushed later, in a batch) | 1 | 0.6 ms p50, 1.7 ms p99 (measured) | 0.6 ms p50, 3 ms p99 (measured) |
| cold `/use` (first after a change, per shard) | 1 | 1 | 1 | the same | + one standing read, one key opened |
| signing | 0 | 0 | 1 | + the signature (ECDSA, about 0.1–1 ms) | as `/use` |
| reveal of 7 keys | 0 warm, 1 cold | 0 or 1 | 1 | as `/use` | 7 decisions; 7 keys opened once |
| CI OIDC sign-in | 0 (binding kept), 1 cold | 0 or 1 | 1 | the JWT's signature check | the jti spent in storage |
| a change (revoke, grant…) | today's change transaction | today's + 2 | one per shard (64), in parallel | — | a fence: one storage write |

Today, for comparison: a cold `/use` is 17 statements and 1–2 vault calls;
a reveal the same; a CI sign-in about 10 statements, 7 of them holding
the head.

**At 1,000 and 2,000 requests a second**, warm, 64 shards:

| | 1,000/s | 2,000/s | Limit |
|---|---|---|---|
| Shard calls in flight (W ≈ 35 ms) | 35 | 70 | — |
| Calls per shard, 100 principals spread | ≈ 16/s | ≈ 31/s | ≈ 500/s per shard with a durable write per call (measured: one shard took 516/s of 1,000) |
| One principal at 1,000/s | K = 4: 250/s per shard, 1.5% refused by Cloudflare; K = 8: 125/s per shard | K = 8 | K × ≈ 400/s with headroom |
| Shard CPU, all shards | 0.8 CPU-s/s | 1.6 CPU-s/s | — |
| Worker CPU per request | 0.6 ms p50, 1.7 ms p99 | the same | 10 ms (Free), 30 s (Paid) |
| Postgres flush statements | ≤ 64 a second at a 1 s interval (≤ 320 at 200 ms) | the same: bounded by the interval, not the rate | — |
| Origin connections busy (statements × t) | 64 × 5 ms ≈ 0.3 at Equisafe's latency | the same | 40 per config, 100 on the database |
| Standing reads | one per active principal per shard after each change | the same | — |

So at 1,000 to 2,000 a second Postgres sees about one statement per
shard per second, whatever the load, and Hyperdrive's pool is idle; the
limit moves to Durable Object throughput per shard, which spreading a
hot principal over K shards answers.

**Latency.** A warm use is the Worker's own time (under 1 ms of CPU), one
Durable Object call (2–5 ms within a region, measured) and the durable
write of its entry, which Cloudflare confirms once 3 of 5 replicas have
it: about 25–30 ms, measured as the difference between a shard call that
writes and one that does not. The measured warm p50 is 31–35 ms at the
Worker. That misses the brief's 10 ms target, and only the write is in
the way: open question 5.

## Bursts of cold requests for one key (W187)

Today a failed vault decision caches nothing, each isolate, pod session
and `coffre run` handle starts cold, and client retries (DFNS ×5,
Clerk's SDK) turn one cold key into a burst of vault calls on the same
rows. W187 proposed coalescing cold misses per key inside an isolate.

With shards that is unnecessary: the app keeps no cache at all, and the
shard is one cache shared by every isolate, pod and handle of the
principal. N cold requests for one key on one shard cost one standing
read and one key opened, whatever N is: the shard shares one in-flight
read among the calls that need it (inside one Durable Object that is
allowed, unlike between isolates). A read that fails is remembered for a
second, and the calls in that second get 503 with `Retry-After` at once
instead of hitting Postgres again. Spread over K shards, the burst costs
K reads.

## The audit head's ceiling (W195)

W195 measured today's head as the next limit after the member-row fix:
about 8 reads a second of one service overload it at 20 ms and a 100 ms
key service, because `lock_timeout` does not bound head waits. Shards
have no head on the hot path: each lane has one writer, the shard, which
holds the lane's head in memory and never waits on a Postgres lock. The
per-principal ceiling is K × (one shard's throughput, ≈ 400–500 durable
calls a second); the instance's is N × that. The control lane's head
remains, held by changes only, at human rate.

## Guarantees

Every invariant coffre holds today, and what the design does with it.
"Kept" means the same promise, by the same or a stronger argument;
"kept, differently" means the same promise to a user, with a mechanism
or a detail that changes; "changed" means a promise that is weaker or
stronger, with an example. Nothing below is weakened without saying so.

| Invariant (today) | 0.15 shards | How, and the example where it differs |
|---|---|---|
| **A value never leaves without its durable audit entry** (audit before return, fail closed) | kept, differently | The entry is durable in the shard's own storage before the answer (output gate), and in Postgres up to ~1 s later. Postgres down: warm uses go on, their entries wait in the shards; today they fail. **Decision for Erwin**: let shards keep serving while Postgres is down, bounded (proposed: refuse once a shard's unflushed tail is older than 60 s), or fail closed at once as today. |
| **A use ordered after a revocation is refused** | kept | By construction: fence every shard, commit, answer. Measured: 0 of 1,076 (v5) and 0 of 1,011 (v2) uses after the answer allowed. Modelled (`NothingReleasedAfterRevocation`), including restarts, lost and duplicated fences, two live instances. |
| A decision reads one consistent view | kept | Standing is one statement at one revision; the floor refuses standing older than any fenced change. |
| Every use audited | **changed: stronger** | Today a warm hit in the app's 60–330 s value cache is not logged; only the miss is. With shards, every use is an entry. Volume: 1,000 uses a second is about 26 GB of entries a day; retention or roll-ups become a real question (open question 3). |
| Revocation reaches cached values | **changed: stronger** | Today the app's value cache outlives a revocation by up to its TTL (330 s at Equisafe). With shards there is no value cache outside the shard, and the shard is fenced. |
| **Log order** | **changed: partial** | Today one chain orders every entry. With lanes, every use is ordered exactly against every change (by revision), and uses are ordered within their lane; two uses on two shards are not ordered against each other. Example: `svc-a` reads `STRIPE_KEY` on shard 3 and `svc-b` reads `DFNS_KEY` on shard 41 in the same millisecond: both name revision 812, and nothing says which came first. Any checkpoint after both orders both against everything before it (every 5 s). |
| Tamper evidence: hash + MAC per entry, chained | kept, per lane | Same codec, plus the lane and revision in what the MAC covers. Cutting entries from the middle of a lane breaks the next entry's MAC, as today. |
| Cutting the newest entries | kept, and stronger | Seen by the next checkpoint or the anchor (R39), as today. Also: each shard keeps its own copy, so Postgres losing a lane's tail is seen by that shard's next flush ("rewound"). |
| Vault-signed checkpoints, verification from the last one (R25) | kept, differently | A checkpoint signs `{revision, control head, every lane head}` (64 + 1 heads), every 5 s instead of 5 min (it is cheap now). Verification from the last checkpoint is O(entries since), lanes in parallel. Format v4; v3 checkpoints stay verifiable. |
| Audit watch, anchor, re-anchor, accept loss (R39, R40) | kept, differently | The anchor holds the multi-head checkpoint; the walk and re-anchor run per lane. "Accept loss of entries X–Y" names a lane. |
| Member rows MAC'd over their grants; a row changed around the vault is refused | kept, differently | Checked when a shard reads standing, not at every decision. A row forged in Postgres after a shard read it is not used by that shard (it keeps the genuine one), and is seen at its next read or at the next checkpoint, which checks every row as today. |
| Access rules R1–R43, natures, sensitive never to people (R16, R32), references, forks, `@me` | kept | The same decision functions (`@coffre/core/access`, `decide.ts`), on standing read at a revision. Every input they read must be written by a fenced change; a trigger enforces it (below). |
| Bulk cap, 1,000 keys per principal per 15 min (R28) | kept | Counted by the principal's home shard, its single writer. A shard of a fanned-out principal asks the home shard only for a key not yet released in the window. |
| Single-use OIDC tokens (`jti`) | kept | Spent by the principal's home shard, in its storage. Never by a fanned-out shard (the TLA+ model shows the double spend otherwise). |
| APP_KEY rotation (R41) | kept | The app writes only control-lane entries now (changes); `key.rotate` and `key.reseal` are changes like any other. |
| Vault key rotation | kept, differently | A rotation is a fenced change; each lane's first entry under the new key marks its own `since`. |
| No app transaction open across a vault call | kept, differently | No app transaction exists on the hot path. A change holds the revision's row across its fence calls; those calls never wait on Postgres (a fence is memory and the shard's own storage), so no cycle through Postgres is possible, and the change has a 5 s statement timeout. |
| Isolates keep only settled values | kept | Workers keep nothing. A shard shares in-flight work between its own calls (one standing read for many calls), which Durable Objects allow; measured without a cancelled call. |
| Few queries per action (R42) | kept, much stronger | Warm `/use`: 0 statements (today 1, plus 16 on a miss). Cold: 1. |
| No instance-wide serialization point on the hot path (R44) | kept | Uses never take a Postgres lock; shards are independent. Changes serialize on the revision row (human-rate). |
| Overload refused fast with Retry-After (R44) | kept | Per-shard admission control. |

**The fence trigger.** Every write that narrows a decision input (to
members, grants, policy, places, secret natures and versions, and a
credential's revocation or expiry) must happen in a fenced change. A
trigger enforces it: it refuses the write unless the transaction set
`coffre.fenced` to the revision it is writing, which only the change
function sets, after its fences succeeded. A 0.14 vault still running
during the deploy, or a 0.15 code path that forgot to fence, fails closed
instead of revoking behind the shards' backs. A new credential (a CI
sign-in, a session) needs no fence: its home shard issues it and knows
it, and any other shard that meets a credential it does not know reads
the principal's standing again.

## Migration from 0.14

Equisafe is live, and 0.15 is a clean slate in code: no 0.14 path
survives. The data mostly stays where it is, because the design changes
who reads it and how, not what it is.

| Data | 0.15 | Migration |
|---|---|---|
| Members, grants, roles, policy, places, secrets and versions, credentials, bindings | the same tables | none |
| The revision | new one-row table | created at the current newest control entry |
| The audit log | today's chain is the **control lane**, carried on | none: it continues |
| Use entries | new table of lanes, `(lane, seq)` | created empty |
| Checkpoints | v4, multi-head | the first v4 checkpoint signs the control lane's head and empty lanes |
| The fence trigger | new | installed in the same migration |
| App value cache, `Accesses`, member-row locks | gone | none |

The migration is additive (`coffre migrate`, seconds on Equisafe's data)
except the trigger, which is what makes the cutover safe: from the moment
it is installed, a 0.14 instance can no longer change grants, members or
credentials (it fails with an error), while 0.15 shards start serving.
The deploy order is migrate, then deploy both Workers, as today. The
costs, for the release notes: between the two, every 0.14 write to a
decision input fails (sign-ins that create credentials, revocations,
secret writes) until the last 0.14 instance is gone; and a 0.14 app
instance still serves values from its own cache for up to its TTL after
a 0.15 revocation, as it does today.

Two cutovers were modelled (`formal/ShardsCutover.tla`):

- **A, recommended: the chain continues.** One migration transaction
  creates the revision and installs the trigger; today's chain is the
  control lane from then on, and 0.14 and 0.15 append to it side by side
  under its head. 0.14 readers decide under the head on current rows, so
  they see 0.15's changes; 0.14 writers hit the trigger. Holds; and fails
  if 0.15 can serve before the trigger is in, or if a 0.15 change appends
  without taking the head.
- **B: close and carry** (the coordinator's default). Copy, close the old
  chain with a final signed checkpoint, revoke the old logins' INSERT. As
  first written it had three races (below); it holds only as one
  transaction that takes the old head first and revokes both the app's
  and the vault's logins. It moves data A does not need to move.

Rollback to 0.14 is possible: drop the trigger (a down migration), deploy
0.14. Nothing 0.14 reads was rewritten. Its audit page shows the control
lane only; the lanes' entries stay in their table, invisible to it, and
its verifier skips v4 checkpoints as entries it does not sign.

`coffre backup` / `restore` / `verify backup` (#339): they walk
`audit_log` and `audit_chain_head` and open `secret_versions`. In 0.15
they walk every lane too, check the v4 checkpoints, and open secret
versions as today. A backup taken while shards run lacks at most each
shard's unflushed tail (about a second); after a restore, every shard is
reset to the restored lanes (a new deployment epoch), or its next flush
reports the restored database as rewound.

## Implementation plan

Each step a pull request, in order; each one ends green on its own.

1. **The model.** `formal/Shards.tla` and its migration module, every
   invariant above and each protection's counterexample
   (`scripts/formal-shards.sh`). This draft PR carries the first version.
2. **The lane codec.** `@coffre/core/audit`: entries with lane and
   revision, the v4 checkpoint, a per-lane verifier; `formal/lean`'s chain
   verifier follows (Lean cases).
3. **Schema.** The revision, the lanes table, the fence trigger, the
   change function's SQL. Tests: a write outside a fenced change fails.
4. **The shard.** `@coffre/vault`: the `Shard` Durable Object, standing
   reads, the decision through `decide.ts`, the lane append and flush,
   fence, unfence and the probe, admission control; the in-process shard
   for Node. Tests on workerd: restarts between fence and commit, two
   instances, a rewound database.
5. **Changes.** Every vault decision that changes an input becomes a
   fenced change; the member-row locks, the head-locked read path and
   `Accesses` go.
6. **The app.** `/use`, signing, reveals and `token.exchange` call
   shards; the app's own writes to decision inputs (places, secrets,
   natures, credential revocation, policy) become fenced changes;
   `credential.use` becomes the shard's entry; the value cache goes.
7. **Readers of the log.** The audit page, `verifyLog`, the audit watch,
   the anchor, `coffre backup`/`restore`/`verify backup`.
8. **Deployments.** `coffre init`, the examples and `dev/`: the shard
   binding and its migration in the vault's wrangler config; Node's lease.
9. **Conformance and bench.** Revocation under load, lanes verified,
   overload answered fast; `pnpm bench:hot-path` on workerd, and the
   Cloudflare runbook from this experiment.
10. **0.15.0**, once Erwin has decided the open questions.

`formal/Coffre.tla` changes with step 5: its global head and member-row
locks go, and each "re-checked under the head" protection becomes "the
write is a fenced change and the decision's standing is at or above the
floor". Its scenarios (Deletion, Reading, Members, Revoking, Bulk,
Exchanging…) keep their invariants and are re-expressed over shards.

## Open questions for Erwin

1. **Postgres down.** Shards keep serving warm uses while Postgres is
   down, their entries waiting in their own storage (bounded at 60 s), or
   fail closed at once as today?
2. **Partial log order.** Accept that uses on different shards are not
   ordered against each other (ordered against every change, and by
   checkpoints every 5 s)?
3. **Every use is an entry.** Keep per-use entries (stronger, about 26 GB
   a day at a sustained 1,000/s), or roll repeated uses of one key by one
   credential into one entry per second?
4. **Shard count and placement.** 64 shards, placed near the database
   (`locationHint`), K = 8 for principals named hot in the configuration?
5. **Latency or durability on the warm path.** A durable write per use
   costs about 30 ms (Cloudflare's 3-of-5 replication). Three ways to
   reach the 10 ms target, each a trade:
   - Write each entry to Postgres by group commit instead, with the
     shards and Hyperdrive placed next to the database: about one round
     trip there (2–5 ms), but the hot path then fails when Postgres does.
   - Keep the durable write for the first use of a key by a credential in
     a window, and count repeats in memory, written every second: a crash
     loses up to a second of repeat counts (never a first release).
   - Accept about 30 ms.

## The model

`formal/Shards*.tla` (`scripts/formal-shards.sh`; [Shards.md](../../formal/Shards.md)
describes it) model the fence, the lanes, CI sign-in and the cutover:
nine scenarios, every invariant above, 1.3 million states for the
largest, about 1.5 minutes for the whole suite. Each protection is
removed in turn and TLC must find the race it closes (23 removals, all
found). Written before the prototype was final, the model found five bugs
in this design as first written, each now fixed in the design and the
prototype:

1. **Revisions are reused after a rollback**, so a probe that lowers the
   floor when "the floor did not change" can undo a new change's fence at
   the same revision. Change A fences at 1 and rolls back; a probe finds
   the row free at 0; change B fences at 1 (the floor stays 1, so the
   probe sees no change) and the probe lowers it to 0; a use reads
   revision 0; B commits and answers; the next use is served the revoked
   grant. Fix: a shard counts the fences it receives, and a probe lowers
   the floor only if none arrived while it ran.
2. **An unfence must not lower the floor itself**: a late unfence from a
   rolled-back change can arrive after the next change's fence at the
   same revision, and a change whose COMMIT succeeded but whose answer was
   lost would unfence a committed change. Fix: an unfence only asks the
   shard to probe.
3. **A database restored from an older backup looks like a rollback** to
   the probe. A floor is never more than one past the revision, so a
   probe that finds the revision further below raises an alarm and keeps
   the floor.
4. **A flush must begin with a storage write**: Cloudflare's output gate
   holds outgoing I/O only while a write is pending, so a stale instance
   with nothing pending could still write to Postgres. The compare-and-swap
   keeps the lane intact, but a stale instance could refill a rewound
   lane before the shard raises its alarm.
5. **The close-and-carry cutover has three races**: 0.14's app login can
   append too, not only the vault's; a 0.14 append can land between the
   closing checkpoint and the revoke; and a 0.14 revocation between the
   copy and the revoke is lost. Fix: one transaction that takes the old
   head first, then copies, closes and revokes both logins; or, as
   recommended above, no close at all, and the fence trigger installed in
   the migration that creates the revision.

It also confirmed that a CI sign-in's `jti` must be spent at the
principal's home shard (two shards would each accept it), and that the
home must not move while a token can still be presented.

What the model assumes, to confirm: of two live instances of one Durable
Object, the storage takes only one's writes. Cloudflare's documentation
says a write is confirmed by 3 of 5 replicas and that a failed write
discards the instance's pending output and restarts it, which implies
it, but does not state the two-instance case.

What it does not cover, where a proof would serve better: any number of
shards, uses and revisions (an inductive invariant: floors at most one
past the revision, every acknowledged fence in storage, kept standing at
or above the floor read at a committed revision; TLAPS, or Apalache's
`--inductive` mode with unbounded integers, where reuse races like bug 1
live); liveness under a bounded rate of changes ("k changes a window: a
use is answered within k + 1 tries"); the bulk cap under fan-out, which
the model shows needs the home shard (a per-shard count would allow K ×
the cap).

## Options measured

Each a prototype in `experiments/lanes/`, the same cold `/use` (the app's
two reads where marked, the decision, the entry), open loop.

| Option | What it is | Ceiling, one principal | Ceiling, many | Notes |
|---|---|---|---|---|
| v0, today | 0.14.2's statements and locks | 5.4/s at 20 ms (local), 2.3/s on Cloudflare | the same | the head held ~7 round trips |
| v1, W185 | no member lock; the head waited for in the read | 6.1/s at 20 ms, 2.6/s on Cloudflare | the same | the app's entry still holds the head 5 round trips |
| v1m, W185 with one entry | the app's entry folded into the vault's | ~20/s at 20 ms, ~10/s on Cloudflare | the same | the best one chain does: 1/(2 × RTT) |
| v3, lanes in Postgres | 16 chains, each locked by the call for one round trip | ~23/s at 20 ms, ~9/s on Cloudflare | 191/s at 20 ms | no Durable Object; the lane lock crosses a round trip |
| v4, a Postgres leader | pending rows; whoever takes an advisory lock chains them; the rest poll | ~78/s on Cloudflare | ~78/s | polling costs ~8 statements per use: the pool is the limit |
| v2, Durable Object lanes | a DO per lane holds its head and writes batches to Postgres by compare-and-swap | 200/s, no failure | 962/s of 1,000 without the app's reads; ~400/s with them | one batch per round trip; app reads saturate the pool |
| v2, one DO for everything | the same with one lane | — | 461/s of 500, p99 1.7 s | the instance-wide sequencer the brief warned of |
| **v5, shards** | standing and keys in the shard, entry in its storage, flushed behind | 983/s of 1,000 at K = 4 (1.5% refused); 516/s at K = 1 | 1,990/s of 2,000, 3,806/s of 4,000 | 0 Postgres statements warm |

## Measurements

Setup: a personal Cloudflare account (Workers Paid), the Worker and its
Durable Objects in Warsaw (WAW, where Cloudflare routed the load
generator), Hyperdrive (20 origin connections, caching off) to a
throwaway Postgres 16 on a host in Helsinki reached through a Cloudflare
Tunnel: 35–85 ms a round trip, much slower than a database next to its
Workers, which makes every lock held across a round trip look worse and
leaves shards almost untouched. The load generator is in Helsinki, open
loop (Poisson arrivals at a fixed rate), and reports latency at the
client and at the Worker (`Server-Timing`). Local runs: workerd (`wrangler
dev`) and Node through a relay that delays each packet by half the round
trip, as W185's decisions bench does. Synthetic data only; everything
was deleted afterwards ([Cleanup](#cleanup)).

**Today and W185, local, real code** (`packages/vault/test/bench/open-loop.ts`:
the vault's `unwrap` and the app's `credential.use` transaction, 15 s a
rate):

| | RTT | 5/s | 10/s | 20/s | 40/s |
|---|---|---|---|---|---|
| 0.14.2, one principal | 20 ms | p50 692 ms, p99 2.2 s | 5.3/s done, p99 9 s, 30 errors | 5.4/s | 5.4/s, 445 errors |
| 0.14.2, 50 principals | 20 ms | p99 0.9 s | 5.5/s, p99 10 s | 5.5/s | 5.5/s |
| 0.14.2, one principal | 5 ms | p99 190 ms | p99 401 ms | 15.1/s, p99 3.5 s | 15.5/s, 293 errors |
| W185 WIP, one principal | 20 ms | p99 1.3 s | 6.1/s, p99 11 s | 6.1/s | 6.1/s |
| W185 WIP, one principal | 5 ms | p99 139 ms | p99 210 ms | p99 961 ms | 20.0/s, 206 errors |
| W185 WIP, vault only (no app entry) | 20 ms | — | p99 217 ms | 19.2/s, p99 1.1 s | 19.5/s, 222 errors |
| W185 WIP, vault only | 5 ms | — | p99 68 ms | p99 79 ms | 40.4/s, p99 222 ms |

**On Cloudflare, every option** (20 s a rate; latency at the client,
which adds 20–50 ms of Helsinki-to-Warsaw):

| Option | Rate, principals | Served | p50 | p99 | Statements per use | Failed |
|---|---|---|---|---|---|---|
| v0 today | 2/s, 1 | 1.7/s | 1.1 s | 2.5 s | 16.8 | 0 |
| v0 today | 5/s, 1 | 2.3/s | 9.4 s | 20 s | 17.1 | 7 timeouts |
| v0 today | 10/s, 50 | 1.6/s | 12.9 s | 19.9 s | 18.0 | 139 timeouts |
| v1 W185 | 10/s, 50 | 2.1/s | 11.6 s | 19.9 s | 15.0 | 92 timeouts |
| v1m W185, one entry | 10/s, 1 | 9.0/s | 1.0 s | 2.8 s | 8.0 | 0 |
| v1m W185, one entry | 40/s, 50 | 9.2/s | 14.2 s | 20 s | 8.0 | 448 timeouts |
| v3 lanes in Postgres | 10/s, 1 | 9.2/s | 1.0 s | 4.5 s | 7.0 | 0 |
| v3 lanes in Postgres | 100/s, 50 | 75.9/s | 1.9 s | 8.3 s | 7.0 | 0 |
| v4 Postgres leader | 100/s, 1 | 77.9/s | 1.7 s | 8.7 s | 8.1 | 0 |
| v4 Postgres leader | 500/s, 50 | 72.7/s | 29.7 s | 58.7 s | 7.2 | 3,639 timeouts |
| v2 DO lanes | 200/s, 1 | 201/s | 170 ms | 569 ms | 2.0 | 0 |
| v2 DO lanes | 1,000/s, 100, no app reads | 962/s | 100 ms | 1.5 s | 0 | 10 |
| v2 DO lanes, one DO | 500/s, 50 | 461/s | 199 ms | 1.7 s | 2.0 | 0 |

**Shards (v5), sustained** (Worker-side latency in brackets):

| Run | Served | p50 | p99 | Failed |
|---|---|---|---|---|
| 100/s, 100 principals, 2 min | 98.2/s | 80 ms (56) | 619 ms (338) | 0 |
| 500/s, 100 principals, 2 min | 498.3/s | 57 ms (33) | 617 ms (393) | 0 |
| 1,000/s, 100 principals, 2 min | 995.7/s | 55 ms (31) | 815 ms (519) | 0 |
| **1,000/s, 100 principals, 5 min** | **992.3/s** | 55 ms (31) | 1.2 s (455) | **1** (an edge 502) |
| 2,000/s, 100 principals, 2 min | 1,989.5/s | 65 ms (35) | 4.8 s (528) | 4 (edge 502s) |
| 4,000/s, 100 principals, 30 s | 3,806/s | 876 ms (38) | 7.8 s (707) | 1 |
| 1,000/s, **one principal**, K = 1, 2 min | 515.7/s | 2.2 s | 4.8 s | 57,498 "Durable Object is overloaded" |
| 1,000/s, one principal, K = 4, 2 min | 983.2/s | 58 ms (35) | 2.0 s (694) | 1,504 "overloaded" (1.5%) |
| **1,000/s, one principal, K = 8, 2 min** | **1,002.9/s** | 55 ms (32) | 972 ms (481) | **1** (an edge 502) |

At 2,000 and 4,000 a second the client's p99 is the load generator's own
queue (one Node process); the Worker's p99 stays near 0.5–0.7 s.
Postgres statements on the warm path: 0 in every run. Shard CPU (from
Cloudflare's analytics, the 1,000–2,000/s runs): 0.57 ms p50, 3.0 ms
p99 per call; Worker CPU 0.62 ms p50, 1.7 ms p99. All 449,387 entries of
the last runs (and 751,048 of the earlier ones) reached Postgres and
verified, every lane chained, without a gap.

**Revocation under load** (one principal at 1,000/s over K shards; the
grant revoked mid-run):

| Run | Uses after the answer | Allowed | Revocation took |
|---|---|---|---|
| v2 DO lanes, 100/s | 1,011 | 0 | 216 ms |
| v5, K = 4 | 14,043 | 0 | 920 ms |
| v5, K = 8, with the model's fixes | 13,517 | 0 | 1.4 s |

In the revocation window the prototype answered 482 calls `503
changing`, but slowly (p99 14 s), and 7 failed with a Postgres error:
every waiting call probed on a connection of its own and they queued
for the pool. The fix, for the real thing: a shard refuses `changing` at
once while its newest fence is young (a change is almost certainly in
flight) and runs at most one probe at a time, and only for a fence older
than a few seconds, which is all the probe is for (an aborted change's
fence). Refusing is always safe. A fence also waits behind the calls
queued at a busy shard, which is why a revocation took 1–1.5 s under
1,000/s; that bounds how long a revocation takes, not whether it holds.

## Cleanup

Everything the experiment created in the personal Cloudflare account is
named `coffre-w194-*` and was deleted at the end, each deletion checked
by listing again: the Worker `coffre-w194-lanes` (and its Durable
Objects), the loader Worker and KV namespace that staged its bundle, the
Hyperdrive config, the Cloudflare Tunnel, its DNS record
`coffre-w194-pg.erwinkn.com`, the Access application and its service
token. Locally: the throwaway Postgres container and its networks.
Cost: within the account's included usage (about 2.5 million Worker
requests, 2 million Durable Object calls, 1.3 million rows written).
