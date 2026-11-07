# Limits and config: every cap, timeout and knob, and what to do with each

Status: **proposal, for Erwin's approval (W331, phase 1); partly decided.**
Written against `main` at `0e7061a5`. Phase 2a (copied values, migrator
lock waits) landed in #503 and #508. Erwin's answers of 2026-11-06 are in
[Decisions](#decisions-2026-11-06), with what each one builds and where;
the rest of the document is the proposal as reviewed, marked where a
decision changed it.

**For Erwin's config review (D172), read [config.md](config.md) first:** the
one config object a deployment writes, every value derived from it or fixed,
the questions still open with a recommendation each, and what goes. This
file stays the audit behind it.

Rule R70 (Erwin, 2026-11-04): every cap, queue, timeout or rate limit
traces to a real constraint (platform, database pool or timeouts,
protocol) or to a policy Erwin set, with its source written beside it.
One resource, one value: derived limits are computed, not configured.
Fewer knobs, no guessed defaults, unjustified limits removed. Overload
still refuses fast (R44).

This document has four parts:

1. [The short version](#1-the-short-version): what can throttle real
   load today, and what to do about it.
2. [The `/use` admission cap](#2-the-use-admission-cap), the limit that
   prompted this, in detail.
3. [The proposal](#3-the-proposal), item by item, with before and after.
4. [The inventory](#4-the-inventory): every limit, package by package,
   classed. Then [platform facts](#5-platform-facts-checked-2026-11-04),
   each checked against the vendor's current docs.

## Decisions, 2026-11-06

Erwin answered seven of the proposals (via the coordinator, W331 phase 2b).
Rules R75 and R76 record two of them.

| # | Decision | What it builds | Where |
|---|---|---|---|
| D1 | **Proxy memory: yes.** A proxy body read whole is at most 1 MiB (from 16 MiB, S26); anything larger streams, up to the existing 5 GiB (S28). Workers' 128 MB is split explicitly into shares: uses in flight, proxy bodies in memory, per-isolate caches. `madeFor`'s 1,000 (S12) becomes least-recently-used inside the caches' share. Node's WebSocket `maxPayload` (S52) follows the new body bound | §3.2 #21 and S26 as written, with the body bound lowered; the uses' share is stated but the `/use` count is not changed while Q1 is open | #519 (open) |
| D2 | **KMS and write locks (R75).** "Writes can take longer, but they shouldn't lock concurrent operations. Otherwise bring down the timeout and prefer retries. KMS can likely get a lower limit, but also shouldn't take a lock. The only real hot path are uses." | First an audit: which locks a write and a KMS call hold, and whether a `/use` or another operation can wait on them. Then: no KMS call under any lock; KMS's timeout lowered (1 s × 3 or lower, from a measurement; C1 is 5 s × 3 today); the 15 s write-lock wait (V17) replaced by a short timeout and retries. TLA+ first (R45). Supersedes §3.1 #4's "not yet" | audit under way, then a PR |
| D3 | **Clock skews: on hold.** Erwin asked what clock skew is and why it is needed | nothing; C15, V9, V31, V32, S3's `SKEW_MS` and S65 keep their values | – |
| D4 | **Service tokens (R76).** At most 365 days (from 366, C14); a deployment may set a lower maximum | `MAX_SERVICE_TOKEN_DAYS = 365`; `signin({ serviceTokenMaxDays })`, whole days 1 to 365. The default lifetime stays 90 days (`DEFAULT_SERVICE_TOKEN_DAYS`), or the maximum where that is lower | #516 |
| D5 | **CI sign-in limits (R76).** "We should have one or two settings here and agreed put them much higher." No 60 a minute per binding, no 300 a minute in all | the proposal in [§3.6](#36-ci-sign-in-limits-the-proposal-for-erwins-numbers), for Erwin to confirm its numbers before anything is built; `formal/Credentials.tla` changes first | #520 (Erwin's D177) |
| D7 | **A removal's revoke batch: 50 ms of the fence (Erwin's D178); 10 ms proposed in its place, for Erwin to confirm.** Dropping D5's per-binding count also dropped what bounded a binding's live credentials, which an unbind revokes under the fence every use shares. Measured through the whole app, a 50 ms hold refuses uses, not only delays them: each use past the 10 a process takes in flight is refused `overloaded` | the batch derived, no setting: the fence held no longer than the uses in flight (`DEFAULT_CONNECTIONS`, 10) take to arrive at R44's 1,000 a second, 10 ms, so on Node `UNBIND_BATCH` = 10 ms ÷ 0.08 ms = 125 (625 at 50 ms); on Workers min(that, what a vault call's 10 ms of CPU fits) = 114. Until Q1. 500 ms rejected: every use beside a removal waits out up to one batch's fence | [§3.6](#36-ci-sign-in-limits-the-proposal-for-erwins-numbers), "A binding's removal"; #520, merged only once Erwin confirms 10 ms |
| D6 | **The unsealed-entry check cap (V11, §3.2 #18): yes**, resized from the measured CPU per entry | `ABOVE_NEWEST` from the check's CPU budget ÷ its measured cost per entry, the derivation beside it | Done on `main`: 1,000, its derivation in `packages/vault/src/verifier.ts` ([config.md](config.md), section 2.9) |

Still open: Q1 (the refusal rule, A or B), Q2 (Node pool split), Q3 (where
the vault learns its connection share), Q5 (statement timeouts from the
remaining deadline), Q6 (retention in the standard setup), Q7 (the proxy's
upstream timeout), and clock skews (D3). Q4 is D5.

## How each limit is classed

| Class | Meaning | Default verdict |
|---|---|---|
| **a** | A real external limit: Cloudflare, Hyperdrive, Postgres, AWS, a protocol or RFC | keep, cite the source beside it |
| **b** | A policy Erwin set (a rule, a decision) or a security choice a design doc states | keep, cite the rule |
| **c** | Derived from another value | compute it from that value, don't restate the number |
| **d** | A defensive bound against abuse or garbage input (sizes, list lengths) | keep if generous and written down |
| **e** | Unjustified: a guess, a copied default, or history | remove, or replace with a/b/c |

Terms used below:

- **use**: one `/use` call, a workload asking the vault for a key's value.
- **hot config**: the Hyperdrive config (Workers) or pool (Node) of
  `coffre_vault_hot`, the login only uses take, with 1 s `lock_timeout`
  and 2 s `statement_timeout`.
- **fence**: the lock row uses take shared and changes take exclusive.
- **seal**, **checkpoint**: the checkpointer signs the log's newest entries
  every 500 ms tick; an entry above the newest signed pair is unsealed.
- **cover**: an isolate's note that it already logged a (credential, key)
  use, so a repeat writes no row (R53).
- **W208**, **T112**, **decision 13**: W208 is the Cloudflare hot-path
  benchmark in [`hot-path-one.md`](hot-path-one.md), section "Cloudflare"
  (line 1187); decision 13 (line 1333) leaves the `/use` cap's number to
  T112, a measurement that never ran.

"Bites" means it could refuse or slow legitimate load at R44's target:
1,000+ `/use` a second on Workers, hundreds at once, some of them from one
principal.

Counts in the [inventory](#4-the-inventory): 238 rows, each one item or
a small group of like items (about 420 values in all). A row with two
classes (31 rows, e.g. "a on Workers, e on Node") is counted under its
first.

| Class | Rows | Rows that can bite R44 load (⚠) |
|---|---|---|
| a, real external | 24 | 3: AWS's STS quota under AWS sign-in (S78), and two for their **e** half: the workload gate on Node (S1), setup's 20 connections on Paid (C2) |
| b, policy | 55 | 4: the sign-in count per binding, in the app and the vault (S8, V30), and its row lock (Q16), all CI sign-in; the 3 s use deadline (C12), which turns any queue into `late`: right, but it makes every other limit here bite sooner |
| c, derived | 37 | 0 |
| d, defensive | 40 | 1: `ABOVE_NEWEST` (V11), sized from a rate: `capped` past 2,000 unsealed entries, e.g. at 4,000 new entries a second |
| e, unjustified | 78 | 11 |
| none (a missing bound, or a knob no deployment can reach) | 4 | 0 |

Format constants (IV and tag sizes, hash and MAC widths, key sizes, UUID
and digit patterns, tile shapes) are listed once per package as "format,
fine" and not counted.

## 1. The short version

### What can throttle real load today

Ranked by how likely each is to refuse or slow legitimate traffic, which is
what happened on Equisafe's instance. Each is class **e** unless marked.

1. **The vault's per-isolate `/use` cap: 10 calls in flight, on Workers
   and on Node** (`packages/vault/src/vault.ts:377`, `use.ts:105`). On
   Workers, 10 is node-postgres's default pool size, applied where there is
   no pool: each call opens one connection of its own. The count covers a
   use's database phase only. Its place is given back when the statement
   answers (`use.ts:1293-1299`), before the key is opened at KMS
   (`use.ts:638-643, 1559`), and a use of several keys opens them all at
   once after that (`use.ts:497-501`). The lead's brief attributes the
   ~470 startup 503s at 1,000 `/use`/s in a cold-start benchmark to this
   cap. I have not seen that run's refusal breakdown, so section 2's
   example shows how a warming isolate *can* fill it, not that it did. On
   Node it is also 10, but by accident: the code meant to read the hot
   pool's size reads a property that is never set (`vault/src/node.ts:101`,
   item V2), so the cap stays 10 even when a deployment passes a database
   with a bigger pool.
2. **`coffre setup` caps each Hyperdrive config at 20 connections, on
   Paid too** (`packages/cli/src/connections.ts:10`, "the most Free
   allows"). Paid allows 100 and defaults to 60. W208 measured that the
   hot config's pool *is* the `/use` ceiling: about 1,040/s at pool 40 on
   its rig, which is Little's law, 40 connections ÷ ~38 ms a use
   (`docs/design/hot-path-one.md:1197-1214`). By the same law 20 would
   serve about half that: an estimate, not a run. Setup also lowers any
   config above the database's share, and that part is right: it keeps
   three configs inside `max_connections`. The 20 lowers it further, with
   no database reason, on Paid.
3. **Workload gate: 1,000 requests a second per service**
   (`packages/server/src/gate.ts:27`, `GATE_CEILING`). Every
   workload-session request (the `coffre serve` sidecar, the SDK) passes
   its service's gate. On Workers this is real (class a): one Durable
   Object per service, and Cloudflare's soft limit is 1,000 requests a
   second per object. That is exactly R44's floor for one principal. On
   Node there is no Durable Object, and the same 1,000 is artificial as a
   rate. It is also the only bound on the gate's replay memory: every
   fresh `jti` stays in a set for two epochs (240 s), ~20 MB at 1,000/s,
   ~200 MB at 10,000/s (`gate.ts:21-27, 112-116, 188-192`), so a
   replacement must bound that memory itself.
   Sharding the gate by session (#30) lifts it for a service, not for
   one session.
4. **CI sign-in: four counts and a row lock.** Each 429 from a count says
   `Retry-After: 60`.
   - 300 a minute for everyone (`WORKLOADS_TOTAL` in the examples'
     `wrangler.jsonc`, `processLimits` on Node). On Workers Cloudflare
     counts it per location, approximately, letting bursts through
     (`wrangler.jsonc:52-56`); on Node, per process
     (`workloads/limits.ts:3-10`; `docs/design/oidc.md:147-154`). So it
     is a burst allowance per minute per location or process, not a
     steady 5 a second for the instance.
   - 30 a minute per source address, counted the same way.
   - 60 a minute per binding, counted in the database, so for the whole
     instance (`EXCHANGES_PER_BINDING_MINUTE`, and in the vault
     `SIGN_INS_PER_WINDOW`). `docs/design/oidc.md:174-175` states it as
     the design's policy and `formal/Credentials.tla` holds it
     (`RateCap`), so it is a documented policy (class b). Whether Erwin
     wants that number is Q4.
   - 32 exchanges in flight per isolate or process
     (`exchangeLimit.inFlight`). It is the only bound on how many wait,
     because an exchange has no deadline of its own (item S6).

   Under all four, the vault's `sign_in` takes its binding's row
   `FOR UPDATE` and holds it until it commits, through the credential's
   insert and the binding's update (`0037_vault_bindings.sql:39-43,
   82-91`). So one binding's sign-ins run one at a time whatever the
   counts say, and each one waiting holds a database connection for up to
   the function's 1 s `lock_timeout`. The same lock also keeps an unbind
   from crossing a sign-in (`docs/formal.md:1941`, `BindingLocked`). R44
   names CI sign-in a hot path at 1,000+/s. Example: 200 matrix jobs on
   one binding need over 3 minutes to all sign in at 60 a minute, and with
   that count gone they would still pass the row lock one by one.
   An AWS sign-in also meets AWS's own limit, which no change in coffre
   lifts: each proof is one `GetCallerIdentity` (`workloads/aws.ts:284-294`,
   not cached), counted against the signing account's STS quota at the
   endpoint the proof names: 600 requests a second per Region at a
   regional host, shared with its `AssumeRole` and the like, and a quota
   of its own at the global host, which coffre's server reaches in
   us-east-1 (S78). Both are adjustable, by a ticket to AWS support. So
   1,000 AWS sign-ins a second from one account needs the quota of the
   endpoint they sign for raised first.
5. **AWS KMS: 8 calls at once per `awsKms` provider object, one per
   isolate in practice** (`packages/core/src/kek/aws-kms.ts:36`). Every
   AWS-backed key a use opens makes one Decrypt: no data key is kept
   between uses. The comment says "a Worker opens at most six connections
   anyway", but that limit is per request, not per isolate, and since
   2026-04 it queues rather than fails. KMS's own quota is 10,000 to
   100,000 a second per account and region. The slot queue also hands a
   slot from one request to the next by resolving the waiter's promise
   (`aws-kms.ts:250-290`), the pattern AGENTS.md ("What an isolate
   keeps") forbids: if the request holding a slot is cancelled before its
   `finally` runs, the slot is gone for good. The `/use` count is released
   before the key is opened (item 1), so these slots are the only bound on
   KMS calls in an isolate today. Workers' six connections would not
   replace them: they count only fetches still waiting for response
   headers, and a KMS call then reads its body (`aws-kms.ts:183-187`).
   Node has no such limit at all.
6. **The migrator's `lock_timeout` is 5 minutes for the whole session**
   (`packages/db/src/migrate.ts:412`). It was meant for the advisory-lock
   wait, but every DDL statement after it waits up to 5 minutes for its
   table lock. While it waits in line for `ACCESS EXCLUSIVE`, every later
   query on that table waits behind it, so `/use` fails `late` for the
   length of the deploy.
7. **The credential proxy's values cache: 1,000 entries per isolate**
   (`packages/server/src/plugins/credential-proxy.ts:3164`, "a handful of
   handles in a dev loop"). Past it, every insert scans the whole map. Two
   requests for one cold entry each make their own vault use: there is no
   sharing between them.
8. **`asked-once`'s 3 s take-over and 6 s wait**
   (`packages/server/src/asked-once.ts:32, 37`): "longer than a deploy's
   write and its seal take", never measured. The call it waits on, the
   vault's `about()` at an isolate's start, has no deadline of its own
   (`vault/src/vault.ts:3683`, `#settled()`). A cold `about()` slower than
   3 s is asked again by one waiting request, once every 3 s, not by the
   whole herd. A request that joined an attempt answers 503 `starting` if
   none settles within 6 s of its joining. The isolate's first request is
   under no such deadline: it awaits its own call directly
   (`asked-once.ts:52`), so a stalled `about()` holds it as long as the
   call takes, while the others give up.
9. **The verifier reads at most 2,000 entries above the newest signed
   pair** (`ABOVE_NEWEST`, `packages/vault/src/verifier.ts:62`). It is a
   defensive bound: past it, a checkpointer that fell behind or rows a
   writer planted are reported (`capped`), never read, and its comment
   measures the 2,000 at 14 ms. But the number comes from a rate, "four
   ticks' worth at R44's 1,000 uses a second", and it counts unsealed
   entries, not requests: a covered repeat writes none, a batch can write
   several (`use.ts:475, 676-691`). More than 2,000 unsealed (2,001 and
   up) reports `capped` (`core/src/audit/verify.ts:350-356`). For
   illustration, at one new entry a request and 500 ms left unsealed, a
   checkpointer on time reports `capped` at 4,000 new entries a second.
   That shows in the audit API and the UI, and fails
   `coffre verify` (`server/src/api/audit.ts:1293`,
   `ui/src/lib/queries.ts:431`, `cli/src/verify/instance.ts:303`), not
   on the hot path.
10. **The SDK and sidecar wait out a `Retry-After` of up to 300 s × 1.5**
    before they prove again (`packages/client/src/workload.ts:704`). A
    session they hold keeps serving meanwhile, and a failed renewal keeps
    the session until it expires (`workload.ts:278-334`). So the wait
    bites only when no session is left: a session that expired while its
    renewals failed. Then every request through that sidecar fails until
    the wait ends: 60 to 90 s after item 4's `Retry-After: 60`. A pod's
    first sign-in is different: `workload()` makes its first exchange
    before any retry loop exists (`workload.ts:213`), so a 429 there
    rejects at once, and `coffre serve` exits before it opens its listener
    (`cli/src/serve.ts:50`). The pod's restart policy decides when it
    tries again.

None of the 10 is set by any deployment. Every example, `dev/deployment`
and `coffre init` run on the defaults.

### What the proposal does, in one paragraph

On Workers, replace the count of 10 with two bounds that each come from a
real resource. First, how many uses an isolate holds at once, computed
from Workers' 128 MB and the measured memory one waiting use holds.
Second, refusing fast on overload, from the outcomes of the isolate's own
recent uses, which reflect the shared Hyperdrive pool and Postgres.
Section 2 specifies two candidates for the second. Neither is proven: each
needs one measured run before it replaces anything. On Node, the one real
value is the hot pool's size, from the database's `max_connections`, as
`coffre setup` already computes it for Hyperdrive. Then:

- remove the `uses` block from the vault's config, all five fields;
- let setup give Paid configs the database's share, up to Paid's 100,
  instead of stopping at 20;
- shard the workload gate so no one service meets the Durable Object's
  1,000/s (TLA+ first);
- replace the KMS slot queue with one that hands nothing between requests
  (its model disposition first);
- make the migrator's lock waits shorter than a use may wait;
- compute every copied value (deadline, statement timeout, clock-ahead
  minute, refresh) from one source;
- say for each `Retry-After` which of three it is: a known window's
  reset, a measured recovery time, or a retry policy chosen and written
  down.

CI sign-in needs a design of its own before any of its limits goes: a
deadline for the whole exchange, and the binding's row lock, which makes
one binding's sign-ins take turns and also protects revocation (section
3.3, TLA+ first).

Section 3 has every item. Section 6 has the questions only Erwin can
answer.

## 2. The `/use` admission cap

### What it is

```ts
// packages/vault/src/vault.ts:377
/** A pool's connections, unless its transport says (pg's default). */
const DEFAULT_CONNECTIONS = 10;

// packages/vault/src/use.ts:104
export function useLimits(connections: number, set: Partial<UseLimits> = {}): UseLimits {
  return { inFlight: set.inFlight ?? Math.max(1, connections), ... };
}
```

Each isolate (Workers) or process (Node) counts its `/use` calls in flight
(`UseCache`, `use.ts:154`). At 10, the next one is answered at once with
503 `busy` `overloaded`, `Retry-After: 1` (`use.ts:454`, mapped in
`packages/server/src/api/keys.ts:376`), before it takes a connection. The
same check guards `use`, `useMany`, `useNamed`, `useNamedMany`, `useRoute`
and `proxyItem` (`use.ts:534, 634, 849, 933, 1874, 2097`).

Introduced in 7c83fd02 (#378, 0.15 PR 5a). Its comment says "T112
measures the number for Workers". T112 never produced a number;
`hot-path-one.md` decision 13 calls it "measured in T112, not here", and
the 0.15 plan lists it as still open (`0.15-plan.md:5082`).

### What each runtime actually has

**On Workers there is no pool per isolate.** Each vault call opens its
own Hyperdrive client with one connection and closes it when the call
ends (`packages/vault/src/cloudflare.ts:115-135`,
`packages/db/src/hyperdrive.ts:228`, `max: 1`). The resources the uses
share are shared by every isolate at once:

| Resource | Limit | Shared by | Source |
|---|---|---|---|
| Hyperdrive origin connections, hot config | `origin_connection_limit`: 5 to 20 on Free, 5 to 100 on Paid, default 60 on Paid. `coffre setup` sets ≤ 20. A **soft** limit: Hyperdrive may open more during network failures, and Cloudflare advises setting it below the database's own limit for that reason | every isolate, worldwide | Hyperdrive limits page; API reference; "Tune connection pool" |
| Postgres CPU and `max_connections` | the database's | every config | the database |
| Connections per request | 6 waiting for headers at once, the 7th queued | one request (the app's, with its service-binding calls) | Workers limits page |
| Isolate memory | 128 MB | one isolate | Workers limits page |
| Requests per isolate | **no documented number** | – | Workers limits; "How Workers works" |

A count per isolate can't express a limit shared by an unknown number of
isolates. W208 measured that: Cloudflare spread 2,500/s over at least ~150
isolates, and "a cap of 8 each still admitted ~1,000 calls at once"
(`hot-path-one.md:1214`).

**On Node, the pool is real, and the driver pipelines.** The hot path's
postgres.js pool has `max` connections (`packages/db/src/connect.ts:26`,
`max ?? 10`, again copied from node-postgres). A query asked while every
connection is busy is sent on a busy one, behind what that connection
already runs, up to 100 queries each (`max_pipeline`,
`packages/db/src/postgres-js/index.ts:548-561, 661`). 100 is a ceiling,
not what a busy pool reaches: a connection takes no more pipelined work
while it is still opening (a cold pool's first queries), while it waits
for a statement's parameter description, while its socket is under
backpressure, or behind a statement carrying a transaction's BEGIN until
Postgres has answered it (`postgres-js/connection.ts:184, 225, 250-258`). Then a query waits in the
driver's queue well before 10 × 100 are outstanding, and that queue has no
size limit and no timeout. So the queue has three parts: queries sent and running,
queries sent behind them on the same connection, and queries not sent.
Postgres runs one connection's queries one after another, so pipelining
saves the round trips between them, not their execution: a pool serves
about `max ÷ execution time` one-statement uses a second, not
`max ÷ round trip`. Two caveats: a transaction keeps its connection to
itself from BEGIN to COMMIT, and a pipelined statement waiting for a lock
(up to the hot login's 1 s) holds up every statement behind it on that
connection. Two problems:

- **The derivation is dead code** (`packages/vault/src/node.ts:101`). It
  reads `hot.$client.options.max`, but Drizzle sets `$client` only in its
  own `drizzle()` factory, and `createDatabase` builds the database
  directly (`packages/db/src/database.ts:124`). So `connections` is
  always undefined, and the cap is always 10. Set the hot pool to 30 and
  the 11th concurrent use is still refused.
- **The URL-based setup exposes no pool size.** `serveVault` and
  `localVault` also accept a `Database` already open
  (`packages/vault/src/node.ts:43-55, 83-85`), so a deployment can pass
  `openDatabase(url, { max: 30 })`; V2 still leaves the cap at 10.
  `createCoffre` takes a URL and passes no `max`.

### Why the count refuses legitimate load

The count bounds the wrong thing on both runtimes.

**Workers, cold start.** An illustration, with plausible numbers rather
than measured ones. An isolate that just started has an empty seal
cache, so its first uses each make the full statement with its probes,
while Hyperdrive opens connections. At 1,000/s, an isolate that
Cloudflare routes 200 requests to in its first second, each taking 80 ms
cold instead of 30 ms warm, has about 16 in flight (200 × 0.08). Six of
those 16 are answered 503 although the database is idle. That is how a
warming isolate can fill the cap; that it explains the ~470 startup 503s
is the brief's diagnosis, not something this document shows.

**Workers, warm, one principal.** A sidecar sending 300/s through one
colo may land on 2 or 3 isolates. At 30 ms each, that is 3 to 4.5 in
flight per isolate: fine. A brief network blip to the database that
doubles latency to 60 ms takes it to 6 to 9, and a 100 ms blip takes it
past 10. The count turns a latency blip into errors, although the
database has room.

**Node.** The pool is 10 and the count is 10. A use keeps its place in
the count for its whole round trip, so with the database 25 ms away the
count admits at most 400 a second (10 ÷ 0.025): the count's ceiling, not
the pool's, since the driver would pipeline more on the same 10
connections. A burst of 30 concurrent uses gets 20 refusals at once,
although the driver would have sent all 30 at once, three to a
connection.

### What does bound overload, measured

W208's "no cap" run (`hot-path-one.md:1197`): 2,500/s offered against a
ceiling of about 1,040/s.

| Run | Served | Worker p50 / p99 | Failed |
|---|---|---|---|
| `one`, no cap | 1,085/s | 461 / 551 ms | 13,592 `late` (did nothing) |
| `one`, cap 8 per isolate, deadline 1.5 s | 1,133/s | 973 ms / 1.2 s | 68,901 `overloaded`, 10,976 `deadline` |

With no cap, goodput stays at the ceiling. A call that Hyperdrive held
past its deadline is cut (`HyperdrivePool.end(by)`, T170), and Postgres
refuses it by `clock_timestamp()` if it still arrives, so the database
does no wasted work. What it doesn't do is refuse *fast*: the excess hears
`late` after up to 3 s rather than at once.

### What should replace it

Two needs, each with its own resource. Neither is a count of
connections, since on Workers there is no pool to count.

**1. How many uses an isolate holds at once: its memory.** A use in
flight holds a socket, the driver's state and buffers, its request and
its timers (`packages/vault/src/cloudflare.ts:128-135`,
`packages/db/src/hyperdrive.ts:224-232`, `packages/vault/src/use.ts:1293-1305`).
The 3 s deadline bounds how *long* each one lives, not how many live at
once: a burst reaches the isolate before any latency is known. The real
limit is the isolate's 128 MB. So the bound is a count, but a computed
one: `the share of 128 MB given to uses in flight ÷ the bytes one holds,
measured`. For example, at 200 KB a use and half the isolate, about 320,
against today's 10. The bytes are measured once, locally, with
`pnpm bench:workers` holding N uses open against a stalled database; the
share is a policy Erwin sets. Past it, 503 `overloaded` at once, as now.

**2. Refusing fast on overload: the outcomes of recent uses.** When the
shared resources (Hyperdrive's pool, Postgres) are saturated, every
isolate sees it in its own uses' outcomes, at the same time. A rule
reading them must never close for good: it must keep admitting some uses
while it refuses, or it never sees the database recover. Two candidates,
both unproven here:

| | A. Predicted lateness | B. Adaptive throttling |
|---|---|---|
| Reads | the time from admission to the statement's answer, of the uses settled in the last second, a `late` one counted as the whole deadline | over the last minute or two, how many uses were asked and how many were *answered in time* (`ok` or refused by access rules, not `late` or `busy`) |
| Refuses | when the 90th percentile of those times, plus what the use does after its statement (the key's opening, measured), passes the deadline. Example: a predicted 2.83 s wait, plus a key's opening at KMS (a Decrypt), leaves none of the 3 s | each new use with probability `max(0, (asked − K × in time) ÷ (asked + 1))` |
| Old samples | dropped after the second; with none, admit | age out of the window |
| Recovery | while refusing, admit one use in every N, so samples keep coming | built in: the probability stays below 1, so some uses always go through, and their success brings it down |
| Numbers | the window, the percentile, N, each unsourced until measured | K: 2 is the published value (Google SRE book, "Handling Overload", client-side throttling) |
| Risks | oscillation: admission opens, the pool refills, every isolate shuts at once | lags: it reacts over the window, not at once |

Both need one run on Erwin's Cloudflare (R34, under $5) to show that goodput
holds at the ceiling as W208's no-cap run did, and how fast admission
reopens after the load drops. **I have not spent it**; see Q1. Until then,
neither replaces the count; the memory bound (1.) can come first on its
own, since it only raises today's 10 to a computed number.

The baseline to beat: with no fast refusal at all, the excess is answered
`late` within 3 s, the database does no wasted work (W208's no-cap run,
above), and R44's "refused fast" is not met. A shared counter in a
Durable Object was rejected in decision 13: at 1,000+/s the object itself
meets its 1,000/s soft limit, and every use pays one more hop.

**On Node**, the same two bounds apply: the process's memory for how many
uses wait, and the same refusal rule. The pool's size is the one real
input to how fast uses go, and it comes from the database. But a Node
pool belongs to one process, where a Hyperdrive config's limit holds for
every isolate at once. Give each of two replicas the share setup computes
for Hyperdrive (`hyperdriveLimit`) and together they open twice the
database's budget: at `max_connections` 100, 3 reserved and 3 held back,
each share is 31, and two replicas' three pools could open 186, before
each checkpointer's own 2 (`vault/src/node.ts:107`). So the budget is
split across every process and every pool, the checkpointers' included,
or the processes share one pooler in front of Postgres (PgBouncer, the
part Hyperdrive plays on Workers) and size their pools to it (Q2). A query not sent by its deadline is dropped
unsent, as postgres.js 4's `queue_timeout` does, so nothing abandoned
piles up in the driver's queue: the concern that made the count hold its
place until the call settled (review r1 of #438). A query already
pipelined behind another can't be taken back; the refusal rule, not the
queue, keeps that part short.

### What happens to `READ_HEAD_WAITERS`

`READ_HEAD_WAITERS = 16` (`packages/vault/src/vault.ts:421`) is a
different resource, and stays separate. "One resource, one value" means
not merging it with the above.

- **What it bounds:** transactions waiting for the audit log's head row on
  the vault's own Hyperdrive config, not the hot one. It counts across the
  whole deployment, because its places are Postgres advisory locks
  (`packages/db/src/log.ts:255`), not a count per isolate.
- **Who takes the head:** secret writes (`wrap`), rewraps, and reads that
  come in with no credential to use. A 0.15 `/use`, reveal or sign never
  does.
- **Why a bound at all:** each waiter holds a database connection while it
  waits, which R44 forbids beyond a bound. So the honest derivation is:
  - waiters ≤ the read's lock wait (3 s, `READ_LOCK_TIMEOUT_MS`, of
    which the comment budgets 2.4 s) ÷ the time one holder keeps the
    head (150 ms, measured through Hyperdrive), which gives 16;
  - **and** waiters < the vault config's connections, or the waiters
    take every connection and everything else on that config stalls.
- **Where it bites:** that second condition fails on a small database
  today. At `max_connections` 25, setup gives each config 6
  (`docs/deploy.md:365`), and 16 waiters can hold all 6.

**Proposal:** keep it, computed (class c): `min(lock wait budget ÷
measured hold, the vault config's share − 2)`, with the derivation
beside it. The vault doesn't see its Hyperdrive config's limit at run
time, so setup writes the share where the vault reads it (question Q3).
This changes how many wait, not what anyone locks or in what order, so
R45 asks for no new model. `formal/WriteLocks` models Postgres's queue,
not this count (`docs/formal.md`).

## 3. The proposal

Each item: what changes, before and after, and why. IDs match the
inventory's rows (V = vault, S = server, D = db, C = core/client/CLI,
Q = SQL). Items that change what a flow locks or waits on are marked
**TLA+ first** (R45).

### 3.1 Delete

| # | Item | Before | After | Why |
|---|---|---|---|---|
| 1 | `uses.connections`, `DEFAULT_CONNECTIONS` (V1) | `vault({ uses: { connections: 10 } })` is accepted; the default is 10 | gone | a pool that doesn't exist on Workers; dead code on Node |
| 2 | `uses.inFlight`, the per-isolate count (V1) | the 11th concurrent use in an isolate gets 503 | first, a count computed from the isolate's memory (section 2, need 1); then a refusal rule from recent outcomes, once a run shows it holds (need 2, Q1) | 10 is a pool size where there is no pool; W208: a count per isolate doesn't bound the shared pool across ~150 isolates |
| 3 | The `$client.options.max` probe (V2) | always undefined | gone; the pool size is passed in | dead code |
| 4 | KMS `Slots(8)` (C1) | 8 KMS calls per provider object; the 9th waits until another request's call resolves its promise | **Decided (D2, R75):** no KMS call under a lock, a lower timeout, from the audit. As proposed before the decision: **not yet.** One bound sized from what a KMS call holds (its memory; the account's KMS quota, which every isolate shares), with no slot handed from one request to another through a promise. E.g. the `/use` count of #2 keeps a use's place until its keys are opened, so one count bounds the hot path's KMS calls; KMS's other callers (writes, sign-in) need theirs. `ThrottlingException` retried as now. **TLA+ first** (R45): it changes what a request waits on. No model holds KMS calls today (`formal/` has none): a gap to fill, not an exemption | 8 cites nothing real: Workers' six connections count fetches waiting for headers, not whole calls, and Node has none; the queue's promise handoff breaks the isolate rule |
| 5 | `GATE_CEILING` on Node (S1) | a Node process refuses a service's 1,001st request in a second | **not yet.** First a bound computed from memory: the `jti`s a gate may hold, from the process's budget (e.g. 50 MB ÷ ~85 B a `jti` ≈ 600,000, ~2,500/s over two epochs). Past it, the gate refuses new proofs (503, `Retry-After` from when the oldest epoch ends) and keeps every replay record it has, never evicts one. Then drop the rate ceiling on Node | the ceiling exists for the Durable Object as a rate; on Node it is a disguised memory bound: the epoch bounds how long a `jti` is kept, not how many (`gate.ts:112-116`) |
| 6 | `exchangeLimit.inFlight = 32` (S6) | 33rd concurrent CI sign-in in an isolate gets 429 `Retry-After: 60` | **not yet.** Kept until an exchange has a deadline of its own (#35); then computed from memory, as #2 | 32 is a guess, but it is the only bound on waiting exchanges today: `signIn` has no deadline for the whole exchange (`api/workloads.ts:1242-1251`), and its reads, `vault.signIn` and sealing each run on their own (`:1382-1438`) |
| 7 | `processLimits` `total: 300` and `WORKLOADS_TOTAL` (S7) | the 301st exchange in a minute, per Cloudflare location (approximate) or per Node process, gets 429 | gone (D5, R76; §3.6) | R44 sets the sign-in rate at 1,000+/s; 300 a minute is "size them to that" (oidc.md), never sized |
| 8 | The sign-in count per binding, 60/min, in app and vault (S8, V30) | 61st sign-in a minute of one binding, instance-wide, gets 429 | **gone (D5, R76; §3.6).** As asked before the decision, Erwin's call (Q4): keep at a number he sets, set it per binding in its policy, or drop it. Dropping it changes `formal/Credentials.tla` (`RateCap`, `RateHeld`), and it alone does not let one binding's sign-ins run together: the row lock does that (#36) | a documented policy (oidc.md:174-175), modelled, but its 60 is "as 0.14 counts them" |
| 9 | `uses.coverMs`, `uses.names`, `uses.batch` as deployment options (V3-V5) | accepted by `vault(…)` | internal constants (tests pass `VaultOptions`) | no deployment, doc or example sets them |
| 10 | `processLimits({ perSource: 30, total: 300 })` restated in `examples/node` | the defaults, retyped | `processLimits()` | one source |

### 3.2 Derive

| # | Item | Before | After |
|---|---|---|---|
| 11 | Node hot pool size (D1) | `max ?? 10` in `connect.ts`; a URL-based setup can't change it | from the database's budget, split across every process and pool (section 2), one value written once (Q2) |
| 12 | `coffre setup`'s Hyperdrive share (C2) | `min(share, 20)`; a config above it is lowered, one below kept (`cappedLimit`, `cli/src/connections.ts:39-46`) | `min(share, the plan's max)`: 20 on Free, 100 on Paid. Ask for the share; if Cloudflare refuses past Free's 20, use 20. Keep lowering a config above the share: that is the database's budget, and the comment names the failure it prevents (53300, `:24-31`). The 3 connections held back (`HELD_BACK`, `:6-7`) are for the administrator, `coffre migrate` and the host's tools, and say so; they are not headroom for Hyperdrive running past its soft limit, since those clients may hold them when it does. How much headroom that needs is unproven: neither the code nor Cloudflare's guidance sizes it (Q2) |
| 13 | `READ_HEAD_WAITERS` (V6) | 16, from one rig's 150 ms | `min(budget ÷ measured hold, vault share − 2)`, the derivation written beside it |
| 14 | `HELD_PAST_DEADLINE_MS = 2_000` (V7) | "the hot login's `statement_timeout`", retyped | imported from the one constant that migration 0022, `HOT_SETTINGS` and conformance also read |
| 15 | The use deadline, 3,000 (V8) | `USE_DEADLINE_MS` (core), `deadline_max()` (SQL 0022:121), `USE_DEADLINE_SECONDS` (`api/proxy.ts:89`), literals in `log-store.ts:485, 487, 629` and inside `AT_SLACK_MS` | `USE_DEADLINE_MS` once; a test holds `deadline_max()` to it |
| 16 | The clock-ahead minute, 60,000 (V9) | `USE_AHEAD_MS`, `use.sqlite.ts:589`, SQL `+ 60000` in 0022 and 0024, inside `AT_SLACK_MS` | `USE_AHEAD_MS` once, `AT_SLACK_MS = USE_DEADLINE_MS + USE_AHEAD_MS`, a test for the SQL |
| 17 | The bulk refresh, `min(60 s, window ÷ 10)` (V10) | `bulk.ts:41`, `log-store.ts:629`, SQL in 0022 and 0024 | `refreshMs` once, a test for the SQL copies |
| 18 | `ABOVE_NEWEST = 2_000` (V11) | "four ticks at 1,000/s", 14 ms measured | **Approved (D6).** A defensive bound on the verifier's work (class d): size it from that work's budget, CPU and memory per check, measured, not from a rate. `WINDOW_MAX` is not a derivation: it bounds what one tick seals, not how many entries wait unsealed. Until resized, document that more than 2,000 unsealed entries reports `capped`, e.g. 4,000 new entries a second with 500 ms unsealed |
| 19 | `TAKE_OVER_MS = 3_000` (S9) | "longer than a deploy's write and its seal", never measured | `about()` has no deadline (`vault.ts:3683`, `#settled()`): measure its cold time on Workers, or give it a deadline of its own, then set the take-over above that and `WAIT_MS` twice it, as now |
| 20 | `UNAVAILABLE_RETRY_AFTER = '5'` (S10) | justified by the 15 s write lock, used for every 503 including reads | each `Retry-After` from what refused (example below) |
| 21 | Per-isolate caches (S11, V12, S12, S13); **approved (D1)** | values cache 1,000; `handles` 1,000; `UI_KEPT` 10,000 (clears all); `UseCache.max` 10,000 (clears all); `Accesses.KEPT` 1,000 | one memory budget for per-isolate caches, out of Workers' 128 MB, each cache's count computed from its entry's size; least recently used first, never clear-all. Optionally, a cold entry asked once for all its requests, in `asked-once`'s Workers-safe way: settled state the isolate keeps, each request polling on its own timers and taking over a call not settled in time (`asked-once.ts:26-95`), never a pending promise shared between requests. **TLA+ first** for that part: it adds a wait between requests (R45), and `asked-once` itself has no model |
| 22 | Ticket lifetimes (V13) | `TICKET_MS` and `REFUSAL_MS`, both 30,000, separately | one constant |
| 23 | Checkpointer bounds on Node and Workers (V14) | `UPKEEP_BOUND_MS`, `OPEN_BOUND_MS`, the 30-day alarm retention, each defined twice | one module |
| 24 | Sign-in session bounds (V15) | 168 h in core's policy check and in the vault's `LONGEST_SESSION_HOURS` | one constant |
| 25 | The audit-watch heartbeat, `11 × 60` (S14) | retyped from the 5-minute schedule | `2 × SCHEDULE_MINUTES + 1` |
| 26 | Tunnel flow constants (C3) | `WINDOW`, `COUNT_EVERY`, `HIGH_WATER`, `KEEPALIVE_MS` defined in the client and the CLI | one export from the client, which the CLI imports |
| 27 | Token and binding defaults in the CLI and UI (C4) | 366, 90, the binding's 30 d / 24 h / 15 min, the role name 40/32/200, retyped | imported from core |
| 28 | Server body caps pegged to the bulk limit (S15) | `MAX_BODY_KEYS` and `revealInput.keys` = 2,000, "above the vault's 1,000-key cap" | two limits, kept apart. `revealInput.keys` is the reveal list, which `bulkLimit` governs: take it from `bulkLimit.count`, so a deployment that raises the policy past 2,000 is not capped silently. `MAX_BODY_KEYS` is a defensive bound (d) on validation's CPU for every top-level map (writes, dismissals, access patches), independent of `bulkLimit`: keep it, and change it only from a measurement of validation's cost per entry within R27's budget. (`MAX_BODY_NODES` counts values, not bytes; `API_BODY_BYTES` is the byte bound.) |

Example for 20. A `Retry-After` is one of three things, and each says
which:

- **a known reset:** the time until a count's window frees a slot, known
  exactly (the gate already answers `ceil(retryAfterMs / 1000)`);
- **a measured recovery:** how long the thing that refused takes to clear,
  from a measurement written beside it;
- **a retry policy:** a number chosen, with no claim about recovery,
  written down as the policy it is (Erwin's or the design's).

A lock timeout is none of these. Postgres's `lock_timeout` bounds one
attempt to take one lock; a queue can clear at once or last longer.

| Refusal | Before | After, and which kind |
|---|---|---|
| `/use` overloaded | 1 | a retry policy, until a run measures how fast admission reopens (Q1) |
| plain 503 on a read | 5 | a retry policy, written as such; a database or KMS outage has no recovery the code can know |
| plain 503 on a write | 5 | the same |
| sign-in 429 from the per-binding count (in the database) | 60 | a known reset: the count and its window are in the rows the same query reads, so the time to the next free slot can be computed |
| sign-in 429 from the per-address and total limiters (Cloudflare's binding, `processLimits`) | 60 | a retry policy, written as such: a limiter answers only `success` (`signin/config.ts:139`), with no reset time, and Cloudflare's counts are approximate |
| migrating | 30 | a retry policy, until a migration's own estimate exists |

### 3.3 Change behaviour

| # | Item | Before | After | TLA+ |
|---|---|---|---|---|
| 29 | Migrator lock waits (D2) | `SET lock_timeout = '5min'` for the session | `SET lock_timeout = '5min'` around `pg_advisory_lock` only, then a lock wait shorter than what a use may wait (the hot login's 1 s) for each DDL statement, retried a few times, failing the migration loudly rather than stalling `/use` | no (the migrator's lock order is unchanged) |
| 30 | Workload gate on Workers (S1) | one Durable Object per service: 1,000/s per service | one object per (service, session-hash bucket), as `workload-access.md:2040` already lists ("several gates, by session hash"). Bucket count from the service's rate: one per 1,000/s observed, starting at 1. A limit stays: one session's requests all hash to one bucket, so one session still meets 1,000/s (`workload-sessions.ts:272-277`, `gate.ts:109`). A busy SDK or sidecar past it would open a second session; sharding within a session would have to keep replay protection (one `jti` set per session) and the policy's counts (summed across buckets). Written down as the limit it is | **yes**: nonce and replay semantics per gate change (`formal/Workload*.cfg`) |
| 31 | Proxy upstream `fetch` (S16) | no timeout | nothing yet: whether to bound an upstream request at all is a policy question (Q7). The values' `sendBy` is not one: it is the last time the credentials may *start* going out (`credential-proxy.ts:2759-2763`), checked just before the fetch (`:2868-2880`), and says nothing of how long an upload or a response may take | – |
| 32 | Binding callers' `expiresAt` (S17) | `now + 60_000` when the caller has no session row: an upper bound of 60 s on longer cache and presign lifetimes, shorter ones kept (`Math.min`, `credential-proxy.ts:2122, 3166`) | the caller's own expiry, if it has one; else keep the 60 s, cited | no |
| 33 | `HyperdrivePool` `connect_timeout` (D3) | the driver's 30 s | the call's deadline (`end(by)` covers uses; app and vault calls get theirs) | no |
| 34 | SDK and sidecar `Retry-After` cap (C5) | obeyed up to 300 s × 1.5, only when no session is left (the held session serves meanwhile) | keep the 300 s as a defensive cap, cited; the fix that matters is an honest `Retry-After` from the server (#20) | no |
| 35 | A deadline for CI sign-in (S6) | none for the whole exchange; a function's 1 s `lock_timeout` bounds one lock, not the pool wait, network silence or the exchange | one deadline, from a policy Erwin sets (R58 allows a sign-in 1-2 s under load), carried into each step: the app's reads, `vault.signIn` and sealing, with cancellation, and into Postgres as the use deadline is. Then S6 becomes a computed memory bound (#6) | check `formal/Credentials` covers an exchange cut between steps |
| 36 | One binding's sign-ins take turns (S8, V30) | `sign_in` holds the binding's row `FOR UPDATE` to commit (`0037_vault_bindings.sql:39-43, 82-91`); each waiter holds a connection up to 1 s; the app's side runs under `audited(…)` (`api/workloads.ts:1306`) | first, measure how long the row is held: one binding then signs in at most `1 ÷ hold` a second, e.g. 200/s at 5 ms. If that misses R44, redesign. The lock serves two properties (`docs/formal.md:1941`): the rate count (`RateHeld`) and an unbind ending every credential (`EndedBindingEndsCredentials`). Removing the rate (#8) leaves the second; a lock that lets sign-ins run together must still exclude an unbind, e.g. sign-ins share the row and an unbind takes it exclusive. And every sign-in also writes the binding's `last_used_at` (`0037_vault_bindings.sql:87`): writes to one row take turns until commit whatever the lock mode (`FOR KEY SHARE` only avoids the upgrade conflict), so the same redesign moves that write off the row (into the log) or coalesces it (written only when a minute old) | **yes** |

### 3.4 Keep, with the source written beside it

These are right. Most already cite their source; the few that don't get
the citation.

- **Policy (b):** the 3 s use deadline (R53, R54), `bulkLimit` (R28,
  R52), the chunk of a full chain walk (`CHAIN_WALK`, R25), the 500 ms tick (R51, R54), the 2 s witness deadline (R51), the
  hot login's 1 s lock / 2 s statement timeouts (R53, decision 13), token
  and session lifetimes (core `access.ts`, `workloads.ts`), clock skews
  (each with its reason), `MAX_PARENTS` (forking.md), `MAX_PROXY_ITEMS`
  (proxy-ui.md), MCP approval windows.
- **External (a):** Postgres's 65,535 bind parameters (`ROWS_AT_ONCE`,
  `GENESIS_BATCH`, `inArray` chunks), SQLite's 32,766 and its compound
  SELECT terms, Workers' 128 MB (`BATCH_BYTES`, `STATEMENTS_AT_ONCE`), the
  Free plan's 10 ms CPU (`STEP_ROWS`), Cloudflare's 100 MB
  body (`MAX_DIGESTED_BODY`), S3's 5 GiB, GitHub's 100 per page, RFC 8628's
  `slow_down`, the Durable Object's 30 s `blockConcurrencyWhile` and its
  128-key delete.
- **Defensive (d):** body sizes, list lengths, name lengths: generous,
  and written down.

### 3.5 Config after the cleanup

What a deployment can set for performance, before and after:

| Where | Before | After |
|---|---|---|
| `vault(env => …)` (Workers) | `uses: { inFlight, connections, coverMs, names, batch }` | nothing |
| `serveVault` / `localVault` (Node) | a URL gets a pool of 10; a `Database` passed in can have any size, but admission stays 10 (V2); `VaultOptions` only through `localVault` | the hot pool's size, from the database's budget across processes (Q2) |
| `createCoffre` (Node) | a URL, a pool of 10, no size option | the app pool's size, the same way |
| Hyperdrive `origin_connection_limit` | setup, ≤ 20 | setup, the database's share, ≤ the plan's max |
| `signin({ workloads: { limits } })` | required: `{ perSource, total }` | `perSource` only, if Erwin agrees (Q4) |
| `credentialProxy({ cacheSeconds, recheckSeconds })`, a credential's `limit`, `bulkLimit` | kept | kept: these are revocation bounds and policy, not tuning |

A Workers deployment ends with no performance knob at all. A Node
deployment has one per pool, which setup writes from `max_connections`
and the number of processes (or from its pooler's size, Q2).

### 3.6 CI sign-in limits: the proposal, for Erwin's numbers

Erwin (D5, R76): one or two settings, defaults far above today's; no 60 a
minute per binding, no 300 a minute in all. Nothing here is built until he
confirms the numbers, and `formal/Credentials.tla` changes first (R45).

**What an exchange passes today**, in order:

| Limit | Counted | Today | Set by |
|---|---|---|---|
| per address (S8b) | per Cloudflare location, approximate; per Node process | 30 a minute | `WORKLOADS_PER_SOURCE` binding; `processLimits({ perSource })` |
| in all (S7) | the same | 300 a minute | `WORKLOADS_TOTAL`; `processLimits({ total })` |
| in flight (S6) | per isolate or process | 32 | `exchangeLimit.inFlight`, internal |
| per binding (S8, V30) | instance-wide, in the database | 60 a minute | `EXCHANGES_PER_BINDING_MINUTE` (app), `SIGN_INS_PER_WINDOW` (vault), `sign_in`'s SQL; `RateCap` in the model |
| one binding at a time (#36) | the binding's row | about one per row hold | `sign_in`'s `FOR UPDATE` and its `last_used_at` write |

MCP has its own three: `MCP_PER_SOURCE` 30 a minute (its unauthenticated
OAuth requests), `MCP_PER_CONNECTION` 120 a minute (a connection's tool
calls), `MCP_TOTAL` 300 a minute.

**Proposal: one setting, `perSource`.**

| Setting | Default | Derivation |
|---|---|---|
| `perSource`: requests one address may make to an unauthenticated entry point (a workload's exchange, MCP's OAuth endpoints), each entry point counted apart (the key names it), one value for both | **10,000 per 10 s** (1,000 a second) | R44: CI sign-in at 1,000/s, and a fleet behind one NAT (a Kubernetes cluster's egress address, a CI provider's runner pool) is one address, so one address may carry the whole target. What it still stops: one address sending more than the instance's whole target, each request costing a token decode and a read of the bindings (`workloadCandidates`) before it is refused. On Workers one binding, `period: 10` (Cloudflare takes only 10 or 60 and sets no maximum limit; docs updated 2026-10-21), so a burst is refused within 10 s, not a minute; still per location and approximate. On Node, `processLimits({ perSource })`, per process, on the same 10 s window |

Gone:

- **in all** (S7), for workloads and MCP alike: R76.
- **per binding** (S8, V30): R76. The app's and the vault's constants, the
  SQL count in `sign_in` (a new migration rewrites the function), and
  `RateCap`/`RateHeld` in `formal/Credentials.tla`, where TLC must still
  pass every other invariant without them.
- **MCP's `perConnection`** (120 a minute): a connection acts as the person
  who approved it, and no other way a person calls the API (a session, a
  personal token) has a rate per credential; no platform or policy gives
  the 120 (R70). If Erwin wants to keep it, it would be the second setting,
  at 100 a second by default, the same ceiling as an address.

Not settings, and what each needs:

- **In flight, 32** (S6) stays until an exchange has a deadline of its own
  (#35); then it is computed from memory, as the `/use` count will be. At
  R44's 1,000/s spread over the ~150 isolates W208 saw at that rate, an
  isolate holds a handful at once, far under 32; a burst that Cloudflare
  packs into fewer isolates could meet it, which the deadline's PR
  measures.
- **One binding's sign-ins take turns** on its row (#36), so dropping the
  count alone does not let one binding sign in at 1,000/s: at a 5 ms hold
  it tops out near 200/s, and R44 asks for hundreds at once from one
  principal. Proposed with D5, TLA+ first: a sign-in takes the binding's
  row shared (`FOR KEY SHARE`) and an unbind takes it exclusive, so
  `EndedBindingEndsCredentials` still holds (TLC must fail with the
  unbind's lock removed); `last_used_at` is written at most once a minute
  (`… WHERE last_used_at < now() - interval '1 minute'`), or moves to the
  log, so concurrent sign-ins do not queue on one row's update. Measured
  before and after: one binding's sign-ins a second on the reference rig.
- **A binding's removal, in batches (D7, Erwin's D178; built in #520).**
  The 60 a minute per binding also bounded a removal's work, which nobody
  had written down: an unbind names every live credential of its binding
  in one vault call and revokes them under the fence, and 60 a minute ×
  five-minute credentials kept that near 300. At 1,000 a second one
  binding holds 300,000; Node's vault message (8 MiB) carries about
  15,000, and each revoke makes every use wait about 0.08 ms a credential.
  It never bounded workload sessions either (an hour each, renewed up to
  the binding's `sessionHours`). Now a removal goes in steps
  (`formal/Unbinding.tla`): the first closes the binding (`closed_at`),
  which refuses its sign-ins and, at the door, every credential it issued,
  revoked yet or not, and every renewal (`standingBinding`); each step
  revokes a batch, and the last ends the binding. The batch is the
  fence's: 10 ms ÷ 0.08 ms = 125 on Node (below). On Workers it is also
  held to a call's 10 ms of CPU (the Free plan's hard limit: a call over
  it is killed, 1102, on every try): (10 − 4.85 ms fixed) ÷ 0.045 ms =
  114, and a request makes two such calls ((10 − 5.05 ms) ÷ 2.0 ms per
  batch) within its 32 invocations, counted, then answers 202
  `{ removing: { left } }`; the client asks again until it is done, and
  the scheduled run finishes one abandoned. Measured with a removal of
  20,000 on the compose Postgres beside uses at 1,000 a second: p99 9.5
  → 64.8 ms, no throughput lost, no pause needed. Since the close refuses
  every use, a removal left to the scheduled run (228 a beat, every five
  minutes) costs no revocation latency; what remains reversible is only
  how fast the vault's records catch up: a plan's CPU limit as a setting
  (Workers Paid allows more than 10 ms), or a one-minute cron for the
  scheduled run.

  *The fence budget, measured (W331, 2026-11-06).* The fence is the
  instance's one advisory lock, which every use of every credential takes
  shared, so a batch's hold stalls every use, of any service. Each use
  past the 10 a process has in flight (the vault pool's,
  `DEFAULT_CONNECTIONS`) is refused at once as `overloaded`, so uses are
  refused once rate × hold passes 10: at D178's 50 ms, above 200 a second.
  One Node process, Postgres, reveals beside the removal of 5,000:

  | uses/s | refused at 50 ms (625) | refused at 10 ms (125) | p99 at 125, beside (alone) |
  |---|---|---|---|
  | 100 | 0 | 0 | 28 ms (18) |
  | 200 | 10% | 0 | 50 ms (24) |
  | 400 | 43% | 11% (0.5% alone) | 41 ms (23) |
  | 800 | 68% | harness saturated | 43 ms |

  So #520 holds a batch to 10 ms: the 10 uses in flight ÷ R44's 1,000 a
  second, until Q1 decides the admission rule. At 400 a second the
  removal's own CPU, in the same process, still fills the slots.

  *Why the batches after the close keep the fence (option (d), rejected
  for #520).* With the fence on the close alone, TLC finds a 16-state
  trace (`formal/Unbinding.tla`, without BatchFenced): a request passes
  the app's check before the close, its vault statement reads its
  credential live after it, an unfenced batch revokes that credential,
  and the use commits numbered after the revoke (`RevokeOrdersUses`). The
  app's close check cannot stop a request whose check ran first. What
  would free the batches: the vault's use statement refusing a credential
  whose binding is closed, under the fence shared (VaultChecksClosed: every
  scenario holds with the batches unfenced), a join on the hot path, with
  `decide.ts`, the Lean model and `request-cost.alone.ts`: a PR of its
  own, if Erwin wants it. Or a time bound instead of the join (the
  lead's idea, not built): a use admitted before the close carries a
  deadline at most `USE_DEADLINE_MS` ahead, which the vault refuses past
  (with `USE_AHEAD_MS` of skew), so none commits later than the close plus
  deadline, skew and statement timeout (about 65 s); unfenced batches that
  start after that cannot race it, at the cost of a minute's wait for
  large removals, already 202-and-resume. Whether the vault holds the
  deadline on its own clock so must be checked in code and modelled.
- **AWS fleets.** Each AWS-proof sign-in is one `GetCallerIdentity` at STS,
  signed by the workload, so it counts against the workload's own account:
  600 a second per account and Region at a regional endpoint, the global
  endpoint's quota apart (S78). A fleet signing in faster than that from
  one account and Region needs its own quota raised; no coffre setting is
  the bound there, and none should pretend to be.
- **`MAX_BINDINGS`, 16 a service** (C29). It bounds two things: the live
  bindings a service holds, and a sign-in's work, since every binding of
  the token's issuer is read, its MAC checked, its policy parsed and
  matched. Proposal: narrow the read in SQL to the bindings that can match
  the token (by the claim that names the workload, e.g. GitHub's
  `repository_id`), so a sign-in reads one or a few rows whatever the
  service holds; then `MAX_BINDINGS` bounds only rows per service, a
  defensive bound (class d), e.g. 256, written as such. Without the
  narrower read, size it from a measured cost per candidate within a share
  of R27's 10 ms (e.g. 2 ms of matching at 50 µs a candidate is 40).
- **`replicas`, 1 to 64** (C17): an enrollment binding's stated fleet size;
  its code admits twice that many live sessions, and its tripwire counts
  against it. No platform constraint sets 64; a fleet larger than 64 on one
  binding cannot enroll today. Proposal: 1 to 1,000, a defensive input
  bound (class d) written as such, the live-session count staying one
  indexed count per enrollment.

**For Erwin to confirm:** `perSource` at 10,000 per 10 s; MCP's
`perConnection` dropped (or kept at 100/s); the row-lock change with D5;
`MAX_BINDINGS` by the narrower read and 256, or measured; `replicas` up to
1,000.

### 3.7 Accepted costs an Owner controls

Under Erwin's 2026-11-06 decision (no artificial limits, R70), #533 (W354,
body bounds) drops the per-field bounds on two pieces of admin-written
display text and accepts what they cost. Only an Owner or admin writes
either, so the cost lands on the instance its own admins configure, not on
what a caller sends.

- **A binding's label, up to ~1 MiB (the API's body bound).** It is copied
  into every credential a CI sign-in issues and into that sign-in's log
  entry, so a 1 MiB label is about 1 MiB written per sign-in, at up to R44's
  1,000 sign-ins a second. Documented in
  [workload-access.md](workload-access.md).
- **Role descriptions, up to 32 roles of ~900 KiB each.** The roles config
  every app and vault isolate holds and parses then reaches ~29.5 MB per
  isolate, out of Workers' 128 MB. Documented in [roles.md](roles.md).

One pre-sign-in byte bound of ~32 KiB, in place of the CI sign-in's CPU
accounting (`SIGN_IN_WORK_NS`, 16 ms, and the claim-matching budget), was
agreed for #533. Its head `b8dc8c73` does not have it yet: there, every body
read before sign-in takes the API's 1 MiB (`API_BODY_BYTES`), and a sign-in
spends from `SIGN_IN_WORK_NS`. [config.md](config.md) section 2.7 carries it
as pending.

## 4. The inventory

Columns: **Name**, **Value**, **Where** (path from the package root),
**Class**, **Source / why** (the comment or rule, short), **Bites** (⚠ if
it can refuse or slow R44 load), **Verdict** (keep, derive, delete, fix,
or move, pointing to section 3's #).

### 4.1 `@coffre/vault` (`packages/vault/src`)

| ID | Name | Value | Where | Class | Source / why | Bites | Verdict |
|---|---|---|---|---|---|---|---|
| V1 | `uses.inFlight` ← `uses.connections` ← `DEFAULT_CONNECTIONS` | 10 per isolate / process | `vault.ts:377, 344`; `use.ts:105, 168`; `cloudflare.ts:57` | e | "pg's default"; "T112 measures it", never measured (7c83fd02, #378). Counts a use's database phase only: released before the key's opening (`use.ts:1293-1299, 638-643`) | ⚠ | delete (#1, #2) |
| V2 | Node's derivation from the hot pool | `$client.options.max`, always undefined | `node.ts:101` | e | dead: `createDatabase` sets no `$client` | ⚠ (via V1) | delete (#3) |
| V3 | `uses.coverMs` | 60 s | `use.ts:105` | b | covers (R53), decision 8 | | internal (#9) |
| V4 | `uses.names` | 10,000 | `use.ts:105, 191` | d | LRU of names → ids, ~3 MB full (22ef27a1, #412) | | internal (#9); fold into #21 |
| V5 | `uses.batch` | 100 keys a statement | `use.ts:105` | c | ~0.4 ms a key under the fence, 100 ≈ 40 ms (review r2 of #433) | | internal (#9) |
| V6 | `READ_HEAD_WAITERS` | 16, deployment-wide | `vault.ts:421`; `db/log.ts:255` | c | 2.4 s ÷ 150 ms measured (fcf8e178, #356, W199) | small DBs | derive (#13) |
| V7 | `HELD_PAST_DEADLINE_MS` | 2 s | `use.ts:117` | c | = hot `statement_timeout`, retyped (T170, #438) | | derive (#14) |
| V8 | `USE_DEADLINE_MS` copies | 3 s | `log-store.ts:485, 487, 629`; SQL `deadline_max()` | c | R53 | | derive (#15) |
| V9 | `USE_AHEAD_MS` and copies | 60 s | `bulk.ts:37`; `use.sqlite.ts:589`; SQL 0022, 0024 | b | "the minute a Worker's clock may run ahead" (#393) | | derive copies (#16) |
| V10 | `refreshMs` and copies | min(60 s, window ÷ 10) | `bulk.ts:41`; `log-store.ts:629`; SQL | c | decision 9 | | derive copies (#17) |
| V11 | `ABOVE_NEWEST` | 2,000 entries (1,000 on `main` since, D6) | `verifier.ts:62` | d | bounds a check's work against a checkpointer behind or planted rows, 14 ms measured; sized as "four ticks at 1,000/s" (f858d18f, #388) | ⚠ > 2,000 unsealed entries (e.g. 4,000 new a second): `capped` in the audit API, UI and `coffre verify` | resize from its work (#18) |
| V12 | `UseCache.max` | 10,000; clears the whole map | `use.ts:154, 180` | d | "past `max`, a map starts over" | many keys | #21 |
| V13 | `TICKET_MS`, `REFUSAL_MS` | 30 s each | `admit.ts:215`; `refusal.ts:49` | e | "the write follows its read" (#474, #498) | | one constant (#22) |
| V14 | `UPKEEP_BOUND_MS`, `OPEN_BOUND_MS` | 60 s; = `TICK_BOUND_MS` | `checkpointer-node.ts:65-66`; `checkpointer-workers.ts:111-113` | e | (205e8255, #437) | | one module (#23) |
| V15 | `LONGEST_SESSION_HOURS` | 168 | `credentials.ts:56` | c | = core's `sessionHours` max | | #24 |
| V16 | `KEY_BUDGET_MS` | 5 s | `vault.ts:389` | e | "a removal waits at most this long for a read at KMS" (87ed75ae) | | keep, cite KMS's latency or derive from `TIMEOUT_MS × ATTEMPTS` |
| V17 | `LOCK_TIMEOUT_MS` | 15 s (D2: a short wait and retries) | `vault.ts:392` | c | "above the key budget" | | keep, computed `3 × KEY_BUDGET_MS` |
| V18 | `READ_LOCK_TIMEOUT_MS` | 3 s | `vault.ts:401` | b | "longer is a queue holding a connection" (ecfaaec4, #347) | | keep |
| V19 | `READ_DEADLINE_MS`, plus `KEY_BUDGET_MS` with a key service | two clock origins. A read that sets no deadline of its own gets 5 s from its first decision, after the vault has settled and cut over (`vault.ts:873-884`). `unwrap`, `wrap` and `rewrap` set theirs earlier, before the KEK check (`vault.ts:1973-1974`): 5 s, plus V16's 5 s with a key service, so 10 s in all. That check can itself start the vault, read the database and call the key service (`vault.ts:3333-3374`), and it spends from the same 10 s: a 2 s check leaves 8 s for the rest | `vault.ts:410` | b | "a caller hears within it" (#356) | | keep; state the stages each covers |
| V20 | `CODE_QUEUE.waiters` | 1 | `vault.ts:427` | b | one call of a deploy's herd waits (#467) | | keep |
| V21 | `CODE_PAUSE_MS`, `CODE_PAUSE_MAX_MS` | 25 → 400 ms, doubling | `vault.ts:430-431` | e | none | | derive from the measured hold (as V6) |
| V22 | `RELEASES_PRUNED` | 10,000 | `vault.ts:434` | d | one short statement (#359) | | keep |
| V23 | `GENESIS_BATCH` | 2,000 rows | `vault.ts:464` | a | 11 parameters each, under 65,535 (#420) | | keep |
| V24 | `KEY_CHECK_SAMPLE` | 3 | `vault.ts:475` | e | "one that opens proves it" | | keep, say why 3 (one suffices; 3 against a bad row) |
| V25 | Decide retries | 3 | `vault.ts:892, 1548` | e | none | | cite the model (`MaxTries`) or derive |
| V26 | `issueToken` tries | 3 | `vault.ts:4356` | b | IssueCheck in the model | | keep |
| V27 | `accessEntriesAbout(…, 100_000)` | 100,000; cuts silently | `vault.ts:3300` | e | none (2426111f) | | fix: page, never cut silently |
| V28 | `WALKS` | 10,000 / 100 / 10,000 | `vault.ts:5378` | c | 40 µs an entry, ~1 s a walk (#270) | | keep |
| V29 | `SIGNATURES_AT_ONCE` | 256 | `vault.ts:5408` | e | none (#87) | | keep, cite CPU per signature |
| V30 | `SIGN_INS_PER_WINDOW`, `SIGN_IN_WINDOW_MS` | 60 per 60 s per binding | `credentials.ts:51-52` | b | stated in `docs/design/oidc.md:174-175`, held by `formal/Credentials.tla` (`RateCap`); its 60 "as 0.14 counts them" (#411) | ⚠ CI | #8, Q4 |
| V31 | Sign-in end slack | +60 s | `credentials.ts:138`; `credentials.sqlite.ts:47` | e | none; differs from `CLOCK_SLACK_MS` | | one slack |
| V32 | `CLOCK_SLACK_MS` | 5 min | `credentials.ts:336` | b | "a host a minute or two ahead" (Fable, PR 2) | | keep |
| V33 | `BUSY_CODES` | 55P03, 57014 | `credentials.ts:75` | a | Postgres codes | | keep |
| V34 | `ROUTE_ATTEMPTS` | 3 | `use.ts:1605` | e | none (#464) | | cite or derive from the deadline |
| V35 | `busy()` `retryAfter` | 1 | `use.ts:454` | e | none | | #20 |
| V36 | `unconfigured` `retryAfter` | 5 | `use.ts:711` | e | none | | #20 |
| V37 | `START_AGAIN_MS` | 10 s | `cloudflare.ts:79` | e | "out of reach, the next call tries again" | | keep, cite |
| V38 | `MAX_BODY` (Node socket) | 8 MiB | `node.ts:118` | d | none | | keep, write why (bigger than any vault call) |
| V39 | Checkpointer pool | `max: 2` | `node.ts:107` | e | "a connection of its own" (#437) | | 1, or say why 2 |
| V40 | `keepAliveTimeout` | 0 | `node.ts:157` | a | avoids Node's ECONNRESET race (#170) | | keep |
| V41 | `FRESH_MS` | 10 min | `checkpointer.ts:186` | d | older than its deadline is a replay (#370) | | keep |
| V42 | `WITNESS_DEADLINE_MS` | 2 s | `checkpointer.ts:189` | b | R51 | | keep |
| V43 | `TICK_BOUND_MS` | 10 s | `checkpointer.ts:198` | d | a stalled tick (#437) | | keep |
| V44 | `SEAL_WAIT_MS` | 5 s | `checkpointer.ts:205` | b | T169 | | keep |
| V45 | `SEALING_STALE_MS` | 5 s | `checkpointer.ts:208` | c | 10 × `TICK_MS` | | compute |
| V46 | `WINDOW_MAX` | 10,000 a tick | `checkpointer.ts:229` | d | after a stall (#437) | | keep |
| V47 | `WINDOW_ENTRY_MS` | 0.01 ms | `checkpointer.ts:240` | c | 1.4 µs measured | | keep |
| V48 | `KEPT_BYTES` | 4 MiB | `checkpointer.ts:464` | d | `WINDOW_MAX` entries (#443) | | keep |
| V49 | Witness retry | 100 ms | `checkpointer.ts:1157` | e | none | | derive from `WITNESS_DEADLINE_MS` |
| V50 | `ALARMS_KEPT_MS` | 30 days | `checkpointer-workers.ts:106` | b | (#376) | | keep, one copy (#23) |
| V51 | `ASK_BOUND_MS` | 2 s | `checkpointer-workers.ts:115` | e | none | | derive (≤ the use deadline) |
| V52 | `SEAL_ASK_BOUND_MS` | 5 + 2 + 1 s | `checkpointer-workers.ts:117` | c | its bound, the witnesses', a second | | keep |
| V53 | `closeIdleMs` | 10 s (1 s for days) | `checkpointer-workers.ts:174, 258` | e | none | | keep, cite Hyperdrive's 10 min idle |
| V54 | Alarm delete batch | 128 | `checkpointer-workers.ts:240` | a | DO `delete([])` takes 128 keys | | keep |
| V55 | Alarm list page | 1,000 | `checkpointer-workers.ts:395` | e | "a list is 1,000 keys at most": that is Workers KV's limit; DO storage `list` has none | | fix the comment |
| V56 | Tick history | 64 | `checkpointer-workers.ts:316` | d | status ring | | keep |
| V57 | Alarm file | past 1,000,000 bytes, rewritten keeping the last 30 days | `checkpointer-node.ts:125-132, 259-265` | d / e | a compaction trigger, not a cap: what 30 days hold can stay above 1 MB, and then every append reads, filters and rewrites the whole file. Neither its size nor that work has a byte bound | | two separate fixes. A file a day, deleting whole days, ends the rewrites (each append is one append) but bounds only time: one busy day can still hold any number of bytes. A byte bound needs a budget (bytes or alarms) and a rule for when it is full (drop the oldest, drop new ones, or alert); left open |
| V58 | `OPEN_AGAIN_MS` | 10 s | `checkpointer-node.ts:275` | e | none | | as V37 |
| V59 | `TICK_MS` | 500 ms | `log-checkpointer.ts:98` | b | R51, R54 | | keep |
| V60 | `DAYS_AHEAD` | 3 | `log-checkpointer.ts:107` | d | a use in a day with no partition fails | | keep |
| V61 | `RETAIN_EVERY_MS` | 1 h | `log-checkpointer.ts:109` | b | | | keep |
| V62 | `PRUNE_EVERY_MS`, `PRUNED` | 60 s, 10,000 | `log-checkpointer.ts:111-112` | d | R52 | | keep; 10k a minute < new (principal, key) pairs at 1k/s only in a pathological load |
| V63 | `WAITING_ALARM_MS` | 1 day | `log-checkpointer.ts:115` | b | | | keep |
| V64 | `DEFAULT_BULK_LIMIT` | 1,000 keys / 15 min | `config.ts:12` | b | R28, R52 | | keep |
| V65 | `MAX_BULK_WINDOW_MINUTES` | 1,440 | `config.ts:20` | c | releases kept a day and an hour (#359) | | keep |
| V66 | `AT_SLACK_MS` | 63,000 | `log-store.ts:50` | c | deadline + the minute ahead, as a literal | | #16 |
| V67 | `PROOF_WINDOW` | 2^20 | `log-store.ts:218` | d | ~17 min at 1,000/s | | keep |
| V68 | `dropTiles` steps | 10,000 | `log-store.ts:442` | d | | | keep |
| V69 | `OBJECTS_AT_ONCE` | 200 | `log-store.ts:644` | a / e | SQLite's 500 terms in a compound SELECT ([`SQLITE_MAX_COMPOUND_SELECT`](https://www.sqlite.org/limits.html#max_compound_select)); each object is one `UNION ALL` term (`log-store.ts:663-669`), two bound parameters each (object and `below`), far under the 32,766 parameters. Why 200 and not 500 is not written | | keep the 500-term ceiling as its source; derive the batch from it (500 on SQLite, or one cap for both engines) or write why it sits lower |
| V70 | `SQLITE_ROWS` | 500 | `log-store.ts:647` | a | 14 params, under SQLite's 32,766 | | keep |
| V71 | `VERIFY_BATCH` | 5,000 | `log.ts:37` | c | a fifth of the trips of 1,000 | | keep; one copy with server `BATCH` |
| V72 | `HASHES_AT_ONCE` | 5,000 | `store.ts:696` | d | | | keep |
| V73 | `RELEASES_KEPT_MS` | 1 day + 1 h | `store.ts:86` | c | also in SQL 0021 | | keep, test the SQL copy |
| V74 | `PROJECTED_AT_ONCE`, steps | 1,000 × 4 a run | `reads.ts:95, 237` | c | "a tick's worth at 1,000/s" (a tick is 500 ms: 2× margin) | | keep, fix the comment |
| V75 | `PROBLEMS_NAMED` | 20 | `reads.ts:277` | d | message length | | keep |
| V76 | `CHUNK` (SQLite) | 500 | `use.sqlite.ts:412` | a | 4,000 params, SQLite's 32,766 | | keep |
| V77 | SQLite chain depth | > 3 | `use.sqlite.ts:293` | c | = `MAX_PARENTS`, retyped | | import |
| V78 | Witness 409 retries | 2 | `witness-workers.ts:103` | e | none | | cite |
| V79 | `round > 2` (batch decide) | 2 | `use.ts:532` | b | DecideBeforeLock | | keep |
| V80 | `SLOTS` (e1-e4) | 4 | `use.ts:386` | c | = `MAX_PARENTS + 1` | | compute |
| V81 | Input bounds | ids ≤ 100, `user:` ≤ 320, labels ≤ 120, jkt ≤ 128, run claims ≤ 32 × (64, 256), clientId ≤ 2,048 … | `credentials.ts:109-328`; `admit.ts:180`; `use.ts:436` | d | | | keep |
| V82 | `MAX_RESERVED` | 1,000 names | `proxy.ts:19` | d | "far more than any deployment's code defines" | | keep |
| V83 | `retainDays` | null: every day kept | `checkpointer-workers.ts:83`; `checkpointer-node.ts:92` | – | not in the standard setup: Workers' `checkpointer()` and `localVault`'s own checkpointer pass none. On Node, `runCheckpointer` and `keepCheckpointer` (`@coffre/vault/node`, `node.ts:36`) accept it, for a deployment that runs its checkpointer itself (`sealThrough`, `heldOutside`). 13.6 GB/day at 1,000/s (`hot-path-one.md:1285`) for the uses' rows; about 68 GB/day with the reads' projection and tiles ([config.md](config.md), Q6) | | not a limit; see Q6 |

Format, fine: `MAC_BYTES` 16 (twice: `log-entry.ts:36`, `reads.ts:97`),
`TAG_BYTES`, `SEAL_BYTES`, the HKDF outputs, the Ed25519 PKCS8 prefix,
key ids, the UUID and digit patterns, `UNBOUNDED`, `TILE_RANGE` and
256-leaf tiles, the purpose encoding, the advisory-lock keys, the KEK id
patterns, and the email bounds (254 / 64 / 63: RFC 5321 and 1035).

### 4.2 `@coffre/server` (`packages/server/src`)

| ID | Name | Value | Where | Class | Source / why | Bites | Verdict |
|---|---|---|---|---|---|---|---|
| S1 | `GATE_CEILING` | 1,000 a second per service | `gate.ts:27, 104-110` | a (Workers) / e (Node) | "a Durable Object's documented soft limit"; also the only bound on the `jti` set, ~20 MB at the ceiling, which grows with the rate (60fc57d2, #301) | ⚠ | Node: replace with a memory bound, then drop the rate (#5); Workers: shard (#30) |
| S2 | `EPOCH_MS` | 120 s | `gate.ts:21` | b | a nonce's life; the client's `FRESH_NONCE_MS` (100 s) assumes it | | keep; client imports it |
| S3 | `FLUSH_MS`, `SKEW_MS`, `DURABLE_WINDOW_MS` | 10 s, 10 s, 1 h | `gate.ts:29-37` | e / e / b | eviction loses ≤ 10 s of counts | | keep, cite |
| S4 | Gate fixed calendar second | – | `gate.ts:104` | e | 1,000 at the end of one second and 1,000 at the start of the next pass; refusals count too | | goes with #30 |
| S5 | `POLL_MS`, `POLL_MAX_MS` | 1 → 20 ms | `asked-once.ts:38-39` | e | cheap | | keep |
| S6 | `exchangeLimit.inFlight` | 32 per isolate | `api/workloads.ts:413` | e | "past it, 429 at once (R44)"; the only bound on waiting exchanges, which have no deadline | ⚠ CI | keep until #35, then compute (#6) |
| S7 | `processLimits` `total`, `WORKLOADS_TOTAL`, `MCP_TOTAL` | 300 a minute, per Cloudflare location (approximate) or per Node process | `workloads/limits.ts:16`; `examples/workers/app/wrangler.jsonc:54-61` | e | "size them to that" (oidc.md §2) | ⚠ CI | #7, Q4 |
| S8 | `EXCHANGES_PER_BINDING_MINUTE` | 60, instance-wide | `api/workloads.ts:407` | b | oidc.md:174-175, modelled; "counted under its row"; copied in the vault (V30) | ⚠ CI | #8, Q4 |
| S8b | `processLimits` `perSource`, `perConnection` | 30, 120 a minute | `workloads/limits.ts:14-15` | d | abuse: anyone may send a token | NAT'd fleets | keep (Q4) |
| S8c | `WINDOW_MS`, `MAX_KEYS` (Node limiter) | 60 s, 10,000 | `workloads/limits.ts:20-22` | b / d | fails open past 10,000 | | keep |
| S9 | `TAKE_OVER_MS`, `WAIT_MS` | 3 s, 6 s | `asked-once.ts:32, 37` | e / c | "longer than a deploy's write and its seal" (T201, #475); `about()` has no deadline to derive from | ⚠ cold | measure, then derive (#19) |
| S10 | `UNAVAILABLE_RETRY_AFTER` | '5' | `api/errors.ts:149` | c (wrongly) | the 15 s write lock, used for reads too | | #20 |
| S11 | Proxy values cache | 1,000; O(n) eviction; no single-flight | `plugins/credential-proxy.ts:3164` | e | "a handful of handles in a dev loop" (#249) | ⚠ | #21 |
| S12 | Proxy `handles` cache (`madeFor`) | 1,000 | `credential-proxy.ts:1011` | e | same | | #21 |
| S13 | `UI_KEPT` | 10,000; clears all | `credential-proxy.ts:576` | e | "a map starts over" (#467) | | #21 |
| S13b | `Accesses.KEPT` | 1,000 principals; no single-flight | `accesses.ts:44` | d | "a few hundred principals is far more than an isolate serves" (#334) | | #21 |
| S14 | `HEARTBEAT_STALE_AFTER_SECONDS` | 11 × 60 | `plugins/audit-watch.ts:293` | c | one late run plus a minute | | compute (#25) |
| S15 | `revealInput.keys` | 2,000 | `api/routes.ts:44` | c | the reveal list, which `bulkLimit` governs; retyped above its default 1,000 | with `bulkLimit` > 2,000 | from `bulkLimit.count` (#28) |
| S15b | `MAX_BODY_KEYS` | 2,000 top-level entries | `api/router.ts:30-41` | d | validation's CPU per entry, before the schema walks a map (writes, dismissals, access patches); "above the vault's 1,000-key cap" is a comparison, not its source | | keep; resize only from a measurement (#28) |
| S16 | Proxy upstream `fetch` | no timeout | `credential-proxy.ts:2875-2881` | – | missing bound; `sendBy` bounds when sending starts, not the response | | #31, Q7 |
| S17 | Binding `expiresAt` | now + 60 s with no session row: caps longer cache and presign lifetimes at 60 s | `plugins.ts:605` | e | none (#306) | | #32 |
| S18 | `TOUCH_INTERVAL_MS` | 5 min; 3 copies; not claimed once | `workload-sessions.ts:52`; `api/signin.ts:319`; `mcp/service.ts:63` | e | "one write per credential per five minutes" | mild herd | one constant; claim the write once (UPDATE … WHERE last_used < …) |
| S19 | `USES_AT_ONCE` | 4 a request | `api/keys.ts:182` | e | "leaves the isolate's admission room (R44)" | | delete with V1 |
| S20 | `USE_DEADLINE_SECONDS` | 3 | `api/proxy.ts:89` | c | copy of `USE_DEADLINE_MS` | | #15 |
| S21 | `DEFAULT_CACHE_SECONDS` | 60 | `api/proxy.ts:88` | c | copy of `cacheSeconds ?? 60` | | one constant |
| S22 | `cacheSeconds`, `recheckSeconds` | 60 s; 0 to 3,600 | `credential-proxy.ts:469-472` | b | revocation bound (#249, #252) | | keep |
| S23 | `RECHECK_DEADLINE_MS` | 10 s | `credential-proxy.ts:532` | e | "the vault has that long to answer" | | derive from the vault call's bound |
| S24 | `WORKLOAD_RECHECK_MS` | 15 s | `credential-proxy.ts:534` | b | design §8.2 | | keep |
| S25 | `refreshWindow`, `REFRESH_ATTEMPT_MS`, `REFRESH_RETRY_MS` | min(cache ÷ 4, 15 s), 5 s, 1 s | `credential-proxy.ts:595-602` | e | none | | derive from `cacheSeconds` and the use deadline |
| S26 | `MAX_BODY_BYTES` | 16 MiB (D1: 1 MiB, larger bodies stream) | `credential-proxy.ts:387` | d | "an API call's, not an upload's" | memory × concurrency | keep, inside the memory budget |
| S27 | `MAX_FIELD_BODY`, `MAX_FIELDS`, `MAX_DEPTH` | 64 KiB, 256, 32 | `credential-proxy.ts:389-396` | d | | | keep |
| S28 | `MAX_STREAM_BYTES` | 5 GiB | `credential-proxy.ts:398` | a | S3's single-request limit | | keep |
| S29 | `MESSAGE_BYTES` (`hmac` `maxBytes`) | 64 KiB, ≤ 1 MiB | `credential-proxy.ts:407` | b | 12× Equisafe's largest in 90 days (#343) | | keep |
| S30 | Compute body cap | ceil(most ÷ 3) × 4 + 4,096 | `credential-proxy.ts:1690` | c (+ e) | base64 of `most`, plus a guessed 4,096 | | cite the 4,096 |
| S31 | `MIN_REDACTED` | 8 chars | `credential-proxy.ts:413` | d | | | keep |
| S32 | Presign `expiresIn` | 900 s; 1 to 3,600 | `credential-proxy.ts:2062` | b | "an hour at most" | | keep |
| S33 | URL decoding passes | 8 | `credential-proxy.ts:2109` | d | | | keep |
| S34 | `failure()` `Retry-After` | only on 503 | `credential-proxy.ts:3961`; `plugins/vault-kv.ts:250` | e | a 429 loses its `Retry-After` | | fix (#20) |
| S35 | Binding `overloaded` RA, gate RAs | '1'; `ceil(ms ÷ 1000)`; '5' | `plugins.ts:506-508`; `workload-sessions.ts:285-301` | e / c / e | | | #20 |
| S36 | Sign-in RA fallback | 503 → 5, `full` → 30, else 60 | `auth-routes.ts:123` | e | | ⚠ CI | #20 |
| S37 | `SEALING_ASKED_MS` | 3 s | `app.ts:382` | e | none | | derive from `SEAL_WAIT_MS` |
| S38 | migrating / app_key / rotating RA | 30 / 30 / 1 | `app.ts:217, 309, 320` | e / e / b | | | keep, cite |
| S39 | Cutover `TRIES`, `HOLD_MS` | 3, 5 s | `cutover.ts:60, 67` | e | one-time | | keep, cite |
| S40 | Cutover chain walk | unbounded | `cutover.ts:151` | e | can pass Workers CPU on a large 0.14 log, unlike `CHAIN_WALK` | | bound by `CHAIN_WALK` |
| S41 | `SPENT_TOKENS_PER_BEAT` | 5,000 per 5 min | `app.ts:344` | c | "where one binding's exchanges spend at most 3,600 an hour": assumes one binding at full rate | | derive from the bindings |
| S42 | `STEP_ROWS` | 100 | `key-rotation.ts:51` | a | 1.4-2.7 ms of CPU, Free's 10 ms | | keep |
| S43 | `NAMED`, `ROTATION_TRIES` | 20, 20 | `key-rotation.ts:54, 242` | d / e | | | keep / cite |
| S44 | `UNKNOWN_KEY_ALERT_MS` | 1 h | `alerts.ts:45` | d | anyone may send one | | keep |
| S45 | `SCHEDULE_MINUTES`, `BACKLOG_WALKS`, `BACKLOG_MARGIN_MS` | 5, 100, 30 s | `node.ts:72-78` | b / c / e | = the examples' `*/5` cron | | keep; one copy of the 5 |
| S46 | `WALK_EVERY_MS` | 1 s | `cloudflare-anchor.ts:42` | e | | | keep, cite |
| S47 | `ADMISSION_MS` (sockets) | 45 s | `socket-admission.ts:14` | b | 64 runs took up to 22 s, × 2 (#286) | | keep |
| S48 | Tunnel `WINDOW`, `MOST_HELD`, `COUNT_EVERY` | 1 MiB, 2 MiB, 128 KiB | `cloudflare-sockets.ts:46-61` | d / c / c | | | keep; one source (#26) |
| S49 | `MOST_SESSIONS` | 32 per object | `cloudflare-sockets.ts:53` | a / c | 32 × 3 windows ≈ 96 MB of the object's 128 MB | | keep |
| S50 | `MOST_DECIDING_MS`, `ADMITTING`, `MOST_WAITING_MS` | 60 s, 4 (1 cold), 15 s | `cloudflare-sockets.ts:59-76` | d / b / e | "past 16 or so ran into their time to decide" | | keep |
| S51 | `IDLE_DATABASE_MS` | 10 s | `cloudflare-sockets.ts:125` | c | = `RECHECK_DEADLINE_MS`, retyped | | import |
| S52 | Node WS `maxPayload` | 16 MiB (D1: the body bound) | `node-sockets.ts:17` | e | = `MAX_BODY_BYTES` | | import |
| S53 | `CHAIN_WALK`, `BATCH` | 10,000, 5,000 | `db/audit.ts:198, 201` | b | R25: a full walk is explicit and chunked; one chunk is ~200 ms of a Worker's CPU (Paid, far above Free's 10 ms), a measured choice, not a platform limit; `BATCH`: memory (#270) | | keep, cite R25; `BATCH` shares V71 |
| S54 | `auditRange` default | 1,000 | `db/queries.ts:3055` | e | callers override | | drop the default |
| S55 | `inArray` chunks | 1,000 | `db/queries.ts:438-440, 735, 2902-2919` | a | bind parameters | | keep |
| S56 | `READS_PER_STATEMENT`, `STATEMENTS_AT_ONCE` | 250, 4 | `db/queries.ts:1942, 1951` | a | SQLite's 500 terms; 130k reads held 617 MiB | | keep |
| S57 | `HIDDEN_COUNTED` | 1,000 | `db/queries.ts:2028` | b | R48 | | keep |
| S58 | `SPENT_TOKENS_KEPT_MS` | 2 h | `db/queries.ts:2110`; SQL 0016 | c | token age + margin | | one source |
| S59 | `RENEW_MARGIN_MS` | 5 s | `db/workloads.ts:285` | b | | | keep |
| S60 | Sign-in field bounds | bodies 4 / 16 KiB, token 8 KiB, labels 120, codes 128 … | `auth-routes.ts:53-432` | d | | | keep |
| S61 | `PENDING_TTL_SECONDS`, `DEVICE_POLL_SECONDS` | 10 min, 5 s (not enforced) | `api/signin.ts:158, 311` | b | RFC 8628 | | keep; import `DEVICE_TTL_SECONDS` |
| S62 | `DEVICE_PENDING_PER_IP`, `_TOTAL` | 5, 200 | `api/signin.ts:312-313` | d / e | unauthenticated device starts | | keep per IP; cite total |
| S63 | `KEYS_FRESH_MS`, `KEYS_COOLDOWN_MS`, `MAX_KEY_SETS` | 10 min, 60 s, 64 | `workloads/keys.ts:15-19` | e / b / d | | | keep, cite |
| S64 | `FETCH_DEADLINE_MS`, `MAX_BODY_BYTES` (issuer fetch) | 5 s, 64 KiB | `workloads/transport.ts:33-35` | e / d | | | keep; UI-route fetches get the same deadline (they have none) |
| S65 | AWS `MAX_SKEW_MS`, `MAX_HEADER_BYTES` | 5 min, 8 KiB | `workloads/aws.ts:35, 37` | b / d | STS refuses past 15 min | | keep |
| S66 | `MAX_ANCESTORS` | 4 | `workload-sessions.ts:49` | b | design §8.4 | | keep |
| S67 | `API_BODY_BYTES`, `MAX_BODY_NODES` | 1 MiB, 20,000 | `api/router.ts:28`; `http.ts:77` | d | a 1,000-key write is ~11k nodes | | keep; answer 413, not 400 |
| S68 | Request field bounds | `secretValue` 64 KiB, roles 40/200, keys 1-32, labels 120, claims 64/1,024/16 … | `api/routes.ts` | d | | | keep; one source for MCP's copies |
| S69 | `GET /audit` limit | 1-500, default 100 | `api/routes.ts:773` | e | client and CLI use 500, UI 200 and 50, MCP 50 and 200 | | one page size |
| S70 | `READS_BEHIND_MS` | 5 s | `api/audit.ts:672` | c | "a few ticks" | | compute from `TICK_MS` |
| S71 | `optimistic` attempts | 16, no backoff | `api/secrets.ts:657` | e | "bound the work under contention" | | cite |
| S72 | `heldWrite`, `admitHeld`, `retrying` tries | 3 | `api/secrets.ts:1016`; `members.ts:813`; `api/changes.ts:274` | b | two-trips.md; `MaxTries` in `formal/Writing*` | | keep |
| S73 | MCP bounds | bodies 256 / 16 KiB, `TTL_MS` 1 h, `WAIT_MS` 25 s, `MAX_CONNECTIONS` 20, approvals 5 / 10 min, `MAX_PENDING` 5 … | `mcp/*.ts` | b / d | | | keep |
| S74 | Postgres tunnel | `STARTUP_MS` 30 s, `MAX_STARTUP` 10 kB, `MAX_LOGIN` 64 KiB, `CANCEL_MS` 5 s, SCRAM ≤ 100,000 rounds | `plugins/postgres-tunnel.ts:182-441` | e / d | | | keep, cite |
| S75 | Credential `limit` (`perMinute`, `perDay`) | none by default; ≥ 1 | `credential-proxy.ts:3976-3990` | b | the operator's own (#308) | by design | keep |
| S76 | `rotateAfterDays` | 365 unless the deployment says; `null` turns it off | `config.ts:43, 62` | b | a deployment's policy: a value unchanged this long is flagged, never refused | | keep |
| S77 | `WRITES_LOST`, `REFUSAL_LOG_MS` | 3 writes again a beat; a refusal logged once a minute by reason and service | `plugins/audit-watch.ts:149`; `api/workloads.ts:418` | e | | | keep, cite |
| S78 | AWS STS request quota | 600 requests a second per AWS account and Region, shared by `GetCallerIdentity`, `AssumeRole`, `GetSessionToken` and three more; adjustable by a support ticket | `workloads/aws.ts:284-294` | a | AWS's [STS request quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-sts-requests). Every AWS proof a binding could take is one `GetCallerIdentity`, forwarded as the workload signed it and not cached, so it counts against the workload's own account, at the endpoint it names. A regional host (`sts.<region>.amazonaws.com`) spends that Region's quota. The global host (`sts.amazonaws.com`, which coffre accepts and checks as signed for us-east-1, `workloads/aws.ts:44, 82-102`) has a quota of its own, apart from every regional one, and is served in us-east-1 unless the DNS lookup goes through Amazon's resolver in a default Region ([global endpoint changes](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html#reference_sts_global_endpoint_changes)). Coffre's server makes the request, so from Cloudflare or a host outside AWS it is us-east-1 | ⚠ CI | keep; Q4: 1,000 AWS sign-ins a second from one account needs the quota of the endpoint they use raised first |

Format, fine: the CSP nonce (16 B), HSTS max-age, the Postgres protocol
magic numbers, the SCRAM sizes, `HANDLE` (43 chars), the hmac MAC (32 B),
DER and OIDs, the private address ranges, PKCE patterns, UUIDs, hex
digests, provider-id and plugin-name patterns.

### 4.3 `@coffre/db` (`packages/db/src`) and the SQL

| ID | Name | Value | Where | Class | Source / why | Bites | Verdict |
|---|---|---|---|---|---|---|---|
| D1 | Node pool `max` | 10 | `connect.ts:26` | e | "as node-postgres's pool was" (986fb7fc, #382) | ⚠ Node | derive (#11) |
| D1b | Node `idle_timeout` | 10 s | `connect.ts:26` | e | pg's `idleTimeoutMillis` | | keep, cite pg |
| D2 | Migrator `lock_timeout` | 5 min, session-wide | `migrate.ts:412` | e | meant for the advisory lock (277928a5) | ⚠ deploys | fix (#29) |
| D3 | `HyperdrivePool` `connect_timeout` | 30 s (driver default) | `postgres-js/index.ts:663` | e | not overridden | | #33 |
| D4 | `HyperdrivePool` `max` | 1 a call | `hyperdrive.ts:228` | a | several connections per call were cancelled as hung (8c05262e, #80) | | keep |
| D5 | `HyperdrivePool.end(by)` | the use's deadline | `hyperdrive.ts:180` | c | `USE_DEADLINE_MS` (T170) | | keep |
| D6 | `idle_timeout` on Durable Objects | 10 s / 1 s | `hyperdrive.ts:229` (callers) | e | | | keep, cite |
| D7 | `max_lifetime` | null, set twice | `postgres.ts:41`; `hyperdrive.ts:231` | b | a backup's session holds its snapshot | | one place |
| D8 | URL settings sent to Postgres | `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` | `postgres.ts:318` | b | they outrank role settings; setup strips them from the hot URL | | keep |
| D9 | `query_timeout` in a URL | refused | `postgres.ts:305` | b | | | keep |
| D10 | SQLite busy timeout | 5 s | `connect.ts:36` | e | tests and dev | | keep |
| D11 | Driver `max_pipeline` | 100 | `postgres-js/index.ts:661` | e | upstream | | keep, cite; on Node it is what lets a busy pool take more (section 2); on Workers a call's one connection sends its own queries only |
| D12 | Driver redial backoff | (0.5..1) × min(3^n ÷ 100, 20) s | `postgres-js/index.ts:665` | e | upstream; Node waits up to 20 s after 7 failed redials | Node outage recovery | cap at the use deadline on the hot pool |
| D13 | Driver `keep_alive` | 60 s | `postgres-js/index.ts:666` | e | no effect on Workers (no `setKeepAlive`) | | keep, note |
| D14 | Parameter cap | ≥ 65,534 refused | `postgres-js/connection.ts:188` | a | Bind's Int16 count (off by one, from upstream) | | keep |
| D15 | Write coalescing | 1,024 B | `postgres-js/connection.ts:252` | e | upstream | | keep |
| D16 | `ROWS_AT_ONCE` | 3,000 rows × 21 params | `log.ts:442` | a | under 65,535 (#278) | | keep |
| D17 | `BATCH_BYTES` | 8 MiB | `log.ts:507` | a | within a Worker's 128 MB (#242) | | keep |
| D18 | `LOOK_BACK` | 32 pages × 32 | `log.ts:621` | e | none (T79) | | cite |
| D19 | Outage codes | 08xxx, 53300, 57P01-3, 58000 … | `dialect.ts:132-139` | a | Postgres and Hyperdrive codes (Hyperdrive's 15 s wait for a slot) | | keep |
| D20 | `holdHotLogin` | 1 s / 2 s | `migrate.ts:85-86` | c | = 0022 | | one source (#14) |
| D21 | Role-catalog retry | 5 × 0.2 s | `migrate.ts:79, 97` | d | another database's migrate | | keep |
| Q1 | `coffre_vault_hot` `lock_timeout` | 1 s | 0022:660 | b | R53, decision 13 | one principal's new keys | keep |
| Q2 | `coffre_vault_hot` `statement_timeout` | 2 s | 0022:661 | b | R53 | | keep |
| Q3 | App and vault logins | no statement or idle timeout | – | – | app statements have no bound in Postgres | | Q5 |
| Q4 | `sign_in`, `revoke_credential`, `change_bindings`, `issue_token` | `lock_timeout` 1 s each | 0037:6; 0047:27, 73; 0064:4, 84 | b | busy, asked again | | keep |
| Q5 | `prune_bulk`, `prune_vault_releases` | `lock_timeout` 3 s | 0022:552; 0021:2 | e | copied | | keep, cite |
| Q6 | `drop_day`, `drop_reads_day` | 100 ms | 0027:49; 0050:42 | b | uses never queue behind the DETACH (#389) | | keep |
| Q7 | `drop_tiles` | 1 s | 0027:81 | e | | | keep, cite |
| Q8 | `deadline_max()` | 3,000 ms | 0022:121 | c | = `USE_DEADLINE_MS`, untested | | test (#15) |
| Q9 | Clock ahead | 60,000 ms | 0068:215, 451 | b | | | test (#16) |
| Q10 | Cap refresh | `greatest(1, least(60000, window ÷ 10))` | 0068:150, 481, 1075 | b | | | test (#17) |
| Q11 | Bulk set read | `LIMIT i.cap_count` | 0068:474 | b | the policy's cap | | keep |
| Q12 | Chain depth | ≥ 3 | 0068:311, 1183, 1438 | d | = `MAX_PARENTS` | | test |
| Q13 | Named batch | `n > p_limit` | 0068:1151 | b | `uses.batch` | | keep |
| Q14 | Spent tokens, releases, bulk rows kept | 2 h; 25 h; window + refresh + deadline + 1 h | 0016:6; 0021:6; 0022:555 | c | | | test each against its TS twin |
| Q15 | Days made ahead | −1..+3 | 0035:3; 0049:171 | b | `DAYS_AHEAD` | | keep |
| Q16 | `sign_in`'s binding row lock | `FOR UPDATE`, held to commit; waiters up to its 1 s `lock_timeout` | 0037:39-43, 82-91 | b | `BindingLocked`: `RateHeld`, `EndedBindingEndsCredentials` (`docs/formal.md:1941`) | ⚠ CI: one binding's sign-ins take turns | measure, then #36 |

### 4.4 `@coffre/core`, `@coffre/client`, `coffre` (CLI), `@coffre/ui`, `@coffre/conformance`

| ID | Name | Value | Where | Class | Source / why | Bites | Verdict |
|---|---|---|---|---|---|---|---|
| C1 | KMS `CONCURRENCY`, `ATTEMPTS`, `TIMEOUT_MS`, backoff | 8 a provider object, one Decrypt per AWS-backed key opened; 3; 5 s; 100 × 4^(n−1) × (1-2) ms | `core/src/kek/aws-kms.ts:33-36, 150` | e | "a Worker opens at most six connections anyway" (cf090259) | ⚠ with KMS | replace the slots (#4); cite the rest |
| C2 | `HYPERDRIVE_CONNECTIONS` | 5 to 20 | `cli/src/connections.ts:10` | a (5, and 20 on Free) / e (20 on Paid) | "the most Free allows, which is plenty" (T78, #202) | ⚠ | #12 |
| C2b | `HELD_BACK`, `CONFIGS` | 3, 3 | `cli/src/connections.ts:7, 16` | e / c | 3 kept "for the administrator, `coffre migrate` and the host's own tools", a guess; the even split of `max_connections` is derived. No headroom for Hyperdrive past its soft limit is sized anywhere | | Q2 |
| C3 | Tunnel flow (client and CLI) | 1 MiB, 128 KiB, 1 MiB, 30 s | `client/src/workload-postgres.ts:53-61`; `cli/src/tunnels.ts:19-43` | d / e (30 s: "under Cloudflare's 100 s idle", which Cloudflare's WebSocket page, updated 2026-08-14, does not give: it says only that an idle connection is closed after "a period of time") | defined twice; the ping also finds a dead peer, a reason of its own | | #26; cite the ping's dead-peer purpose, and the idle timeout as unverified |
| C4 | Retyped defaults | 366, 90 d, 30 d / 24 h / 15 min, 40 / 32 / 200, 120 | `cli/src/manage.ts:883-892`; `cli/src/trust.ts:235-775`; `ui/src/components/*` | c | | | #27 |
| C5 | SDK `retryAfter()` cap, `backoff()` | 300 s × (1-1.5); 1 s × 2^n ≤ 60 s × (0.75-1.25) | `client/src/workload.ts:704-712` | e | "a fleet's replicas spread out" (121c64ca); waited only when no session is left | ⚠ sidecar | #34 |
| C6 | SDK `/use` resend | once, on 401 `use_dpop_nonce` only | `client/src/workload.ts:467` | b | | | keep |
| C7 | SDK enrollment and session timers | 100 s nonce, 5 / 10 min waits, 30 s renew, 5 s margin, 3 s logout | `client/src/workload.ts:124-332` | c / e | | | import `EPOCH_MS`, cite the rest |
| C8 | `MAX_DIGESTED_BODY` | 95 MiB | `client/src/dpop.ts:184` | a | Cloudflare's 100 MB on Free and Pro | | keep |
| C9 | `coffre serve` | Node's and undici's defaults; no concurrency cap | `cli/src/serve.ts`; `cli/src/workload.ts:159-260` | – | | | keep: no artificial limit |
| C10 | CLI retries | 2, after 2 / 5 s × (0.5-1.5); RA ≤ 15 s; 409 once after 300 ms | `cli/src/main.ts:269-373` | b | "a CI step, not a daemon" (W187) | | keep |
| C11 | `HOT_SETTINGS` | 1 s / 2 s | `cli/src/setup.ts:658` | c | = 0022 | | #14 |
| C12 | `USE_DEADLINE_MS` | 3 s | `core/src/vault.ts:1765` | b | R53 | ⚠ under any queue | keep, the one source |
| C13 | `USE_METADATA_LENGTH` | 16,384 | `core/src/vault.ts:1495` | e | "a use naming a few hundred keys" | | cite |
| C14 | Token and session lifetimes | personal ≤ 7 d, service ≤ 366 d (D4: 365, or the deployment's lower maximum; #516), device code 10 min, exchanged credential 5 min, session 1 h | `core/src/access.ts:581-590`; `core/src/identity/workloads.ts:677-680` | b | | | keep |
| C15 | Clock skews (D3: on hold) | ID token 30 s, sign-in proof 60 s, DPoP 300 s, Access 0 s | `core/src/identity/*.ts` | b | each has its reason | | keep |
| C16 | `MAX_TOKEN_AGE_SECONDS` | 3,600 | `core/src/identity/workload-token.ts:18` | b | | | keep |
| C17 | Binding policy ranges | sessionHours 1-168, sessionDays 1-90, overlap 1-60, replicas 1-64 | `core/src/identity/workloads.ts:841-844` | e | replicas 64 may bite a large fleet | | cite, or raise replicas |
| C18 | Input bounds | slugs 63, names 120 / 64 / 128, emails 320, scopes 1,000, constraints 32, JWKS 32 keys, WebAuthn sizes … | `core/src/schemas.ts` and others | d / a | | | keep |
| C19 | `MAX_PARENTS` | 3 | `core/src/vault.ts:592` | b | forking.md | | keep |
| C20 | `MAX_PROXY_ITEMS`, `MAX_DEFINITION_BYTES`, proxy text bounds | 256, 8,192, … | `core/src/proxy.ts:64-443` | c / e / d | the index stays under 17 KB | | keep |
| C21 | `MAX_MESSAGE_BYTES` | 1 MiB | `core/src/proxy-match.ts:292` | a | CPU on Workers' Free plan | | keep |
| C22 | Access JWKS cache, OIDC discovery, sign-in HTTP timeouts | 30 s / 10 min, 1 h, 10 s | `core/src/identity/verifier.ts:39-40`; `signin/oidc.ts:14, 52` | e | jose's defaults | | keep, cite |
| C23 | GitHub App listing | 100 a page, 40 requests, 5 min margin, 10 s | `core/src/identity/github-app.ts:72-78` | a / c / b / e | | | keep |
| C24 | Audit verification | `PAGE` 100, `MAX_SIGNATURES` 100, `VOUCHED_AT_ONCE` 2,000 | `core/src/audit/verify.ts:88`; `note.ts:122`; `vault.ts:606` | e / a / d | Go's `note.Open` | | keep |
| C25 | CLI setup and verify timers | 10 s, 90 s, 2 s, Cloudflare's 50 a page; `COVERED_MS` 90 s, `LISTED_WITHIN_MS` 20 s | `cli/src/setup/*.ts`; `cli/src/verify/token.ts:74-77` | e / c | | | keep; conformance imports the verify pair |
| C26 | HSTS check | `max-age=\d{7,}` | `cli/src/verify/anonymous.ts:97` | e | 7 digits is ~11.6 days; the message says "months" | | fix the pattern |
| C27 | UI timers and pages | staleTime 10 s, audit page 200, actions 50, reveal 45 s, lookup 700 ms, proxy limit ≤ 9 digits | `ui/src/lib/queries.ts`; `ui/src/components/*` | e / b | the 9-digit cap silently truncates | | keep; one audit page size (S69) |
| C28 | Conformance requirements | bulk 1,000, credential ≤ 5 min + 5 s, 429 within 200 tokens, hot login 1 s / 2 s, read listed in 20 s, readiness 10 / 20 s | `conformance/src/checks/*.ts`; `main.ts:36` | c | | | import each from its source |
| C29 | `MAX_BINDINGS` | 16 live bindings a service; the 17th gets 409 | `core/src/identity/workloads.ts:184`; `server/src/api/workloads.ts:641`; read as a sign-in's candidate count, `:319` | e | none written (a2eece64, #100). It also bounds a sign-in's work: every candidate binding of the issuer is read and matched | a service signed into from more than 16 CI configurations | cite the sign-in's work, or size it from that work's cost |
| C30 | Binding shape | claims 16, a claim 256 B, issuer 400 B, `reads` 64 environments × 256 keys, `sources` 16 | `core/src/identity/workloads.ts:185-187, 253, 699-701` | d | input bounds on a row every sign-in reads | | keep |
| C31 | CLI tunnel `HANDSHAKE_MS` | 70 s for coffre to answer the upgrade, then both ends close | `cli/src/tunnels.ts:44-50, 61` | e | its comment says it outlasts coffre's 15 s wait for a turn and 45 s to admit (S50, S47), so coffre's refusal is the one said. It does not: `MOST_WAITING_MS` does not end the wait, it lets 4 admissions run at once and the connection still waits its turn (`cloudflare-sockets.ts:203-218`). With 4 admissions under way, the 5th to 8th connections can wait one 45 s wave, then take 45 s of their own: 90 s, past 70. And 15 + 45 is 60, not 70: the 10 s is an unexplained margin | | a real bound on coffre's queue first (a deadline for the whole wait, or a policy), then compute this from it |
| C32 | DPoP proof bounds | proof 2,048 characters, 32 signed headers | `client/src/dpop.ts:20-22` | d | the verifier refuses past them, the signer never makes them | | keep |
| C33 | SDK redirects | 20 | `client/src/workload.ts:137` | a | the Fetch standard's redirect limit | | keep |
| C34 | CLI and core timers | `watch`'s interval 5 s to 24 h (`--interval`), and after a failed round a wait that doubles up to the larger of 15 min and that interval (`--interval 1h` keeps 1 h), a new Worker 90 s to answer, a pasted address retried 2 s, clipboard cleared after 30 s, clipboard tool 3 s; an unwritten fork 10 min (`UNWRITTEN_FORK_MS`) | `cli/src/watch.ts:12, 36-43, 92`; `cli/src/workers.ts:103`; `cli/src/cloudflare.ts:215`; `cli/src/clipboard.ts:9, 89`; `core/src/access.ts:230` | e / b | the fork's is argued ("a fork writes its row only well within it"); the CLI's are a person's patience | | keep |

Format, fine: IV 12, tag 16, KEK and DEK 32, hashes 32, tile height 8
and width 256, seeds 32, RSA 2,048-4,096, token patterns, 2^53 leaves.
Conformance harness timeouts (Chrome, SIGKILL, polls) and the dev IdP's
token lifetimes are test tooling, not product limits.

### 4.5 Deployments, dev and benchmarks

| Where | What it sets | Note |
|---|---|---|
| `examples/workers/*/wrangler.jsonc`, `dev/deployment/*/wrangler.jsonc` | `nodejs_compat` only: no `limits.cpu_ms`, no `placement` | Paid's default CPU is 30 s; Free's 10 ms is what R25 and R27 hold to |
| `examples/workers/app/wrangler.jsonc:54-61` | rate-limit bindings: workloads 30 / 300, MCP 30 / 120 / 300, all per 60 s | S7, S8b. Cloudflare's rate limits are approximate and per location, not global |
| `examples/node/app/src/coffre.ts:46, 54` | `processLimits` with the defaults retyped | #10 |
| `examples/*/vault` | no `uses`, no `bulkLimit` | every vault runs on V1's 10 |
| `docs/deploy.md:789-825` | `--origin-connection-limit=20` per config | C2 |
| `dev/deployment/app/src/coffre.ts:107, 110` | dev-only proxy limits (60 / min, 10 / min) | dev |
| `packages/server/test/bench/ci.ts:443`, `proxy-uses.ts:71-87` | `pools: { app: --use-pool, vault: 8, hot: 16 }` | its hot pool has 16 connections, but admission stays 10: it passes `createDatabase(hotPool)` to `localVault`, which V2's probe can't read |
| `packages/vault/test/bench/standing.ts:85` | `uses.inFlight: 1000` | |

### 4.6 TLA+ models (`formal/`)

| Module | Constant | Mirrors | As a parameter? |
|---|---|---|---|
| HotPathOne | `D` (deadline), `BulkCount`, `BulkWindow`, `Refresh`, `MaxSkew`/`Ahead`, `Holds`, `Chunks` | `USE_DEADLINE_MS`, `bulkLimit` (R52), `refreshMs`, `USE_AHEAD_MS`, Hyperdrive holding a call, `WINDOW_MAX` | yes |
| Batching, Bulk | `BulkCount`; `Cap`, `Window` | `bulkLimit` | yes |
| Credentials, Lifecycle | `RateCap`, `Rate`; `BindingLocked` | the sign-in count per binding (S8, V30); the binding's row lock (Q16) | yes: removing #8 removes a protection the model shows necessary, so the model changes with it; #36 changes the lock |
| Tunnel | `R`, `D`, `Bound` | `recheckSeconds`, `RECHECK_DEADLINE_MS` | yes, but `Bound = R + D` is entered by hand |
| Routing, Workload | `W`; `CacheTicks`, `Recheck`, `Life` | `cacheSeconds`; `WORKLOAD_RECHECK_MS` | yes |
| Audit, Reads | `Walk`, `AppBatch`, `CkptWalk`, `ScrubWalk`; `Chunk` | `CHAIN_WALK`, `BATCH`, `WALKS`; `PROJECTED_AT_ONCE` | yes |
| Seal | `Fresh`, `MaxTicks`, `MaxStalls` | `FRESH_MS`; ticks are untimed | partly |
| Writing | `MaxTries` | `retrying(…, 3)` | yes |
| none | – | `READ_HEAD_WAITERS`, `uses.inFlight` (Probing treats overload as a nondeterministic `busy`), pool sizes, `TICK_MS`, `WITNESS_DEADLINE_MS`, `TAKE_OVER_MS` | not modelled; deleting V1 changes no model |

## 5. Platform facts, checked 2026-11-04

Each against the vendor's page, quoted.

**Cloudflare Workers** ([limits](https://developers.cloudflare.com/workers/platform/limits/), updated 2026-10-29):

- CPU: "10 ms" on Free; "5 min (default: 30 seconds)" on Paid. Waiting
  on network "does not count toward CPU time".
- Requests: "100,000/day" on Free, resetting at midnight UTC, then error
  1027 (or the route fails open); "No limit" on Paid. At R44's 1,000
  requests a second, Free's day lasts about 100 seconds: **every R44
  number in this document assumes Workers Paid.** Free's limits matter
  only where R25 and R27 hold a request to Free's 10 ms of CPU.
- Memory: "128 MB", "per-isolate, not per-invocation. A single isolate can
  handle many concurrent requests." No number for requests per isolate is
  documented anywhere.
- Connections: "Each Worker invocation can have up to six connections
  simultaneously waiting for response headers … a seventh … is queued".
  Since [2026-04-09](https://developers.cloudflare.com/changelog/post/2026-04-09-relaxed-connection-limiting/)
  it no longer cancels stalled connections. "Workers triggered via Service
  bindings share the same connection limit." A Hyperdrive socket's place
  in this rule is not documented.
- Subrequests: 50 on Free; "10,000 (up to 10M)" on Paid, since
  [2026-02-11](https://developers.cloudflare.com/changelog/post/2026-02-11-subrequests-limit/).
  Anything that assumes 1,000 on Paid is stale.
- Service bindings: "a maximum of 32 Worker invocations" per request; RPC
  payloads up to 32 MiB.
- `waitUntil`: "up to 30 seconds after the response".
- [Rate-limit bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/):
  period "Must be either `10` or `60`"; "approximate and apply separately
  in each Cloudflare location".

**Durable Objects** ([limits](https://developers.cloudflare.com/durable-objects/platform/limits/)):
"An individual Object has a soft limit of 1,000 requests per second."

**Hyperdrive** ([limits](https://developers.cloudflare.com/hyperdrive/platform/limits/),
[API](https://developers.cloudflare.com/api/resources/hyperdrive/subresources/configs/methods/create/)):

- Origin connections per config: "~20" on Free, "~100" on Paid; "If not
  specified, defaults to 20 for free tier and 60 for paid tier"; "a
  minimum of 5 connections".
- It is "a 'soft limit'": "it is possible for Hyperdrive to make more
  connections to your database than this limit" during network failures,
  so set it "lower than the limit of your origin database"
  ([tune connection pool](https://developers.cloudflare.com/hyperdrive/configuration/tune-connection-pool/),
  updated 2026-06-09).
- "Hyperdrive does not limit the number of concurrent client connections
  from your Workers."
- Query duration: 60 s. Initial connection: 15 s. Idle: 10 min.
- Pooling: "transaction mode"; `pg_advisory_xact_lock` is supported, but
  not session-level advisory locks.
- No queue size or wait is documented for a full pool. Our
  `dialect.ts:132` records 15 s before error 58000.

**Postgres 16**:

- `max_connections` "typically 100"; `superuser_reserved_connections` 3.
- `statement_timeout`, `lock_timeout` and
  `idle_in_transaction_session_timeout` all default to 0 (off).
  `lock_timeout` "applies separately to each lock acquisition attempt".
- A function's `SET` clause is restored on exit.
- Bind carries an Int16 count of parameters (65,535, read unsigned).

**AWS KMS** ([request quotas](https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html)):
the shared quota for symmetric cryptographic operations is "10,000
(shared)", or 20,000 or 100,000 in some regions, per account and region,
and adjustable.

**AWS STS** ([request quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-sts-requests)):
"600 requests per second, per account, per Region" for requests made with
AWS credentials, shared by `AssumeRole`, `DecodeAuthorizationMessage`,
`GetAccessKeyInfo`, `GetCallerIdentity`, `GetFederationToken` and
`GetSessionToken`; an increase is "a ticket with AWS support". The global
endpoint ([endpoint changes](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html#reference_sts_global_endpoint_changes)): "Requests handled by the AWS STS
global endpoint do not share a requests per second quota with Regional
AWS STS endpoints", and they "will continue to be served in US East (N.
Virginia)" when resolved by "any other DNS provider" than Amazon's.

**Drivers:** node-postgres's `max` "By default this is set to 10"
([pool](https://node-postgres.com/apis/pool)). postgres.js: `max: 10`,
`connect_timeout: 30`; version 4 adds `queue_timeout`, which "rejects it
with `QUEUE_TIMEOUT` if it waits longer, without ever sending it"
([README](https://github.com/porsager/postgres)).

## 6. Questions for Erwin

- **Q1. Fast refusal on Workers.** Two steps (section 2). First, replace
  the count of 10 with one computed from memory: what share of an
  isolate's 128 MB may uses in flight take (I'd say half), with the bytes
  per use measured locally? Second, a refusal rule from recent outcomes:
  A (predicted lateness) or B (adaptive throttling, the published one).
  Neither is proven; I'd like one run on your Cloudflare to compare them
  with no fast refusal at all (R34, under $5, about an hour of a throwaway
  deployment): goodput at the ceiling, and how fast admission reopens.
  Without the run, the choice is no fast refusal, the excess answered
  `late` within 3 s.
- **Q2. Pool sizes on Node.** The database's `max_connections`, less
  what is reserved and held back, is one budget for every process's pools
  and their checkpointers'. Either setup writes each pool's size from
  that budget and a replica count the deployment states (scaling out past
  it oversubscribes the database: 53300), or a Node deployment runs one
  pooler (PgBouncer) in front of Postgres and sizes its pools to it, as
  Hyperdrive does on Workers. Which? And should the split stay even, a
  third each, when the hot path carries most of the load?
- **Q3. Where the vault learns its config's connection share** (for
  `READ_HEAD_WAITERS`, #13): from setup, written into `vault(…)`; or a
  fixed fraction, documented. The first is one more line of config, but a
  derived one.
- **Q4. CI sign-in limits.** *Answered: D5; the proposal that follows from it is §3.6.* R44 names CI sign-in a hot path at
  1,000+/s. Today, per Cloudflare location (or Node process), 300
  exchanges a minute in all and 30 per address; for the instance, 60 a
  minute per binding; and one binding's sign-ins take turns on its row
  (#36). Proposal: keep the per-address count as it is, counting
  attempts (anyone may send a token, and each costs a signature check);
  drop the 300 for everyone. Counting only refused exchanges would spare
  a fleet behind one NAT address, but it needs another admission: a
  limiter counts as it checks, with no check-only call and no refund
  (`signin/config.ts:139`), so a count taken after the signature check
  can't refuse before paying for it, the cost the count is there to
  guard. Left open, not proposed. The per-binding 60 is the design's policy
  (`docs/design/oidc.md:174`), modelled (`RateCap`): keep it at a number
  you set, set it per binding in its policy, or drop it? Whatever you
  pick, one binding's sign-ins stay one at a time until the row lock is
  redesigned (#36, TLA+ first), and the 32 in flight stays until a
  sign-in has a deadline (#35): what deadline do you want for a sign-in
  under load (R58 allows 1-2 s)? An AWS fleet at that rate also needs its
  own account's STS quota raised at the endpoint it signs for (600 a
  second per Region at a regional host; the global host's is apart, S78):
  a prerequisite for the deployment, not a coffre setting.
- **Q5. A statement bound for the app's and vault's logins.** Only the
  hot login has a `statement_timeout`. An app statement has no bound in
  Postgres. Should the app's and vault's logins get one, derived from
  what is left of each call's own deadline, without starting it again?
  V19 has two origins: 5 s from the first decision for a plain read, and
  5 s (10 s with a key service) from before the KEK check for
  `unwrap`, `wrap` and `rewrap`, whose check spends from it first.
- **Q6. Retention can't be turned on in the standard setup.** `retainDays`
  exists, but only a Node deployment that runs its own checkpointer
  (`runCheckpointer`, `keepCheckpointer`) can reach it. The uses log
  grows about 13.6 GB a day at 1,000/s, and a day kept holds about 68 GB
  in all, the reads' projection and tiles included ([config.md](config.md),
  Q6). It isn't a limit, but it is a
  knob that a deployment needs and, in the standard setup, can't set.
  Expose it there (policy: days kept), or keep every day?
- **Q7. A bound on the proxy's upstream request.** The credential proxy's
  `fetch` to an upstream has no timeout (S16). The values' `sendBy` is not
  one: it bounds when the credentials may start going out, not an upload
  or a response. Bounding the upstream is a choice: a slow upstream holds
  the request's memory and the Worker's connection, but a long upload or
  a streamed response is legitimate. Leave it unbounded, or give it a
  limit, for the headers only or for the whole response?
