# Limits: every cap, timeout and rate, and where its number comes from

This note covers the bounds coffre puts on load: what bounds the hot paths, why each number is
what it is, and the limits whose number has no source yet. The settings a deployment chooses, and
the values coffre derives from them, are in [config.md](config.md). Each constant's own comment, in
the code, carries its derivation; this note gives the picture and points at them.

## The rule

Every cap, queue, timeout or rate limit traces to one of:

- a real external limit: Cloudflare, Hyperdrive, Postgres, AWS, a protocol;
- a policy choice, or a security choice a design doc states;
- another value it is computed from, never restated as a number;
- a defensive bound against abuse or garbage input (a size, a list length), generous and written
  down.

Its source is written beside it. One resource gets one value: a limit derived from another is
computed in code, not configured. A guess, a copied default or a leftover is not a source. Under
overload coffre refuses fast, at once and cheaply, rather than letting a queue grow.

The load the numbers are sized for: 1,000 or more `/use` calls a second on Workers, hundreds of
them at once, some from one principal; CI sign-in at 1,000 a second. Every such number assumes
Workers Paid (Free's 100,000 requests a day last about 100 seconds at that rate); Free's 10 ms of
CPU still matters where a single invocation must fit it.

Terms used below:

- **use**: one `/use` call, a workload asking the vault for a key's value.
- **hot login**: `coffre_vault_hot`, the Postgres login every use runs as, with its own Hyperdrive
  config on Workers and its own pool on Node.
- **fence**: the instance's one advisory lock, which every use takes shared and a revocation takes
  exclusive.
- **seal**: the checkpointer signs the log's newest entries every 500 ms (`TICK_MS`); an entry
  above the newest signed pair is unsealed.

## `/use`

### What each runtime has

**On Workers there is no pool per isolate.** Each vault call opens its own Hyperdrive client with
one connection (`max: 1` in `packages/db/src/hyperdrive.ts`) and closes it when the call ends:
several connections per call were now and then cancelled as hung. What the uses share, they share
with every isolate at once:

| Resource | Limit | Shared by |
|---|---|---|
| Hyperdrive origin connections, hot config | 5 to 20 on Free, 5 to 100 on Paid; a soft limit | every isolate, worldwide |
| Postgres CPU and `max_connections` | the database's | every config |
| Connections per invocation | 6 waiting for response headers, the 7th queued | one request and its service-binding calls |
| Isolate memory | 128 MB | one isolate |
| Requests per isolate | no documented number | – |

The Hyperdrive pool is the ceiling. Measured on Cloudflare (hot-path-one.md, "Cloudflare"): a
pool of 40 served about 1,040 uses a second, Little's law at about 38 ms a use. Past that ceiling,
goodput held: a call Hyperdrive kept past its deadline is cut (`HyperdrivePool.end(by)`), and
Postgres refuses one that still arrives by `clock_timestamp()`, so the database does no wasted
work. The same run spread 2,500 uses a second over at least 150 isolates, so a count per isolate
cannot bound the shared pool: a cap of 8 each still admitted about 1,000 calls at once.

**On Node the pool is real, and the driver pipelines.** The hot pool has `max` connections
(`openDatabase` in `packages/db/src/connect.ts`, 10 unless the caller says). A query asked while
every connection is busy is sent on a busy one, behind what it already runs, up to 100 queries a
connection (`max_pipeline` in `packages/db/src/postgres-js/index.ts`). Postgres runs one
connection's queries in turn, so pipelining saves round trips, not execution time: a pool serves
about `max ÷ execution time` one-statement uses a second. A transaction keeps its connection from
BEGIN to COMMIT, and a pipelined statement waiting on a lock holds up every statement behind it.

### Admission: places in flight, from memory and CPU

An isolate (Workers) or process (Node) holds at most `USES_IN_FLIGHT` keys in flight
(`packages/core/src/memory.ts`). A call holds one place for each key it uses, from its admission
until it has answered, its wait at the key service included. Past it, the use is answered at once,
503 `overloaded` with `Retry-After: 1`, before it takes a connection.

```
USES_IN_FLIGHT = min(USES_BYTES ÷ USE_IN_FLIGHT_BYTES, USE_DEADLINE_MS ÷ USE_CPU_MS)
               = min(64,000,000 ÷ 30 KiB, 3,000 ms ÷ 2.4 ms) = min(2,083, 1,250) = 1,250
```

- Half the isolate's 128 MB goes to uses in flight (a policy choice). 30 KiB is the largest
  measured cost of one key held (`packages/vault/test/bench/held.ts` says how to measure again).
- 2.4 ms is one warm use's CPU in the vault's isolate (`pnpm bench:workers`): a use admitted past
  what the CPU can serve within the deadline could only be answered `late`.

The deadline bounds how long each use lives, not how many live at once: a burst reaches the
isolate before any latency is known. So the count is still needed, but it is computed, never set.
On Node the same two bounds hold per process, as defensive bounds.

A call of more keys than the count runs alone. A place outlives its use's deadline by up to
`HELD_PAST_DEADLINE_MS`, 2 s, the hot login's `statement_timeout`. A batch's statement uses at most
100 keys (`uses.batch` in `packages/vault/src/use.ts`): at about 0.4 ms a key under the fence, about
40 ms, which a change or the checkpointer's barrier waits behind. The vault isolate's own maps (names
to ids, seals, covers, a route's places and keys) hold 10,000 entries each, counted by entries, not
bytes, and unmeasured.

### Refusing fast on overload: adaptive throttling

Places bound memory; they do not refuse fast when the shared pool or Postgres is saturated. Each
isolate sees that in its own uses' outcomes, at the same time as every other. `Throttle`
(`packages/vault/src/throttle.ts`) counts, over the last two use deadlines (6 s), the uses it
answered or refused (`requests`) and those settled before their deadline (`accepts`), and refuses a
new use at once with probability

```
p = max(0, (requests − K × accepts) ÷ (requests + 1)),   K = 1.5
```

Example: 2,500 uses a second offered, 1,040 answered in time, over a window: 15,000 requests,
6,240 accepts, so p ≈ 38% refused at once and about 1,560 a second let through, 520 of them late.

Why each choice:

- **K = 1.5, not the published 2.** A use let through past capacity is not refused cheaply
  downstream: it goes `late`, holding its place and a hot connection for the whole 3 s. Past
  K × capacity everything is refused and the K − 1 between goes `late`; at 2.5 times the capacity,
  the late outnumber the refused from K = 1.75 up, and at K = 2 half a burst went late on
  Cloudflare. Near K = 1 the refusals long outlive the overload, since what an isolate lets through
  grows by roughly K each window. In the model, K = 1.5 is back to full service 9 to 12 s after such
  a burst (`packages/vault/test/throttle.test.ts` holds the shape).
- **A 6 s window, not two minutes.** A use's outcome is known at most one deadline after it is
  asked; a two-minute window kept refusing a light load minutes after the burst.
- **p stays below 1**, so an isolate never shuts and needs no rule to reopen.
- **A use counts once its outcome is known**, not when asked: counted on arrival, a cold isolate's
  first burst would refuse itself (its 17th use, none answered yet, would see p = 16 ÷ 17).
- **Refusals are spread, not drawn**: each use adds p to a credit and is refused when the credit
  reaches 1. At p = 0.2, one use in five, in a fixed pattern.
- **What counts as not in time:** `late` (Postgres's lock or statement timeout included), a use
  refused because its places were taken, a connection the database or Hyperdrive refused, and a key
  KMS throttled to its last try. A use refused at once by KMS for another reason (a disabled key, bad credentials) does
  not count, so a misconfigured vault does not throttle itself.

### Hyperdrive connections

`coffre setup` gives each of the three Hyperdrive configs (app, vault, hot) an even share of what
the database lets its logins open (`hyperdriveLimit` in `packages/cli/src/connections.ts`):

```
⌊(max_connections − reserved − 3) ÷ 3⌋, at least 5, at most 20
```

Example: `max_connections` 100, 3 reserved: 31 each, cut to 20. At 25: 6 each. Lowering a config
to the share is right: left at Cloudflare's default (60 on Paid) the configs outgrow a small
database, which then refuses connections (53300). The 3 held back are for the administrator,
`coffre migrate` and the host's tools. Below a share of 5, `coffre setup` refuses and names the
`max_connections` it needs. The cap of 20 is Free's maximum, applied on Paid too: see
[Limits without a source yet](#limits-without-a-source-yet).

## Lock waits and deadlines

A use's path is the only true hot path. Writes may take longer, but they must not hold up uses: no
lock is held while a key service answers, and every wait for a lock is short and retried rather
than long.

| Name | Value | Where | Why |
|---|---|---|---|
| `USE_DEADLINE_MS` | 3 s | `packages/core/src/vault.ts` | a policy choice; held in Postgres too (`deadline_max()`), so no use is decided later than 3 s after its time |
| `HOT_LOCK_TIMEOUT_MS`, `HOT_STATEMENT_TIMEOUT_MS` | 1 s, 2 s | same | the hot login's settings, inside the deadline, so a statement cannot run on after its Worker gave up |
| `LOCK_WAIT_MS` | 500 ms | same | every other lock wait (app writes, vault decisions, the migrator): half a use's |
| `CALL_DEADLINE_MS` | 5 s | `packages/vault/src/vault.ts` | a vault read call, start to answer; a write's lock waits retry within it |
| `KEY_BUDGET_MS` | 5 s | same | every key operation of one call, with no lock held |
| `READ_LOCK_TIMEOUT_MS` | 3 s | same | a read's decision statements; longer is a queue holding a connection |
| `RUNTIME_STATEMENT_TIMEOUT_MS` | 60 s | `packages/core/src/vault.ts` | the app's and vault's logins: Hyperdrive's own bound on a query, so nothing running today is cut |
| `UNAVAILABLE_RETRY_AFTER` | 1 s | `packages/server/src/api/errors.ts` | `LOCK_WAIT_MS` in whole seconds, rounded up |

**A read's 5 s is nominal, not a strict total.** Its clock starts once the vault is prepared, not at
the call's start. Each transaction sets `lock_timeout` and `statement_timeout` once, at BEGIN, to
what is left (at most 3 s), and Postgres applies them per statement: two statements of 2.8 s each
end at 5.6 s, neither timed out. A strict bound would need the client to cancel the query at the
deadline. A write's work has no such bound; its lock waits are retried for up to 5 s from its first
attempt.

Why half a use's wait: Postgres grants a lock in the order it was asked, so a writer waiting for
the fence exclusive, or a DDL statement for a table, holds back every use that asks after it.
Example: a write queues for the fence; a use arrives 100 ms later and queues behind it. The write
gives up at 500 ms, so the use gets the fence with half its own 1 s to spare instead of being
refused `busy`.

The 60 s statement timeout is a ceiling, not a design value: it becomes a read call's 5 s once no
runtime statement grows with history (`scripts/growth-sweep-known.txt` empty). Transactions with a
deadline tighten it for themselves (`SET LOCAL`). It is a role setting, so a `statement_timeout`
in the login's URL outranks it ([deploy.md](../deploy.md), "Statement timeouts").

**The migrator** (`packages/db/src/migrate.ts`) waits `LOCK_WAIT_MS` for each table lock, so `/use`
never queues behind a DDL statement for long. All migrations run in one transaction, tried 5
times a second apart (`MIGRATION_LOCK_ATTEMPTS`, `MIGRATION_LOCK_PAUSE_MS`): that outlasts a holder
of a few seconds and gives up within about 7 s on one that will not end (a `pg_dump`, a session
idle in a transaction), naming the sessions that held the tables. Waiting for another migrator's
run, which holds no table, takes up to 5 minutes.

**Reads waiting for the log's head** are a separate resource with their own bound,
`READ_HEAD_WAITERS`, 16 across the deployment (its places are Postgres advisory locks). Secret
writes, rewraps and reads with no credential to use take the head; a use never does. A read holds
it about 150 ms through Hyperdrive, so 16 clear within 2.4 s of a read's 3; the 17th is refused at
once, holding no connection.

## AWS KMS

`awsKms` (`packages/core/src/kek/aws-kms.ts`):

| Name | Value | Why |
|---|---|---|
| `CONCURRENCY` | 6 requests of one call at once | Workers lets an invocation have 6 connections waiting for headers, a service binding's callee sharing its caller's; the same 6 on Node |
| `KMS_ATTEMPTS` | 3 | a retry policy, while KMS throttles, fails or does not answer |
| `KMS_ATTEMPT_MS` | 878 ms | the slowest p99 measured (506 ms, a Worker an ocean from its key, new connection) plus one lost segment's retransmit on that path (124 + max(2 × 124, 200) ms) |
| backoff | 100 ms × 4^(n−1), jittered up to twice | – |
| `KMS_REQUEST_MAX_MS` | 3,634 ms | one request with every retry: 3 × 878 + 200 + 800 |

Each attempt is cut at what is left of its operation's deadline, so a use's key opening ends by
the use's 3 s. A call's requests wait only for each other, never another call's
(`formal/KeyService.tla`): no request waits behind another request's hung KMS calls, nor on a
promise another request settles, which Workers would cancel with that request. Every AWS-backed key
a use opens is one Decrypt; KMS's own quota is 10,000 to 100,000 a second per account and Region.

**What `KEY_BUDGET_MS` covers.** All of a call's key operations share its 5 s, so a read with a key
service may take 5 s + 5 s. One request with every retry fits. A rewrap decrypts and then encrypts
each key: two full retry runs, 7.3 s, do not fit, so a rewrap whose decrypt spent its retries fails
and its caller retries. More than 6 keys run in waves of 6, each getting what the earlier left. A
budget covering every case would grow with the batch, and a caller's deadline cannot. A key
service's intent is overdue 15 s after it is recorded (2 × `CALL_DEADLINE_MS` + `KEY_BUDGET_MS`).

## Memory, per isolate

Workers ends an isolate past 128 MB, with every request it serves. `packages/core/src/memory.ts`
splits it into named shares:

| Share | Bytes | Holds |
|---|---|---|
| uses in flight (`USES_BYTES`) | 64,000,000 | the `/use` calls an isolate holds open |
| proxy bodies (`BODIES_BYTES`) | 16 MiB | request bodies the credential proxy reads whole, all at once |
| caches (`CACHES_BYTES`) | 16 MiB | answers kept between requests |
| runtime (`RUNTIME_BYTES`) | the rest, 30.4 MB | code and the runtime's own; the app's Worker holds 8.6 MB idle |

- **Caches** are `Lru` maps weighed in bytes, never counted in entries: the app's seven caches
  (the proxy's values, handles and UI state, and `Accesses`) each get an equal slice of
  `CACHES_BYTES`. Past its slice, a cache drops its least recently used entry, one at a time; it
  never clears all at once. Settled values only, never a pending promise.
- **Bodies.** The proxy reads a body whole up to `BODY_READ_WHOLE_BYTES`, 1 MiB; a larger one
  streams, up to 5 GiB (`MAX_STREAM_BYTES`, S3's single-request limit). A burst of large bodies is
  refused fast, 503 with `Retry-After`, rather than ending the isolate. Node's WebSocket messages
  are held to the same 1 MiB.
- **Field bodies.** A body the proxy fills a form or JSON field of is at most 64 KiB
  (`MAX_FIELD_BODY`, a token refresh's or a siteverify's), and at most 256 fields, 32 deep
  (`MAX_FIELDS`, `MAX_DEPTH`), refused before parsing, so a body built to cost the most costs no more
  than a real one.
- **Raw messages to sign** (`MAX_RAW_MESSAGE_BYTES` in `credential-proxy.ts`), 12 MiB, streamed,
  never held. Signing hashes the message twice (the HMAC and a `Content-Digest` check), 1.2 ms per
  MiB on Node, so (20 ms − 4 ms fixed) ÷ 1.2 ms ≈ 13 MiB, rounded down. That bounds the signing's own
  CPU; delivering the body is the platform's, as for any streamed body. On Free, a raw sign past
  about 5 MiB overruns 10 ms. A message as JSON is 64 KiB by default, up to 1 MiB with an `hmac()`'s
  `maxBytes`.
- On Node nothing ends a process at 128 MB; each process holds to the same numbers as defensive
  bounds, so a deployment behaves alike on both runtimes.

**Request bodies before routing** (`packages/core/src/schemas.ts`), all from the request CPU
policy (20 ms at p99, 10 ms at the median):

- `API_BODY_BYTES`, 1 MiB: any route once the caller has a credential; about 5 MiB of an
  isolate's memory while read.
- `MAX_BODY_NODES`: values a body may hold, counted before it is parsed, `(20 ms − 4 ms to read
  the largest body) ÷ 10 µs a value` = 1,600.
- `SIGN_IN_BODY_BYTES`: every body before sign-in, the smaller of what a token tried against each
  of 32 keys allows within 16 ms (135 kB) and what a passkey's answer allows (200 kB), rounded down
  to a power of two: 128 KiB. The token's cost is 32 × (230 µs + 2 ns × B), the answer's 80 ns × B,
  each within the 16 ms left once a body is read. `packages/server/scripts/sign-in-cost.ts`
  measures the inputs. Real bodies are a few kB.
- `MAX_VALUE_BYTES`, 64 KiB: a secret's value, half of Linux's 128 KiB environment string, since
  `coffre run` makes each value one.
- `AUTHORIZATION_URL_BYTES`, 16,000 (`packages/server/src/api/routes.ts`): OAuth's authorize
  parameters together, under a Workers URL's 16 KB.
- `PUBLISHED_BYTES`, 64 KiB (`packages/core/src/identity/fetched.ts`): a provider's discovery
  document or key set.

On Free neither of the first three bounds holds: a body of 1,600 values may take 20 ms, and 32 key
tries alone take 7.4 ms of the 10 ms before a byte is hashed, so a Free bound would also lower
`MAX_KEYS`.

## CI sign-in

What an exchange (a CI job's ID token for a credential) passes, in order:

| Bound | Value | Counted | Where |
|---|---|---|---|
| per address | 10,000 per 10 s | per Cloudflare location (approximate), or per Node process | `deployment.services.signInsPerAddress`; the examples' `SIGN_IN_PER_SOURCE` binding; `processLimits` |
| in flight | 32 | per isolate or process | `exchangeLimit.inFlight` in `packages/server/src/api/workloads.ts` |
| the binding's row | shared | the database | `sign_in` takes it `FOR KEY SHARE` |

**Per address.** 1,000 a second for one window. A fleet behind one NAT (a cluster's egress
address, a CI provider's runner pool) is one address, so one address may carry the whole target.
What it still stops: one address sending more than the instance's whole target, each request
costing a token decode and a read of the bindings. The window is 10 s because Cloudflare's
rate-limit binding takes only 10 or 60; a refusal says `Retry-After: 10`. The same per-address
limit covers MCP's unauthenticated OAuth endpoints, each entry point counted apart. Node's limiter
keeps 10,000 addresses at most (about 2 MB); past that the oldest window goes, so no address is
refused for another's requests.

**No count per binding.** An ID token buys one credential (`spent_id_tokens`), and the per-address
limit is the bound. One binding's sign-ins run together: `sign_in` takes the binding's row
`FOR KEY SHARE`, which every sign-in shares and only an unbind's `FOR UPDATE` excludes, so removing
a binding still ends every credential it issued (`formal/Lifecycle.tla`). `last_used_at` is written
only when a minute old, by whichever sign-in gets the row's update lock first; one that finds
another stamping it skips (`SKIP LOCKED`) rather than wait. Both are in
`packages/db/src/migrations/postgres/0079_sign_in_shares.sql`.

**A binding's removal goes in batches** (`formal/Unbinding.tla`). Without a count, one binding can
hold hundreds of thousands of live credentials, more than one vault message carries. So a removal
first closes the binding (`closed_at`), which refuses its sign-ins and, at the door, every
credential it issued and every renewal. Then each step revokes a batch under the fence, and the
last ends the binding. Batches after the close still take the fence: a request whose check passed
before the close can reach the vault after it, and an unfenced revoke would number its use after
the revoke. A batch is the smallest of:

- **the fence**: revoking never holds `/use` more than a few ms. At about 0.08 ms a credential, a
  10 ms hold is `UNBIND_BATCH` = 125. At 1,000 uses a second, about 10 uses wait meanwhile, none
  refused, far below `USES_IN_FLIGHT`.
- **the message**: half of Node's 8 MiB vault message, at 600 bytes a credential.
- **on Workers, the CPU**: a removal's vault call is held to Free's 10 ms, since one over it is
  killed on every try and its binding could never be removed: `WORKERS_BATCH` =
  ⌊(10 − 4.85 ms fixed) ÷ 0.045 ms⌋ = 114, two such calls a request
  (`packages/server/src/removal.ts`). A request then answers 202 with what is left; the client asks
  again, and the scheduled run finishes a removal left behind.

**Other sign-in bounds:**

- `MAX_BINDINGS`, 16 live bindings a service (`packages/core/src/identity/workloads.ts`). A sign-in
  reads and matches every binding of its token's issuer, so this also bounds a sign-in's work.
- An enrollment binding's `replicas`, 1 to 64: its fleet size; twice that many live sessions are
  admitted.
- `SPENT_TOKENS_PER_BEAT` = 2 × 1,000 a second × 5 minutes = 600,000 spent tokens pruned a
  scheduled run, twice what the target rate spends (`packages/server/src/app.ts`).
- **AWS proofs.** Each is one `GetCallerIdentity` at STS, signed by the workload, not cached, so it
  counts against the workload's own account: 600 a second per account and Region at a regional
  endpoint; the global endpoint has a quota of its own, served in us-east-1. A fleet faster than
  that needs its own quota raised, by a ticket to AWS; no coffre setting is the bound there.

## Other bounds on load

- **Workload gate**, `GATE_CEILING`, 1,000 requests a second per service
  (`packages/server/src/gate.ts`). Every workload-session request passes its service's gate. On
  Workers the gate is one Durable Object per service, whose documented soft limit is 1,000 a
  second. The ceiling also bounds the gate's replay memory: every fresh `jti` is kept two epochs
  (`EPOCH_MS`, 120 s each), 240,000 at the ceiling, about 20 MB. It counts per calendar second, so
  1,000 at the end of one second and 1,000 at the start of the next both pass.
- **The verifier's unsealed entries**, `ABOVE_NEWEST`, 1,000 (`packages/vault/src/verifier.ts`).
  A check reads at most that many entries above the newest signed pair; past it, it reports
  `capped` rather than read on (a checkpointer far behind, or rows a writer planted). Sized from the
  check's CPU budget, 20 ms: 4.5 ms fixed and 13.4 µs an entry fit 1,150. Its floor: an honest log
  holds a tick's worth above the pair, 500 entries at 1,000 uses a second, 1,000 with one tick late.
  `capped` shows in the audit API, the UI and `coffre verify`, never on the hot path.
- **The vault's `about()`, asked once an isolate** (`packages/server/src/asked-once.ts`). The first
  request makes the call; others arriving meanwhile poll it on their own timers rather than await
  its promise. One takes over after `TAKE_OVER_MS`, 3 s; a request that waited `WAIT_MS`, 6 s, in
  all answers 503 `starting`.
- **The credential proxy's upstream request** has no time bound of coffre's own: it ends, response
  body included, when the app's request does (its caller hangs up, or its own timeout aborts), as it
  would without coffre in the path. On Workers this needs `enable_request_signal`, which the
  examples' `wrangler.jsonc` sets.
- **Seals.** A change waits up to 5 s for its seal (`SEAL_WAIT_MS`); on Workers the vault asks the
  checkpointer's Durable Object for one up to 8 s (`SEAL_ASK_BOUND_MS`: 5 s + a witness's 2 s + a
  1 s margin, not measured).
- **Proxy items**, `MAX_PROXY_ITEMS`, 256 in one environment (`packages/core/src/proxy.ts`): its
  index stays under 17 KB, which every use of the environment carries. A presigned URL lasts 1 s to
  1 h.
- **Bulk reads**: `deployment.reads.bulkLimit` ([config.md](config.md)), 1,000 keys per 15 minutes
  unless set; the window is a day at most, as long as the releases it counts are kept.

## Limits without a source yet

Each of these is a number the rule does not yet account for. A change that touches one should give
it a source, or say why it cannot.

| Limit | Value | Where | What is missing |
|---|---|---|---|
| Hyperdrive's cap in `coffre setup` | 20 a config, on Paid too | `HYPERDRIVE_CONNECTIONS` in `packages/cli/src/connections.ts` | Free's maximum. Paid allows 100; the ceiling is the pool (Little's law), so 20 would serve about half of what the measured 40 did |
| Connections held back | 3 | `HELD_BACK`, same file | a guess; nor is any headroom sized for Hyperdrive running past its soft limit |
| Node pools | 10 a pool; the checkpointer's 2 | `openDatabase`; `localVault` in `packages/vault/src/node.ts` | node-postgres's default. Pools belong to one process, so two replicas each sized to the database's share open twice its budget; nothing splits it across processes |
| `READ_HEAD_WAITERS` | 16 | `packages/vault/src/vault.ts` | must also stay below the vault config's connections: at `max_connections` 25 setup gives each config 6, and 16 waiters can hold all of them |
| Exchanges in flight | 32 | `exchangeLimit.inFlight` | the only bound on waiting exchanges, because an exchange has no deadline of its own |
| `MAX_BINDINGS` | 16 | `packages/core/src/identity/workloads.ts` | not sized from a sign-in's measured cost per candidate |
| `replicas` | 1 to 64 | same | no platform limit; a fleet of more than 64 on one binding cannot enroll |
| The gate on Node | 1,000 a second | `GateState` in `packages/server/src/gate.ts` | no Durable Object there: the ceiling is a memory bound in disguise and should be one, from the process's budget |
| `TAKE_OVER_MS` | 3 s | `packages/server/src/asked-once.ts` | never measured against a cold `about()` |
| `USES_AT_ONCE` | 4 uses a request | `packages/server/src/api/keys.ts` | its reason, leaving admission room, predates admission's 1,250 places |
| Node's alarm file | rewritten past 1,000,000 bytes, keeping 30 days | `packages/vault/src/checkpointer-node.ts` | a compaction trigger, not a bound: 30 days can stay above 1 MB, and then every append rewrites the whole file |
| `MAX_DEFINITION_BYTES` | 8,192 bytes a proxy definition | `packages/core/src/proxy.ts` | no reason written; an editable definition past it is refused far below the 1 MiB body bound |
| `TOUCH_INTERVAL_MS` | 5 minutes, three copies | `workload-sessions.ts`, `api/signin.ts`, `mcp/service.ts` in `packages/server/src` | one constant, and the write claimed once |

## Platform facts

Checked against the vendors' pages on 2026-11-04 unless dated otherwise.

**Cloudflare Workers** ([limits](https://developers.cloudflare.com/workers/platform/limits/)):

- CPU: 10 ms an invocation on Free; up to 5 minutes on Paid, 30 s by default. Waiting on the
  network does not count.
- Requests: 100,000 a day on Free; no limit on Paid.
- Memory: 128 MB, "per-isolate, not per-invocation. A single isolate can handle many concurrent
  requests." No number of requests per isolate is documented.
- Connections: "up to six connections simultaneously waiting for response headers"; a seventh is
  queued, and since
  [2026-04-09](https://developers.cloudflare.com/changelog/post/2026-04-09-relaxed-connection-limiting/)
  stalled ones are no longer cancelled. Service-binding callees share their caller's limit.
- Subrequests: 50 on Free; 10,000 (up to 10 million) on Paid.
- Service bindings: at most 32 Worker invocations a request; RPC payloads up to 32 MiB.
- `waitUntil`: up to 30 s after the response.
- A URL: 16 KB. A request body through Cloudflare: 100 MB on Free and Pro.
- [Rate-limit bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/):
  a period of 10 or 60 s; "approximate and apply separately in each Cloudflare location".

**Durable Objects** ([limits](https://developers.cloudflare.com/durable-objects/platform/limits/)):
"An individual Object has a soft limit of 1,000 requests per second."

**Hyperdrive** ([limits](https://developers.cloudflare.com/hyperdrive/platform/limits/),
[tune connection pool](https://developers.cloudflare.com/hyperdrive/configuration/tune-connection-pool/)):

- Origin connections a config: about 20 on Free, about 100 on Paid, 5 at least; 20 and 60 by
  default. A soft limit: Hyperdrive may open more during network failures, so set it below the
  database's own.
- It does not limit concurrent client connections from Workers.
- A query: 60 s. An initial connection: 15 s. Idle: 10 minutes. A full pool fails a query after
  15 s with 58000 (`packages/db/src/dialect.ts`).
- Transaction-mode pooling: transaction-level advisory locks work, session-level ones do not.

**Postgres 16**: `max_connections` typically 100, 3 reserved for superusers. `statement_timeout`,
`lock_timeout` and `idle_in_transaction_session_timeout` default to off; `lock_timeout` applies to
each lock attempt separately. A function's `SET` clause is restored on exit. Bind carries an Int16
parameter count (65,535).

**Linux**: one environment string is at most 128 KiB (`MAX_ARG_STRLEN`).

**AWS KMS** ([request quotas](https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html)):
symmetric cryptographic operations share 10,000 a second per account and Region (20,000 or
100,000 in some Regions), adjustable.

**AWS STS** ([request quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-sts-requests)):
600 requests a second per account and Region, shared by `GetCallerIdentity`, `AssumeRole` and four
others; raised by a ticket to AWS support. The global endpoint has a quota of its own and is
served in US East (N. Virginia) unless resolved through Amazon's DNS
([endpoint changes](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html#reference_sts_global_endpoint_changes)).
