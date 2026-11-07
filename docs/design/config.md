# One config object: what a deployment chooses, and what coffre derives

Status: **proposal, for Erwin's one-pass review (D172), for 0.16.** Written
against `main` at `f9261451`, with the values of the open PRs that change
limits at their heads: #519 (`f5d3eb02`, proxy memory), #520 (`66815898`,
sign-in limits), #533 (`f3f43ba4`, body bounds), #538 (`231e66d1`, locks and
key service). #516 (service tokens) is merged. The audit behind it, every
limit and where it lives, is [limits.md](limits.md).

Erwin's ask (D172): "review together all the real settings / policies we want
to have as one config object and what we want to derive from it", and "the
actual config values and derived values we are going to use to make sure
nothing is excessive".

Four parts:

1. [The object](#1-the-object): every setting a deployment chooses, with its
   default. Nothing else.
2. [Everything else](#2-everything-else-fixed-or-derived): what is fixed by
   a rule of Erwin's or a platform, and what is computed from those and from
   the object, each with its formula and source.
3. [Open questions](#3-open-questions), each with a recommendation and one
   example of what it changes.
4. [What goes](#4-what-goes): the knobs that become derived or vanish,
   before and after.

## 1. The object

Today a deployment's choices sit in six places: `signin({…})` (passkeys,
session lifetimes, the longest service token, and in `workloads` whether
services may hold bearer tokens or list reads), `vault({…})` on Workers and
`serveVault({…})` on Node (the bulk read cap, the `uses` block),
`credentialProxy({…})` (two revocation delays, whether definitions are editable), `createCoffre({…})` (when a
value is flagged for rotation), five rate-limiting bindings in
`app/wrangler.jsonc`, and a retention setting no standard deployment can
reach. Most deployments set none of them, so the defaults are the policy.

The proposal: one file, `policy.ts`, beside `app/` and `vault/`. The app and
the vault each import it at build time and each enforce their part; neither
takes policy from the other at run time, so a compromised app cannot loosen
what the vault holds.

```ts
// policy.ts: what this instance allows. Imported by the app and by the vault.
import { definePolicy } from '@coffre/core/policy';

export const policy = definePolicy({
  people: {
    passkeys: 'optional', // 'off' | 'optional' | 'required'
    browserSessionHours: 12, // above 0, at most 168
    cliSessionDays: 30, // above 0, at most 365
  },
  services: {
    tokenMaxDays: 365, // 1 to 365 (R76)
    signInsPerAddress: 10_000, // per 10 s, each sign-in entry point counted apart (R76, #520)
    useOnly: false, // true: no service token issued or taken; services sign in with a key
    noReads: false, // true: no binding lists reads (plain values only, with useOnly: true)
  },
  reads: {
    bulkLimit: { count: 1_000, windowMinutes: 15 }, // window at most a day (R28, R52)
  },
  values: {
    rotateAfterDays: 365, // null: never flag
  },
  proxy: { // read only with the credential proxy
    revokedWithinSeconds: 60, // 3 to 3,600
    cacheValues: true, // false: every request asks the vault, nothing kept
    editable: false, // Owners may add and change definitions in the UI
  },
  audit: {
    keepUsesDays: null, // null: every day kept; else days of uses kept (Q6)
  },
});
```

Each runtime passes the same object, once per side:

```ts
// Workers: app/src/coffre.ts and vault/src/worker.ts
createCoffre((env) => ({ /* wiring as today */ policy }));
vault((env) => ({ /* wiring as today */ policy }));

// Node: app/src/coffre.ts and src/vault.ts
createCoffre({ /* wiring as today */ policy });
await serveVault({ /* wiring as today */ policy });
```

A Workers deployment has no other knob, and neither has a Node one: pool
sizes come from the database (Q2), and the `uses` block goes (section 4).

### Each field

| Field | Default | Enforced by | Today | Why it is a choice |
|---|---|---|---|---|
| `people.passkeys` | `'optional'` | app | `signin({ passkeys })` | how much a person proves beyond the provider ([passkeys.md](passkeys.md)). `rpId` stays in `signin`: it names a domain, it is wiring |
| `people.browserSessionHours` | 12; above 0, at most 168, as today | app | `signin({ browserSessionHours })` | how often a person signs in again in a browser |
| `people.cliSessionDays` | 30; above 0, at most 365, as today | app | `signin({ cliSessionDays })` | the same for `coffre login` |
| `services.tokenMaxDays` | 365, 1 to 365 | app **and vault** | `signin({ serviceTokenMaxDays })`, app only (#516) | R76. New: the vault holds an issue to the deployment's number too, where today it holds only the 365. The default lifetime offered stays min(90, this) |
| `services.signInsPerAddress` | 10,000 per 10 s | app | Workers: `SIGN_IN_PER_SOURCE` in `app/wrangler.jsonc` (#520); Node: `processLimits({ perSource })` | R76 asked for one or two settings. The default is R44's 1,000 sign-ins a second over one window, since a fleet behind one NAT is one address. A deployment with no such fleet may set it lower |
| `services.useOnly` | `false` | app | `signin({ workloads: { useOnly } })` | whether a service may hold a bearer token at all. `true` refuses to issue one (`forbidden`, `use_only`), refuses those already issued at use (`unauthenticated`, `use_only`), and gives every new binding a policy, so that it signs in only for a key-bound session ([workload-access.md](workload-access.md), section 6.3). Enforced on `main`, though `signin`'s type comment still says "not yet enforced": a P3 |
| `services.noReads` | `false` | app | `signin({ workloads: { noReads } })` | no binding may list `reads`: a key-bound session gets plain values only, and a binding made with reads before the switch is refused at its next sign-in. Alone it leaves bearer service tokens and `/api/auth/oidc`'s exchanges reading as today ([workload-access.md](workload-access.md), section 6.3); only `useOnly` ends those. A deployment whose services read plain values only sets **both** to `true`. Neither flag is held by the vault today; like `tokenMaxDays`, the vault could hold both from the same object |
| `reads.bulkLimit` | 1,000 keys per 15 min | vault | `vault({ bulkLimit })` | R28, R52 |
| `values.rotateAfterDays` | 365, or `null` | app | `createCoffre({ rotateAfterDays })` | when the UI and `coffre list` flag a value nobody changed |
| `proxy.revokedWithinSeconds` | 60, 3 to 3,600 | app | two settings, `credentialProxy({ cacheSeconds, recheckSeconds })`, both 60 | see below |
| `proxy.cacheValues` | `true` | app | `credentialProxy({ cacheSeconds: 0 })` | whether opened values serve later requests at all. `false` keeps today's uncached mode: every request asks the vault, so each one is a decision and an entry in the log, and a revocation ends the next request, not one up to R later. R still bounds the send window and the tunnels |
| `proxy.editable` | `false` | app | `credentialProxy({ editable })` | whether an Owner may add and change proxy definitions in the UI, beside those the deployment's code names |
| `audit.keepUsesDays` | `null`, every day kept, as today | vault | `retainDays`, reachable only by a Node deployment that runs its own checkpointer | Q6 |

**`proxy.revokedWithinSeconds` merges two settings that mean one thing.**
Both bound how long a revoked credential keeps working through the proxy:
`cacheSeconds` is how long its opened values serve requests from memory,
`recheckSeconds` how often an open database tunnel checks it still stands.
With two settings a deployment could make them 60 and 600 and get an answer
nobody meant.

Today the two are not even one bound at 60. A tunnel checks every
`recheckSeconds`, and each check has min(`recheckSeconds`, 10 s)
(`RECHECK_DEADLINE_MS`) to answer, so a revoked handle's tunnel can carry
bytes for 60 + 10 = 70 s. The proposal derives both from the one number R:

- values served from memory: R;
- a handle's tunnel: each check given d = min(R ÷ 2, 10 s), the checks
  R − d apart, so that a check's interval and its deadline add up to R;
- a fresh request's window to send (or, for a signature, to answer), from
  its start: max(R, 3 s), the 3 s being the use's own deadline
  (`USE_DEADLINE_MS`), so that a cold request whose use took most of its
  3 s still goes out; R once R is at least 3.

**Today only editable definitions have that window.** Their paths set it
at max(cache, 3 s) (`sendBy` and `answerBy` in `credential-proxy.ts`). A
credential defined in code has none: its handle requests and its
workloads' requests reach `send` with no `sendBy` (`forward` and
`workloadForward` in `credential-proxy.ts`), whose check runs only when
one is set, and `sign`, `verify` and `presign` answer with no
`answerBy`. So a request that paused after its values opened (a slow
upload, a stalled isolate) sends or answers whenever it resumes, however
long after a revocation. The promise below needs the window on every path
that forwards, signs or checks a signature: a code change, part of this
proposal, not a setting.

*Example:* an Owner revokes a CI token at 12:00:00. At R = 60, its last
request through the proxy leaves by 12:01:00 (once every path has the
window; today a code-defined credential's may leave later); its open Postgres tunnel
checks every 50 s, each check given 10 s, and closes by 12:01:00. At R = 4,
the tunnel checks every 2 s with 2 s to answer.

The range is 3 to 3,600. Below 3, the promise would not hold: at R = 1, a
request that started at 11:59:59.9, its use decided just before the
revocation at 12:00:00, may still send at 12:00:02.8, inside its 3 s
window, where R promised 12:00:01. Capping that window at R instead
would keep the promise and fail every cold request whose use takes longer
than R (503 `late`, to ask again), which a slow key service makes common:
one KMS attempt alone may take 706 ms. So the floor is the use's deadline,
derived, not a choice. Today `cacheSeconds: 0` (no cache) is allowed and
`recheckSeconds: 0` is refused; one number cannot be both, and a tunnel
cannot check continuously, so R has no 0. No cache is a different policy,
not a short one: at R = 3 a request may reuse values another opened up to
3 s before, and asks the vault nothing, where `cacheSeconds: 0` asks it
every time (`credential-proxy.ts`, `opened`: `cacheMs > 0` guards the
cache's write). So it stays, as its own field, `proxy.cacheValues: false`.
*Example:* a deployment that wants every proxied request in the log as a
decision of its own sets `cacheValues: false` and keeps R = 60 for its
tunnels. A workload's tunnel keeps its own 15 s bound (`WORKLOAD_RECHECK_MS`,
design section 8.2), or R if less, as today.

**`services.signInsPerAddress` on Workers.** Cloudflare reads a rate limit's
number from the binding in `wrangler.jsonc` and nowhere else; the code cannot
set it. So the number must be written there too. Proposal: the deployment's
build (`@coffre/ui/vite`, which already fails on drifted pins) fails when the
binding's `limit` and `period` differ from the policy. On Node the policy is
the only place. If Erwin prefers, this field can instead stay out of the
object and live where each platform keeps it; the object is then one field
shorter, and Workers deployments set it in `wrangler.jsonc`.

**`cloudflareAccess(…)` deployments** sign people in through Cloudflare
Access, which owns their sessions: the `people` fields do not apply there.

### What is not in it, and why

- **Wiring**, which says where things are, not how much is allowed: the
  public URL, the databases, every key (`kek`, `signingKey`,
  `auditChainKey` and the keys they replaced), the providers, the plugins
  and what they define (`generate`, the credentials, tunnels, signers),
  witnesses, `passkeys.rpId`.
- **`credentialProxy({ insecureUpstreams })`**, though it is a policy: it
  lets the proxy's upstreams be plain HTTP and private addresses. Default
  `false`, which is the right default. It stays beside the credentials
  because it differs per environment, as `owners` does: a dev deployment's
  upstreams are `http://localhost`, production's must not be. The same
  holds for `signin({ workloads: { allowLoopbackIssuersForDevelopment } })`,
  which `signin` already refuses on an instance not on loopback.
- **Who a provider lets authenticate**: `google({ domain })` and
  `github({ organization })`. Each narrows sign-in to one Workspace's
  accounts or one organization's members (`wrong_domain`,
  `not_in_organization`). Default: none, so any account the provider
  vouches for may authenticate. It is a policy, but it belongs to the
  provider it filters, not to the deployment as a whole: two providers
  can carry two different ones, and `oidc(…)` and `microsoft(…)` have
  no such option (a Microsoft tenant is already one directory). It is a
  second gate, not the only one: signing in proves who someone is, and
  only an active member, whom the vault decides (an invitation or the
  `owners` list), gets in ([deployment-auth.md](../deployment-auth.md)).
  Today `coffre init` writes `github({ app })` with no organization (both
  examples). Recommendation: keep both options on the providers, and have
  `init` ask for the organization when it sets up GitHub, so a new
  deployment starts with one.
- **`owners`** (R3): who owns the instance, not how much anyone may do. It
  differs per environment (dev, prod) and comes from its environment, so it
  stays in the vault's wiring.
- **Per-item policy**, set where the item is: a proxy credential's
  `limit` (per minute, per day), a trust binding's session hours, overlap
  and fleet size. These are data an Owner edits, not deployment settings.
- **Rules Erwin set for every deployment**: the 3 s use deadline, the
  500 ms seal tick, R44's 1,000 a second and the rest of section 2.1. They
  are constants in code, and in Postgres functions where the database holds
  them. Making one a setting is a separate decision, not proposed here.

### Moving to it

0.16 reads the old places for one release, warns, and refuses them in 0.17,
as #520 does for its limits. `coffre init` writes `policy.ts`; the examples
show it; `docs/deploy.md` gets one section on it.

## 2. Everything else: fixed or derived

Every other number in the 0.16 code is one of three things: a platform fact,
a rule of Erwin's, or a value computed from those and the object. The tables
give each one's formula and source. **⚠** marks a value with no source yet,
which the questions in section 3 or a later PR settle. They hold every value
D172 changes or derives, and the fixed ones a reviewer of those needs;
[limits.md](limits.md)'s inventory (its V and S rows) lists the rest, each
with its source and verdict, and those stand as it says.

### 2.1 Inputs: platform facts and Erwin's rules

| Input | Value | Source |
|---|---|---|
| A Worker isolate's memory | 128 MB, read as 128,000,000 bytes (the smaller reading) | [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) |
| A Workers invocation's CPU on Free | 10 ms. Cloudflare tolerates an occasional overrun and ends invocations that cross it consistently (1102). coffre sizes a request to R27 below, 20 ms at p99 and 10 ms at the median, so Free's 10 ms holds at the median only: each bound derived from the 20 ms (bodies, a stranger's sign-in, `ABOVE_NEWEST`) says what it does on Free | Workers limits; R27 |
| Worker invocations per request | 32 | Workers service bindings |
| A URL on Workers | 16 KB | Workers limits |
| A request body through Cloudflare | 100 MB (Free, Pro) | Cloudflare |
| A rate-limiting binding's period | 10 or 60 s, counted per location, approximately | [rate limit bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) |
| A Durable Object's requests | 1,000 a second, soft | Durable Objects limits |
| A Hyperdrive config's connections | 5 to 20 on Free, up to 100 on Paid (default 60); soft | Hyperdrive limits |
| Postgres `max_connections`, reserved | the database's (100 typical); 3 for superusers | the database |
| Postgres bind parameters; index entry | 65,535; 2,704 bytes | Postgres protocol; `BTMaxItemSize` |
| SQLite variables; compound terms | 32,766; 500 | SQLite limits |
| One S3 request | 5 GiB | S3 |
| AWS KMS; AWS STS | 10,000+ a second; 600 a second, per account and Region | AWS quotas |
| One environment string on Linux | 128 KiB (`MAX_ARG_STRLEN`) | Linux |
| **R44:** the rate everything is sized to | 1,000 `/use` a second, and 1,000 CI sign-ins a second | Erwin |
| **R27:** a request's CPU | 20 ms at p99 (10 ms at p50) | Erwin |
| **R53, R54:** a use's deadline | 3 s, held in Postgres too (`deadline_max()`) | Erwin |
| **R53, decision 13:** the uses' own login | 1 s `lock_timeout`, 2 s `statement_timeout` | Erwin |
| **R51, R54:** the seal tick; a witness's wait | 500 ms; 2 s | Erwin |
| **R25:** a full walk of the audit chain | in chunks of 10,000 entries | Erwin |
| **R76:** a service token's ceiling | 365 days | Erwin |
| **D177:** a binding's `last_used_at` | written at most once a minute | Erwin (#520) |
| Fixed lifetimes | personal token 7 days; a CI exchange's credential 5 min; a workload session 1 h; a device code 10 min | design docs, RFC 8628 |
| Clock skews (D3, on hold) | ID token 30 s, sign-in proof 60 s, DPoP 300 s, a Worker clock ahead 60 s, sign-in slack 5 min | each design's reason |

### 2.2 Memory, per Worker isolate (#519)

Erwin's D1 split the isolate's 128 MB into named shares. The split is a
choice, not a measurement, so each share is listed for Erwin to judge.

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Uses in flight (`USES_BYTES`) | 64,000,000 bytes | half the isolate | choice (D1, Q1) |
| Proxy bodies read whole (`BODIES_BYTES`) | 16 MiB | what one body could take before #519 | choice (D1) |
| Caches (`CACHES_BYTES`) | 16 MiB | as much as the bodies | choice (D1) |
| Left for the runtime | 30,445,568 bytes | 128,000,000 − 64,000,000 − 2 × 16 MiB | the app Worker holds 8.6 MB idle, measured |
| A forwarded body read whole (`BODY_READ_WHOLE_BYTES`) | 1 MiB | D1 | Erwin; larger bodies stream |
| A body a form or JSON rule fills a field of (`MAX_FIELD_BODY`) | 64 KiB | a token refresh's or a siteverify's, never an upload's | #519 |
| A sign or verify request | ⌈m ÷ 3⌉ × 4 + 4,096 bytes, m the longest message: 91,480 bytes at the 64 KiB default, 1,402,200 at 1 MiB (an `hmac()`'s `maxBytes`, or any editable proxy) | the message as base64url in JSON, and 4 KiB for the rest | #519 (`compute`) |
| Bodies read whole at once, each counted twice (its bytes and a copy) out of the 16 MiB | 8 forwarded bodies of 1 MiB; 5 sign or verify requests at 1 MiB messages; 128 field bodies | 16 MiB ÷ (2 × the body's bound) | #519's code. (`memory.ts`'s comment says sixteen: a P3 for #519) |
| One cache's slice | 2,396,745 bytes | 16 MiB ÷ 7 caches, least recently used out first | #519 |
| Uses an isolate can hold | about 2,083 | 64,000,000 ÷ 30 KiB per held use | 30 KiB measured (W331, local workerd); stated in #519, not used until Q1, which first has it re-measured over a use's whole life, its key's opening included |
| A plugin's WebSocket message on Node | 1 MiB | the body bound | #519 |
| A streamed body | 5 GiB | S3's one request | platform |
| A body whose digest is declared | 95 MiB | under Cloudflare's 100 MB | platform |

### 2.3 Uses

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Uses in flight per isolate or process | **10** ⚠ | node-postgres's default pool, where Workers has no pool | none: Q1. It counts a use's database phase only, and a batch as one: a use waiting on its key service holds no place (Q1) |
| How long a use's place outlives its deadline (`HELD_PAST_DEADLINE_MS`) | 2 s | the uses' login's `statement_timeout` | R53 |
| A use's time tolerance (`AT_SLACK_MS`) | 63 s | deadline 3 s + a clock 60 s ahead | R53, D3 |
| The bulk cap's refresh | 60 s at 15 min | in ms, max(1, min(60,000, ⌊window ÷ 10⌋)): a 1 ms window refreshes every 1 ms | decision 9 (`refreshMs`, `packages/vault/src/bulk.ts`) |
| How long a key counts against a **new** key (`bulkRule`) | 17 min 3 s at 15 min | window + refresh + the use's deadline 3 s + a clock 60 s ahead, against the stored periods: a key may still be refused 17 minutes after the 1,000th entered | `packages/vault/src/bulk.ts` (TLC's HotPathOneClock, HotPathOneBulkSkew). The object's window is not the one a caller sees: `deploy.md` should say both |
| The bulk window's maximum | 1 day | releases kept a day and an hour | R52 |
| Keys a statement uses at once (`uses.batch`) | 100 | about 0.4 ms a key under the lock every use shares, so about 40 ms | measured (review of #433) |
| How long a use's cover serves repeats (`uses.coverMs`) | 60 s | none written | ⚠ a choice, `useLimits` (`packages/vault/src/use.ts`) |
| Names the vault's isolate remembers (`uses.names`) | 10,000 in each of two maps: names to ids, and a key's name in an environment to its id | none written; least recently used out first | ⚠ a choice, `useLimits` |
| Seals and covers the vault's isolate keeps (`UseCache`'s `max`) | 10,000 in each of two maps: each key's newest seals, and the covers repeats ride | none written; a full map is cleared whole | ⚠ a choice, `UseCache` |
| A route use's maps (`madeFor`, `routeKeys`, T186) | 10,000 in each of two maps: a handle's made-for places by its token, and each route's keys' ids by place and route | bounded as `uses.names`, least recently used out first | ⚠ the same choice, `UseCache` (`use.ts`) |
| All six together | up to 60,000 entries | counted by entries, not bytes: they live in the vault's isolate, outside #519's caches share, and nobody has measured an entry | ⚠ unmeasured |

### 2.4 Lock waits and deadlines (#538, #508)

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| A write's lock wait (`LOCK_WAIT_MS`) | 500 ms | the uses' 1 s ÷ 2 | R75: a writer that waits in Postgres's queue holds back every use behind it, so it leaves within half a use's wait. Not every wait: reads and `sign_in`/`issue_token` below keep longer ones |
| The migrator's lock waits | 500 ms for **each lock** a statement waits for, so one statement that waits for several may wait longer in all; then the run is tried again, up to 5 times, 1 s apart, and a try is the **whole transaction** of the pending migrations: one that gives up on its third migration applies the first two again | `LOCK_WAIT_MS` (Postgres's `lock_timeout` counts each wait); `MIGRATION_LOCK_ATTEMPTS`, `MIGRATION_LOCK_PAUSE_MS` | #508, #538 (`packages/db/src/migrate.ts`, `waitingBriefly`). The migration lock itself and the roles' last statements wait up to 5 min, for another run |
| The two credential writers that take the uses' lock exclusively, in SQL (`revoke_credential`, `change_bindings`) | 500 ms (from 1 s) | `LOCK_WAIT_MS` | #538 (migration 0076) |
| `sign_in`, `issue_token` | 1 s | they take only the issue lock, which no use asks for | #538 |
| A read's deadline (`CALL_DEADLINE_MS`, was `READ_DEADLINE_MS`) | 5 s, nominal: **not from the call's start**, and **not a strict total** after it. Its clock starts once the vault is settled and cut over (`#decideNow`); `unwrap`'s once it has loaded the versions, read the references, settled and read the environments, at `#keys`. That preparation has no bound of its own beyond each statement's. And the transaction sets what is left, once, at its BEGIN, as a `SET LOCAL statement_timeout` that Postgres times per statement: two statements of 2.8 s each end at 5.6 s, neither timed out | a choice: "a caller hears within it" | #356 ⚠ not derived; #538 (`vault.ts`, `#decide`; `store.ts`, `boundLockWaits`). A strict 5 s needs the client to cancel the call's query at the deadline (Postgres's cancel request), not one more `SET` per statement, which a batch sent under one Sync computes before any of it runs |
| A read with a key service | 10 s; 8.1 s once `KEY_BUDGET_MS` is 3,118 ms (below), from `#keys`, after the preparation above | `CALL_DEADLINE_MS` + `KEY_BUDGET_MS` | #538 |
| A write call | its lock waits retried for up to 5 s from its first attempt; its work itself unbounded | `CALL_DEADLINE_MS` as a retry budget | R75: writes may take longer |
| Its retry pauses | 25 ms doubling to 400 ms, ×0.5 to ×1.5 | a retry policy, written as one | #538 |
| A read's lock wait (`READ_LOCK_TIMEOUT_MS`) | 3 s, or what is left of the call's deadline if less | a choice | #347 ⚠ |
| The app's first ask of the vault's `about()` and the proxy's gate: a request that joins another's attempt takes it over after (`TAKE_OVER_MS`) and gives up with 503 after (`WAIT_MS`) | 3 s; 6 s, for joiners only: the isolate's first request awaits its own call as long as that call takes, with no bound from this helper (only the vault's own deadlines, above) | "longer than a deploy's write and its seal take"; 2 × `TAKE_OVER_MS` | T201 (`packages/server/src/asked-once.ts`) ⚠ the 3 s is not measured; the first request's wait has no bound of its own |
| Waiters for the log's head (`READ_HEAD_WAITERS`) | 16 | 2.4 s ÷ 150 ms measured; should also be ≤ the vault's request connections − 2, a database-wide count that leaves no connection free on any one Hyperdrive shard | Q3 |
| A plain 503's `Retry-After` | 1 s (from 5) | `LOCK_WAIT_MS` rounded up to whole seconds | #538 |
| An app write's lock wait | 500 ms (from unbounded) | `LOCK_WAIT_MS`; then 503 at once | #538 |
| An AWS KMS attempt's timeout | 706 ms (from 5 s), or what is left of the caller's deadline if less | a measured p99 of a KMS call | #538's stacked KMS PR (its measurement table not yet in a PR) |
| AWS KMS attempts | 3 (unchanged), pauses 100-200 ms then 400-800 ms | `100 × 4^(attempt−1) × (1 + random)`, as in `aws-kms.ts` | a retry policy, written as one |
| One KMS operation's HTTP attempts, every retry spent | 3,118 ms | 3 attempts × 706 ms + the two longest pauses (200 + 800 ms) | derived. Not the operation's worst case: before its first attempt it awaits the provider's AWS credentials (`aws-kms.ts`, `#call`), under no timeout of its own, inside the batch's budget ⚠ |
| The key service, per batch of a call's operations (`KEY_BUDGET_MS`) | 3,118 ms (from 5 s): **a ceiling for the operations batch**, not a sufficient budget, and not for the call | one operation's full retries; every key operation of the batch spends from it (`settle` in `vault.ts`, one deadline for all) | a choice, sized to one operation: see below. A read with a key service is then 5 s + 3.1 s |
| A cold vault's KEK checks (`#checkKeks`) | up to 3,118 ms **per configured KEK**, before the batch | each check gets `KEY_BUDGET_MS` again, or what is left of the call's deadline if less | #538. So KMS time in one call is bounded only by the call's 8.1 s: two KEKs whose checks take 2 s each, then a 2 s unwrap, spend 6 s at KMS |
| AWS KMS calls at once | 8 per provider object → per call | the isolate-wide `Slots(8)` goes: a `/use` waited 5 s behind 8 hung calls (measured). The 8 cited "six connections", which Workers counts per request, not per isolate ([limits.md](limits.md), item 5) | same PR, with `formal/KeyService.tla` |
| When a key service's intent is overdue (`expiresAt`), and how far back a rotation looks for open ones | 15 s today; 13,118 ms with the ceiling above | `at` + 2 × `CALL_DEADLINE_MS` + `KEY_BUDGET_MS`: the call's budget, and one more call deadline as a margin for its COMMIT, which nothing bounds | #538 (`#keys`, `#closeIntents`); the margin is not measured ⚠ |

**What a 3,118 ms ceiling covers, and what it does not.** The budget
belongs to the call's batch of key operations, and every key the batch
opens or wraps spends from the same deadline. A cold vault first checks
each KEK, each check with a budget of its own, all inside the call's
8.1 s: what follows holds for a warm vault, and a cold one's batch gets
what the checks left of the call. 3,118 ms is one operation's HTTP worst
case, attempts and pauses. It assumes the AWS credentials are already
in hand: the provider awaits its credential callback first, inside the
same budget, so a refresh that takes 1 s leaves 2,118 ms for the
attempts, two and their pause, not three. With credentials in hand, it
covers every retry only when each key needs one operation and they all
run at once:

- a read or a wrap of up to 8 keys: one wave, each key with its three
  attempts. Covered.
- a rewrap: each key decrypts under its old wrap, then encrypts, one after
  the other (`vault.ts`, the rewrap's operation). On first tries the pair
  takes at most 2 × 706 = 1,412 ms; a decrypt that spends all three attempts
  leaves the encrypt nothing, and the call fails with a
  `KekUnavailableError` (each key's outcome recorded as `cancelled`,
  `kms_unavailable` or `kms_uncertain`), which its caller may retry.
- more than 8 keys: the per-call slots run them in waves of 8, and each wave
  gets what the earlier ones left.

A budget that covered every case would be ⌈keys ÷ 8⌉ × operations per key
× 3,118 ms: 6,236 ms for a rewrap of up to 8 keys, about 25 s for a read of
64. It grows with the batch, and a caller's deadline cannot. So the
proposal states it as a ceiling: past one wave of single operations, a call
completes on early tries or fails and is retried. *Example:* a decrypt's
first attempt times out at 706 ms, and after a 150 ms pause the second
answers in 100 ms: 956 ms. A read of that key is done. A rewrap of it has
3,118 − 956 = 2,162 ms left for its encrypt: two attempts and the pause
between them (at most 706 + 200 + 706 = 1,612 ms), not a third. If Erwin
wants a rewrap's two legs covered whole, the ceiling is 6,236 ms, and a
read call with a key service 11.2 s.

### 2.5 Database connections

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| A Hyperdrive config's connections, set by `coffre setup` | ⌊(max_connections − reserved − 3) ÷ 3⌋, at least 5, at most **20** ⚠ | an even third for each login (app, vault, uses), less 3 held back | the 20 is Free's maximum, applied on Paid too: [limits.md](limits.md) #12 proposes the plan's maximum. Example at 100: 31 each, cut to 20 |
| Held back (`HELD_BACK`) | 3 | for the administrator, `coffre migrate`, the host's tools | a guess ⚠ (Q2) |
| A Node pool | **10** ⚠ | `max ?? 10`, node-postgres's default; proposed: setup's share, at least 5, or the process refuses to start | Q2 |
| The Node checkpointer's pool | 2 | its own connection | ⚠ (limits.md V39) |
| A Workers call's connections | 1 | several at once were cancelled as hung on Cloudflare | measured (#80) |

### 2.6 Sign-in (#520, #533)

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Sign-ins per address | 10,000 per 10 s | R44's 1,000 a second × the 10 s window | the object's `signInsPerAddress`; 10 s is Cloudflare's shorter period |
| Its 429's `Retry-After` | 10 s | the window | #520 |
| A sign-in the vault found busy | 503, `Retry-After: 1` | one lock wait | #520 |
| Node's limiter keys | 10,000 | the addresses one window's target can come from; about 2 MB | #520 |
| Exchanges in flight per isolate | **32** ⚠ | none written | stays until a sign-in has a deadline of its own (limits.md #35) |
| A binding removal's batch, Node (`UNBIND_BATCH`) | 125 | 10 ms ÷ 0.08 ms a credential, measured | the 10 ms is `FENCE_BUDGET_MS` = 10 uses in flight ÷ 1,000 a second: **derived from Q1's 10**, see Q1 and its refusal table |
| The same, on Workers | 114 a call, 228 a request | (10 ms − 4.85 ms fixed) ÷ 0.045 ms; 2 calls in the request's CPU, within 32 invocations | measured on workerd (#520) |
| A batch's bytes | 4 MiB | half the Node vault socket's 8 MiB message | #520 |
| Spent sign-in tokens forgotten a beat | 600,000 | 2 × 1,000 a second × 300 s | R44 (#520; was 5,000) |
| Open bindings per service (`MAX_BINDINGS`) | **16** ⚠ | none written | limits.md §3.6 proposes 256, once a sign-in reads only the bindings that can match |
| A binding's fleet size (`replicas`) | 1 to **64** ⚠ | none written | limits.md §3.6 proposes 1 to 1,000 |
| A sign-in's CPU accounting (`SIGN_IN_WORK_NS`, 16 ms, and its unit costs) | gone | a stranger's body is bounded by its bytes instead (`SIGN_IN_BODY_BYTES`, 2.7) | #533 |
| Keys in a key set, fetched or uploaded (`MAX_KEYS`) | 32 | none written: the pre-sign-in body bound is derived from it | #533 ⚠ the 32 itself is a choice |
| A key tried against a token that does not verify (`KEY_TRY_CPU_US`), and each token byte per try (`TOKEN_BYTE_CPU_NS`) | 260 µs; 14 ns | measured over tokens of 1 to 32 KiB, ES256 and RS256, the dearest rounded up | #533 (its `sign-in-cost.ts` script) |
| A binding's issuer | 1,670 bytes (from 400) | 2,704 (index entry) − 1,034 (the entry's other columns) | #533 |
| A provider fetch: discovery document, key set, GitHub's API (`FETCH_DEADLINE_MS`) | 5 s, DNS to last byte | none written | ⚠ a choice, `packages/server/src/workloads/transport.ts` (limits.md S64, which proposes the same deadline for the UI routes' fetches, today unbounded) |
| A workload's gate | 1,000 a second per service | a Durable Object's soft limit | platform; on Node it stands in for a memory bound ⚠ (limits.md #5) |

### 2.7 Bodies (#533)

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Every control-plane body once its caller has a credential (`API_BODY_BYTES`) | 1 MiB | about 5 MiB held while read, 4% of an isolate | #533. Past it, 413 `too_large` (was 400), refused as it streams |
| Values in a body (`MAX_BODY_NODES`) | 1,600 (from 20,000) | (20 ms − 4 ms) ÷ 10 µs a value, measured | R27; counted on the text before it is parsed. ⚠ Not Free's: the costliest body of 1,600 values takes up to 20 ms, past Free's 10 ms, where Cloudflare may end it (1102). Sized to 10 ms, the same formula gives (10 ms − 4 ms) ÷ 10 µs = 600 values |
| A secret's value | 64 KiB of UTF-8 | half of Linux's 128 KiB, since `coffre run` makes each value one | platform |
| OAuth's authorize parameters together | 16,000 bytes | a Workers URL's 16 KB | platform |
| A provider's discovery document or key set | 64 KiB | about 1/2,000 of an isolate | #533 |
| Every body before sign-in (`SIGN_IN_BODY_BYTES`): device login, CI and workload exchanges, a passkey's answer, MCP's OAuth token, revocation and registration | 16 KiB | the largest B with `MAX_KEYS` × (`KEY_TRY_CPU_US` + `TOKEN_BYTE_CPU_NS` × B) ≤ 20 ms − 4 ms: 32 × (260 µs + 14 ns × B) ≤ 16 ms gives B ≤ 17.1 kB, rounded down to a power of two | #533 (R27). Measured: 32 tries of a 16 KiB token cost 7.1 to 12.0 ms; of 32 KiB, up to 21.4 ms. ⚠ Not Free's: a stranger's worst sign-in at 16 KiB, up to 12 ms before the rest of the request, runs past Free's 10 ms. No body size fits 32 keys in Free's 10 ms less the 4 ms read: 32 × 260 µs is 8.3 ms before a byte, so a Free bound would also lower `MAX_KEYS` (to 23 at most). The device login's 4 KiB and MCP's 256 KiB go; the exchanges' 16 KiB stays |
| Field bounds with no source | gone | – | R70 (#533): labels, role names and descriptions, claims, scopes and the rest |
| A field body's fields and depth, in the proxy (`MAX_FIELDS`, `MAX_DEPTH`) | 256; 32 | refused before parsing, so that a body made to cost the most (65,000 empty pairs in 64 KiB) costs no more than a real one, unauthenticated; a siteverify has four fields | `credential-proxy.ts`, kept by #533 (limits.md S27). The reason is written; the two numbers are not derived from it ⚠ |

### 2.8 Proxy

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Values served from memory | 60 s | R, the object's `revokedWithinSeconds`; none with `cacheValues: false` | policy |
| A fresh request's window to send, or to answer with a signature, from its start | 60 s | max(R, 3 s), 3 s the use's deadline (`USE_DEADLINE_MS`), so R's floor is 3 | `sendBy`, `answerBy` (`credential-proxy.ts`), policy. Today editable definitions only: code-defined forwarding, signing, verifying and presigning check no window, and must (section 1, `revokedWithinSeconds`) |
| A handle's tunnel: a check's deadline; the checks' interval | 10 s; 50 s | d = min(R ÷ 2, 10 s); R − d (today 10 s and 60 s, a 70 s bound) | policy |
| A workload's tunnel (and a UI tunnel a workload opens): two checks | (1) its session still stands: bound b = min(R, 15 s), checked every 2b ÷ 3 with b ÷ 3 to answer, today every 10 s with 5 s; (2) the vault still grants the key, and for an editable tunnel the item is the one dialled: every R with min(R, 10 s) to answer, today every 60 s with 10 s | (1) design section 8.2's 15 s; (2) proposed as the handle's: every R − d, d = min(R ÷ 2, 10 s), so a lost grant or a changed definition ends it within R | `credential-proxy.ts` (`workloadTunnel`, `uiTunnel`), policy |
| The refresh window before values lapse | min(cache ÷ 4, 15 s) | none written ⚠ | limits.md S25 |
| A message to sign or verify | 64 KiB by default; an `hmac()`'s `maxBytes` up to 1 MiB; editable definitions are counted at 1 MiB | 12 × Equisafe's largest in 90 days; 1 MiB costs about 5 ms of CPU | measured |
| A presigned URL | 1 s to 1 h | "an hour at most" | policy |
| Proxy items in one environment (`MAX_PROXY_ITEMS`) | 256 | its index stays under 17 KB, which every use of the environment carries | `packages/core/src/proxy.ts`, unchanged by #533. The 17 KB itself has no source ⚠ |
| One proxy definition, as JSON (`MAX_DEFINITION_BYTES`) | 8,192 bytes | none written | ⚠ no source, and unchanged by #533, which removed the other unsourced field bounds (R70): an editable definition past 8 KiB is refused far below the 1 MiB body bound. Erwin's call: keep it with a reason, or let the 256 items' bound and the body bound stand alone |
| The upstream request | no time bound | – | Q7 |

### 2.9 Audit and the uses log

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| The seal tick; a witness's wait | 500 ms; 2 s | – | R51, R54 |
| A change waits for its seal | 5 s | – | T169 |
| A seal is stale after | 5 s | 10 ticks | derived |
| The vault's wait on the checkpointer's Durable Object for a seal, on Workers (`SEAL_ASK_BOUND_MS`) | 8 s | `SEAL_WAIT_MS` 5 s + a witness's 2 s + 1 s margin | `checkpointer-workers.ts`; the 1 s is not measured ⚠ |
| The same for anything else: a start, its status, the pair it remembers (`ASK_BOUND_MS`) | 2 s | none written | ⚠ a choice, `checkpointer-workers.ts` |
| A tick's bound (`TICK_BOUND_MS`) | 10,000 + span × 0.01 ms, span the numbers the barrier's window covers (`WINDOW_ENTRY_MS`) | past it the checkpointer stalls, is closed for good, and its host opens another. Bounded by the work asked, so a drain of millions goes on | `packages/vault/src/checkpointer.ts` (T169, Fable's review) |
| An open's bound (`OPEN_BOUND_MS`) | 10 s, fixed | `TICK_BOUND_MS`, without the per-entry extension | `checkpointer-node.ts`, `checkpointer-workers.ts` |
| Entries one tick seals (`WINDOW_MAX`) | 10,000 | a backlog is sealed in parts, each a pair, the next tick at once: read whole, a stall of minutes at R44 would pass the tick's bound and stall again | the same
| Unsealed entries a check reads (`ABOVE_NEWEST`) | 1,000, on `main` | 4.5 ms fixed + 13.4 µs an entry fits 1,150 in R27's 20 ms at the median; 1,000 below it, where the p90 reaches 20 ms. Its floor: one late tick's entries at R44, 1,000 | D6, measured (`packages/vault/src/verifier.ts`). An exception to R27 at p99: the slowest check at 1,000 took 27 to 42 ms, and a cap that held it under 20 ms would sit below the floor. On Free, a check past about 400 entries fails instead |
| Days of uses made ahead | 3 | – | a use with no day's table fails |
| What one logged use stores, all of it kept as long as its day | **about 790 bytes**: the use's row 141 (heap and index), its level-0 tiles 47.5, its read in the reads' projection 322 (`log_reads`: heap 186, indexes 136), and the projection's place indexes about 280 | measured each; their sum is not measured as one | the row: [hot-path-one.md](hot-path-one.md) (W211); tiles: [audit-tree.md](audit-tree.md); the projection: [0.15-plan.md](0.15-plan.md) (0049, T175), whose days retention drops with the uses' |
| The same, per day | about 68 GB at a steady 1,000 uses a second; far less when repeats are covered | 790 B × 86.4 M | derived |
| The uses' row's WAL | 248 bytes a use: about 21.4 GB a day at 1,000 a second, written, then recycled or archived as the database's own WAL settings say. The projection's and the tiles' WAL come on top, unmeasured here | measured | [hot-path-one.md](hot-path-one.md) |
| Days of uses kept | **every day**, as today | the object's `keepUsesDays` | Q6 |
| How often retention runs (`RETAIN_EVERY_MS`) | hourly | – | `log-checkpointer.ts` |
| Days detached per run | **one** | each DETACH makes every backend plan the uses again; two close together stall uses (measured for a DROP, [0.15-plan.md](0.15-plan.md)) | `retention.ts`. A backlog drains a day an hour: switching on 30 days on a database a year old detaches its 335 extra days over about 14 days |
| A day's freshness margin before it goes | 20 min | 2 × `FRESH_MS` (10 min) past the day's cut, read from the signer's own pair | `checkpointer.ts`, `retention.ts` (FreshBeforeDrop) |
| How long a tick waits on the log's upkeep (`UPKEEP_BOUND_MS`): retention's drop of a day and its tiles | 60 s | none written | ⚠ a choice (T169, 205e8255), `checkpointer.ts` (limits.md V14) |
| Alarms a checkpointer keeps, in its Durable Object or the Node runner's file (`ALARMS_KEPT_MS`) | 30 days | none written; on Node a compaction trigger past 1,000,000 bytes, not a byte bound | ⚠ a choice, `checkpointer.ts` (limits.md V57, which leaves a byte bound open) |
| Reads the projector takes a step (`PROJECTED_AT_ONCE`), steps a run | 1,000; 4 | a tick's worth at R44, 500 entries, twice over: 4,000 a run | `packages/vault/src/reads.ts` (limits.md V74) |
| The audit watch's staleness | 11 min | 2 × the 5 min schedule + 1 | #503 |

## 3. Open questions

These are Q1 to Q7 of [limits.md](limits.md#6-questions-for-erwin). Q4 is
settled: Erwin's D5 and R76 ("one or two settings … much higher"), built in
#520. The others are open; R75 and R76 settle none of them, though #538
(R75) does part of Q5's work.

### Q1. Refusing `/use` fast on Workers

**Facts.** Each isolate refuses its 11th use in flight with 503
`overloaded`. The 10 is node-postgres's default pool size, applied where
there is no pool (limits.md §2). Measured since:

- A held use costs about 30 KiB in the vault's isolate, 36 KiB by heap
  snapshot, flat from 100 to 500 held. CPU is about 2.4 ms a use (local
  workerd).
- Beside a binding removal, on one Node process with its own Postgres
  16.14, removing 5,000 credentials in batches of 125 (10 ms each). Indicative
  only: a shared host at load 37-41 (#520's helper, D181):

  | Target | Run | Alone: answered, refused, p99 | Beside the removal: answered, refused, p99 |
  |---|---|---|---|
  | 1,000/s | 1 | 672/s, 0.9%, 24 ms | 421/s, 17%, 44 ms |
  | 1,000/s | 2 | 249/s, 2.8%, 116 ms | 241/s, 33%, 137 ms |
  | 400/s | 3 | 307/s, 4.0%, 116 ms | 210/s, 28%, 131 ms |

  With the cap bypassed, driving the vault's use statement directly
  (`packages/server/test/bench/ci.ts --uses 1000 --unbind 20000`, #520's
  `--unbind` flag), every use was answered at
  1,000 a second beside a removal of 20,000 credentials, even in 50 ms
  batches: zero refused. **The cap of 10 causes the refusals, not the
  lock the removal holds.** A quiet-host run at 1,000 a second is still to
  come.
- W208, on Cloudflare: with no cap at all, goodput stays at the database's
  ceiling, and the excess is answered `late` within 3 s, doing no work in
  the database.

**Recommendation: two steps.**

**Step 1, now, with no Cloudflare run:** replace the 10 with what an
isolate can actually carry, the smaller of its memory and its CPU within one
deadline:

> min(uses' share ÷ bytes a use holds, deadline ÷ CPU a use takes)
> = min(64,000,000 ÷ 30 KiB, 3,000 ms ÷ 2.4 ms) = min(2,083, 1,250) = **1,250**

On Node, the same two bounds for the process, as #519 does for its shares.

**What the count must cover first.** Today a use's place in admission is
taken for its database phase alone: `raced` (`packages/vault/src/use.ts`)
admits it, and releases the place when the statement and its reads after
it settle, before `opening` unwraps the value's key at the key service.
And a batch is admitted once per round, as one place: `useMany`'s round
holds every key the call asks, sent `uses.batch` = 100 keys a statement,
in turn, under that one admission (`inStatements`). So neither today's 10
nor a 1,250 bounds what an isolate holds: a use waiting on KMS for its key,
for what is left of its own 3 s deadline (the hot path hands KMS the use's
deadline, not `KEY_BUDGET_MS`), holds its row and request but no place,
and a round of 100 keys, or of more, counts as one use.
*Example:* an isolate taking 400 uses a second while KMS answers each key
in about 3 s admits each use for its few ms in the database, then holds
about 1,200 uses waiting on their keys, none of them counted; and 1,250
rounds of 100 keys would be 125,000 keys under the same count, more if a
round asks more. Step 1
therefore needs two code changes before its number means anything:

- a place is held from admission until the value is opened or the use
  fails (its key opened, refused, or `late`), so a use waiting on its key
  service counts;
- a batch takes one place per key, not one for the call.

And the 30 KiB must be measured over that lifetime: held uses with a slow
key service, and batches, not only uses held as today's admission counts
them. The formula stays; its byte input is re-measured, and 1,250 holds
only if the new figure is at most 50 KiB (64,000,000 ÷ 1,250 = 51,200
bytes), where the CPU bound is still the smaller.

*Example:* a cold isolate that Cloudflare sends 200 uses in its first
second, each taking 80 ms, has about 16 in flight: today 6 of them are
refused with the database idle; after step 1, none.

Step 1 changes one derived value: a removal's batch is 10 ms of the lock
every use takes only because 10 uses in flight arrive in 10 ms at 1,000 a
second (`FENCE_BUDGET_MS`). With 1,250 in flight, uses wait behind a batch
instead of being refused, so the batch's bound becomes how much latency a
use may gain beside a removal: Erwin's D178 50 ms (625 a batch on Node)
again, or the 10 ms if he prefers the lower p99. Or remove the question: the
vault's use statement refuses a credential whose binding is closed, and the
batches stop needing that lock at all. TLC holds every scenario so
(`VaultChecksClosed`), at the cost of a join on the hot path (limits.md
§3.6). Recommendation: step 1 and 50 ms batches; the join only if a
removal's latency shows up in a real p99.

**Step 2, fast refusal from recent outcomes, A or B:** B, adaptive
throttling (Google SRE book, "Handling Overload"). Each isolate counts, over
a trailing window, the uses it was asked (`requests`) and those the vault
answered in time (`accepts`), and refuses a new use with probability
max(0, (requests − K × accepts) ÷ (requests + 1)). It has two numbers, both
from the source: K = 2 and a 2-minute window. The window is how much history
an isolate keeps, not how long an overload must last or how long refusals
outlive it: the probability follows the ratio of requests to accepts in that
window. K = 2 means nothing is refused until requests exceed twice the
accepts. Two consequences, both from the formula: a cold isolate whose first
use failed (1 request, 0 accepts) refuses the next with probability 1 ÷ 2;
and successes after an overload bring the probability back to 0 while the
failures are still in the window, once accepts are half the requests again.
The probability stays below 1, so it never shuts and needs no reopening
rule. A needs three numbers nobody has measured (window, percentile,
reopening rate) and risks every isolate shutting at once. *Example:* 2,500
uses a second offered against W208's ceiling of 1,040, for two minutes:
300,000 requests, 124,800 accepts. A new use is refused with probability
(300,000 − 2 × 124,800) ÷ 300,001 ≈ 17%. The rest of the excess still goes
`late`, so K = 2 trades some lateness for fewer refusals while the vault
still answers more than half of what it is asked. Either rule needs one run on Erwin's Cloudflare (R34, under $5, about
an hour) before it ships. Without that run, there is no step 2: the excess
is answered `late` within 3 s, as W208 measured, and R44's "refused fast"
waits.

### Q2. Node pools, and processes beyond one

**Facts.** A Node pool is 10 connections, node-postgres's default; the code
meant to read its size reads a property that is never set (limits.md V2). A
Node deployment already runs one app process and one vault process: the
sign-in limits and the gates count per process, and the vault runs the
checkpointer (the examples say so).

**Recommendation: no setting.** Each process asks the database at start
(`max_connections`, the reserved slots) and sizes its pools with the formula
`coffre setup` already uses for Hyperdrive: an even third each for the app,
the vault and the uses, less 3 held back. The checkpointer's 2 come out of
the vault's third. Keep the even split, one rule on both runtimes, until a
Node run shows the uses' pool needs more. More than one process per role
needs a pooler in front (PgBouncer, the part Hyperdrive plays on Workers):
documented, not built. *Example:* at `max_connections` 100 (3 reserved),
each login's share is 31: the app's pool and the uses' pool are 31, the
vault's request pool 29 and its checkpointer's 2, against 10 each today,
and nothing to configure. At 25 the share is 6: pools of 6, 6, 4 and 2.

**The formula's floor: a share of 5.** Each pool must keep a connection,
and Q3's waiters need the vault's request pool to leave 2 free, so the
request pool needs at least 3, and the share at least 5. That is setup's
minimum for a Hyperdrive config (`HYPERDRIVE_CONNECTIONS.fewest`), one
floor on both runtimes. Below it a Node process refuses to start, naming
the `max_connections` it needs, as `coffre setup` refuses on Workers;
today setup checks the minimum for Workers alone (`setup.ts`), and Node
checks nothing. *Example:* at `max_connections` 14, 3 reserved and 3 held
back, the share is ⌊8 ÷ 3⌋ = 2: the vault's request pool would be 0 and
Q3's waiters −2, so the process refuses, asking for 21 (3 + 3 + 3 × 5). At
21, pools of 5, 5, 3 and 2, and 1 waiter.

### Q3. Where the vault learns its connection share (`READ_HEAD_WAITERS`)

**Facts.** Up to 16 reads wait for the log's head, each holding a vault
connection while it waits. On a small database the vault's config has fewer
connections than that: at `max_connections` 25, setup gives it 6, and 16
waiters take all 6.

**Recommendation:** the vault computes the share itself, from the database,
with setup's formula, and holds the waiters to min(16, request
connections − 2): its request connections are the share on Workers, and
the share less the checkpointer's 2 on Node (Q2). It asks for the two
numbers with its first reads, in the round trip it already makes (T206),
so this adds no round trip. The plan's 20 or 100 never matters: it caps
the share only above 20, where 16 is already under the request connections
− 2. *Example:* at 25, share 6. On Workers, 6 request connections, so 4
waiters, and two connections stay free for everything else. On Node, 4
request connections (the checkpointer's 2 are a pool of their own), so 2
waiters, and two stay free. At 100, 16 on both, as now. One caveat: a
Hyperdrive config someone set by hand below setup's number makes the vault count more
connections than it has: the formula assumes setup set the config.

**What the count does not hold on Workers.** The waiters' places are
advisory locks, counted across the whole database (`lockLogHeadQueued`,
`packages/db/src/log.ts`), but Hyperdrive splits a config's connections
among its pool's shards (`docs/deploy.md`, beside setup's numbers). At
6 connections a location may run them as several shards of one or two
each, so 4 waiters, all admitted, can each hold the only connection of
the shard its call landed on, and the requests routed there wait while the
2 "free" connections sit on other shards. The two free connections are a
global figure, not a per-shard one. So on Workers the formula is a
heuristic that caps the damage, not a guarantee: it needs a Workers run at
setup's minimum share before it ships. Holding the guarantee takes an
admission that holds no connection while it waits: take a place, try the
head with `NOWAIT`, and on a miss commit, pause and try again, so a waiter
gives its shard back between tries (one round trip per try; unmeasured).
Node has no shards: there the count is exact.

### Q5. Statement timeouts for the app's and the vault's logins

**Facts.** Only the uses' login has a `statement_timeout` (2 s). #538 (R75)
bounds a write's lock waits to 500 ms (section 2.4 lists the longer ones:
reads 3 s, `sign_in` and `issue_token` 1 s), and the vault's transactions
that carry a deadline bound each statement by what was left of it at
BEGIN (`SET LOCAL statement_timeout`, which Postgres counts per
statement), so the transaction as a whole may run past it (section 2.4). What is left unbounded: every app statement, and vault statements
outside a deadline's transaction. Postgres runs such a statement until it
ends or Hyperdrive gives up at 60 s.

Two ways to bound them:

- **Per call, from its remaining deadline.** Hyperdrive pools by
  transaction and `RESET`s a connection it takes back, so a `SET` sent on
  its own does not reach the next query. But it applies a `SET` sent in the
  same transaction, or in the same query (`SET X; SELECT …`)
  ([Hyperdrive, pooling mode](https://developers.cloudflare.com/hyperdrive/concepts/connection-pooling/#pooling-mode)).
  So a statement can carry its bound: `BEGIN; SET LOCAL statement_timeout
  = <left>; <statement>; COMMIT`, sent under one Sync, is still one round
  trip, as the vault's transactions already are (T206's grouping). It
  needs each app call to carry a deadline to subtract from, and touches
  every query path.
- **Per login, a ceiling.** `ALTER ROLE … SET statement_timeout`. It
  catches every statement whatever path sent it, and needs no code. Two
  catches. Altering a role takes a superuser, or `CREATEROLE` and `ADMIN`
  on that role ([`ALTER ROLE`](https://www.postgresql.org/docs/16/sql-alterrole.html)),
  and a login that only migrates has neither: `docs/deploy.md` supports
  it. And Postgres applies the setting at the next login: a connection
  Hyperdrive already holds keeps its old one until it is replaced
  ([Hyperdrive's connection lifecycle](https://developers.cloudflare.com/hyperdrive/concepts/connection-lifecycle/#how-connections-are-managed)).
  Main already meets the first catch twice: migrate sets the hot login's
  timeouts or stops with the SQL an administrator must run
  (`holdHotLogin`), and resets 0.15's planner settings only where it
  may, `deploy.md` giving the SQL otherwise (`clearPlannerSettings`).

**Recommendation: the ceiling now, per-call bounds where a call has a
deadline.** A role setting of 5 s for `coffre_runtime` and
`coffre_vault_runtime`, set where the privilege is:

- `coffre setup` sets it, as it makes the logins.
- `coffre migrate` sets it when its login has `CREATEROLE` and `ADMIN` on
  both. A login without them leaves it, as `clearPlannerSettings` does,
  says so, and `deploy.md` gives the administrator the two `ALTER ROLE`s
  to run once per server.
- Whoever sets it then ends those logins' idle backends, so a warmed pool
  reconnects with it. `pg_terminate_backend` asks for more than `ALTER
  ROLE`: the privileges of the login's role, or `pg_signal_backend`.
  Where nobody may, the pool takes the ceiling as Hyperdrive replaces its
  connections. Either way the rollout is tested against a warmed pool,
  not a fresh one.
- The app and the vault read `current_setting('statement_timeout')`
  with their first reads (T206's round trip, so none added) and log a
  warning when their login runs without the ceiling, so a deployment that
  skipped the administrator's step hears it.

Without the step, the ceiling waits; nothing breaks, as today. Unlike the
hot login's settings, which 0.15's uses need to be correct, this is not
worth stopping a migration for.

The 5 s is a chosen ceiling, not a derived one: it
equals a read call's deadline (`CALL_DEADLINE_MS`), and no statement of a
caller who hears within 5 s needs longer. Writes may take longer (R75), so
before the migration the suites run with it on, to find any write
statement that legitimately does. The vault's transactions keep tightening
it to what their deadline had left at BEGIN, as today: per statement,
not a bound on the whole (section 2.4 says what a strict one needs). Backups and migrations use
logins of their own, untouched. *Example:* today a slow vault statement on
a small database holds one of its config's 6 connections for up to
Hyperdrive's 60 s; with the role's 5 s, Postgres ends it at 5 s and the
connection is free again.

### Q6. Retention in the standard setup

**Facts.** `retainDays` exists, but neither Workers' `checkpointer()` nor
`serveVault` passes it, so every standard deployment keeps every day of
uses. Retention drops only uses; changes are kept forever.

Days kept no longer cost a use anything. When retention was built, a use's
plan named every day attached, and at 95 days 40 new connections at once
passed the uses' 2 s `statement_timeout`. Migration 0057 (T187) fixed that:
the cover check names only its own day. Measured since, at 5 and at 109
days, 23 locks a use at either, and a new day costs one call, not every
connection a replan; at 500 days, 1,000 uses a second at 0.63 ms of CPU
([0.15-plan.md, "As built: PR 7"](0.15-plan.md#as-built-pr-7-w229), the
paragraph on T187). `use-days.alone.ts` holds it.

So the days kept are a choice between storage and evidence, nothing else.
A day kept holds more than its uses' rows: each logged use also leaves its
level-0 tiles and its row in the reads' projection, with that projection's
indexes, and retention drops them all together. About 790 bytes a use in
all (section 2.9: four measurements added up, never measured as one), and
a backup carries them too.

| uses a second, steady | a day | 30 days | a year |
|---|---|---|---|
| 1,000 (R44) | 68 GB | 2.0 TB | 25 TB |
| 10 | 683 MB | 20.5 GB | 249 GB |

The use's own row is 141 of the 790 bytes (12.2 GB a day at 1,000 a
second); the projection's 602 are most of it. Far less when repeats are
covered (80% on covers: about a quarter).

**Recommendation:** expose it as `audit.keepUsesDays`, **default `null`,
every day kept**, as today. The uses are the record of who read which
secret, which an audit may ask for years later; dropping them should be a
deployment's decision, with its numbers in front of it, not a default. A
deployment at R44's rate sets a number, and `docs/deploy.md` shows the
table above. *Example:* a deployment that must keep a year of evidence and
runs at 10 uses a second sets nothing and holds about 250 GB after a year;
one at 1,000 a second that keeps 30 days sets 30 and holds about 2 TB.
Kept forever at R44's rate, a year is 25 TB, which is why `deploy.md`
puts the table in front of whoever deploys at that rate.
Switching retention on late is slow on purpose: one day detached an hour
(section 2.9), so a year-old database that sets 30 sheds its 335 extra
days over about two weeks, each day at least 20 minutes past its cut.

### Q7. A bound on the proxy's upstream request

**Facts.** The credential proxy's `fetch` to an upstream has no timeout. No
platform limit or memory pressure calls for one: a body read whole is held
to the bodies' share (#519), and a Worker's connections are counted per
request, so one slow upstream holds only its own request. But the proxy also
keeps waiting after the app has given up: it does not pass the incoming
request's abort signal on. On Node, `fetch` (undici) then waits up to its
own default, 300 s for the headers.

**Recommendation:** no time bound of coffre's own (R70), and end the
upstream request when the app's request ends: pass the incoming request's
signal to the upstream `fetch`. The app's own timeout is then the bound, as
it would be without coffre in the path.

Passing the signal is not enough on Workers today. An incoming request's
signal fires on a disconnect only with the `enable_request_signal`
compatibility flag, or a compatibility date of 2026-11-17 or later
([compatibility flags](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#enable-requestsignal-for-incoming-requests)).
The examples' app pins `2026-08-06` with `nodejs_compat` alone
(`examples/workers/app/wrangler.jsonc`). So the change adds the flag to the
app's `wrangler.jsonc` in the examples and in what `coffre init` writes, and
a deployment that does not update its file keeps today's behavior. On Node,
a test shows srvx's request signal fires when the client disconnects before
the change relies on it. *Example:* an app with a 30 s
client timeout calls a hung upstream through the proxy. Today, on Node, the
proxy holds the request for up to 300 s after the app left; with the signal,
it ends at 30 s with the app's.

### Also waiting on Erwin (not Q1-Q7)

- **D7's 10 ms batch** (limits.md §3.6, #520): merged only once Erwin
  confirms 10 ms. Q1's step 1 changes the answer: see Q1.
- **Clock skews (D3)**: on hold since Erwin asked what they are for.
- **limits.md §3.6's other numbers**: MCP's per-connection count dropped
  (done in #520), `MAX_BINDINGS` 256 by a narrower read, `replicas` up to
  1,000.

## 4. What goes

| Knob | Before | After |
|---|---|---|
| The vault's `uses` block on Workers (`inFlight`, `connections`, `coverMs`, `names`, `batch`) | five settings, none set by any deployment | gone: the in-flight count derived (Q1), the rest internal constants at today's defaults (60 s, 10,000, 100; section 2.3) |
| `DEFAULT_CONNECTIONS` and Node's pool probe | 10 per isolate or process; the probe always reads nothing | gone, with Q1's step 1 |
| `USES_AT_ONCE` (4 per request) | "leaves the isolate's admission room" | gone with the count it protects |
| Node pool size (`max ?? 10`) | 10 per pool; a deployment passing a URL cannot change it | derived from the database at start (Q2) |
| `coffre setup`'s Hyperdrive maximum | 20, Free's, on Paid too | the plan's maximum (limits.md #12) |
| `READ_HEAD_WAITERS` | 16, whatever the database | min(16, request connections − 2), the share computed (Q3) |
| `signin({ workloads: { useOnly, noReads } })` | in `signin`'s `workloads`, both `false` | `policy.services.useOnly`, `policy.services.noReads`; `workloads` keeps its wiring (the limiters' bindings, `github`, `alert`) |
| `vault({ bulkLimit })`, `serveVault({ bulkLimit })` | in the vault's config | `policy.reads.bulkLimit` |
| `signin({ passkeys, browserSessionHours, cliSessionDays, serviceTokenMaxDays })` | in `signin` | `policy.people.*`, `policy.services.tokenMaxDays`; `passkeys.rpId` stays in `signin` |
| `credentialProxy({ cacheSeconds, recheckSeconds })` | two settings, both 60: a tunnel's bound 70 s | `policy.proxy.revokedWithinSeconds`, the tunnel's checks derived to fit it; `cacheSeconds: 0` becomes `policy.proxy.cacheValues: false` |
| `credentialProxy({ editable })` | in the plugin's options | `policy.proxy.editable` |
| `createCoffre({ rotateAfterDays })` | in `createCoffre` | `policy.values.rotateAfterDays` |
| `retainDays` | only through `runCheckpointer`/`keepCheckpointer` on Node | `policy.audit.keepUsesDays`, default every day, as today (Q6) |
| Sign-in rate limits | five Workers bindings (per address and in all, for workloads and MCP; MCP per connection), 30 / 300 / 120 a minute; `processLimits` the same | one, per address, 10,000 per 10 s (#520), its number in the policy |
| The per-binding count | 60 sign-ins a minute, in the app, the vault and `sign_in` | gone (#520, R76) |
| `exchangeLimit.inFlight` | 32, unsourced | a memory bound, once a sign-in has a deadline (limits.md #35) |
| The vault's 15 s write lock wait (`LOCK_TIMEOUT_MS`) | 15 s | `LOCK_WAIT_MS`, 500 ms, retried for up to 5 s from the first attempt (#538) |
| A plain 503's `Retry-After` | 5 | 1 (#538) |
| `MAX_BODY_KEYS` and the field bounds | 2,000 top-level entries; labels 120, role names 40, descriptions 200, claims, scopes and the rest | gone (#533): one 1 MiB body bound, its values counted |
| The pre-sign-in body bounds | 4 KiB, 16 KiB, 256 KiB by entry point | one, 16 KiB, derived from a stranger's worst sign-in (#533) |
| A sign-in's CPU accounting (`SIGN_IN_WORK_NS`) | 16 ms, spent step by step | gone, the body bound holding the same 16 ms (#533) |
| The proxy's caches | 1,000 or 10,000 entries, some cleared whole | least recently used, within a slice of 16 MiB (#519) |
| The proxy's body read whole | 16 MiB | 1 MiB; larger bodies stream (#519) |
| KMS's 8 calls at once | slots handed from one request to the next | per call (#538's KMS PR) |
| KMS's attempt timeout and key budget | 5 s each; 5 s in all | 706 ms each, measured; 3,118 ms per operations batch, a ceiling sized to one operation's retries; a cold vault's KEK checks each get their own, all inside the call's 8.1 s (2.4) |

What a deployment writes after all of this: its wiring, as today, and
`policy.ts`, thirteen fields, each with a default it can leave alone.
