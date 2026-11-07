# One config object: what a deployment chooses, and what coffre derives

Status: **proposal, for Erwin's one-pass review (D172), for 0.16.** Written
against `main` at `f9261451`, with the values of the open PRs that change
limits at their heads: #519 (`f5d3eb02`, proxy memory), #520 (`0e197735`,
sign-in limits), #533 (`b8dc8c73`, body bounds), #538 (`c539928c`, locks and
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
session lifetimes, the longest service token), `vault({…})` on Workers and
`serveVault({…})` on Node (the bulk read cap, the `uses` block),
`credentialProxy({…})` (two revocation delays), `createCoffre({…})` (when a
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
    browserSessionHours: 12, // 1 to 168
    cliSessionDays: 30, // 1 to 365
  },
  services: {
    tokenMaxDays: 365, // 1 to 365 (R76)
    signInsPerAddress: 10_000, // per 10 s, each sign-in entry point counted apart (R76, #520)
  },
  reads: {
    bulkLimit: { count: 1_000, windowMinutes: 15 }, // window at most a day (R28, R52)
  },
  values: {
    rotateAfterDays: 365, // null: never flag
  },
  proxy: {
    revokedWithinSeconds: 60, // 0 to 3,600; read only with the credential proxy
  },
  audit: {
    keepUsesDays: 30, // null: every day kept (Q6)
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
| `people.browserSessionHours` | 12, at most 168 | app | `signin({ browserSessionHours })` | how often a person signs in again in a browser |
| `people.cliSessionDays` | 30, at most 365 | app | `signin({ cliSessionDays })` | the same for `coffre login` |
| `services.tokenMaxDays` | 365, 1 to 365 | app **and vault** | `signin({ serviceTokenMaxDays })`, app only (#516) | R76. New: the vault holds an issue to the deployment's number too, where today it holds only the 365. The default lifetime offered stays min(90, this) |
| `services.signInsPerAddress` | 10,000 per 10 s | app | Workers: `SIGN_IN_PER_SOURCE` in `app/wrangler.jsonc` (#520); Node: `processLimits({ perSource })` | R76 asked for one or two settings. The default is R44's 1,000 sign-ins a second over one window, since a fleet behind one NAT is one address. A deployment with no such fleet may set it lower |
| `reads.bulkLimit` | 1,000 keys per 15 min | vault | `vault({ bulkLimit })` | R28, R52 |
| `values.rotateAfterDays` | 365, or `null` | app | `createCoffre({ rotateAfterDays })` | when the UI and `coffre list` flag a value nobody changed |
| `proxy.revokedWithinSeconds` | 60, 0 to 3,600 | app | two settings, `credentialProxy({ cacheSeconds, recheckSeconds })`, both 60 | see below |
| `audit.keepUsesDays` | 30 (proposed; `null` today) | vault | `retainDays`, reachable only by a Node deployment that runs its own checkpointer | Q6 |

**`proxy.revokedWithinSeconds` merges two settings that mean one thing.**
Both bound how long a revoked credential keeps working through the proxy:
`cacheSeconds` is how long its opened values serve requests from memory,
`recheckSeconds` how often an open database tunnel checks it still stands.
Example: an Owner revokes a CI token at 12:00:00. At 60, its last request
through the proxy leaves by 12:01:00, and its open Postgres tunnel closes by
12:01:00. With two settings a deployment could make them 60 and 600 and get
an answer nobody meant. At 0, every request asks the vault and a tunnel
checks every second, its smallest step. A workload's tunnel keeps its own
15 s (`WORKLOAD_RECHECK_MS`, design section 8.2), or this if less, as today.

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
  and their features (`editable`, `generate`, `insecureUpstreams`, the
  credentials), witnesses, `passkeys.rpId`.
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
which the questions in section 3 or a later PR settle.

### 2.1 Inputs: platform facts and Erwin's rules

| Input | Value | Source |
|---|---|---|
| A Worker isolate's memory | 128 MB, read as 128,000,000 bytes (the smaller reading) | [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) |
| A Workers invocation's CPU on Free | 10 ms, hard: an invocation over it is killed (1102) | Workers limits; R25 and R27 hold every request to it |
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
| One body read whole | 1 MiB | D1 | Erwin; larger bodies stream |
| Bodies read whole at once | 8 | 16 MiB ÷ (2 × 1 MiB): each counted twice, its bytes and a copy | #519's code. (`memory.ts`'s comment says sixteen: a P3 for #519) |
| One cache's slice | 2,396,745 bytes | 16 MiB ÷ 7 caches, least recently used out first | #519 |
| Uses an isolate can hold | about 2,083 | 64,000,000 ÷ 30 KiB per held use | 30 KiB measured (W331, local workerd); stated in #519, not used until Q1 |
| A plugin's WebSocket message on Node | 1 MiB | the body bound | #519 |
| A streamed body | 5 GiB | S3's one request | platform |
| A body whose digest is declared | 95 MiB | under Cloudflare's 100 MB | platform |

### 2.3 Uses

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Uses in flight per isolate or process | **10** ⚠ | node-postgres's default pool, where Workers has no pool | none: Q1 |
| How long a use's place outlives its deadline (`HELD_PAST_DEADLINE_MS`) | 2 s | the uses' login's `statement_timeout` | R53 |
| A use's time tolerance (`AT_SLACK_MS`) | 63 s | deadline 3 s + a clock 60 s ahead | R53, D3 |
| The bulk cap's refresh | 60 s at 15 min | min(60 s, window ÷ 10) | decision 9 |
| The bulk window's maximum | 1 day | releases kept a day and an hour | R52 |
| Keys a statement uses at once (`uses.batch`) | 100 | about 0.4 ms a key under the lock every use shares, so about 40 ms | measured (review of #433) |

### 2.4 Lock waits and deadlines (#538, #508)

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Every lock wait but a use's (`LOCK_WAIT_MS`) | 500 ms | the uses' 1 s ÷ 2 | R75: a writer that waits in Postgres's queue holds back every use behind it, so it leaves within half a use's wait |
| The migrator's wait per statement | 500 ms, 5 tries, 1 s apart | `LOCK_WAIT_MS` | #508 |
| The two credential writers that take the uses' lock exclusively, in SQL (`revoke_credential`, `change_bindings`) | 500 ms (from 1 s) | `LOCK_WAIT_MS` | #538 |
| `sign_in`, `issue_token` | 1 s | they take only the issue lock, which no use asks for | #538 |
| A vault call, retries included (`CALL_DEADLINE_MS`, was `READ_DEADLINE_MS`) | 5 s | a choice: "a caller hears within it" | #356 ⚠ not derived |
| Its retry pauses | 25 ms doubling to 400 ms, ×0.5 to ×1.5 | a retry policy, written as one | #538 |
| A read's lock wait (`READ_LOCK_TIMEOUT_MS`) | 3 s | a choice | #347 ⚠ |
| Waiters for the log's head (`READ_HEAD_WAITERS`) | 16 | 2.4 s ÷ 150 ms measured; should also be ≤ the vault's connections − 2 | Q3 |
| A plain 503's `Retry-After` | 1 s (from 5) | `LOCK_WAIT_MS` rounded up to whole seconds | #538 |
| An app write's lock wait | 500 ms (from unbounded) | `LOCK_WAIT_MS`; then 503 at once | #538 |
| The key service, per call (`KEY_BUDGET_MS`) | 5 s | **pending:** the KMS measurement and its derivation (706 ms an attempt, 3,118 ms in all), from #538's follow-up | placeholder |
| AWS KMS calls: tries, timeout, at once | 3, 5 s each, 8 per provider object | unchanged by #538 | **pending**, as above. The 8 cites "six connections", which Workers counts per request, not per isolate ([limits.md](limits.md), item 5) |

### 2.5 Database connections

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| A Hyperdrive config's connections, set by `coffre setup` | ⌊(max_connections − reserved − 3) ÷ 3⌋, at least 5, at most **20** ⚠ | an even third for each login (app, vault, uses), less 3 held back | the 20 is Free's maximum, applied on Paid too: [limits.md](limits.md) #12 proposes the plan's maximum. Example at 100: 31 each, cut to 20 |
| Held back (`HELD_BACK`) | 3 | for the administrator, `coffre migrate`, the host's tools | a guess ⚠ (Q2) |
| A Node pool | **10** ⚠ | `max ?? 10`, node-postgres's default | Q2 |
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
| A binding removal's batch, Node (`UNBIND_BATCH`) | 125 | 10 ms ÷ 0.08 ms a credential, measured | the 10 ms is `FENCE_BUDGET_MS` = 10 uses in flight ÷ 1,000 a second: **derived from Q1's 10**, see Q1. **Pending:** D181's derivation, its refusal table and follow-ups, from #520's helper |
| The same, on Workers | 114 a call, 228 a request | (10 ms − 4.85 ms fixed) ÷ 0.045 ms; 2 calls in the request's CPU, within 32 invocations | measured on workerd (#520) |
| A batch's bytes | 4 MiB | half the Node vault socket's 8 MiB message | #520 |
| Spent sign-in tokens forgotten a beat | 600,000 | 2 × 1,000 a second × 300 s | R44 (#520; was 5,000) |
| Open bindings per service (`MAX_BINDINGS`) | **16** ⚠ | none written | limits.md §3.6 proposes 256, once a sign-in reads only the bindings that can match |
| A binding's fleet size (`replicas`) | 1 to **64** ⚠ | none written | limits.md §3.6 proposes 1 to 1,000 |
| A sign-in's CPU budget (`SIGN_IN_WORK_NS`) | 16 ms | R27's 20 ms − 4 ms to read the largest body | #533 |
| Keys in an uploaded key set | 32 | 32 failed checks ≈ 4.3 ms | #533 |
| A binding's issuer | 1,670 bytes (from 400) | 2,704 (index entry) − 1,034 (the entry's other columns) | #533 |
| A workload's gate | 1,000 a second per service | a Durable Object's soft limit | platform; on Node it stands in for a memory bound ⚠ (limits.md #5) |

### 2.7 Bodies (#533)

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Every control-plane body, before sign-in too (`API_BODY_BYTES`) | 1 MiB | about 5 MiB held while read, 4% of an isolate | #533. The device login's 4 KiB, the exchanges' 16 KiB and MCP's 16 and 256 KiB are gone |
| Values in a body (`MAX_BODY_NODES`) | 1,600 (from 20,000) | (20 ms − 4 ms) ÷ 10 µs a value, measured | R27; counted on the text before it is parsed |
| A secret's value | 64 KiB of UTF-8 | half of Linux's 128 KiB, since `coffre run` makes each value one | platform |
| OAuth's authorize parameters together | 16,000 bytes | a Workers URL's 16 KB | platform |
| A provider's discovery document or key set | 64 KiB | about 1/2,000 of an isolate | #533 |
| Before sign-in | **pending**: a ~32 KiB bound on what is read before anyone is signed in was agreed for #533 (W354), and is not in its head `b8dc8c73`, which reads those bodies to 1 MiB | – | see [limits.md §3.7](limits.md#37-accepted-costs-an-owner-controls) |
| Field bounds with no source | gone | – | R70 (#533): labels, role names and descriptions, claims, scopes and the rest |

### 2.8 Proxy

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| Values served from memory; a tunnel's check | 60 s | the object's `revokedWithinSeconds` | policy |
| A workload's tunnel check | 15 s | design section 8.2 | policy |
| The refresh window before values lapse | min(cache ÷ 4, 15 s) | none written ⚠ | limits.md S25 |
| A message to sign or verify | 64 KiB | 12 × Equisafe's largest in 90 days | measured |
| A presigned URL | 1 s to 1 h | "an hour at most" | policy |
| The upstream request | no time bound | – | Q7 |

### 2.9 Audit and the uses log

| Name | 0.16 value | Formula | Source |
|---|---|---|---|
| The seal tick; a witness's wait | 500 ms; 2 s | – | R51, R54 |
| A change waits for its seal | 5 s | – | T169 |
| A seal is stale after | 5 s | 10 ticks | derived |
| Unsealed entries a check reads (`ABOVE_NEWEST`) | 2,000 | resized from the check's measured CPU per entry | D6, PR to come |
| Days of uses made ahead | 3 | – | a use with no day's table fails |
| The uses log's growth | about 12.2 GB a day at a steady 1,000 uses a second (13.6 estimated before it was built); far less when repeats are covered | 141 bytes a row and WAL, measured | [hot-path-one.md](hot-path-one.md) (W211) |
| Days of uses kept | **every day** today; 30 proposed | the object's `keepUsesDays` | Q6 |
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
- Beside a binding removal, at a 1,000-a-second target on one Node process
  (indicative: a shared host at load 37-41, from #520's helper):
  17% to 33% of uses were refused beside the removal, 1% to 4% alone. With
  the cap bypassed, driving the vault's use statement directly, every use
  was answered at 1,000 a second beside a removal of 20,000 credentials,
  even in 50 ms batches. **The cap of 10 causes the refusals, not the
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
throttling. It has one number, K = 2, with a published source (Google SRE
book, "Handling Overload"), and its refusal probability stays below 1, so it
never shuts and needs no reopening rule. A needs three numbers nobody has
measured (window, percentile, reopening rate) and risks every isolate
shutting at once. *Example:* 2,500 uses a second offered against W208's
ceiling of 1,040. An isolate refuses each new use with probability
(2,500 − 2 × 1,040) ÷ 2,501 ≈ 17%. The rest of the excess still goes
`late`, so K = 2 trades some lateness for never refusing during a short
blip. Either rule needs one run on Erwin's Cloudflare (R34, under $5, about
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
documented, not built. *Example:* at `max_connections` 100, every Node pool
is 31, against 10 today, and nothing to configure. At 25, each is 6.

### Q3. Where the vault learns its connection share (`READ_HEAD_WAITERS`)

**Facts.** Up to 16 reads wait for the log's head, each holding a vault
connection while it waits. On a small database the vault's config has fewer
connections than that: at `max_connections` 25, setup gives it 6, and 16
waiters take all 6.

**Recommendation:** the vault computes the share itself, from the database,
with setup's formula, and holds the waiters to min(16, share − 2). It asks
for the two numbers with its first reads, in the round trip it already makes
(T206), so this adds no round trip. The plan's 20 or 100 never
matters: it caps the share only above 20, where 16 is already under the
share − 2. *Example:* at 25, share 6, so 4 waiters, and two connections stay
free for everything else; at 100, 16, as now. One caveat: a Hyperdrive
config someone set by hand below setup's number makes the vault count more
connections than it has: the formula assumes setup set the config.

### Q5. Statement timeouts for the app's and the vault's logins

**Facts.** Only the uses' login has a `statement_timeout` (2 s). #538 (R75)
already bounds every lock wait but a use's to 500 ms, and the vault's
transactions that carry a deadline set a statement bound from what is left
of it (`SET LOCAL`). What is left
unbounded: every app statement, and vault statements outside a transaction.
Postgres runs such a statement until it ends or Hyperdrive gives up at 60 s.

**Recommendation:** a timeout per login, as a role setting in a migration,
equal to a vault call's deadline, 5 s (`CALL_DEADLINE_MS`), for both
`coffre_runtime` and `coffre_vault_runtime`. Transactions keep tightening it
from their own remaining deadline, as the vault's reads do. Not "from each
call's remaining deadline" for every statement: a statement outside a
transaction cannot carry a `SET LOCAL`, and a session `SET` does not hold
under Hyperdrive, which pools connections per transaction. Before the
migration, run the suites with the timeout on, to find any statement that
legitimately runs longer. Backups and migrations use logins of their own,
untouched. *Example:* today a slow vault statement on a small database holds
one of its config's 6 connections for up to Hyperdrive's 60 s; with the
role's 5 s, Postgres ends it at 5 s and the connection is free again.

### Q6. Retention in the standard setup

**Facts.** `retainDays` exists, but neither Workers' `checkpointer()` nor
`serveVault` passes it, so every standard deployment keeps every day of
uses. Retention drops only uses; changes are kept forever. Measured when
retention was built ([0.15-plan.md, "As built: PR 7"](0.15-plan.md#as-built-pr-7-w229)):
a use's plan covers every day attached. At 95 days attached, 40 new
connections at once take 2.0-2.1 s for their first use, past the uses'
2 s `statement_timeout`, and each day's new table stalls uses about 460 ms.
At 35 days, neither shows.

**Recommendation:** expose it as `audit.keepUsesDays`, **default 30** (about
34 days attached, counting today and the 3 made ahead), not "every day".
Keeping every day is not neutral: somewhere between 35 and 95 days
attached, an instance on 0.15 starts failing uses whenever a burst opens
many new connections at once, and it reaches 95 days about three months
after it starts. A deployment that must keep uses
longer (an audit requirement) needs days kept detached, as tables of their
own, outside the plan: later work, not 0.16. *Example:* at a steady 1,000
uses a second, 30 days is about 370 GB of uses; every day kept is about
4.5 TB a year, with the failures above from about the fourth month.

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
it would be without coffre in the path. *Example:* an app with a 30 s
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
| The vault's `uses` block on Workers (`inFlight`, `connections`, `coverMs`, `names`, `batch`) | five settings, none set by any deployment | gone: the in-flight count derived (Q1), the rest internal constants |
| `DEFAULT_CONNECTIONS` and Node's pool probe | 10 per isolate or process; the probe always reads nothing | gone, with Q1's step 1 |
| `USES_AT_ONCE` (4 per request) | "leaves the isolate's admission room" | gone with the count it protects |
| Node pool size (`max ?? 10`) | 10 per pool; a deployment passing a URL cannot change it | derived from the database at start (Q2) |
| `coffre setup`'s Hyperdrive maximum | 20, Free's, on Paid too | the plan's maximum (limits.md #12) |
| `READ_HEAD_WAITERS` | 16, whatever the database | min(16, share − 2), the share computed (Q3) |
| `vault({ bulkLimit })`, `serveVault({ bulkLimit })` | in the vault's config | `policy.reads.bulkLimit` |
| `signin({ passkeys, browserSessionHours, cliSessionDays, serviceTokenMaxDays })` | in `signin` | `policy.people.*`, `policy.services.tokenMaxDays`; `passkeys.rpId` stays in `signin` |
| `credentialProxy({ cacheSeconds, recheckSeconds })` | two settings, both 60 | one, `policy.proxy.revokedWithinSeconds` |
| `createCoffre({ rotateAfterDays })` | in `createCoffre` | `policy.values.rotateAfterDays` |
| `retainDays` | only through `runCheckpointer`/`keepCheckpointer` on Node | `policy.audit.keepUsesDays`, default 30 (Q6) |
| Sign-in rate limits | five Workers bindings (per address and in all, for workloads and MCP; MCP per connection), 30 / 300 / 120 a minute; `processLimits` the same | one, per address, 10,000 per 10 s (#520), its number in the policy |
| The per-binding count | 60 sign-ins a minute, in the app, the vault and `sign_in` | gone (#520, R76) |
| `exchangeLimit.inFlight` | 32, unsourced | a memory bound, once a sign-in has a deadline (limits.md #35) |
| The vault's 15 s write lock wait (`LOCK_TIMEOUT_MS`) | 15 s | `LOCK_WAIT_MS`, 500 ms, with retries within a 5 s call (#538) |
| A plain 503's `Retry-After` | 5 | 1 (#538) |
| `MAX_BODY_KEYS` and the field bounds | 2,000 top-level entries; labels 120, role names 40, descriptions 200, claims, scopes and the rest | gone (#533): one 1 MiB body bound, its values counted |
| The pre-sign-in body bounds | 4 KiB, 16 KiB, 256 KiB by entry point | the API's 1 MiB (#533); ~32 KiB pending |
| The proxy's caches | 1,000 or 10,000 entries, some cleared whole | least recently used, within a slice of 16 MiB (#519) |
| The proxy's body read whole | 16 MiB | 1 MiB; larger bodies stream (#519) |
| KMS's 8 calls at once | slots handed from one request to the next | pending the KMS measurement (placeholder in 2.4) |

What a deployment writes after all of this: its wiring, as today, and
`policy.ts`, nine fields, each with a default it can leave alone.
