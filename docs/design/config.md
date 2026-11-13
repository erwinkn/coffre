# One config object: what a deployment chooses, and what coffre derives

A deployment's policy is one object, `deployment`, in one file, `deployment.ts`, beside `app/`
and `vault/` (Workers) or `app/` and `src/` (Node). `defineDeployment` in
`@coffre/core/deployment` checks it, fails on an unknown group or field rather than ignore a typo,
and fills in each default; `coffre init` writes the file
([deploy.md](../deploy.md#deploymentts-what-the-instance-allows)). Section 1 is the object;
section 2 is every value computed from its fields. Every fixed constant and platform fact is in
[limits.md](limits.md).

It is not the instance's access policy (`Policy`: the roles and protected environments an Owner
edits in the UI, kept in the vault's log). That one is data, changed at run time; this one is code,
fixed by the build.

## 1. The object

```ts
export const deployment = defineDeployment({
  people: { browserSessionHours: 12, cliSessionDays: 30 },
  services: { tokenMaxDays: 365, signInsPerAddress: 10_000, useOnly: false, noReads: false },
  reads: { bulkLimit: { count: 1_000, windowMinutes: 15 } },
  values: { rotateAfterDays: 365 },
  proxy: { revokedWithinSeconds: 60, cacheValues: true, editable: false },
  audit: { keepUsesDays: null, repeatsWithinSeconds: 60 },
});
```

The app's `createCoffre` and the vault's `vault(…)` or `serveVault(…)` each take it as
`deployment`, imported at build time. Each side enforces its own part, and neither takes policy
from the other at run time, so an attacker who controls the app cannot loosen what the vault holds.
*Example:* a compromised app that asks for a 3-year service token is refused by the vault, which
checks `tokenMaxDays` itself (`weighIssue`).

| Field | Default, range | Enforced by | What it decides |
|---|---|---|---|
| `people.browserSessionHours` | 12; above 0, at most 168 | app | how often a person signs in again in a browser |
| `people.cliSessionDays` | 30; above 0, at most 365 | app | the same for `coffre login` |
| `services.tokenMaxDays` | 365; whole, 1 to 365 | app **and vault** | the longest a service token may last |
| `services.signInsPerAddress` | 10,000 per 10 s | app | sign-ins one address may start, below |
| `services.useOnly` | `false` | app | whether a service may hold a bearer token at all, below |
| `services.noReads` | `false` | app | whether a binding may list `reads`, below |
| `reads.bulkLimit` | 1,000 keys per 15 min; window at most a day | vault | distinct keys one principal may open in a window |
| `values.rotateAfterDays` | 365, or `null` | app | when the UI and `coffre list --stale` flag a value nobody changed |
| `proxy.revokedWithinSeconds` | 60; 3 to 3,600 | app | how long a revoked credential keeps working through the proxy, below |
| `proxy.cacheValues` | `true` | app | whether opened values serve later requests at all, below |
| `proxy.editable` | `false` | app | whether Owners may add and change proxy definitions in the UI, beside the code's |
| `audit.keepUsesDays` | `null`, every day; else whole, at least 1 | vault | how many full days of uses retention keeps (section 2) |
| `audit.repeatsWithinSeconds` | 60; 0 to 3,600 | vault | the longest a repeat may ride an earlier use's log entry, below |

The bulk window is at most a day because the vault keeps the releases it counts for a day
(`prune_vault_releases`).

**`useOnly` and `noReads`.** `useOnly: true` refuses to issue a service token (403 `forbidden`,
reason `use_only`), refuses one already issued when it is used (401 `unauthenticated`, `use_only`),
and gives every new binding a policy, so a service signs in only into a key-bound session
([workload-access.md](workload-access.md), section 6.3). `noReads: true` refuses a binding that
lists `reads`, when it is made and at its next sign-in, so key-bound sessions get plain values only.
Alone, `noReads` leaves bearer service tokens and `/api/auth/oidc`'s exchanges reading as before.
A deployment whose services must read plain values only sets **both**.

**`signInsPerAddress`** counts each entry point that takes anyone apart (`/api/auth/oidc`,
`/api/auth/workload`, MCP's OAuth endpoints); past it, 429 with `Retry-After: 10`. The default is
1,000 sign-ins a second over one 10 s window, because a CI fleet behind one NAT is one address. On
Workers, Cloudflare reads a rate limit's number only from its binding (`SIGN_IN_PER_SOURCE` in
`app/wrangler.jsonc`), so the number is written there too, and the build (`@coffre/ui/vite`) fails
when the two differ. On Node, `processLimits({ perSource })` counts to it in memory.

**`cloudflareAccess(…)` deployments** sign people in through Cloudflare Access, which owns their
sessions: the `people` fields do not apply there.

### `proxy.revokedWithinSeconds`

One number, R, bounds how long a revoked credential keeps working through the proxy, on every path.
Each window is derived from it (`proxyTimes` in `credential-proxy.ts`):

- opened values serve the caller's next requests from memory for R (none with `cacheValues: false`);
- a request whose values were just opened must send, or answer with a signature, a presigned URL or
  a check, within R, or it fails 503 `late` and the caller asks again (`sendBy`, `answerBy`);
- a handle's database tunnel checks with the vault every R − d, each check given d = min(R ÷ 2,
  10 s) to answer, so a check's interval and deadline add up to R;
- a workload's tunnel also checks its session, within b = min(R, 15 s): every 2b ÷ 3, with b ÷ 3 to
  answer.

*Example:* an Owner revokes a CI token at 12:00:00. At R = 60, its last request through the proxy
leaves by 12:01:00, and its open Postgres tunnel, checked every 50 s with 10 s to answer, closes by
12:01:00. At R = 4, the tunnel checks every 2 s with 2 s to answer.

**Why the floor is 3.** A use may take up to its deadline, 3 s (`USE_DEADLINE_MS`). At R = 1, a cold
request whose use took 2 s would always fail `late`. So the floor is the use's deadline
(`LEAST_REVOKED_WITHIN_SECONDS`), not a choice.

**Why "no cache" is its own field.** R has no 0: a tunnel cannot check continuously. And no cache is
a different policy from a short one: at R = 3 a request may reuse values opened 3 s before and ask
the vault nothing, where `cacheValues: false` asks it for every request, each a fresh decision. A
fresh decision is still not a log entry: repeats stay covered (next field).

### `audit.repeatsWithinSeconds`

A repeat is a use with the same credential, key, place, purpose and route as an earlier one, in the
same vault isolate or process. The vault decides a repeat in full, and refuses it if anything it
depends on changed; it only writes no log entry while the earlier entry's cover is younger than this
field. So the log answers "did this service use this key in that minute", not "how many times",
and keeping every day cannot bring back what a cover left out. A deployment that must count each use
sets `0`, at about 800 bytes a use (section 2). That bounds how fine the log is, so it is policy.

**The field is a ceiling, not the grain.** A cover is also refused while the principal's bulk row for
that key is stale. That row is one per principal and key, shared by every credential, purpose and
route. Each refresh period (60 s at the default window), at a phase of its own, the row goes stale,
and the first use after the boundary writes an entry, which freshens it (`bulk_last >= period` in the
use statement; CoverFresh in `formal/HotPathOne.tla`).

*Example:* a key whose refresh boundary falls at 12:00:11. Uses at 12:00:00 and 12:00:20 write two
entries, though nothing changed: a steady lone caller logs about one entry per key per refresh, and a
longer field suppresses nothing more. With two purposes: A at 12:00:00 (an entry, covered until
12:01:00), B at 12:00:12 (an entry, the row fresh again), A at 12:00:20 (rides its cover, no entry).
So the principal and key appear every refresh, but which callers appear depends on who came first.

The range does not depend on the bulk window: tying it to the refresh would make the default depend
on `reads.bulkLimit`, and a 5 min window, refreshing every 30 s, would refuse 60.

### What is not in it, and why

- **Wiring**, which says where things are, not how much is allowed: the URL, the databases, every
  key, the providers, the plugins and what they define, witnesses, `passkeys.rpId`.
- **`signin({ passkeys })`**, though it is policy ([passkeys.md](passkeys.md)): `off` is the recovery
  when the last Owner lost their passkey ([deployment-auth.md](../deployment-auth.md)), set in the
  platform's dashboard. A field the build reads would make that recovery a rebuild. The examples read
  it from a var (`PASSKEYS`).
- **`credentialProxy({ insecureUpstreams })`** and
  **`signin({ workloads: { allowLoopbackIssuersForDevelopment } })`**: they differ per environment
  (a dev deployment's upstreams are `http://localhost`, production's must not be).
- **Who a provider lets sign in**: `google({ domain })` and `github({ organization })`
  (`wrong_domain`, `not_in_organization`). Each belongs to the provider it filters; two providers can
  carry two. They are a second gate: only an active member, whom the vault decides, gets in. The
  examples read the organization from a var, `GITHUB_ORGANIZATION`.
- **`owners`**: who owns the instance, which differs per environment; it stays in the vault's wiring.
- **Per-item policy**: a proxy credential's `limit`, a trust binding's session hours and fleet size.
  Owners edit these as data.
- **Fixed rules** ([limits.md](limits.md)): constants in code, and in Postgres functions where the database
  holds them.

**Old places.** 0.16 still reads each setting from where 0.15 took it (`signin({…})`,
`vault({ bulkLimit })`, `vault({ uses: { coverMs } })`, `credentialProxy({ cacheSeconds,
recheckSeconds, editable })`, `createCoffre({ rotateAfterDays })`), warns once per isolate or
process, and 0.17 refuses them (`resolveDeployment`). A deployment that passes both `deployment` and
an old setting fails to start, since one of the two would be ignored.

## 2. What coffre derives from the object

Only values computed from the object's own fields are here. Every fixed constant and platform fact
(memory shares, places in flight, deadlines, lock waits, KMS, connections, body bounds) is in
[limits.md](limits.md), once.

### The bulk limit's clock

| Name | At the default window | Formula |
|---|---|---|
| The bulk row's refresh (`refreshMs`) | 60 s | max(1 ms, min(60 s, window ÷ 10)) |
| How long a key counts against a new one (`bulkRule`) | 17 min 3 s | window + refresh + the use's 3 s deadline + 60 s of clock skew (`USE_AHEAD_MS`) |

So a caller sees a longer window than the object's: at the default, a key may still be refused 17
minutes after the 1,000th entered. The refresh also sets how often `audit.repeatsWithinSeconds`'s
covers are broken (section 1).

### The proxy's windows, from R

R is `proxy.revokedWithinSeconds` (`proxyTimes` in `credential-proxy.ts`).

| Name | Formula | At R = 60 |
|---|---|---|
| Values served from memory | R; none with `cacheValues: false` | 60 s |
| A request's window to send, from its values' opening | R, never past the credential's end | 60 s |
| A cache entry asked for again before it lapses | min(R ÷ 4, 15 s) | 15 s |
| A handle's tunnel: each check's deadline, d; the interval | min(R ÷ 2, 10 s); R − d | 10 s; 50 s |
| A workload's tunnel: its session's check, within b | b = min(R, 15 s): every 2b ÷ 3, b ÷ 3 to answer | every 10 s, 5 s to answer |

### Days of uses kept, and what they cost

Retention follows `audit.keepUsesDays`. With `null`, the default, nothing is dropped. With a number,
the checkpointer runs retention hourly (`RETAIN_EVERY_MS`) and detaches one day a run, since each
detach makes every backend plan the uses again and two close together stall uses. A day goes at the
earliest 20 minutes past its cut (2 × `FRESH_MS`). Retention drops only uses, with their tiles and
projection rows; changes are kept forever. Days kept cost a use nothing, since a use's statement
names only its own day.

**Storage.** A logged use keeps about 800 bytes, as long as its day: its row (141 bytes,
[hot-path-one.md](hot-path-one.md)), its share of the audit tree's tiles (57,
[audit-tree.md](audit-tree.md)), its row in the reads' projection (322) and that projection's place
indexes (about 280). Each part is measured; the sum is not. Backups carry it too. A repeat that
rides a cover (`audit.repeatsWithinSeconds`) costs nothing.

| uses a second, steady | a day | 30 days | a year |
|---|---|---|---|
| 1,000 | 69 GB | 2.1 TB | 25 TB |
| 10 | 691 MB | 20.7 GB | 252 GB |

**Why every day is kept by default.** The uses are the record of who read which secret, which an
audit may ask for years later: dropping them is a deployment's decision, with these numbers in front
of it, not a default. *Example:* at 10 uses a second, a year of evidence is about 250 GB with nothing
set; at 1,000 a second, `keepUsesDays: 30` holds about 2 TB. Switching retention on late is slow on
purpose, a day an hour: a year-old database that sets 30 sheds its 335 extra days over about two
weeks.
