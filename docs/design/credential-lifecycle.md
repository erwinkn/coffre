# 0.15: who owns a credential's life (T149, W246)

Steps 1 and 2 of T149: how a credential is issued, revoked and checked
today, statement by statement, and a TLA+ model
([`formal/Lifecycle.tla`](../../formal/Lifecycle.tla)) that weighs two
placements against each other. Nothing here is implemented yet: the
coordinator confirms the placement first.

- **A, the vault.** An issue (a person's token, a service token, a CI
  run's sign-in) and a revoke are each one vault call, one statement in
  Postgres. The app verifies the request and names it; the vault weighs it
  on its own rows, under their locks, writes the row, seals and numbers
  it, and commits, all inside Postgres.
- **B, the app** (0.15 as built, W220 and W224, with W242's sealed
  generation). The app weighs the request, has the vault seal the row it
  proposes (`prepare`, which reads nothing and weighs no right), and writes
  it in its own transaction under 0.14's head, with `app_change` numbering
  it.

In both, the app resolves a bearer token to its credential, and the vault
decides each use on the credential's sealed row and its account's
generation.

**Recommendation: A** (reversible until it ships). It is the only one of
the two that meets R44 without new work: no instance-wide head, no lock
held across a round trip, a sign-in in one Postgres round trip. And the
vault stops sealing whatever the app proposes. B can lose 0.14's head
too, but then each of its checks needs a lock of A's, held across three
round trips instead of none (the model shows both halves).

## 1. Today, statement by statement

With 0.15's switch on (`log: '0.15'`). "Under the head" means while the
transaction holds 0.14's `audit_chain_head` row `FOR UPDATE`, which every
0.14 append, and so every app write, waits for.

### A CI run's sign-in: `POST /api/auth/oidc` (`WorkloadService.#exchange`)

| # | where | what | under the head |
|---|---|---|---|
| 1 | app → Postgres | `exchangeCandidates`: the service's live bindings on the token's issuer, whether the token was spent, the newest policy change | |
| 2 | app | the ID token's signature (JWKS, cached or fetched), audience, times and claims against the bindings (`verify`) | |
| 3 | app → vault | `about` (the switch; once per vault object) | |
| 4 | app → vault → Postgres | `access(member)`: status, generation, grants, policy | |
| 5 | app → vault | `prepare`: seals the `credential.issue` the app proposes, from the columns it passes; reads nothing, weighs no right | |
| 6 | app → Postgres | `BEGIN`, `SELECT … FROM audit_chain_head FOR UPDATE` | yes |
| 7 | app → Postgres | `exchangeStill`: the member, the binding and its rate (credentials it issued in the last minute, at most 60), one read | yes |
| 8 | app | the token's times again | yes |
| 9 | app → Postgres | `exchangeToken`: the token spent (`consumed_tokens`, unique), the credential inserted (its `auth_mac` under APP_KEY), the binding stamped, one statement | yes |
| 10 | app → Postgres | the head again, with the clock and the newest entry (`appendAudit`) | yes |
| 11 | app → Postgres | `token.exchange` appended and the head moved, `app_change` in the same statement: the head again, the issue lock shared, ChangeChecksSeal, ChangeCAS, the change numbered | yes |
| 12 | app → Postgres | `COMMIT` | yes |
| 13 | app → vault | `waitSealed(n)`: answers once a signed checkpoint holds the change (R51) | |

Measured (`request-cost.test.ts`; `bench/ci.ts`): 8 app statements, 6 of
them under the head, 1 vault statement, 4 vault calls (1 with 0.14's log).
At 20 ms round trips, one sign-in alone takes 192 ms (p50, §4).

**Where each check lives:** the proof, the binding's match and its keys:
the app (step 2). The binding still standing and its rate: the app, under
the head (7). The token spent once: the unique insert (9). The account
active, at the binding's generation: the vault's answer (4), read again by
the app under the head (7). The row's integrity: its APP_KEY MAC (9) and
the vault's seal (5, 11). Its order against uses: its number (11), under
the issue lock, never the fence (T123).

### A workload's sign-in: `POST /api/workloads/session` (`WorkloadService.#signIn`)

Kubernetes, GitHub and AWS proofs, DPoP-bound sessions. The same shape,
with more under the head: the proof checked outside it (its bindings, one
read; the spent key, one read), `access`, the places, `prepare`; then
under the head `stillMember`, `standingBinding`, `frozenTargets`,
`exchangesSince`, `consumeToken`, the proof's own `commit` (an
enrollment's capacity), `insertSession`, the binding stamped, the append
with `app_change`, `COMMIT`; then `waitSealed` and the proof's `after`. If
the proof decided another scope or end than the one prepared, the whole
transaction is prepared and run again (`ObjectMoved`).

### A service token: `POST /api/services/<id>/tokens` (`SigninService.issueServiceToken`)

1. `issuerNow`: the newest policy change and the newest entry about the
   issuer's access (2 statements), then `access(issuer)` (vault).
2. `#tokenScope`: `access(service)` (vault) and `issuedScope` (R15: the
   scope asked, within what the service holds and what the issuer could
   give; R32: sensitive reads only from an Owner covering the place).
3. `prepare` (vault).
4. Under the head: `policyStill`, `issuerStill` (no access entry about the
   issuer since step 1), `credentialStill` (the issuer's own credential and
   member), `stillMember` (the service), the insert, the append with
   `app_change`, `COMMIT`.
5. `waitSealed`.

A **personal token** (`issuePersonalToken`) and a **handle**
(`issueHandle`) are the same, the person's own scope in place of the
service's, `#currentCaller` in place of `issuerStill` and
`credentialStill`.

### A revoke: `DELETE /api/credentials/<id>` (`SigninService.revokeCredential`)

1. `liveCredentialsWhere` (1 statement), then `prepare` the
   `credential.revoke` (vault).
2. Under the head: `policyStill`, `findCredential`, whether the caller may
   (their own; one of a service they manage; or they run the instance),
   `updateAuth` (`revoked_at`, its MAC), the append with `app_change`,
   which takes **the fence exclusive**: every use waits from here to the
   commit, one round trip later.
3. `COMMIT`, then `waitSealed`.

`signOut` is the same on the token's own credential. A member's removal,
an unlink and a binding's end revoke sets, prepared from a read and read
again under the head (`expectRevoked`).

### Each request's bearer token (`SigninService.verify`)

1. The credential by its token's hash: `findCredential` (1 statement), or
   none when `app_read` read it ahead for `/use` (T135). The app checks its
   APP_KEY MAC, its end, revoked, its identity, its binding.
2. The vault's answer about its member: `access` (1 vault call), or a kept
   answer the request confirms later (`Accesses`).
3. `last_used_at`, at most once per credential per 5 minutes.
4. After a read, the credential and member again (`credentialStill`, 1
   statement), unless the vault decided it: a 0.15 `/use` hands
   `use_credential` the credential's id, and its one statement reads the
   row, checks its seal and its account's generation (W242), decides and
   numbers the use.

## 2. The model: `formal/Lifecycle.tla`

One constant, `Placement`, switches the issue, sign-in and revoke paths
between A and B; uses and the vault's member changes are the same in both.
A step is one statement, or the part of one between two lock waits. A
step's label says whether the process is in Postgres or at the app, a
round trip away between two statements of its transaction (`AtApp`): what
a lock holder does at the app, everyone waiting for that lock waits for.

The cast: Ada, an Owner, gives the service account `svc` a token reading
sensitive values, on her session `cA`; two CI runs sign in as `svc` through
one binding that makes at most one credential a window; an admin demotes
Ada, removes `svc`, or removes it and admits it again; a revoke of Ada's
session, `svc`'s token or Ada's new token; `svc`'s uses; a database writer
holding no key; and the app's own code, an attacker's.

**Invariants** (the brief's three, and the comparison's):

| invariant | says |
|---|---|
| `RevokeOrdersUses` | no use of a credential allowed is numbered after its revoke: one that starts after the revoke commits reads it revoked; one in flight is numbered before it |
| `UsesNeverWaitOnIssues` | R58: a use never waits on an issue or a sign-in |
| `SensitiveOnlyFromOwners`, `IssuedByLiveCredential` | rights never widen (R15, R32): a token is numbered before any demotion of its issuer, and before any revoke of the credential it came in on |
| `RateHeld` | the binding makes at most its rate |
| `AllowedAtCurrentGeneration` | removed, an account's credentials end, whatever admits it again |
| `AllowedOnSealed` | only rows the log sealed decide a use: nothing a writer put back, forged or edited |
| `SignInsNeverWaitOnHead` | R44: no sign-in queues on 0.14's head |
| `IssuesHoldNoLockAtApp` | no issue or sign-in holds a lock across a round trip |
| `UsesWaitOnlyOnDbWork` | a use waits on a revoke only while the revoke runs in Postgres |

**Scenarios**, each under both placements: `LifecycleIssue` (Ada's token,
demotion, revokes, a use), `LifecycleSignIn` (two sign-ins, removal and
admission, revokes, a use), `LifecycleForge` (a database writer, two uses),
`LifecycleCompromised` (the app's attacker issues in Ada's name while she is
demoted or revoked).

**Results** (`scripts/formal.sh Lifecycle…`, a few seconds each, 1k to 68k
states):

| | A | B |
|---|---|---|
| `RevokeOrdersUses`, `UsesNeverWaitOnIssues`, `RateHeld`, `AllowedAtCurrentGeneration`, `AllowedOnSealed`, `SensitiveOnlyFromOwners` (honest app) | hold | hold |
| `SignInsNeverWaitOnHead` | holds | **broken**: a second sign-in waits on the head the first holds |
| `IssuesHoldNoLockAtApp` | holds | **broken**: a sign-in holds the head from its `BEGIN` to its `COMMIT`, three round trips |
| `UsesWaitOnlyOnDbWork` | holds | **broken**: a revoke holds the fence across its `COMMIT`'s round trip |
| `SensitiveOnlyFromOwners`, `IssuedByLiveCredential` with the app compromised | hold | **broken**: `prepare` seals the token the attacker proposes, Ada demoted |

**Each protection is necessary** (TLC finds the invariant broken without
it):

| protection | A, without it | B, without it |
|---|---|---|
| the revoke takes the fence (`RevokeTakesFence`) | `RevokeOrdersUses` | `RevokeOrdersUses` |
| an issue takes the issue lock, not the fence (`IssueOffFence`) | `UsesNeverWaitOnIssues` | `UsesNeverWaitOnIssues` |
| the issuer and her credential read where nothing changes them before the commit (`IssuerLocked`: A, their rows shared in the statement; B, `issuerStill` and `credentialStill` under the head) | `SensitiveOnlyFromOwners`, `IssuedByLiveCredential`; also with the app compromised | `SensitiveOnlyFromOwners` |
| the rate counted under a lock (`RateLocked`: A, the binding's row; B, the head) | `RateHeld` | `RateHeld` |
| the account under a lock (`MemberLocked`), or W242's generation at use (`UseChecksGeneration`): each covers for the other | `AllowedAtCurrentGeneration` without both | `AllowedAtCurrentGeneration` without both |
| the use checks seals (`SealChecked`) | `AllowedOnSealed` | `AllowedOnSealed` |
| B's head (`HeadInB`) | | `SensitiveOnlyFromOwners`, `IssuedByLiveCredential`, `RateHeld`, and `AllowedAtCurrentGeneration` without W242 |

The last row is B's catch: drop 0.14's head to meet R44, and every check
it covered needs a lock of its own, the same ones A takes (the issuer's
row and credential shared, the account's row shared, the binding's row).
In B they would be held from the check to the `COMMIT`, three round trips
(about 60 ms through Hyperdrive). In A, for the statement's own work.

**Example: why A's issue locks Ada's row** (TLC's trace without
`IssuerLocked`): Ada's issue reads her an Owner; Omar's demotion commits
as number 1; the issue takes number 2 and commits a token reading
sensitive values. The log now says a non-Owner gave sensitive reads (R32).
With her row locked shared, the demotion waits for the issue's commit, or
the issue reads her demoted.

**Example: what B's head costs** (TLC's trace, every protection on): run 1
takes the head (`BEGIN … FOR UPDATE`), and goes back to the app; run 2
waits on the head, and so does every other write of the instance, for run
1's next three round trips.

## 3. The comparison

### Cost per request

At 20 ms round trips (Hyperdrive). B as measured; A as the design would be,
not yet measured.

| | B (today) | A |
|---|---|---|
| CI sign-in | 8 app statements (7 round trips: `BEGIN` rides with the head's; 6 statements under the head) + 4 vault calls (1 statement) + the seal wait; 192 ms alone | 1 app statement (the bindings, to verify the token) + 1 vault call: 1 statement, 1 round trip, then the seal wait inside the call; about 50 to 60 ms alone (estimate: 2 round trips, the Worker-to-Worker call, a seal tick) |
| service or personal token | about a dozen app statements, eight of them under the head, and 4 vault calls (2 `access`, `prepare`, `waitSealed`) | 1 vault call: 1 statement, or 2 when the vault's kept objects moved (below) |
| revoke | about 8 app statements, six under the head, and 2 vault calls (`prepare`, `waitSealed`); the fence held across `COMMIT` | 1 vault call, 1 statement; the fence held for the statement's work |
| bearer token per request | unchanged: the app's `findCredential` (or `app_read`), the vault's `access` or a kept answer | the same |
| `/use` | unchanged: `app_read`, then `use_credential` | the same |

How A gets to one statement: the vault decides in TypeScript on the sealed
objects it holds (the issuer's and the account's, from its kept state or
the request's own `access`), computes the seal, and the statement checks
that those objects' seals are still their newest (as `app_change` does
today) while it holds their rows. A mismatch answers "moved", and the vault
reads again: a second round trip, only after a change. The credential's
row carries the app's APP_KEY MAC, which the vault does not hold: the app
computes it over the columns it proposes, and the vault writes exactly
those columns once it has checked the ones it decides on (principal,
generation, scope, end).

### What a writer could forge

| attacker | A | B |
|---|---|---|
| **a database writer, no key** | the same as B: a row put back, forged or edited is `stale` or `tampered` at its use (`LifecycleForge`); a `consumed_tokens` row deleted lets a captured ID token sign in again within its life (as today; A could number the spend in the log, its request id the token's hash, closing that) | the same as A |
| **the app compromised** (its code, or APP_KEY and `coffre_app`) | it can still name any live credential on a use (`UseInput.credential` is an id), but it mints nothing: an issue is weighed on the issuer's live credential and rights (`LifecycleCompromisedA`). A CI sign-in is still the app's word on the ID token: the vault would need the JWKS to check it too | the vault seals any credential it proposes, for any member, at any scope: an Owner's session after all of theirs were revoked, a service's sensitive reads (`LifecycleCompromisedB`) |

Closing the compromised app's last door (naming a live credential on a
use) means the vault resolving bearer tokens too: the token, not its id,
reaching the vault on each use. That may be what Erwin's "maybe tokens
too" asks; it is out of this task's scope (T147, T148 touch it).

### Under a burst of sign-ins (R44, R58)

- **A use never waits on a sign-in, in either** (`UsesNeverWaitOnIssues`):
  issues take the issue lock, never the fence (T123). Measured for B in
  §4.
- **B serializes every sign-in of the instance** on 0.14's head, each
  holding it for six statements: a burst of N waits about N × 6 round
  trips at its tail. A serializes only the sign-ins of one binding, on its
  row, each for its statement's work and commit (about 1 to 3 ms): 60 at
  once on one binding wait about 100 ms at the tail.
- **R44's "refused fast":** both keep the in-process cap (32 sign-ins in
  flight per isolate, then 429) and the binding's rate (60 a minute, then
  429). A's sign-in takes no head at all, so there is no queue on it to
  refuse from (0.14's `HeadBusy`).
- **A revoke may hold uses briefly** (R58): in B for its `COMMIT`'s round
  trip (20 ms through Hyperdrive), in A for the statement's work.

## 4. Numbers: B today, on the Debian rig

`packages/server/test/bench/ci.ts --log 0.15 --signin-only --uses 1000
--rtt 20`, Postgres `postgres:16.14` (Debian, R62), local, a project of
its own; 1,000 `use_credential` calls a second beside, each one round
trip; 3 rounds a level. W242's run of the same bench (with each job's list
and reveal) reads the same: 30 jobs at p50 1.9 s, p99 3.6 s.

| sign-ins at once | sign-in p50 / p99 | of which waiting on locks (per sign-in) | uses p50 / p99 / max | uses refused |
|---|---|---|---|---|
| 0 | | | 22.9 / 25.3 / 29.4 ms | none |
| 1 | 190 / 192 ms | 15.5 ms | 22.6 / 25.3 / 27.0 ms | none |
| 10 | 763 / 1,374 ms | 527 ms, nearly all on 0.14's head | 22.9 / 26.6 / 29.2 ms | none |
| 30 | 1,795 / 3,451 ms | 1,616 ms, nearly all on 0.14's head | 22.9 / 25.1 / 28.8 ms | none |

- R58 holds today: uses beside 30 sign-ins read as uses beside none.
- R44 does not: every sign-in queues on the head. At 30 at once, 90% of a
  sign-in's time is that queue.
- A level of 60 at once did not finish within the hour's limit (stopped;
  1 to 30 take 30 s together). Not chased here: the binding's rate is 60 a
  minute, so the bench binds afresh between rounds, and the head's queue is
  60 deep. To look at with A's numbers.

## 5. What the model abstracts

- The checkpointer's barrier and R51's seal wait: `HotPathOne`'s
  (HotPathOneIssue holds the issue lock against the barrier). The
  placement changes neither.
- Postgres's lock queue: a shared request behind a waiting exclusive one is
  `HotPathOne`'s.
- The proof itself (the ID token's signature and claims), and the
  binding's match: the app's in both.
- One credential's row lock for Ada's session only; a removal's sweep
  takes the rows as one step.
- The vault's member changes take the member's row, 0.14's head and the
  fence, in Postgres throughout, in both placements (`change_input`).

## Open, for the coordinator

1. **The placement** (above): A recommended.
2. **0.14's `token.exchange` entry.** In A a sign-in writes none: its entry
   is the 0.15 change (`credential.issue`, with the run's claims). The 0.14
   audit page stops showing sign-ins under 0.15's switch until PR 8's
   surfaces (#388) show the new log. The same holds for a B without the
   head.
3. **The CI sign-in's proof in the vault** (A's strong form): the vault
   checking the ID token itself, so that a compromised app cannot mint a
   run's credential either. It costs the vault the JWKS (fetched and
   cached per isolate). Not needed for R44 or R58.
