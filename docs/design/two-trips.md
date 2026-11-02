# A change in two round trips (T179)

Status: design and model (formal/Writing.tla). The routes follow it in later PRs.

R57 wants a change answered in under 200 ms in 0.16. Erwin's target (2026-11-02):
**a key write and a member add each make at most two database round trips on the
request path**, then wait for their seal (R51, kept: D165 A). The other change
routes take the same shape after these two.

## Where we are

Measured at `0029f0be` with `packages/server/test/change-cost.test.ts`, every
Sync held 20 ms (Cloudflare's round trip to its database, T112), the seal
apart (here at once; about 75–90 ms on Cloudflare, T171):

| route | app Syncs | vault Syncs | ms at 20 ms a Sync |
|---|---|---|---|
| key set, one | 13 | 3 | 384 |
| member added | 8 | 6 | 329 |

A key write today, in order:

```
app    credentials (the session) + the newest policy.change         1
vault  access: the caller's member row, grants, policy               1
app    the path, the key's head, its levels (read twice)             3
vault  wrap: BEGIN + member row FOR SHARE + snapshot | 0.14 append   2
       prepare (memory)
app    BEGIN + head + policy + place | insert | lock | 4 reads |     9
       version | key | 0.14 append + app_change + COMMIT
vault  waitSealed                                                    (the seal)
```

The first line is the request's front door (`authenticate`), the third the
router's (`locate`, its `needs`) and the handler's reads. The budget counts
the whole request, front door included, as `change-cost.test.ts` does.

## The shape

```
key write    vault  one statement, as a use's                1 round trip
                    the Worker decides, wraps, seals the change
             app    one statement under the head              1 round trip
             vault  waitSealed                                the seal
member add   vault  read                                      1 round trip
                    the Worker decides, builds the rows, their MACs and seals
             vault  write, held to what the read decided on   1 round trip
             vault  waitSealed                                the seal
```

At Cloudflare's 20 ms that is 40 ms of database, plus the seal's 75–90 ms and the
Workers' hops: about 120–130 ms.

## What takes the two-trip path

The common case, by the same rule a named use follows (`named-use.ts`): a
**patch of values** (new values, regenerates, `replaces`) **by a caller with a
token** (a session, an API token). Everything else keeps today's path and its
own budget in `change-cost.test.ts`, and may join later:

- a patch that makes, replaces or ends a reference: the vault seals a
  reference's making and its end in calls of their own today
  (`vault.reference`, `vault.endReferences`), after its decision. Folding
  them in means `write_request` sealing them, a step of its own (PR 7);
- a patch that marks a key's sensitivity, or removes a key;
- a caller through a way in with no token: Cloudflare Access, a binding, an
  MCP connection, a workload (`WaysIn.tla`);
- `dev@me` before the caller has a personal config: the first write makes
  one, in a transaction of its own, once per member.

Example: `PATCH /secrets/market/dev { API_KEY: "sk-…" }` with Ada's session
cookie takes two trips. `PATCH /secrets/market/dev { DB_URL: { ref: … } }`
takes today's.

## A key write

`PATCH /secrets/market/dev { API_KEY: "sk-…" }`, Ada's session.

1. **The front door reads nothing.** The write is served before
   `authenticate` and the router, as a named use is: the app reads the
   token's kind from the token itself, refuses on that alone what it
   refuses so (`refusedByKind`), makes a DEK per key, and calls the vault
   with the token's hash, what the deployment's config `accepts`, the path
   by name, the keys, their DEKs, and the route's checks (its `needs`).
   It holds the plaintext. A vault that serves no such call (an old
   isolate, `writeNamed === undefined`, as `useNamed`) sends the write down
   today's path.
2. **The vault's statement** (`write_request`, a SECURITY DEFINER function
   beside `use_credential`, shaped like it):
   - takes the fence shared;
   - reads, by name, every input the decision and the app's checks stand on:
     the credential by its token's hash and its identity, the member row and
     grants, the policy, the project, the environment and each one of its
     fork chain, each key's row and current version, each key a value says
     it `replaces` (the parent's, in a fork), the keys a fork inherits and
     each one's sensitivity;
   - with each input, its newest change in `log_changes`, to which the
     Worker holds its row (StaleFirst: a row put back is refused);
   - records the request, numbered (below);
   - commits, and answers the rows and the newest change of each input.

   One round trip, and nothing held after it.
3. **The Worker** refuses first everything the app would (AcceptedFirst, as
   a named use): the config's `accepts`, the token's kind, an ended or
   expired session, an earlier generation, all at the vault's clock. Then it
   decides with `decide.ts` (unchanged, still tied to the Lean model), the
   route's checks among its inputs; wraps each DEK, bound to its key's owner
   and decided sensitivity; and seals the app's change from each key's
   object as read (`prepareChanges`, in memory, with keys only the vault
   holds). It answers the app: the caller (credential and identity rows,
   with their `auth_mac`), each key's id and sensitivity, the envelopes,
   the prepared changes, and the guards: each input and the number of its
   newest change as read.
4. **The app** checks the rows' `auth_mac` in memory (as `named-use.ts`
   does) and only then encrypts: the AAD binds `project|environment|key` by
   id (`envelope.ts`), which it learns from the answer. No round trip. Then
   it sends **one Sync**: BEGIN, 0.14's head `FOR UPDATE` (until PR 6), the
   new rows and the key's update, each change through `app_change_strict`
   (the issue lock, the fence exclusive, ChangeCAS; a new key, from no row,
   is its insert's uniqueness), then **the guards**, then COMMIT.
   A guard that fails raises, Postgres skips the COMMIT, and the write asks
   again from 2 (`ObjectMoved`), up to 16 times, as `setSecrets` does now,
   carrying the keys it learnt are sensitive into each new request.
5. `waitSealed`, then the answer (R51).

### The guards

One per input: **no change of that object numbered after the one the vault
read.** In SQL, `NOT EXISTS (SELECT 1 FROM log_changes WHERE object = $o AND
number > $n)`, an index probe.

- **The log, not the row.** A row's `seal` column is what a database writer
  can put back (R64): Ada's session revoked, then its row restored, live,
  would pass a guard on the column. The log's newest change of an object is
  what `ChangeChecksSeal` already trusts; the checkpointer checks each
  change's MAC before sealing it. (`WritingTamper` turns this off.)
- **Statements of their own, after `app_change_strict`'s.** Under READ
  COMMITTED each statement reads afresh, so these read once the fence is
  held: a revoke that commits before it shows; one after it waits for our
  COMMIT. Folded into the same statement (a CTE, a subquery), they would
  read that statement's snapshot, taken before the fence.
- **No locks.** A `FOR SHARE` taken after the fence would order a row after
  the fence, against `change_input`'s row, head, fence: a cycle Migration015
  does not check.
- **Every input.** The credential, the member, the policy, the environment
  and its fork chain, each replaced key: the same set the vault read. Leave
  one out and its change slips through (`Held`, each left out in turn).

### The request and its refusals

The statement records the request, not its outcome (R53), as a use does: a
row per key, beside `log_uses` (its table or `log_uses` with a write
purpose, PR 2's choice), numbered from `log_number`, holding the request
id, the clock, the credential, the path and the key as asked, and the
Worker's MAC over exactly those, computed before the call. The statement
adds the ids it resolved and the newest change of each input. The outcome
is the replay's, from the sealed inputs at the request's number:

- allowed and committed: the change in `log_changes` under the same
  request id;
- refused: no change, and the replay says why. That is where a refusal
  lives; today `Refusal` appends a 0.14 deny entry;
- allowed but asked again (a guard moved): no change; the next try is a
  request of its own.

## A member add

`PUT /members/svc`, Bob's session, with svc's first grants or none (`admit`
and `setAccess(…, admit)` alike).

1. **The vault's read**: the session, Bob's member row and grants, the
   policy, svc's row if any, each with its newest change; and what the app
   reads around the admit today (`serviceSettingFor`, `places`, each
   grant's scope by slug to its id). No lock, nothing written (Lifecycle's
   issue, statement 1).
2. **The Worker** decides (`#standing`, `#setsUp`), builds svc's new row and
   its grants, their MACs and seals, and their changes, from the rows as
   read (none).
3. **The vault's write**, one statement (`admit_write`): both members' queue
   locks and rows in principal order (`lockMembers`), 0.14's head, the
   fence; it goes ahead only while Bob's object, the policy and svc's row are
   the ones step 1 read (IssuerCAS); the rows, `change_input_strict`,
   COMMIT. Otherwise it writes nothing, answers `moved`, and the vault reads
   again.
4. `waitSealed`, then the answer.

The app's `endPriorMembership` runs only when svc had an earlier generation
(a re-admit): the vault's answer says so. A first add is the vault's two
statements and nothing of the app's.

A warm vault could skip step 1: the isolate keeps the actor's inputs with
their seals, as the use path keeps its seal cache, and the write's CAS
refuses them if they moved. That is one round trip when warm. It is not the
target, since Cloudflare may send the next request to another isolate.

## What made two round trips possible, and what stays out of reach

**The vault decides in TypeScript, after its statement.** A use already does:
the statement reads and logs, the Worker decides, the replay decides the same
from the same sealed inputs (HotPathOne, `ReplayAgrees`). A write's vault
statement is the same kind of request. What the decision guards is the app's
commit, which comes after it. So `decide.ts` and its Lean tie stay as they
are. Porting the rules into PL/pgSQL would save no round trip on a key write.
On a member add it would save one, at the price of a second copy of the rules
that the Lean cases do not hold.

**Seals and MACs stay in the Worker.** A change's seal and its entry's MAC are
the vault's keys at work (a database writer must not be able to make one,
R64, Seal.tla's `NoForgerySealed`). So SQL never computes one. A statement can
only store a seal the Worker made from what it read before, which is why a
member add is a read and then a write. A key write's change is made from the
vault's read too, but the app's statement is the write.

**0.14's appends leave the change path.** An app entry in `audit_log` carries
`mac = HMAC(appKey, prev_hash ‖ fields)`, where the fields hold the entry's
number and the database's clock (`core/src/audit/chain.ts`). All three come
from the head, read under its lock. The app can only finish the entry after
that read, which is a second round trip. Or the database would have to compute
it, holding the app's key, which defeats the MAC. The vault's 0.14 entries
(`key.wrap`, `member.add`) are the same. So the two-round-trip routes write no
`audit_log` entry. Their record is the request and the change in the log:
actor, request, object, payload, MAC'd by the vault (`log-entry.ts`). SQL
stores them, and the checkpointer checks them before sealing. This is the
contract 0.16 already plans (0.15-plan.md, "11. The contract, in 0.16").

**The audit pages have to read them first.** Today the sealed pages render
sign-ins only (`sealedPage`), a place-filtered page never reaches the log,
and an offboarding report's "wrote" side reads `secret.write` entries
(`queries.ts`). Stopping the appends before that changes would lose records:
a removed member's report would stop naming the values they wrote. So the
pages render writes, their refusals and member changes from the log, place
filters included, and the offboarding report reads its "wrote" from the log,
a release before the appends stop (§11's own precondition: readers leave
`audit_log` first).

## What it guarantees

formal/Writing.tla checks it (docs/formal.md, "Writing.tla"):

| protection | turned off, TLC finds |
|---|---|
| the vault's statement reads and numbers in one statement under the fence shared (RequestUnderFence) | `RequestsReplay`: the session read, then revoked, then the rest read and numbered; the Worker allows what the log at the number denies |
| the app's statement holds every input to the object the vault decided on (`Held`, each of six left out in turn) | `WritesStandAtCommit`: a write committed after a revoke, a session's end, a policy change, an archive of the environment or its fork parent, or a write of the key a regenerate replaces |
| ... checked once it holds the fence (GuardsAfterFence) | `WritesStandAtCommit`: a session's revoke, which takes the fence and not the head, between the guards and the write |
| ... by the log's newest change, not the row's column (GuardOnLog) | `WritesStandAtCommit`: a revoked session's row put back, live, by a database writer |
| the key's change from the seal it was made from (ChangeCAS) | `KeyChangesFlip`: two writes from one version both commit |
| a member add's write holds the actor's object and the policy (`AdmitHeld`, each left out) | `AddsStandAtCommit`: a demoted admin's add; an add after the policy gave adding to Owners |
| ... and the principal's row as read (PrincipalCAS) | `AddsFlip`: two adds of one member both commit |
| a change answers once sealed (WaitForSeal, R51) | `AnsweredSealed` |

**One guarantee is new.** `WritesStandAtCommit` is stronger than today's
code. Today a write decided by the vault before a revoke can still commit
after the revoke has answered: the app's transaction checks the policy
(`policyStill`), not the writer's standing. With the guards under the fence,
a write stands at its commit, not only at its decision, against every change
that moves a seal. A session's expiry moves none: it is judged at the
vault's clock, at the decision, as today. The guards cost no round trip:
they are statements of the same Sync.

**Locks, in the order Migration015's `NoWaitCycle` already checks:**
- the app's statement: 0.14's head, then its rows, then the issue lock
  shared, then the fence, as `audited` and `app_change` do now; the guards
  take none;
- the vault's request: the fence shared alone, as a use;
- a member add's write: both members' queues and rows in principal order,
  then 0.14's head, then the fence, as `change_input` and `lockMembers` do
  now.

The fence is held from `app_change` to COMMIT, as now, plus a few index
probes inside the same Sync. No round trip is spent while it is held.

**A session's revoke takes 0.14's head too, today.** 0047 put the head first
in `revoke_credential`, to order it against 0.14's checks on isolates still
serving them (Migration015's `EntryLessHead`). The model leaves it out, as
0.16 will once 0.14's path is gone: a revoke that takes the fence alone is
the stronger adversary, and the guards after the fence are what hold then.
Dropping it is a migration of its own (PR 6).

## The seal wait

Kept (R51, D165 A). A change's number exists only once it commits, so the seal
wait cannot overlap the app's statement. What it costs is the checkpointer's
tick: barrier, window, sign, write (T171: 75–90 ms on Cloudflare). The barrier
and the window could share a round trip, but the fence would then be held
while the window is read, and every use would wait on it (R44, R58). This is
left out again. The wait reads the app's database only if the COMMIT's own
answer was lost (`newestCommitted`), never on the way.

## Compatibility

A deploy runs the old isolates beside the new until the old drain (expand,
then contract). Each direction:

- **Old vault isolates, new rows.** They check a member row's `access_seq`
  against its newest 0.14 access entry (`#integrity`). A member added with
  no such entry, its row MAC'd without one, would be refused there (fail
  closed) until they drain. So the vault's own decisions move to seals
  first (the row is its object's newest change, as a use checks), in a
  release that still writes 0.14's entries. The appends stop one release
  later.
- **Old app isolates, new writes.** They fence their writes on the newest
  `policy.change` in `audit_log` (`policyStill`). So a policy change keeps
  its 0.14 entry until no isolate reads it. It is not on this target's path.
- **Old isolates' changes, new guards.** Every 0.15 release logs each change
  of a credential, a member, the policy, an environment and a key in
  `log_changes` (through `app_change` and `change_input`). So a revoke or a
  policy change made by an old isolate moves exactly what a new guard
  probes.
- **A new app, an old vault.** The vault's binding has no `writeNamed`: the
  write takes today's path. An old app never calls it.
- **SQLite** holds the whole file per transaction: the same steps run in
  TypeScript inside one transaction, with no round trip to save.

## The PRs

Each with what the key write and the first member add then cost:

1. This design and formal/Writing.tla.
2. **The key write's front door, `write_request` and the app's guarded
   statement**, with the 0.14 entries still written. The vault's
   `key.wrap` entry needs its head (a transaction of two trips); the app's
   statement keeps its head read for its own entry's MAC (two). Key write:
   1 + 2 + 2 = 5 round trips (16 today).
3. **The audit pages and the offboarding report read the log**: writes,
   their refusals and member changes, place filters included. After it,
   nothing reads these routes' 0.14 entries.
4. **The vault's decisions on seals**, not 0.14's access entries (the
   compatibility step above).
5. **The member add's read and write.** Its 0.14 `member.add` entry still
   needs the head read before its MAC: read, head, write, 3 round trips
   (14 today).
6. **0.16, the contraction.** The two routes stop writing 0.14's entries;
   `revoke_credential` drops the head (a migration). `change-cost.test.ts`
   holds a key write to `{ app: 1, vault: 1 }` and a first member add to
   `{ app: 0, vault: 2 }`.
7. **The other change routes**, each in the same shape; references join the
   key write once `write_request` seals their making and their end.

Each PR that changes what a statement re-checks changes formal/Writing.tla
in the same PR.
