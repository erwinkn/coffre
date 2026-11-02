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
- a value written over a key that is a reference now (the patch ends it),
  or archived now (it refuses `secret_archived`, or, a fork's override
  reset, unarchives it, a change from the object the log last sealed), or
  one whose level resolves through a reference's source, live or ended
  (`levelsAt`): `write_request` reads each key's row and current version
  and answers *not served*, and the write takes today's path;
- a patch that marks a key's sensitivity, or removes a key;
- a dry run (`?dryRun`): it answers what would happen and writes nothing;
- a caller through a way in with no token: Cloudflare Access, a binding, an
  MCP connection, a workload (`WaysIn.tla`);
- `dev@me` before the caller has a personal config: the first write makes
  one, in a transaction of its own, once per member;
- a token whose scope is not yet sealed (`served: false`, as a named use
  answers it);
- a deployment whose key-encryption key is remote (AWS KMS, `call.remote`):
  the vault logs a `key.intent` before it calls the key service and each
  key's outcome after, `kms_uncertain` included, each a transaction of its
  own. It joins once the request record (below) stands for the intent,
  since it is numbered before the wrap, and the outcome record for the
  outcome, uncertain or not. The key service's own round trip puts such a
  deployment past the target anyway.

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
   today's path. Everything else the front door and the router do without
   the database stays, before any DEK is made: the same-origin check on a
   change a cookie carries (CSRF), the body's and the entries' caps, the
   route's input validation. A new key's insert that meets another's
   (`unique_violation`) asks again, as today. The front door answers no
   refusal of its own that writes a denial today (a token kind a route
   refuses, `token.use`'s denied entry): it sends that request down today's
   path, which writes it, as a named use answers `served: false`.
2. **The vault's statement** (`write_request`, a SECURITY DEFINER function
   beside `use_credential`, shaped like it):
   - takes the fence shared, and only then reads, in statements after the
     lock (READ COMMITTED: each reads afresh, so all of them read once it is
     held, HotPathOne's "reads are a statement after the lock");
   - reads, by name, every input the decision and the app's checks stand on:
     the credential by its token's hash and its identity, the member row and
     grants, the roles and the policy (two objects: a role's definition is
     `roles`, the instance's policy `policy`; a role edit moves only the
     first), the project, the environment and each one of its fork chain
     (an environment's protection is its own object's change), each key's
     row and current version, and the parent's keys weighed: each key a
     value says it `replaces`, and each inherited key whose level the write
     takes (`levelsAt`: a key's level is its own mark, else the one it
     inherits from the fork chain);
   - with each object among them, its newest change in `log_changes`, to
     which the Worker holds its row (StaleFirst: a row put back is
     refused); and the names' resolution as a whole, `write_names` (below,
     "Names");
   - records the request, numbered (below);
   - commits, and answers the rows and the newest change of each input.

   One round trip, and nothing held after it.
3. **The Worker** refuses first everything the app would (AcceptedFirst, as
   a named use): the config's `accepts`, the token's kind, an ended or
   expired session, an earlier generation, all at the vault's clock. It
   builds the caller's `Reader` from the statement's rows as the vault does
   now (`readerOf`: the account, the credential, the roles object, the
   places). Then it decides with `decide.ts` (unchanged, still tied to the
   Lean model), the route's checks among its inputs; wraps each DEK, bound
   to its key's owner and decided sensitivity; and seals the app's change from each key's
   object as read (`prepareChanges`, in memory, with keys only the vault
   holds). It answers the app: the caller (credential and identity rows,
   with their `auth_mac`), each key's id and sensitivity, the envelopes,
   the prepared changes, and the guards: each input and the number of its
   newest change as read.
4. **The app** checks the rows' `auth_mac` in memory (as `named-use.ts`
   does) and only then encrypts: the AAD binds `project|environment|key` by
   id (`envelope.ts`), which it learns from the answer. No round trip. Then
   it sends **one Sync**: BEGIN, 0.14's head `FOR UPDATE` (its first
   statement, and kept after PR 6 as a lock alone: see "Locks"), **the
   names' hold**, the new rows and the key's update, each change through
   `app_change_strict` (the issue lock, the fence exclusive, ChangeCAS; a
   new key, from no row, is its insert's uniqueness), then **the guards**,
   then COMMIT.
   A hold or a guard that fails raises, Postgres skips the COMMIT, and the write asks
   again from 2 (`ObjectMoved`), up to 16 times, as `setSecrets` does now,
   carrying the keys it learnt are sensitive into each new request.
5. `waitSealed`, then the answer (R51).

### What the app's statement holds

**Every row the vault's statement reads is one of two kinds**, and the
app's statement holds each by its kind:

- **an object** (a credential, a member, the roles, the policy, an
  environment, a key's level): a seal moves on each change of it. Held by
  a guard, by number (below);
- **a name's resolution** (a slug to its project or environment, the fork
  chain, a key's name to its row, in each environment of the chain, or to
  none, a dismissal): no seal moves when it changes. Held by the names'
  hold (below, "Names").

Nothing the statement reads is neither. That is the rule `write_request`
is reviewed against, row by row, rather than a list of inputs to keep up.

### The guards

One per object: **no change of that object numbered after the one the vault
read.** In SQL, `NOT EXISTS (SELECT 1 FROM log_changes WHERE object = $o AND
number > $n)`, an index probe. It compares numbers, which only grow, never
seal values: an object changed and changed back has a newer number, so the
guard sees it (no ABA).

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
- **Every input.** The credential, the member, the roles, the policy, the
  environment and its fork chain, each parent key weighed (replaced, or
  whose level is inherited): the same set the vault read. Leave one out and
  its change slips through (`Held`, each of seven left out in turn).
  Example: Ada overrides `API_KEY` in fork `dev-ada`, which inherits it
  from `dev` as secret; meanwhile `dev`'s `API_KEY` is marked sensitive.
  Its guard fails, and the write asks again, now sensitive.
- **Except the keys it writes.** A regenerate in the same environment
  replaces the key it writes: after `app_change_strict` the log holds our
  own change of it, and its guard would fail every try. ChangeCAS holds the
  keys being written; the guards hold the rest.

### Names

A key's object holds neither its name nor its folder: a rename or a move
changes no object (`patchSecret`'s "a rename or a move is none"). A key
that does not exist yet has no object at all. So no guard sees either:

- **A rename.** Ada writes `dev { API_KEY: "new" }`; the vault reads it as
  key S. A maintainer renames `API_KEY` to `OLD_KEY` and answers. The app's
  statement updates S: ChangeCAS passes (S's seal did not move), every
  guard passes, and "API_KEY written" lands on `OLD_KEY`. A parent's key
  renamed is the same for a regenerate whose `replaces` it names (Coffre's
  `RegeneratesReplaceWhatTheyListed`), and a project or environment
  renamed for its slugs.
- **A key that appears.** Fork `dev-ada` of `dev`, neither holding
  `API_KEY`. Ada writes it in the fork, weighed at secret, as nothing above
  marks it. Meanwhile `dev` gains `API_KEY`, sensitive. The fork's write
  would commit at secret, its value wrapped looser than its level at
  commit. A nearer override in a fork of a fork, or a dismissal, the same.

Today each of these is caught by the reads under the head (`regenerated`,
`levelsAt`, `checkEnvironment`). Here the resolution is **one SQL function,
`write_names(project, environment, keys)`**: the project and environment
by slug, its fork chain, and for each key and each environment of the
chain the row the name resolves to (its id, current version, archived or
not, a reference or not) or none, and whether a dismissal stands. The
vault's statement calls it and answers its result as canonical JSON. The
app's statement calls it again, as its second statement, right after the
head, and raises `CF001` when the result differs from the vault's
(`hold_names(…, expected)`): the write asks again. One function both sides
call, so the hold cannot resolve less than the decision did.

Right after the head, before the rows: after them it would read our own
new version. And the head suffices: every write that changes a name, a
fork chain, a key's row or a dismissal (`patchSecret`, `setSecrets`,
`missing.ts`'s dismissals, a project's or environment's rename) is an
`audited` write, which takes 0.14's head first. One that committed before
ours took the head is read by the hold, a statement after it; one after
waits for our COMMIT. This is one more reason the head stays a lock after
PR 6. The named use does the same in its one call: `use_credential`
resolves the request's names under the fence and answers `moved` when they
no longer name the ids it was passed (0045, D153).

Names are app rows, unsealed, here as today: a database writer who renames
a key is not stopped today either. The AAD binds each value to its key by
id, so a rename does not move a value to another key.

### The request and its refusals

The statement records the request, not its outcome (R53), as a use does: a
row per key, beside `log_uses` (its table or `log_uses` with a write
purpose, PR 3's choice), numbered from `log_number`. The Worker can only
MAC what it knows before the call, and it does not know the ids: it has the
token's hash, not the credential. So the row's MAC covers the request id,
the Worker's clock, the token's hash, and the path and keys **by name, as
asked**. The ids the statement resolves and each input's newest change sit
beside, unsealed: an index, which nothing proves from.

What binds a request to ids is a record the Worker MACs once it has the
statement's answer, as a use's second call writes its MAC'd row:

- allowed and committed: **the change** in `log_changes`, under the same
  request id. Its MAC (the vault's, made by `prepareChanges`) covers every
  column but the change's own number (`log-entry.ts`), so what it binds
  must sit in one: the key's id is its `object`; the request's one id, the
  same for every change of the patch (today `prepareChanges` mints one per
  change), its `request_id`; and the request's number, the credential's
  id and the identity's ride its payload, as `request`, which
  `loggedChange` leaves beside `old` (today's `actor` names the principal
  alone, and a session and an API token of one person carry different
  scopes). No extra trip;
- refused, or not done for any other reason (out of time, the key service
  failing): **an outcome record**, the request id, its number, the ids it
  resolved, each object's newest change, the names' resolution and the refusal's code, MAC'd by the
  Worker and written by a second vault statement (`write_outcome`). One
  more round trip, on a refusal only: a refusal is not a change, and today
  `Refusal` pays a 0.14 deny entry for it;
- allowed but asked again (a guard moved): nothing more; the next try is a
  request of its own.

A request with neither (the app's statement never ran, the Worker died)
binds no ids: the log says it was asked, by that token's hash, and nothing
more. The replay decides from the bound record's ids, at the request's
number. Example: a database writer edits the resolved credential id on a
refused write's row. Nothing reads it: the outcome record's MAC names the
credential the Worker decided on, and an edited outcome record fails its
MAC at the checkpointer.

## A member add

`PUT /members/svc`, Bob's session, with svc's first grants or none (`admit`
and `setAccess(…, admit)` alike).

**What takes it.** The first add of a principal with no member row, with
its role and first grants or none, by a caller with a session or an API
token of a member; by a caller who does not run the instance (no admin,
setting up a service account as the services setting lets them), only
with first grants. Such a caller's standing is `#setsUp`: may they give
access at some live place? With a first grant, that grant's place answers
it, and the write holds that place. With none, only every live place
would, which no single object holds. Everything else keeps today's path: a re-admit (an
earlier generation, whose end the app writes, `endPriorMembership`), a role
or grant change on an existing member (`member.role`, the last-Owner
checks), a caller through a way in with no token, a dry run.

**The front door** is the write's: served before `authenticate` and the
router, the app reads the token's kind from the token and refuses on that
alone (a personal token never reaches an access route: refused, as the
router refuses it today), checks the origin and the body, and calls the
vault with the token's hash, the config's `accepts`, svc, its role and its
grants by place name. The vault resolves Bob from the token's hash and
refuses first what the app would (AcceptedFirst). Today `vault.admit`
trusts the `actor` the app authenticated; here nothing the app says names
the actor.

1. **The vault's read**: the session by its token's hash, Bob's member row
   and grants, the roles and the policy, the services setting (its newest
   `settings.change`), svc's row if any, and each place a first grant
   names, by slug, with its environment's object; each with its newest
   change. No lock, nothing written (Lifecycle's issue, statement 1).
2. **The Worker** holds each row to its newest change (StaleFirst, as a
   write's), decides (`#standing`, `#setsUp`), and builds svc's new row and
   its grants, their MACs and seals, and their changes, from the rows as
   read (none). The setting is the newest entry the vault wrote, by its MAC
   (`#settingsAt`); when that entry fails its MAC (a forged one), the Worker
   pages back as `#settingsAt` does: more trips, only then.
3. **The vault's write**, one statement (`admit_write`): both members' queue
   locks and rows in principal order (`lockMembers`), 0.14's head, the
   fence; it goes ahead only while everything step 1 decided on is what it
   read (IssuerCAS): Bob's object, the roles, the policy, no `settings.change`
   after the one read, each first grant's environment, and svc's row
   (none: for a first add, the members' primary key, a second insert
   failing). The rows, `change_input_strict`, COMMIT. Otherwise it writes
   nothing, answers `moved`, and the vault reads again.
4. `waitSealed`, then the answer.

Example: Bob, no admin, sets up svc with a grant at `market/dev` while the
services setting is open; an Owner closes it between the read and the
write. The write sees a newer `settings.change`, writes nothing, and the
read again refuses Bob.

**A refused add** writes an outcome record, as a refused key write does:
the request id, the ids the read resolved, each object's newest change and
the refusal's code, MAC'd by the Worker and written by a second vault
statement (`admit_outcome`). The read writes nothing, so without it a
refused add would leave no record once 0.14's `member.add` deny entry
stops (PR 6). Two trips on a refusal, off the budget.

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
| the app's statement holds every input to the object the vault decided on (`Held`, each of seven left out in turn) | `WritesStandAtCommit`: a write committed after a revoke, a session's end, a role redefined, a policy change, an archive or protection of the environment or its fork parent, a write of the key a regenerate replaces, or a new level on the key an override inherits |
| ... and the names' resolution as the vault read it (NameHold) | `WritesStandAtCommit`: a write committed after its key was renamed, or after the parent gained the key it inherits, sensitive, or a dismissal there |
| ... checked once it holds the fence (GuardsAfterFence) | `WritesStandAtCommit`: a session's revoke, which takes the fence and not the head, between the guards and the write |
| ... by the log's newest change, not the row's column (GuardOnLog) | `WritesStandAtCommit`: a revoked session's row put back, live, by a database writer |
| the key's change from the seal it was made from (ChangeCAS) | `KeyChangesFlip`: two writes from one version both commit |
| a member add's write holds what its read decided on (`AdmitHeld`, each of five left out) | `AddsStandAtCommit`: a demoted admin's add; an add after a role redefined or the policy gave adding to Owners; a set-up after the services setting closed; a first grant at a place archived meanwhile |
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
  take none. The head stays its first statement after 0.16 stops the
  appends, a lock and nothing read: `app_change` takes the head again
  inside, after the rows, so without it a two-trip write (rows, then head)
  and a route still head-first (`patchSecret`: head, then rows) would wait
  on each other until Postgres kills one, and two multi-key writes in
  opposite key order likewise. Neither Writing (one atomic step) nor
  Migration015 (the head first, assumed) would see it;
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
  later. That move comes before `write_request` too (PR 2, below): the
  0.14 check is a walk back through the member's access entries, by MAC
  (`newestAuthentic`, a page at a time), which one statement cannot do.
- **Old app isolates, new writes.** They fence their writes on the newest
  `policy.change` in `audit_log` (`policyStill`). So a policy change keeps
  its 0.14 entry until no isolate reads it. It is not on this target's path.
- **Old isolates' changes, new guards.** Every 0.15 release logs each change
  of a credential, a member, the policy, an environment and a key in
  `log_changes` (through `app_change` and `change_input`). So a revoke or a
  policy change made by an old isolate moves exactly what a new guard
  probes. And its renames and dismissals take 0.14's head, as the names'
  hold needs.
- **A new app, an old vault.** The vault's binding has no `writeNamed`: the
  write takes today's path. An old app never calls it.
- **SQLite** holds the whole file per transaction: the same steps run in
  TypeScript inside one transaction, with no round trip to save.

## The PRs

Each with what the key write and the first member add then cost:

1. This design and formal/Writing.tla.
2. **The vault's decisions on seals**, not 0.14's access entries (the
   compatibility step above), so that one statement can read what a
   decision needs. No route's cost moves.
3. **The key write's front door, `write_request`, `write_outcome` and the
   app's guarded statement**, with the 0.14 entries still written. The
   vault's `key.wrap` entry needs its head (a transaction of two trips);
   the app's statement keeps its head read for its own entry's MAC (two).
   `write_names` and `hold_names` come with it.
   Key write: 1 + 2 + 2 = 5 round trips (16 today).
4. **The audit pages, the offboarding report and the members' watermark
   read the log**: writes, their refusals and member changes, place
   filters included; and `memberAccess`, `missingMembers` and
   `tamperedMembers`, which take a member's newest 0.14 access entry
   (`ACCESS_ACTIONS`: `member.add`, `access.grant`, …) as the newest
   legitimate change against a `vault.tampered` finding, take the
   principal's newest change in the log instead. Otherwise, once the adds
   stop appending, the watermark freezes, and a member added later with any
   later finding reads tampered for good. After it, nothing reads these
   routes' 0.14 entries.
5. **The member add's front door, read, write and `admit_outcome`.** Its 0.14 `member.add`
   entry still needs the head read before its MAC: read, head, write, 3
   round trips (14 today).
6. **0.16, the contraction.** The two routes stop writing 0.14's entries;
   `revoke_credential` drops the head (a migration); the app's statement
   keeps it as a lock (above). The services setting's changes move into
   `log_changes` with §11's other vault changes, and the add's guard probes
   it there. `change-cost.test.ts` holds a key write to `{ app: 1, vault: 1 }`
   and a first member add to `{ app: 0, vault: 2 }`.
7. **The other change routes**, each in the same shape; references join the
   key write once `write_request` seals their making and their end, and a
   remote key-encryption key once the request and outcome records stand
   for its intent and outcome.

Each PR that changes what a statement re-checks changes formal/Writing.tla
in the same PR.
