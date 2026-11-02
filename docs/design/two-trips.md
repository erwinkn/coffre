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

## The shape

```
key write    vault  one statement, as a use's                1 round trip
                    the Worker decides, wraps, seals the change
             app    one statement under the head              1 round trip
             vault  waitSealed                                the seal
member add   vault  read                                      1 round trip
                    the Worker decides, builds the row, its MAC and its seal
             vault  write, held to what the read decided on   1 round trip
             vault  waitSealed                                the seal
```

At Cloudflare's 20 ms that is 40 ms of database, plus the seal's 75–90 ms and the
Workers' hops: about 120–130 ms.

### A key write

`PATCH /secrets/market/dev { API_KEY: "…" }`, Ada's session cookie.

1. **The app reads nothing.** It makes the DEK and the ciphertext, as now, and
   calls the vault with the session's token, the path by name, the keys and
   their ciphertexts' DEKs.
2. **The vault's statement** (`write_request`, a SECURITY DEFINER function
   beside `use_credential`, shaped like it):
   - takes the fence shared;
   - reads, by name: the credential by its token's hash, the member row and
     grants, the policy, the project and environment (a fork's chain), each
     key's row and current version, each one's seal and its newest change;
   - numbers the request, its entry (R53: the request, not the outcome);
   - commits, and answers the rows, the app's credential row with its
     `auth_mac`, and the log's newest change number.

   One round trip, and nothing held after it.
3. **The Worker** checks the seals (StaleFirst), decides with `decide.ts`
   (unchanged, still tied to the Lean model), wraps each DEK, and seals the
   app's change from each key's object as read (`prepareChanges`, in memory,
   with keys only the vault holds). It answers the app: the caller, the
   heads as read, the envelopes, the prepared changes, and what the decision
   stood on, each input with its seal.
4. **The app** checks the credential row's `auth_mac` in memory (as a named
   use does, `named-use.ts`), then sends **one statement**: BEGIN, 0.14's head
   `FOR UPDATE`, the new rows and the key's update, each change through
   `app_change_strict` (the issue lock, the fence exclusive, ChangeCAS), and
   then, **under the fence**, the guards: the credential, the member, the
   policy and the environment are each still the object the vault decided on
   (their seals). A guard that fails raises, Postgres skips the COMMIT, and
   the write asks again from 2 (`ObjectMoved`, at most 16 times, as now).
   COMMIT goes in the same Sync. One round trip.
5. `waitSealed`, then the answer (R51).

The app's checks that need its own rows (the key archived, a regenerate's
`replaces`, a fork's inherited keys, a loosening) move into the vault's read
(the vault reads every app table a decision needs already) or into the app's
statement as guards. Nothing reads before the vault's call.

### A member add

`PUT /members/svc`, Bob's session.

1. **The vault's read**: the session, Bob's member row and grants, the policy,
   svc's row if any, each with its seal. No lock, nothing written (Lifecycle's
   issue, statement 1).
2. **The Worker** decides (`#standing`, `#setsUp`), builds svc's new row, its
   MAC and its seal, and the change, from the row as read (none).
3. **The vault's write**, one statement (`admit_write`): svc's queue lock and
   row, Bob's row shared, 0.14's head, the fence; it goes ahead only while
   Bob's object, the policy and svc's row are the ones step 1 read
   (IssuerCAS); the row, `change_input_strict`, COMMIT. Otherwise it writes
   nothing, answers `moved`, and the vault reads again.
4. `waitSealed`, then the answer.

The app's `endPriorMembership` runs only when svc had an earlier generation
(a re-admit): the vault's answer says so. A first add is the vault's two
statements and nothing of the app's.

A warm vault can skip step 1: the isolate keeps the actor's inputs with their
seals, as the use path keeps its seal cache, and the write's CAS refuses
them if they moved. That is one round trip when warm. It is not the target,
since Cloudflare may send the next request to another isolate.

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
`audit_log` entry. Their record is the change in `log_changes`: actor, request,
object, payload, MAC'd by the vault at prepare time (`log-entry.ts`). SQL
stores it, and the checkpointer checks it before sealing. This is the contract
0.16 already plans (0.15-plan.md, "11. The contract, in 0.16"). Pages render
these changes, as they do a member's or a sign-in's since T156.

## What it guarantees

formal/Writing.tla checks it (docs/formal.md, "Writing.tla"):

| protection | turned off, TLC finds |
|---|---|
| the vault's statement reads and numbers under the fence shared (RequestUnderFence) | `RequestsReplay`: a change numbered between the read and the request; the replay decides otherwise |
| the app's statement holds the session, the member, the policy and the environment to the objects the vault decided on (`Held`, each left out in turn) | `WritesStandAtCommit`: a write committed after a revoke, a session's end, a protection or an archive committed |
| ... checked once it holds the fence (GuardsAfterFence) | `WritesStandAtCommit`: a session's revoke, which takes the fence and not the head, between the guards and the write |
| the key's change from the seal it was made from (ChangeCAS) | `KeyChangesFlip`: two writes from one version both commit |
| a member add's write holds the actor's object and the policy (AdmitCAS) | `AddsStandAtCommit`: a demoted admin's add |
| ... and the principal's row as read (PrincipalCAS) | `AddsFlip`: two adds of one member both commit |
| a change answers once sealed (WaitForSeal, R51) | `AnsweredSealed` |

`TwoTrips` holds throughout: a write or an add that commits at its first try
made exactly two round trips.

**One guarantee is new.** `WritesStandAtCommit` is stronger than today's
code. Today a write decided by the vault before a revoke can still commit
after the revoke has answered: the app's transaction checks the policy
(`policyStill`), not the writer's standing. With the guards under the fence, a
write stands at its commit, not only at its decision. The guards cost no round
trip: they are statements of the same Sync.

**Locks, in the order Migration015's `NoWaitCycle` already checks:**
- the app's statement: 0.14's head, then its rows, then the issue lock
  shared, then the fence, as `audited` and `app_change` do now;
- the vault's request: the fence shared alone, as a use;
- a member add's write: the member's queue and row, then 0.14's head, then
  the fence, as `change_input` does now.

The fence is held from `app_change` to COMMIT, as now, plus a few guard
statements inside the same Sync. No round trip is spent while it is held.

## The seal wait

Kept (R51, D165 A). A change's number exists only once it commits, so the seal
wait cannot overlap the app's statement. What it costs is the checkpointer's
tick: barrier, window, sign, write (T171: 75–90 ms on Cloudflare). The barrier
and the window could share a round trip, but the fence would then be held
while the window is read, and every use would wait on it (R44, R58). This is
left out again.

## Compatibility

A deploy runs the old isolates beside the new until the old drain (expand,
then contract).

- **Old vault isolates** check a member row's `access_seq` against its newest
  0.14 access entry (`#integrity`). A member added with no such entry, its row
  MAC'd without one, would be refused there (fail closed) until they drain.
  So the vault's own decisions move to seals first (the row is its object's
  newest change, as a use checks), in a release that still writes 0.14's
  entries. The appends stop one release later.
- **Old app isolates** fence their writes on the newest `policy.change` in
  `audit_log` (`policyStill`). So a policy change keeps its 0.14 entry until
  no isolate reads it. It is not on this target's path.
- **SQLite** holds the whole file per transaction: the same steps run in
  TypeScript inside one transaction, with no round trip to save.

## The PRs

1. This design and formal/Writing.tla.
2. The key write's vault statement (`write_request`) and the Worker's one
   call, with the 0.14 entries still written: the app's transaction keeps
   its head read for their MAC. So 1 + 2 round trips.
3. The vault's decisions on seals, not 0.14's access entries (the
   compatibility step above).
4. The member add's read and write.
5. 0.16: the two routes stop writing 0.14's entries, and the app's statement
   becomes one round trip. `change-cost.test.ts` holds key writes to
   `{ app: 1, vault: 1 }` and a first member add to `{ app: 0, vault: 2 }`.
6. The other change routes, each in the same shape.

Each PR that changes what a statement re-checks changes formal/Writing.tla
in the same PR.
