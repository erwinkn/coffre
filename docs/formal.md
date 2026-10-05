# A model of the locking protocol

coffre's app and vault share one database. The vault decides every access,
and the audit log's head row serialises appends and decisions
([single-database.md](design/single-database.md), "Transactions, locks and
serialised decisions"). The tests and the property tests run operations one
after another. The races are in how operations interleave, and two of them
reached #134's review, found only by reasoning. So the protocol is also
written as a TLA+ specification, and TLC checks it over every interleaving
of a few concurrent requests:

```sh
pnpm formal                  # every scenario, about a minute
scripts/formal.sh Deletion   # one, with its runs without a protection
```

- [`formal/Coffre.tla`](../formal/Coffre.tla) is the model: the state, one
  step per SQL statement, and the invariants.
- [`formal/MC.tla`](../formal/MC.tla) holds the scenarios: who runs what, and
  from which state. Each one has a configuration, `formal/<Name>.cfg`.
- [`scripts/formal.sh`](../scripts/formal.sh) downloads TLC, checks its
  checksum and runs everything.
- [`scripts/formal-trace.mjs`](../scripts/formal-trace.mjs) prints a
  counterexample one step per line.

CI runs it in the *Formal model* job of `validate.yml`.

## What it checks

Every scenario must hold. Then each one runs again with one of the code's
protections turned off, and must fail on the invariant that protection
keeps. If a change to the model ever stopped it seeing a race it once
caught, that run would pass, and the script fails. Each of these
counterexamples is printed in CI's log.

| Protection, in the code | Turned off, TLC finds | Found by |
|---|---|---|
| A deletion re-reads the place's grants under the head (`projects.ts`, `granted_meanwhile`) | a grant left on a deleted place, which no path can revoke (`EveryGrantRevocable`) | #134's review |
| `setAccess` reads whether the place is deleted after taking the head | the same, from the other order | #134 |
| A deletion re-checks under the head that the place is archived (`restored`) | a place erased after it was restored (`DeletedOnlyWhenArchived`) | #134's review |
| A rename, archive or restore resolves the place again under the head (`stillThere`) | a tombstone given back a live slug, or un-archived (`TombstonesKeepTheirSlug`, `TombstonesStayArchived`) | this model, fixed in #147 |
| A key decision re-checks the place under the head (`#keys`) | a key released after its place's deletion committed (`NothingReleasedAfterDeletion`, `DeletedStaysUnreachable`) | this model, fixed in #147 |
| Adding an environment resolves its project again under the head, and reads whether it is archived there (`putEnvironment`, `stillThere`) | an environment added to a deleted project (`DeletedStaysUnreachable`) | reported with #147, fixed in #149 |
| Renaming, archiving or restoring a key resolves its environment again under the head (`patchSecret`, `checkEnvironment`) | a key renamed in a deleted place, its tombstone's names changed (`DeletedStaysUnreachable`) | reported with #147, fixed in #149 |
| Sign-in re-reads the member's generation under the head (`#stillMember`) | a credential issued at a generation a removal had moved past (`CredentialsAtCurrentGeneration`) | |
| Member rows are locked in principal order (`lockMembers`) | two decisions waiting on each other (`NoWaitCycle`) | |

Here is #134's first race, as `scripts/formal.sh` prints it, with the grant
re-read turned off:

- Olga deletes the archived project. Her scope read finds Ada's grant on
  the environment, and the vault revokes it (steps 4 to 12).
- Omar then grants Ada the project (14 to 20).
- Olga's transaction commits the deletion (22).
- Ada's grant on the project outlives it, and no path can name the place to
  revoke it.

```
  4. deleter   DeleteScope     delete proj by olga     -> delete.next
 12. deleter   CallCommit      delete proj by olga     -> delete.next     grants -ada@env; head deleter -> none
 13. deleter   DeleteNext      delete proj by olga     -> delete.head
 14. admin     GrantResolve    grant ada@proj by omar  -> call.lock
 20. admin     CallCommit      grant ada@proj by omar  -> idle            log +access.grant proj (admin); grants +ada@proj
 21. deleter   DeleteHead      delete proj by olga     -> delete.commit   head none -> deleter
 22. deleter   DeleteCommit    delete proj by olga     -> idle            log +delete proj (deleter); slug[proj] s1 -> tomb; held true -> false
```

And the second, with the archived re-check turned off: Omar restores the
project after Olga's revocations and before her transaction, and the
deletion erases a live project.

```
 12. deleter   DeleteNext      delete proj by olga     -> delete.head
 16. admin     PatchCommit     unarchive proj by omar  -> idle            archived[proj] true -> false
 17. deleter   DeleteHead      delete proj by olga     -> delete.commit   head none -> deleter
 18. deleter   DeleteCommit    delete proj by olga     -> idle            log +delete proj (deleter); slug[proj] s1 -> tomb; held true -> false
```

Each line is one step:
- the process that took it;
- the step, an action of `Coffre.tla`;
- the operation it belongs to;
- the step that process takes next;
- what changed in the rows, the locks and the log.

Traces are shortened here; the script prints every step.

## The invariants

| Invariant | What must hold in every state |
|---|---|
| No deadlock | TLC's own check: a run that can no longer finish is reported |
| `NoWaitCycle` | No request waits, however indirectly, for itself |
| `EveryGrantRevocable` | Every grant is on a standing place, which the API can name and so revoke |
| `NothingReleasedAfterDeletion` | No `secret.read` follows a place's deletion in the log |
| `DeletedStaysUnreachable` | Nor does anything else that reads, writes or grants there: a `key.wrap`, a `secret.write`, an `access.grant`, an `environment.create` or a key's rename, archive or restore |
| `DeletedOnlyWhenArchived` | A deletion commits only on a place that is archived when it commits |
| `TombstonesKeepTheirSlug`, `TombstonesStayArchived` | A deleted place stays deleted, and archived |
| `AuditBeforeRelease` | A value reaches its caller only once its `secret.read` entry has committed |
| `CredentialsAtCurrentGeneration` | A credential is issued to an active member, at the generation they hold when it commits |

## The model

- **Steps.** Each step is one SQL statement, or a run of statements that
  nothing can interleave with, because the step holds the lock they need.
  Isolation is READ COMMITTED: a statement reads what was committed when it
  ran, and a transaction's writes become visible when it commits.
- **Locks.** Two kinds, each held to the end of its transaction:
  - a member's row, taken one row at a time, in principal order;
  - the log's head.

  A process whose next step takes a lock that another holds simply cannot
  take it until that lock is released: that is the wait.
- **Requests.** Each is a process, which runs a bounded number of
  operations, choosing each from its set:
  - read a value, or write one;
  - grant or revoke;
  - delete, archive, restore or rename a place;
  - add an environment, or rename, archive or restore a key;
  - sign in;
  - remove a member;
  - rotate the vault's key.
- **Each operation** follows its code path. For example, a read takes these
  steps:
  - the app resolves the path outside any transaction;
  - the vault reads the version, unlocked;
  - the vault locks the reader's row and checks their standing and the place;
  - it takes the head, appends `secret.read` and commits;
  - the app decrypts.

  A deletion reads its scope, revokes through `setAccess` (the same steps
  as a grant), then takes the head and re-checks, erases and renames in
  one transaction.

### The scenarios

| Scenario | Who runs what | States |
|---|---|---|
| `Deletion` | One owner deletes a project or an environment, twice. Another grants, revokes, restores or renames, twice | 19 thousand |
| `Reading` | A place is archived, then deleted. Meanwhile a root admin, a holder of a grant on every project and a holder of a project grant read and write there, and an owner adds an environment or renames a key, twice | 14 thousand |
| `Members` | A member signs in, reads and writes, while an owner removes them or changes their grants, and the vault rotates its key | 214 thousand |
| `Locks` | Two owners change each other's grants and remove a member, while the vault rotates its key, which locks every member's row | 12 thousand |
| `Mixed` | Two owners run nearly every operation on places and grants, while a member reads, writes, signs in or rotates | 951 thousand |

Every scenario starts from one project and its one environment, holding one
secret.

## What it abstracts

- **App rows.** Each is locked only under the head, which every app
  transaction takes first (`audited`), so they never decide who waits.
  Foreign-key share locks are compatible with `FOR NO KEY UPDATE` and are
  left out too.
- **Refusal entries.** A refusal rolls back and appends its entries in a
  transaction that takes the head alone. It can wait for nobody and decides
  nothing, so it is left out.
- **Roles.** A grant is a grant. Which role allows what is a pure function,
  which the property tests check ([property-tests.md](property-tests.md)).
- **Grants on one environment slug in every project** (`*/prod`). They are
  checked exactly as grants on every project are, and are modelled as those.
- **The key service.** A remote KEK's intent transaction, budget and
  partial outages are left out. The key decision is modelled as with a
  local KEK, which holds the same locks in the same order.
- **Retries.** A write whose version moved prepares again in the code; in
  the model it ends. A deletion asked again is a second operation.
- **Admission and restoring a member**, checkpoints, sessions beyond their
  generation, and lapsed grants.

## What it does not prove

- **That the code is the model.** The model was written from the code, and
  each step names the function it stands for. Nothing checks that they stay
  alike. A change to the order of locks or re-checks in `vault.ts`,
  `projects.ts`, `secrets.ts` or `signin.ts` should change `Coffre.tla` in
  the same pull request.
- **Beyond the bounds.** The bounds are two places, a few members, and three
  or four requests of one or two operations each. Races that need more are
  not explored. The races found so far needed two requests.
- **Liveness.** It checks that nothing bad happens, not that every request
  finishes. A deadlock does show, since every run is finite.
- **Postgres itself.** It assumes Postgres's row locks and READ COMMITTED
  behave as documented. It does not cover SQLite, where every transaction
  holds the whole file and so nothing interleaves.
- **Security outside concurrency:** MACs, the chain, the database's owner.

## TLC

[TLC](https://github.com/tlaplus/tlaplus) is the TLA+ tools' explicit-state
model checker. It explores breadth first, so every counterexample is a
shortest one.

- **Version:** `tla2tools.jar` 1.7.4, released 2024-08-05, the latest
  stable release. It is one jar with no dependencies, pinned in
  `scripts/formal.sh` by SHA-256 and checked before every use.
- **Not 1.8.0:** that tag is a prerelease, rebuilt nightly, which no pin
  would hold.
- **Java:** TLC needs Java 11 or newer. CI's `ubuntu-24.04` runners carry
  Java 17, so the job installs nothing else.
- **Other tools considered:**
  - Apalache checks symbolically, by trace length, and is much larger.
  - Quint's simulator samples traces rather than covering every one, and
    its exhaustive mode downloads Apalache at run time.
