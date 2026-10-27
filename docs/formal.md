# Models of the protocols

coffre's app and vault share one database. The vault decides every access,
and the audit log's head row serialises appends and decisions
([single-database.md](design/single-database.md), "Transactions, locks and
serialised decisions"). The tests and the property tests run operations one
after another. The races are in how operations interleave, and two of them
reached #134's review, found only by reasoning. So the protocol is also
written as a TLA+ specification, and TLC checks it over every interleaving
of a few concurrent requests:

```sh
pnpm formal                  # every scenario: about an hour on one machine, CI shards it
scripts/formal.sh Deletion   # one, with its runs without a protection
```

- [`formal/Coffre.tla`](../formal/Coffre.tla) is the model of the locking
  protocol: the state, one step per SQL statement, and the invariants.
- [`formal/MC.tla`](../formal/MC.tla) holds its scenarios: who runs what, and
  from which state. Each one has a configuration, `formal/<Name>.cfg`.
- Six smaller models, each with its scenarios beside it, hold other
  protocols to the same discipline ([below](#credentials-issuing-and-the-bulk-limit)):
  - [`formal/Credentials.tla`](../formal/Credentials.tla), a CI run's ID
    token exchanged for a credential, and every way a credential ends;
  - [`formal/Issuing.tla`](../formal/Issuing.tla), who may hand a service
    account sensitive values (R32);
  - [`formal/Bulk.tla`](../formal/Bulk.tla), the vault's bulk limit (R28);
  - [`formal/Audit.tla`](../formal/Audit.tla), the audit chain's
    heartbeats, checkpoints, anchor and readiness against someone who
    writes the database ([below](#the-audit-chain-the-app-key-and-the-tunnel));
  - [`formal/Tunnel.tla`](../formal/Tunnel.tla), how long a revoked
    handle's tunnel session lives;
  - [`formal/AppKey.tla`](../formal/AppKey.tla), the app key's rotation,
    against instances still under the old key and someone who holds it
    ([below](#appkeytla)).

  A configuration names the module of its scenarios on its second line,
  `\* model MCCredentials`; one that names none is `MC.tla`'s.
- Four more hold the workload-access design before it is built
  ([below](#workload-access)): `formal/Workload.tla` and the three
  `formal/Workload*.tla` beside it.
- Three hold 0.15's rewrite of the vault and the audit log, the spec its
  code follows ([below](#015-the-hot-path-sealing-and-the-cutover)):
  - [`formal/HotPathOne.tla`](../formal/HotPathOne.tla): uses, changes,
    sealed inputs, covers, the deadline and the bulk cap;
  - [`formal/Seal.tla`](../formal/Seal.tla): sealing into two Merkle trees;
  - [`formal/Migration015.tla`](../formal/Migration015.tla): the cutover
    from 0.14.
- [`scripts/formal.sh`](../scripts/formal.sh) downloads TLC, checks its
  checksum and runs everything.
- [`scripts/formal-trace.mjs`](../scripts/formal-trace.mjs) prints a
  counterexample one step per line.

CI runs it in the *Formal model* job of `validate.yml`, and skips TLC when
the model's inputs are unchanged ([below](#in-ci)).

## What it checks

Every scenario must hold. Then each one runs again with one of the code's
protections turned off, or two that each cover for the other, and must
fail on the invariant they keep. If a change to the model ever stopped it seeing a race it once
caught, that run would pass, and the script fails. Each of these
counterexamples is printed in CI's log. Coffre.tla's are these; the other
models' are [below](#credentials-issuing-and-the-bulk-limit).

| Protection, in the code | Turned off, TLC finds | Found by |
|---|---|---|
| A deletion re-reads the place's grants under the head (`projects.ts`, `granted_meanwhile`) | a grant left on a deleted place, which no path can revoke (`EveryGrantRevocable`) | #134's review |
| `setAccess` reads whether the place is deleted after taking the head | the same, from the other order | #134 |
| A deletion re-checks under the head that the place is archived (`restored`) | a place erased after it was restored (`DeletedOnlyWhenArchived`) | #134's review |
| A rename, archive or restore resolves the place again under the head (`stillThere`) | a tombstone given back a live slug, or un-archived (`TombstonesKeepTheirSlug`, `TombstonesStayArchived`) | this model, fixed in #147 |
| A key decision re-checks the place under the head (`#keys`; with a key in memory, it decides under the head from the start) | a key released after its place's deletion committed (`NothingReleasedAfterDeletion`, `DeletedStaysUnreachable`) | this model, fixed in #147 |
| Adding an environment resolves its project again under the head, and reads whether it is archived there (`putEnvironment`, `stillThere`) | an environment added to a deleted project (`DeletedStaysUnreachable`) | reported with #147, fixed in #149 |
| Renaming, archiving or restoring a key resolves its environment again under the head (`patchSecret`, `checkEnvironment`) | a key renamed in a deleted place, its tombstone's names changed (`DeletedStaysUnreachable`) | reported with #147, fixed in #149 |
| Sign-in re-reads the member's generation under the head (`#stillMember`) | a credential issued at a generation a removal had moved past (`CredentialsAtCurrentGeneration`) | |
| Member rows are locked in principal order (`lockMembers`) | two decisions waiting on each other (`NoWaitCycle`) | |
| A read decides under the reader's row, shared with their other reads, which a revocation or a removal waits for (`#keys`, through `#decide`, `reads`; `lockMembers`, `FOR SHARE`, not `KEY SHARE`, which they would not wait for) | a value released to a member after their removal committed (`NothingReleasedAfterRevocation`, in `Members` and `Sharing`) | |
| A read through a reference checks again, under the head, that it has not ended (`unwrap`'s `vet`, run again in `underLock`) | a value read through a reference after it was broken (`NothingReleasedThroughEndedReference`) | |
| Making a reference checks its source again under the head (`secrets.ts`, `setSecrets`) | a reference made to a source archived or deleted meanwhile (`ReferencedSourcesStayLive`) | #152 |
| Archiving is refused while a live reference held in an unarchived place elsewhere reads the place (`references.ts`, `archiveBlockers`) | a reference in a live holder reading an archived source (`ReferencedSourcesStayLive`) | #152 |
| A deletion re-reads the references into and out of the place under the head (`projects.ts`, `referenced_meanwhile`) | a reference held in a deleted place, which no path can break, and whose source can never be archived (`EveryReferenceBreakable`) | this model, fixed in #155 |
| Demoting or removing an Owner of the whole instance counts the others under the head (`vault.ts`, `#keepAnOwner`) | two Owners, each leaving or stepping down at once, under rows the other does not lock: none left (`OwnerStays`) | |
| A regenerate in a fork resolves each key it replaces again under the head, the parent's rows included (`secrets.ts`, `setSecrets`, `regenerated`) | an override written under a key name the parent renamed meanwhile, beside the renamed key the fork still inherits (`RegeneratesReplaceWhatTheyListed`) | #244's review |

Here is #134's first race, as `scripts/formal.sh` prints it, with the grant
re-read turned off:

- Olga deletes the archived project. Her scope read finds Ada's grant on
  the environment, and the vault revokes it (steps 4 to 11).
- Omar then grants Ada the project (13 to 20).
- Olga's transaction commits the deletion (22).
- Ada's grant on the project outlives it, and no path can name the place to
  revoke it.

```
  4. deleter   DeleteScope     delete proj by olga     -> delete.next
 11. deleter   CallCommit      delete proj by olga     -> delete.next     grants -ada@env; log +access.revoke ada@env (deleter); head deleter -> none
 12. deleter   DeleteNext      delete proj by olga     -> delete.head
 14. admin     GrantResolve    grant ada@proj by omar  -> call.lock
 20. admin     CallCommit      grant ada@proj by omar  -> idle            log +access.grant ada@proj (admin); grants +ada@proj
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

And the race this model found in references, with the re-read turned
off. Olga deletes the archived holder's environment, and her scope read
finds no reference (steps 7 to 9). Meanwhile it is restored, its key is
made a reference to the secret, and it is archived again (10 to 25). The
deletion commits (27), and the reference is still live, held in a
tombstone: no path names its holder to break it, and archiving its source
is refused while it reads it.

```
  8. deleter   DeleteScope       delete hold by olga        -> delete.next
 14. admin     PatchCommit       unarchive hold by olga     -> idle            head admin -> none; archived[hold] true -> false
 23. maker     ReferCommit       refer hold by olga         -> idle            ref none -> maker; head maker -> none
 25. admin     PatchCommit       archive hold by olga       -> idle            head admin -> none; archived[hold] false -> true
 27. deleter   DeleteCommit      delete hold by olga        -> idle            head deleter -> none; slug[hold] s1 -> tomb; log +delete hold (deleter)
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
| `NothingReleasedAfterRevocation` | No `secret.read` for a member follows the `access.revoke` or `member.remove` that took their last grant covering where it was decided, unless an `access.grant` covering it again comes between |
| `NothingReleasedThroughEndedReference` | No `secret.read` through a reference follows its `reference.end`, or the deletion of its source's place or its holder's, in the log |
| `EveryReferenceBreakable` | A reference that has not ended is held in a standing place, where the API can name its holder, and so break it |
| `OwnerStays` | Once the instance has an active Owner of all of it, it always has one |
| `DeclaredStay` | Someone the deployment names, once the vault made them an Owner, stays one: nobody demotes or removes them, themselves included |
| `RegeneratesReplaceWhatTheyListed` | A regenerate in a fork commits only over what it was listed with: the parent's key still under the name it regenerates, at the version it replaces |
| `ReferencedSourcesStayLive` | And if it is held in a live place, its source is neither archived nor deleted. The exception is a holder that was archived when its source was archived, and has been restored since: its reads refuse, as any broken reference's |

## The model

- **Steps.** Each step is one SQL statement, or a run of statements that
  nothing can interleave with, because the step holds the lock they need.
  Isolation is READ COMMITTED: a statement reads what was committed when it
  ran, and a transaction's writes become visible when it commits. A
  statement that takes a lock and reads other tables in the same go, as a
  vault decision takes the head with all it decides on, reads them as of
  the lock only because it never waits for it (`SKIP LOCKED`; held, it
  waits in a statement of its own and reads again:
  [single-database.md](design/single-database.md), rule 4). So the model
  takes the lock and the reads in one step, or the lock and then the reads.
- **Locks.** Two kinds, each held to the end of its transaction:
  - a member's row, taken one row at a time, in principal order: alone,
    or shared by a read or a wrap with others like it;
  - the log's head.
- **Giving up.** A read waiting for the head another holds may give up
  instead (`ReadGivesUp`): its statement's bound ran out, its call's
  deadline passed, or every place in the head's line was taken
  (`lockLogHeadQueued`). It rolls back having released nothing and
  appended no `secret.read` (a key service's intent, committed before, is
  accounted for as after any failure), and every invariant holds with or
  without the step. The model's other waits never
  give up; in the code they do, at fifteen seconds, the same way.

  A process whose next step takes a lock that another holds simply cannot
  take it until that lock is released: that is the wait. A share lock also
  waits for a process about to take the row alone, as the advisory lock
  each row comes with queues it (`lockMembers`). That the queue keeps a
  removal from waiting for ever behind a stream of reads is a matter of
  how long, which the model's bounded runs do not check: the test `a
  removal amid a steady stream of one member's reads is not starved` does.
- **Requests.** Each is a process, which runs a bounded number of
  operations, choosing each from its set:
  - read a value, or write one;
  - grant or revoke;
  - delete, archive, restore or rename a place;
  - add an environment, or rename, archive or restore a key;
  - sign in;
  - remove a member, or take away their Owner role;
  - make someone the deployment names an Owner;
  - rotate the vault's key;
  - make a reference, or break one;
  - in a fork of the environment, regenerate the key it inherits, or type
    a value over it.
- **Each operation** follows its code path. For example, a read takes these
  steps:
  - the app resolves the path outside any transaction;
  - the vault reads the version, unlocked;
  - the vault shares the reader's row and checks their standing and the place;
  - it takes the head, appends `secret.read` and commits;
  - the app decrypts.

  A read through a reference takes the same steps. The reader's grants on
  the holder decide, and both places, and whether the reference ended, are
  checked under the row and again under the head.

  A deletion reads its scope and the references into and out of the
  place. It revokes through `setAccess` (the same steps as a grant), ends
  the references through the vault's `endReferences`, then takes the head
  and re-checks, erases and renames in one transaction.

  Making a reference: the app checks both places, the vault seals it with
  `reference.create` under the maker's row and the head, the reference it
  replaces is ended, then the app writes its row under the head.

### The scenarios

| Scenario | Who runs what | States |
|---|---|---|
| `Deletion` | One owner deletes a project or an environment, twice. Another grants, revokes, restores or renames, twice | 22 thousand |
| `Reading` | A place is archived, then deleted. Meanwhile an Owner, a holder of an instance role and a holder of a project grant read and write there, and an owner adds an environment or renames a key, twice | 19 thousand |
| `Members` | A member signs in, reads and writes, while an owner removes them or changes their grants, and the vault rotates its key | 249 thousand |
| `Sharing` | A member reads and wraps in two requests at once, each sharing their row, while an owner revokes their grant, gives them another, or removes them | 1.4 million |
| `Locks` | Two owners change each other's grants and remove a member, while the vault rotates its key, which locks every member's row | 15 thousand |
| `Mixed` | Two owners run nearly every operation on places and grants, while a member reads, writes, signs in or rotates | 1 million |
| `References` | A member reads through a reference while an owner breaks it, makes it again, or revokes or removes the reader, and either place is archived, then deleted | 113 thousand |
| `Referencing` | An owner makes a reference while another archives, restores and archives again either place, and a third deletes one | 13 thousand |
| `Owners` | Two Owners of the whole instance each leave, step down, or take the other's role, while an Admin, who is no Owner, tries to demote or remove either | 3 thousand |
| `Regenerating` | A fork regenerates the key it inherits while, in the parent, an owner renames or writes it, and a value is typed in the fork | 1 thousand |
| `Declare` | Two people the deployment names are made Owners at once on an instance nobody owns, while one tries to leave or step down, the other, an Owner once made one, to demote them, and an Admin, no Owner, to demote or remove one | 13 thousand |

Every scenario starts from one project and its one environment, holding one
secret, under the key name `k1`, which a fork of the environment inherits. A third environment, in another project, holds a key that is a
reference to that secret in `References`, and none yet elsewhere.

## What it abstracts

- **App rows.** Each is locked only under the head, which every app
  transaction takes first (`audited`), so they never decide who waits.
  Foreign-key share locks (`KEY SHARE`) are compatible with `FOR NO KEY
  UPDATE` and with `FOR SHARE`, and are left out too.
- **Refusal entries.** A refusal rolls back and appends its entries in a
  transaction that takes the head alone. It can wait for nobody and decides
  nothing, so it is left out.
- **Roles.** A grant is a grant. Which role allows what is a pure function,
  which the property tests check ([property-tests.md](property-tests.md)).
- **Instance roles and their scopes.** A role reaches places by its scope,
  the ones made later too, and is set under the same locks as a grant (the
  member's row, then the head): the model's grant on every project, `"*"`,
  stands for one, scoped or not. Which places a scope takes in is a pure
  function, which the property tests check. The vault replacing the grants
  on every project of 0.4 is one decision per member, under those same
  locks, and is not modelled apart. Who owns the whole instance is state of
  its own (`owners`), apart from the `"*"` an Owner reads by: the last-Owner
  rule and the deployment's list decide on it, not on what anyone reads.
  The list itself is configuration (`Listed`), the same in every process
  of the model; during a deploy an old process and a new one may name
  different people, which changes who is refused, never which locks are
  taken. Refusing to demote or remove someone on it takes no lock, and
  making them an Owner takes their row, then the head, whoever else owns
  the instance. Who may unmake an Owner,
  an Owner of the whole instance (`ChangesOwners`), is read under the
  actor's row, as the rest of the check is; making one is admission,
  which is left out (below).
- **The key service.** A remote KEK's intent transaction, budget and
  partial outages are left out. The key decision is modelled as with a
  local KEK, which holds the same locks in the same order.
- **Retries.** A write whose version moved prepares again in the code; in
  the model it ends. A deletion asked again is a second operation.
- **Admission and restoring a member**, checkpoints, sessions beyond their
  generation, and lapsed grants. A service account admitted with its first
  grants (`setAccess` with `admit`) takes a grant's locks, the member's row
  and then the head, in one decision, so it is a grant to the model.
- **References, to their shape.**
  - There is one holder and one source, in different projects. A holder
    inside what is archived, which doesn't block the archive, is left out.
  - A holder given a value of its own ends its reference with the same
    vault call as making another, so only the latter is modelled. Making
    it again to the source it already reads replaces it in the model,
    where the code leaves it unchanged.
  - A reference whose write stored no row is ended as `abandoned`
    afterwards. In the model such a reference has no row, so nothing reads
    through it either way, and the end is left out.
  - Left out because they decide nothing about locks or ends: a source
    that is itself a reference, archiving a single key, and a read refused
    because the source's version moved.
  - A holder key archived on its own counts as an archived holder, as its
    environment or project does: archiving its source isn't refused. The
    model archives places only, so it checks the rule through the holder's
    environment.

## What it does not prove

- **That the code is the model.** The model was written from the code, and
  each step names the function it stands for. Nothing checks that they stay
  alike. A change to the order of locks or re-checks in `vault.ts`,
  `projects.ts`, `secrets.ts`, `references.ts` or `signin.ts` should change
  `Coffre.tla` in the same pull request; one in `workloads.ts`, `signin.ts`,
  `services.ts` or `context.ts`, `Credentials.tla` or `Issuing.tla`; one in
  the vault's count, `Bulk.tla`; one in `plugins/audit-watch.ts`, `anchor.ts`, `audit.ts` or
  the vault's `checkpoint`, `Audit.tla`; one in the proxy's `watch`, `Tunnel.tla`;
  one in `key-rotation.ts`, or in what an append reads under the head
  (`log.ts`), `AppKey.tla`.
- **Beyond the bounds.** The bounds are three places, a few members, and three
  or four requests of one to three operations each. Races that need more are
  not explored. The races found so far needed two requests, or three for
  the one in references.
- **Liveness.** It checks that nothing bad happens, not that every request
  finishes. A deadlock does show, since every run is finite.
- **Postgres itself.** It assumes Postgres's row locks and READ COMMITTED
  behave as documented. It does not cover SQLite, where every transaction
  holds the whole file and so nothing interleaves.
- **Security outside concurrency:** MACs, the chain, the database's owner.

## Credentials, issuing and the bulk limit

Three protocols outside the locking one, each modelled on its own, with the
same steps (one SQL statement each, READ COMMITTED), the same two locks
(members' rows, then the head) and the same discipline: every scenario
holds, and fails without each protection.

### Credentials.tla

A service account with one trust binding and a token someone issued it.
Each CI run holds an ID token, good for one credential.

- **Exchanging** (`workloads.ts`, `#exchange`):
  1. the live bindings, unlocked;
  2. whether the token is spent, a read;
  3. the vault's answer about the account;
  4. then, under the head, the account and the binding again, the
     binding's rate, the token spent, the credential issued and
     `token.exchange` logged.
- **Using a credential** (`signin.ts`, `verify`; `secrets.ts`, `reveal`;
  `context.ts`, `recorded`):
  1. its row, unlocked;
  2. the vault's answer, or one kept from an earlier request
     (`accesses.ts`, `accessFor`) at the generation the credential names;
  3. the vault's decision, under the account's row and the head; on a
     kept answer that is no longer the vault's, none: the use starts
     over, asking (`#keys`, `accessRevision`; `AccessChanged`);
  4. through the credential proxy, `credential.use`: appended by the vault
     beside its read, in its decision (`unwrap`'s `use`), and the
     credential then checked again with no lock, as an export's; or,
     with a vault older than 0.14.5, plain values only, or a record too
     long for the vault, by the app,
     under the head, the credential checked again under it;
  5. the value answered.
- **Ending one:**
  - revoking it (`revokeCredential`);
  - untrusting its binding or replacing the issuer's keys (`unbind`,
    `replaceKeys`, `#revoke`);
  - removing the account, the vault's step then the app's sweep
    (`removeMember`), and admitting it again.

| Protection, in the code | Turned off, TLC finds | Found by |
|---|---|---|
| The exchange spends the ID token in the transaction that issues its credential, a primary key on its hash (`exchangeToken`) | one ID token bought two credentials (`SingleUse`) | |
| It reads its binding again under the head (`exchangeStill`) | a credential issued after its binding's `token.unbind` (`NoExchangeAfterUnbind`) | |
| And the account, in the same read (`exchangeStill`) | a credential at a generation a removal had moved past (`ExchangedAtCurrentGeneration`) | |
| The binding's rate is counted under the head, in it too (`exchangeStill`) | more credentials in the minute than the rate (`RateHeld`) | |
| Once the vault has released, the app reads the credential and the member's generation again before it answers (`credentialStill`), under the head when it appends a use of its own (a vault older than 0.14.5, plain values only, or a record too long for the vault) | a value released through a token revoked after it was checked (`NoReleaseAfterEnd`) | this model, fixed with it |
| And with no lock for an export, and for a use the vault appended, which commit nothing more | the same, by an export (`NoReleaseAfterEnd`) | this model, fixed with it |
| Untrusting or replacing a binding revokes the credentials it issued (`#revoke`) | the same, through a credential whose binding was untrusted (`NoReleaseAfterEnd`) | |
| A read on a kept answer is decided only while that is still the vault's answer, under the account's row (`#keys`, `accessRevision`) | a `secret.read` logged on an answer kept from before a removal and an admission (`NoReadOnStaleAnswer`, which states the check itself: a wiring check, as this model carries no grants or policy, what the check is for); the fence still withholds the value, so `NoReleaseAfterEnd` holds without it | |
| That, and each use checking the binding still stands (`bindingStands`): each covers for the other | a credential of an untrusted binding that still verifies (`UnboundStayUnusable`) | |

The race this model found, as the script prints it with the export's fence off. A
run's token is checked (step 5), its revocation commits (6), and the vault,
which decides on the account and is only told the credential, releases
the value (10). Removed and admitted again meanwhile, the account is
active to the vault too, at a generation the token was not issued at.

```
  3. owner     RevokeHead        revoke cred tok            -> revoke.commit   head none -> owner
  5. reader    UseVerify         use cred tok               -> use.access
  6. owner     RevokeCommit      revoke cred tok            -> idle            log +token.revoke cred <<tok, 0>> gen 0 (owner); head owner -> none
  8. reader    UseLock           use cred tok               -> use.head        rowShared +reader
 10. reader    UseDecide         use cred tok               -> use.fence       log +secret.read cred <<tok, 0>> gen 0 (reader); rowShared -reader; head reader -> none
 12. reader    UseAnswer         use cred tok               -> idle
```

### Issuing.tla

Olga and Omar are Owners of a project, where a service account holds a
grant. A token an older release issued the account, by Olga, is not
sealed yet.

- **Issuing a token** (`signin.ts`, `issueServiceToken`; a binding is made
  the same way, `bind`, `replaceKeys`):
  1. the newest entry about the issuer's access, before the vault is asked;
  2. the vault's answers about the issuer and the account;
  3. under the head, both again, then the token.
- **Sealing the older token at its first use** (`services.ts`,
  `sealCredentials`):
  1. the row;
  2. the vault's answer about its issuer;
  3. under the head, the issuer again, then the row, only as read.
- **Changing access, in the vault:** demoting Olga, removing her and
  admitting her again, an Owner again, at a new generation, removing the
  account.

| Protection, in the code | Turned off, TLC finds | Found by |
|---|---|---|
| The issuer is weighed from the vault's answer, read after the newest entry about their access, and committed only while that entry is still the newest (`issuerNow`, `issuerStill`) | a token reading sensitive values issued by someone demoted before it committed (`SensitiveOnlyFromOwners`) | this model, fixed with it |
| And so is a seal's (`sealCredentials`) | the older token sealed reading them, for someone demoted meanwhile (`SensitiveOnlyFromOwners`) | this model, fixed with it |
| Issuing reads the account's standing again under the head (`#stillMember`) | a token at a generation a removal had moved past (`TokensAtCurrentGeneration`) | |
| A seal updates the row only as it read it (`updateAuth`, matched on its scope) | the older token sealed twice (`SealedOnce`) | |
| The vault's answer about the issuer counts only at the generation the request came in at (`issuerNow`), and under the head the request's credential and member still stand at it (`credentialStill`): each covers for the other | a token issued by a membership the request did not come in as, Olga removed and admitted again meanwhile, with what she holds now (`IssuedAsAuthenticated`) | #292's review |

The race it found, with the fence off. Olga's request is weighed as an
Owner's (steps 3 and 4), Omar demotes her (9), and her token commits
reading the project's sensitive values (11). A demotion is no
`policy.change`, so `policyStill` let it through. Before the fix the
request was weighed on the answer its authentication got; the same held
for a binding, and for a seal, where the code said so and let it be.

```
  3. olga      IssueLoad         issue actor olga who svc   -> issue.access
  4. olga      IssueAccess       issue actor olga who svc   -> issue.head
  9. omar      DemoteCommit      demote actor omar who olga -> idle            owners -olga; log +member.role who olga (omar); head omar -> none
 10. olga      IssueHead         issue actor olga who svc   -> issue.commit    head none -> olga
 11. olga      IssueCommit       issue actor olga who svc   -> idle            log +token.create who olga sensitive true (olga); head olga -> none
```

### Bulk.tla

One principal reads, on two credentials at once, with a local key or a
key service, while a clock runs. Each decision counts the distinct keys
of the principal's `secret.read` entries stamped inside the window, with
those it would release (`snapshot.postgres.ts`). The code reads them from
`vault_releases`, which a trigger keeps from those entries in their own
transaction, under the same head: the model's count of the log is what the
table holds.

- **With a local key**, the vault takes the head in the statement that
  counts, right after the row.
- **With a key service**, it counts without the head, opens the keys, then
  counts again in the statement that takes the head.
- **Either way**, that last count is the decision, at its statement's
  clock, which stamps the entries; the commit, and the keys handed over,
  come after it, while the clock runs on.

| Protection, in the code | Turned off, TLC finds |
|---|---|
| With a key service, a read counts again under the head (`#keys`, `late`): the reader's row, which their reads share, orders none of them | two reads, each counted before the other's entries, together past the limit (`CapHolds`) |
| The count takes in the keys the read would release | one read past the limit on its own (`CapHolds`) |
| The count is the principal's, all their credentials' together | two credentials of one principal each up to the limit (`CapHolds`) |
| The entries are stamped with the clock of the statement that counted last | keys released later than their entries say, which leave the window early (`CapHolds`) |

`CapHolds` reads when each decision was, not what its entries say: so a
stamp older than the decision is caught. It holds of decisions. A key
reaches its caller at the commit after its decision, a transaction later,
so a window of releases rather than decisions may hold one more read's
keys at its edge, by that transaction's length: milliseconds, against a
window of fifteen minutes. #292's review.

### Their invariants

| Invariant | What must hold in every state |
|---|---|
| `SingleUse` | An ID token buys one credential, however many runs present it at once |
| `NoExchangeAfterUnbind` | No exchange through a binding follows its `token.unbind` in the log |
| `ExchangedAtCurrentGeneration`, `TokensAtCurrentGeneration` | A credential is issued to an active account, at its generation when it commits |
| `IssuedAsAuthenticated` | And by the membership its request came in as |
| `RateHeld` | A binding issues no more than its rate |
| `NoReleaseAfterEnd` | No value reaches a caller through a credential whose release, the vault's `secret.read`, follows the entry that ended it: its `token.revoke`, its binding's `token.unbind`, or a removal past its generation |
| `UnboundStayUnusable` | A credential an untrusted or replaced binding issued never verifies again |
| `NoReadOnStaleAnswer` | No `secret.read` is logged on an answer of the vault's kept from an earlier request that is no longer its answer |
| `SensitiveOnlyFromOwners` | A scope reads a project's sensitive values only if whoever issued it is an Owner of the project when it commits |
| `SealedOnce` | The older release's token is sealed once, however many first uses race |
| `CapHolds` | At most the limit's keys decided for the principal in any window |

### Their scenarios

| Scenario | Who runs what | States |
|---|---|---|
| `Exchanging` | Two runs present one ID token at once, and each another of its own, while an owner untrusts the binding, replaces its keys, or removes the account and admits it again | 112 thousand |
| `Revoking` | A run reads through its token, by the proxy or an export, and through an exchanged credential, on the vault's answer or one kept from an earlier request, while an owner revokes, untrusts, replaces keys or removes the account, and another admits it again | 162 thousand |
| `Proxying` | A reader uses its token through the credential proxy alone, its use logged by the vault or by the app, while an owner revokes the token or removes the account: each fence shown needed on the proxy's own path | 505 |
| `Issuing` | Olga issues the account a token, twice, while Omar demotes her, removes and admits her again, or removes the account, and two first uses seal the older token at once | 20 thousand |
| `Bulk` | One principal reads two keys of three at most in a window of two ticks, on two credentials, with either kind of key, over three ticks | 12 thousand |

### What they abstract

- **Credentials.tla:**
  - The token's signature, audience, times and claims, which decide
    nothing about concurrency.
  - A binding's tombstone, its `token.unbind` entry, which commits with
    its `revoked_at`: the model reads the latter.
  - The credential's expiry. An exchanged one lasts five minutes, and
    `#revoke` revokes only those not expired by the app's clock. Two
    isolates' clocks apart by more than the time left could leave one
    unrevoked that a use still finds live, which the binding check at use
    refuses. The fence reads `revoked_at` and the generation alone.
  - The credential proxy's cache, which serves a handle's values for up to
    `cacheSeconds` with no check at all (docs/design/credential-proxy.md).
    The model is a use that asks the vault.
- **Issuing.tla:**
  - Who counts as an Owner of the project, a pure function
    (`ownsProject`) of the vault's answer.
  - The policy, which `policyStill` already fences (Coffre.tla's
    discipline, and the roles tests).
  - A grant that lapses by its end time, with no entry, between the
    answer and the commit.
- **Bulk.tla:**
  - The intent a key service's read logs first, which counts the same way
    and releases nothing.
  - The database clock moving backwards, or the window's test offset.

### What they do not prove

- **A write in flight.** A request writes with a credential checked before
  it was revoked, as a read did before the fence. Writes release nothing,
  and the fence is on reads, and on issuing a service account a credential.
- **What a read tells without the vault.** A dry run's comparison of a
  value, and a listing that shows plain values, do not go through
  `recorded`: a credential revoked while one is under way still gets its
  answer, an equality or a plain value.
- **The credential proxy's caches and tunnels.** A revoked handle keeps
  working for `cacheSeconds` from the cache, and a tunnel until its next
  check, as docs/design/credential-proxy.md says: by design, and not
  modelled.

## Workload access

[docs/design/workload-access.md](design/workload-access.md) is a design that
is not built yet. Its section 12.1 asks for its protocol as a model before the
code exists, so that each PR that builds a part has the invariant it must keep
and the protection that keeps it. These four models are of the design, not of
code. Each protection is named by the design's section, and should name its
code once that lands.

- [`formal/Workload.tla`](../formal/Workload.tla): a workload's requests.
  Each one carries a DPoP proof signed by the session's key. It is single use
  through the workload's gate and checked live by one statement. Narrowing
  makes children of a session.
- [`formal/WorkloadEnrollment.tla`](../formal/WorkloadEnrollment.tla):
  enrollment codes. The model covers minting a code and its scope, exchanging
  it up to the capacity, renewing on the database's clock, and promoting the
  next code.
- [`formal/WorkloadTripwire.tla`](../formal/WorkloadTripwire.tla): which
  histories of a code's sessions trip the contention rule.
- [`formal/WorkloadReads.tla`](../formal/WorkloadReads.tla): what a session
  may read, whatever is renamed, referenced or copied.

Their scenarios are in `MCWorkload.tla`, `MCWorkloadEnrollment.tla`,
`MCWorkloadTripwire.tla` and `MCWorkloadReads.tla`, with one configuration
`formal/Workload<Name>.cfg` each.

### Workload.tla

Two workloads, A and B, each a service account with one binding and one
session, `sA` or `sB`, bound to its key. `c` is the child that `narrow` makes
of `sA`, bound to its recipient's key. The attacker, eve, learns every token and
every request that crosses a channel. It holds a key of its own, but no
workload's. Eve's key stands in for a workload's second key: the row's
`jkt` tells it from the session's key just as it would another of the
workload's own.

- **A request** (5.1 to 5.3) takes two steps. The client signs it with the
  gate's newest nonce and sends it, and from then on the attacker holds a
  copy. Then Coffre decides it, in one step:
  1. the statement: the row, its member's generation, its binding, its
     ancestors and the freezes;
  2. the proof's token, key and digest;
  3. a child's constraints;
  4. the gate's admit, one call to one object.

  A renewal is a request too. A freeze does not stop it, since a renewal
  uses nothing (below).
- **The attacker** sends a copy as it was, or one with another body or a
  header added on the way. It may also send a proof of its own key over a
  token it read, or a proof under another session's token. Coffre decides
  each at once, and the original may still be on its way.
- **The gate** restarts, which draws a new epoch and forgets every `jti`, or
  rotates, which keeps the previous epoch's.
- **What ends a session or stops its uses:** a freeze of any target over
  it, revoking it, untrusting its binding, and removing its member, which
  is the vault's step and then the app's sweep. A target is frozen while
  its newest `workload.freeze` or `workload.unfreeze` entry is a freeze
  (8.2), and a lift is one more entry.
- **The tunnel** is opened under the statement. It carries bytes while its
  last good check is less than `Recheck` old: a recheck that has not
  answered by its deadline counts as no. Its rechecks run the statement.

| Protection, in the design | Turned off, TLC finds |
|---|---|
| The proof's key is the row's, `thumbprint(jwk) = row.jkt` (5.1, step 5) | a request accepted under `sA` with a proof by eve's key (`CopyIsUseless`) |
| `req` is recomputed from what arrived (5.1) | a copy with another body forwarded under the original's proof (`ForwardedIsSigned`) |
| Only the headers `hdr` names are forwarded | a header added on the way forwarded upstream (`ForwardedIsSigned`) |
| The gate's nonces are epochs, and `jti`s are kept under them (5.2) | a copy accepted again after the gate restarted (`ProofOnce`) |
| Every request runs the statement before the proxy's value cache (5.3) | a use accepted from a warm cache after its instance was frozen (`FreezeBound`) |
| A tunnel's recheck runs the statement with its freezes (8.2) | tunnel bytes still flowing a recheck after a freeze (`FreezeBound`) |
| The statement compares the row's generation with its member's | a request accepted between the vault's removal and the app's sweep (`RevokeBound`) |
| The statement checks each ancestor (8.4) | the child used after its parent was frozen, revoked or expired; the trace TLC prints is the expiry (`NarrowSubset`) |
| Its expiry included | the child, which narrow gave a longer life, used after its parent stopped renewing and expired (`NarrowSubset`) |
| A child's paths are matched on the resolved URL, and a path holding an encoded `.`, `/` or `\`, a `%25` or a `;` is refused (8.4): each covers for the other on an encoded dot segment | `/v1/refunds/%2e%2e/charges` forwarded to `/v1/charges` for a child of `/v1/refunds` (`NarrowSubset`) |
| The refusal of encoded segments alone | `/v1/refunds/..;/charges`, which resolves under `/v1/refunds` and which Tomcat reads as `/v1/charges`, forwarded (`NarrowSubset`) |
| A child reaches only `/use`, narrow and logout | a child's read or renewal accepted (`NarrowSubset`) |
| A renewal never moves `expires_at` past `not_after` (5.4) | a session renewed past its `not_after` (`NotAfter`) |

### WorkloadEnrollment.tla

The service `api` has one enrollment binding with one replica, and codes
`c1`, `c2` and `c3`. Each step is one SQL statement, as in the other models.
The exchange's commit, a mint and a promote take the head. Renewal does not.
Time is the database's statement clock, and a session is live while its
`expires_at` is ahead of it.

- **The exchange** (4.1, step 7) runs under the head. It checks the code's
  tombstone and counts the code's live roots, then inserts the session and
  `token.exchange`. An instance that enrolls again has restarted, and its old
  session renews no more.
- **Renewal** (4.4, item 1) takes two steps, because the app computes the
  row's MAC. It reads the clock and computes the new expiry. Then it updates
  the row, only as it read it, and only if the row is still live by the
  update's own clock. The tombstone is checked in that same statement.
- **Minting** (4.4) is weighed like issuing a token (`Issuing.tla`). It
  reads the newest entry about the minter's access, then the vault's answer.
  Under the head it checks that entry again and writes the row, whose scope
  is the binding's intersected with the minter's holdings. The scope reads
  sensitive values only if the minter is an Owner, as a person.
- **Promote** (4.4, item 4) runs under the head. It writes one
  `enrollment.supersede` per other code, and with `--now` it also revokes
  their sessions.

| Protection, in the design | Turned off, TLC finds |
|---|---|
| The exchange counts live roots inside its commit, under the head | two exchanges each counting one live root, both admitted: three live roots (`Capacity`) |
| A renewal updates only a row still live at its own statement's clock (`$old > statement_timestamp() + 5s`) | a renewal that read the clock in time, then updated a session the count had already seen as dead: three live roots (`Capacity`) |
| The exchange refuses a code a supersede names | a session made from a superseded code (`Superseded`) |
| So does renewal | a superseded code's session renewed (`Superseded`) |
| Renewal checks the tombstone in its update, after reading the clock | the same, checked in a statement before it (`Superseded`) |
| A session takes its code's scope, not the binding's | a Viewer's code whose session reads sensitive values (`MinterBound`) |
| A code reads sensitive values only from an Owner minter, as a person (R32) | CI's code, which holds sensitive reads itself, reading them (`MinterBound`) |
| The mint is fenced on the minter's access, as issuing is | Omar demoted while their mint was under way, and the code still reading sensitive values (`MinterBound`) |
| The mint and promote routes refuse an enrollment session, and `checkPolicy` refuses a `mintedBy` naming the service itself: each covers for the other | the thief inside the app minting a code of its own (`MinterBound`) |
| They refuse every child | a child of CI's session, which holds only the uses it was narrowed to, minting a code that reads CI's values (`MinterBound`) |

Here is the race behind the renewal's condition, with the condition off.
Instance e1 reads the clock at tick 1, while its session, which expires at
2, is still live. At tick 2 the session has expired, so e3's exchange
counts one live root, e2's, and is admitted (step 14). Then e1's update
lands and revives the session the count saw as dead (15): three live roots.
With TLC's workers, steps that do not depend on each other, such as 10 and
11, may print in either order.

```
 10. e1        RenewClock        renew                      -> renew.update
 11. e2        ExCommit          enroll code c1             -> idle            log +token.exchange code c1 time 1 (e2); sessions +[…, expires 3]
 13.           Tick                                         ->                 now 1 -> 2
 14. e3        ExCommit          enroll code c1             -> idle            log +token.exchange code c1 time 2 (e3); sessions +[…, expires 4]
 15. e1        RenewUpdate       renew                      -> idle            sessions +[code c1, id <<e1, 2>>, …, expires 3]; sessions -[…, expires 2]
```

### WorkloadTripwire.tla

The contention rule (4.4, item 3) is arithmetic over a code's roots, live or
ended. So this model is a timeline rather than a race. The deployment's
instances crash, restart, redeploy with overlap and narrow. A thief holding a
copy of the code enrolls and leaves. After each exchange and each tick, the
rule reads the rows. In `WorkloadLifting`, as the rule runs outside the
exchange's and the renewal's transactions, a run takes steps of its own:
it reads the binding's newest freeze or lift, counts the rows, then
commits its freeze, while a person may lift the freeze. A tick is a
renewal period. A session that stops renewing lives `Life` ticks more, and
the run fits in the rule's hour.

| Protection, in the design | Turned off, TLC finds |
|---|---|
| The excess, `∫ (live − replicas)⁺ dt` over every root, ended ones included | under review r3's rule (the age of the `(replicas + 1)`-th live root), a thief that leaves and enrolls again within the threshold, never frozen (`TripwireFires`, in `WorkloadReenroll`) |
| The count of roots made, more than `4 × replicas` | a thief enrolling and leaving within one renewal, five times, never frozen (`TripwireFires`) |
| Only roots count, never children | a deployment that narrows and redeploys, frozen (`NoFalseContention`) |
| A full code answers `full` | under review r1's rule (admit, and fence the oldest live root): the new instance of a redeploy crashes, its restart is admitted, and the old instance, still serving its requests, is fenced (`NoFalseContention`) |
| A run's freeze commits under the head only while the binding's newest freeze or lift is the one the run read | two runs count the code contended; the first freezes it, Omar lifts the freeze, and the second freezes it again on the history the lift discarded (`LiftHolds`, in `WorkloadLifting`) |
| The run reads that entry before it counts the rows | a run counts the rows, Omar lifts the freeze, and the run then reads the lift: its fence passes, and its freeze stands on the history before the lift (`LiftHolds`, in `WorkloadLifting`) |
| A `full` answer is no signal | under review r2's rule (two `full` in a row freeze), two redeploys refused during a crash's tail freezing the code (`NoFalseContention`) |

The tripwire is not a guarantee, and the model says so. `CopyCaught` states
that every copy that has been in for longer than the threshold is frozen
out. It holds only under an assumption, which is the design's first
evasion, and the model must fail without it. The second evasion, a thief
that stays under both thresholds, is below what `TripwireFires` promises:
the rule freezes nobody under them.

| Assumption | Without it, TLC finds |
|---|---|
| The deployment never leaves a slot free | a replica down, the thief in its slot for longer than the threshold, never frozen (`CopyCaught`) |

### WorkloadReads.tla

`market/prod` holds `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`.
`market/dev` is a fork of it and inherits the first. The binding's `reads`
lists the webhook secret in prod, by ID, and `"*"` in dev. The workload reads
any key of either place, and copies or references one of prod's into dev.
Meanwhile Omar renames prod's keys onto each other's names, deletes and makes
one again, or copies one into dev themselves. No step races another. Each one is
a vault decision that reads its rows under its locks (`Coffre.tla`), so TLC
explores every sequence of them.

| Protection, in the design | Turned off, TLC finds |
|---|---|
| The vault checks `reads` at the place where the value is held: a reference's source, a fork's parent | dev's inherited `STRIPE_SECRET_KEY` read through dev's `"*"` (`NoLaundering`) |
| `reads` holds environment and key IDs | the webhook secret deleted and made again under its name, and the new key read (`NoLaundering`) |
| A workload may not make a reference or a copy from a source it may not read | the workload's copy of `STRIPE_SECRET_KEY` into dev read through dev's `"*"` (`NoLaundering`) |

A person's copy is that person's choice, so the model never counts it as
laundered. A copy the workload made of a value it could not read is
laundered, and so is any copy of that copy.

### Their invariants

| Invariant | What must hold in every state |
|---|---|
| `CopyIsUseless` | Every accepted request was signed by the holder of its session's key |
| `ForwardedIsSigned` | What Coffre forwards upstream (method, path, query, headers, body) is what the key signed |
| `ProofOnce` | No `(jkt, jti)` is accepted twice, across gate restarts |
| `FreezeBound` | No use is accepted once a freeze of its target, or of an ancestor's, has committed, and no tunnel byte flows `Recheck` after it |
| `RevokeBound` | The same for revoking a session or an ancestor, untrusting its binding and removing its member; renewals included |
| `NarrowSubset` | A child's accepted requests are uses that its constraints and every ancestor's allow, on the path sent upstream, while every ancestor lives |
| `NotAfter` | No session is usable, or renewed, past `not_after` |
| `Capacity` | A code has at most `2 × replicas` live roots, under concurrent exchanges and renewals |
| `Superseded` | No session is made from a code once a supersede names it, none renews after, and each of its sessions ends within a session's life of the supersede |
| `MinterBound` | A code, and its sessions, hold no more than its minter held at the mint's commit, a child holding only its narrowed uses, and read sensitive values only if the minter was then an Owner, as a person; no enrollment session mints or promotes |
| `NoFalseContention` | With no foreign holder, the deployment's crashes, restarts, redeploys and children never freeze the code, nor fence a running instance's session, while their excess stays within the threshold and their roots within `4 × replicas` (`WithinOwnBudget`, checked beside it, so a scenario past it fails rather than holding vacuously) |
| `TripwireFires` | A thief whose excess beside the deployment passes the threshold since the newest lift, in any number of sessions with any gaps, or who makes more than `4 × replicas` roots since, has frozen the code |
| `LiftHolds` | Every freeze counts from the newest lift before it: a lift is not undone by the history before it |
| `CopyCaught` | Every copy that has been in, in one session, for longer than the threshold is frozen out, under the assumption above |
| `NoLaundering` | A workload reads a value only if `reads` lists the key, by ID, where the value is held, and the value reached that key through no copy the workload could not read |

### Their scenarios

| Scenario | Who runs what | States |
|---|---|---|
| `WorkloadReplay` | A sends two requests and B one. Eve replays, tampers with, forges and swaps them, and A's gate restarts or rotates | 30 thousand |
| `WorkloadEnding` | A uses its session, renews it and holds a tunnel open. Omar freezes any target over it, revokes it, untrusts its binding or removes the service, and the clock runs to its `not_after` | 175 thousand |
| `WorkloadFreezing` | A uses its session and reads through it, while Omar freezes it, its instance or its credential, and Olga lifts either, in any order | 4 thousand |
| `WorkloadNarrow` | A narrows its session to refunds for an agent, which uses every path, reads and renews. Omar revokes or freezes the parent, or it expires, unrenewed, before the child | 6 thousand |
| `WorkloadCapacity` | Two instances enroll on one code of one replica, renew, restart and log out, and a third enrolls. The clock runs, and CI promotes the next code, with or without `--now` | 471 thousand |
| `WorkloadMinting` | Omar (an Owner), Vic (a Viewer who manages the service) or CI mints a code, while Olga demotes Omar. A thief in the app or in a child mints or promotes, and an instance enrolls on what was minted | 9 thousand |
| `WorkloadDeploys` | One replica crashes once and restarts, trying twice, redeploys twice on its code and narrows once. Nobody else holds the code | 421 thousand |
| `WorkloadThief` | A thief enrolls up to five times beside one replica, leaving whenever it likes, and the replica may crash | 256 thousand |
| `WorkloadReenroll` | A thief enrolls up to three times beside one replica that keeps running, leaving whenever it likes | 3 thousand |
| `WorkloadLifting` | A thief enrolls beside one replica and stays, the rule's runs read, count and commit in steps of their own, and Omar lifts the freeze | 10 thousand |
| `WorkloadCopy` | A thief enrolls beside one replica, which may go down and come back, and may leave | 3 thousand |
| `WorkloadReads` | The workload reads, copies and references, while Omar renames, deletes and remakes, and copies | 10 thousand |

### What the design said, and what the code must follow

- **Found: `NoFalseContention`, as section 12.1 first stated it, does not
  hold.** It said a deployment's crashes and restarts, plus up to two
  same-code redeploys an hour, "each with under half the threshold's excess
  session-minutes", never freeze the code. But a crash's session lives out
  its 90 seconds beside its restart, and that tail is excess too. Take the
  defaults (`replicas: 2`, 30 session-minutes). Two redeploys of 14.9
  session-minutes each, plus one crash's 1.5, make 31.3 and freeze the
  binding. The rule is right; the claim was loose. Section 12.1 now states
  it as the model holds it: the deployment's own excess (each redeploy's
  overlap, and 90 seconds per crash) stays within the threshold, and its
  roots within `4 × replicas`. The 4.4 table's examples (16 session-minutes
  and a crash) are within it.
- **Renewal checks the supersede tombstone in its `UPDATE` statement**,
  after reading the clock, as it checks liveness. Checked in a statement
  before the update, a renewal can commit after the supersede. Checked
  before the clock read, it also extends a session past the 90-second
  drain. This is for PR 3's `PROOFS` `renew.check`.
- **A mint is fenced on the minter's access, as issuing is.** It is weighed
  on the vault's answer read after the newest entry about the minter, and
  commits only while that entry is still the newest (`Issuing.tla`'s
  `issuerNow` and `issuerStill`). The design says only that the scope is
  "fixed at minting, as a token's is"; this is what it means, for PR 3.
- **The renewal statement leaves out the freeze clause.** Renewal is not a
  use, and section 8.2 says a freeze keeps the sessions, so that a lift
  restores service without a redeploy. If renewal checked freezes, every
  enrollment session would die 90 seconds into a freeze, and a lift would
  restore nothing. Section 5.4 now says so. PR 1a implements renewal this
  way, and PR 5's SDK can count on it.
- **Found: the tripwire's freeze must be fenced on the lift.** The rule runs
  after an exchange or a renewal, outside their transactions. Two runs can
  each count the code contended before either freezes it. The first
  freezes it, a person lifts the freeze, and the second, which counted the
  hour before the lift, freezes it again: section 4.4's "a lift is not
  undone by the same hour's history" fails. With `replicas: 2` a run starts
  every 15 seconds or so, so every lift has the window. Section 4.4 now
  says the run reads the binding's newest freeze or lift before it counts
  the rows, from that lift, and its freeze commits under the head only
  while that entry is still the newest (the shape of `MinterFence`). Read
  after the rows, a lift between the two reads passes the fence. A run on
  a frozen binding does nothing. This is for PR 3.
- **A tunnel stops when its last good check is older than its recheck
  interval**, even if no recheck ran, so a late recheck cannot keep bytes
  flowing. This is for PR 1d.

### What they abstract

- **Cryptography.** Signatures cannot be forged: a proof's key is whoever
  signed it. Thumbprints and digests are injective, and `req` is the signed
  request's fields compared as they are. The encodings (`htu`'s
  normalization, `canonicalRequest`, the path's escapes) are property tests
  (section 12.1), not modelled. Paths are four values: `refunds`,
  `charges`, `dotdot` (`/v1/refunds/%2e%2e/charges`), which starts with
  refunds as received and resolves to charges, and `semi`
  (`/v1/refunds/..;/charges`), which resolves under refunds and which the
  upstream reads as charges.
- **Platform proofs.** Nobody exchanges a copied platform token here.
  Spending a bearer ID token once is `Credentials.tla`'s `SingleUse`, in
  `Exchanging`. An audience or `x-coffre-key` that names the key binds the
  proof to that key cryptographically, as the proof's signature does here.
  Keeping workload bindings out of `/api/auth/oidc` is a static match on the
  binding's policy (4.1), with nothing to interleave.
- **The gate.** Its `iat` window, its ceiling and its counters (8.1) are
  left out. Several Node processes, each with a gate of its own, are a
  restart to a proof: its nonce names an epoch the other gate never drew.
- **The cache.** It matters only when the statement is skipped. A grant
  lost within `cacheSeconds` is by design, and not modelled.
- **Enrollment.**
  - The renewal's 5-second margin covers an `UPDATE` that starts before the
    expiry and runs after it, for instance behind a row lock. The model runs
    each statement at the clock it reads, so it assumes that delay stays
    under the margin.
  - A renewal's `UPDATE` whose snapshot predates a promote may commit just
    after it: the promote takes the head, renewal does not, and without
    `--now` the promote writes no session row. So "none renews after" and
    the drain hold up to the promote transaction's length, milliseconds.
  - `approve` and `pending` are left out, and so are `sources`, which is a
    per-request check like a freeze, and the alerts.
  - Children are no slot, so they are left out of the count, and the
    tripwire model holds the rule to that.
- **The tripwire.** One replica, time in renewal periods, and a run shorter
  than the hour, which counts from the newest lift. Only `WorkloadLifting`
lifts, and only there do the rule's runs commit after they count.
- **Reads.** One binding and two places. A deleted key's ID is never used
  again. With every protection on, the vault's check and the invariant's
  truth are close to the same expression, so what this model shows is in
  its removals. A fork's inherited key is a row
  that resolves to its parent's, as a reference does. R32's `sensitive` on
  a listed key is `MinterBound`'s and `Issuing.tla`'s concern.

### What they do not prove

- **That the code will be the model.** None of it is built. Each PR that
  builds a part should name its functions in the switch's comment, and
  change the model when it changes a check.
- **Column G2.** A taken-over app authenticates whomever it likes, and the
  vault trusts its scope (section 3). The models start from Coffre's own
  code.
- **Liveness.** They do not prove that the SDK renews in time, that the gate
  rotates, or that a thief is ever caught beyond `CopyCaught`'s
  assumptions.
- **The platforms.** STS, Kubernetes, Railway's addresses and Cloudflare's
  `props` are trust roots (section 3), which the PRs check live.

## The audit chain, the app key and the tunnel

Three more, with the same discipline: the chain's verification against
someone who writes the database, the app key's rotation against someone
who holds the old key, and how long a revoked handle's tunnel session
lives.

### Audit.tla

The chain's verification against someone who can write the database and
holds no key. They edit an entry in place, heartbeat rows among them, and
put it back, as often as their budget allows, or rewrite one and chain
everything after it again, the head row too. An entry's hash is
abstracted to the chain's version where it is: a rewrite moves every
entry from there on to a new one. An entry's MAC binds its content and
the hash before it, so one rewritten, or after one, fails it, unless it
was appended after the rewrite. An edit leaves the stored hash, and only
recomputing it finds the edit. The vault's scrub runs in a snapshot of
its own, so it is one step. The vault's checkpoint and the app's walks
run in no transaction, a batch a statement, so as to hold no connection
while they rehash. The checkpoint's walk is an entry a step, each linked
to the one before as the walk read it, finer than the code's batches.
The app's walks, in `Tampering`, where the log is rewritten and edited
while they walk, are a step after the anchor's prefix is read, then two
entries a step, each batch linked to the hash computed last
(`AppWalkSteps`, `AppBatch`); in the scenarios about beats and the anchor
racing each other, one step, as in a snapshot, which keeps their state
spaces as they were.

The anchor (`anchor.ts`) is out of their reach: one variable, which a
beat, or a walk between beats, writes by compare-and-set, a step. It holds the newest checkpoint a
beat saw, where its prefix ends and its hash; how far the app verified;
the entry a walk found, or that the vault refused; and the beat that
wrote it.

- **A heartbeat** (`plugins/audit-watch.ts`, `beat`):
  1. the anchor, read;
  2. the beat's row, under the head;
  3. the vault's checkpoint, below, which returns the prefix it signed, or
     the newest one, or a refusal;
  4. the anchor's prefix still there, by its hash, and no longer than
     the one the vault returned (`AnchorHeld`), then, in no transaction,
     the walk from where the app verified to, toward that prefix, at most
     `CHAIN_WALK` entries, each link and hash and the app's MACs, ending
     at the hash the vault signed; a finding of the app's that stands is
     checked alone instead, its entry, until it verifies again;
  5. the anchor written, over the record read in step 1 (`AnchorCas`). If
     a walk between beats wrote it first, toward the same checkpoint, the
     beat reads that record and goes again from step 4, as it would had
     it read that record in step 1 (`BeatRetries`); any other record
     written first, and it writes nothing.
- **A walk between beats** (`plugins/audit-watch.ts`, `walkOn`; the
  Durable Object's alarm, Node's job): an anchor with a backlog read, the
  walk of step 4 toward its own checkpoint, and the anchor written over
  that record, its beat and age unchanged.
- **A checkpoint** (`vault.ts`, `checkpoint`), as before the anchor:
  1. in a snapshot, where it resumes, the newest one, its prefix still
     holding its hash; then the walk on from there, in no transaction, at
     most `walks.checkpoint` entries, each link and hash, and the vault's
     MACs;
  2. a stretch of the scrub in another, each hash of the signed prefix
     recomputed;
  3. under the head, whether another call checkpointed or refused
     meanwhile, the prefixes still holding their hashes, then, if the walk
     reached the head, the rest walked and the head signed, or else where
     the walk got to, behind it, unless another call signed as far;
  4. a refusal's entry, in a transaction of its own.
- **Readiness** (`plugins/audit-watch.ts`, `readiness`): the anchor, then, in another read,
  the log's entry at its checkpoint, by its hash (`ReadinessChecksHeld`).

Why that is enough. Readiness vouches for the prefix the anchor's
checkpoint signed, and only once the app verified through it: every
entry of it was walked by one beat or walk or another, each from where
the one before ended, which the anchor keeps and nobody else can move. A
rewrite inside it, the chain after it hashed again, changes the hash at
its end, which readiness reads. A finding
leaves the anchor where it was, and stands in it until the entry it names
verifies again; then the walk goes on from where the anchor was, over that
entry and on. Two beats at once: the one that writes second named a record
no longer stored, and writes nothing; one that a walk between beats
overtook walks again from that walk's record, which holds its checkpoint. What is past the anchor is the next
beat's: readiness says nothing of it.

| Protection, in the code | Turned off, TLC finds | Found by |
|---|---|---|
| A beat's walk checks each app entry's MAC (`walkChain`, `verifyEntries`) | readiness green over a rewrite of app entries the vault cannot check (`GreenIsReal`) | |
| A checkpoint's walk checks the vault's MACs, and under the head the prefix signed last (`rehash`, `carries`) | a prefix signed over a vault entry chained after a rewrite (`SignsNoForgedVault`) | |
| The checkpoint's walk, in no transaction, links each batch to the hash it verified last (`rehash`, `startPrevHash`) | a prefix signed over a vault entry the log was rewritten from while the walk read it (`SignsNoForgedVault`) | |
| Under the head, a call that another overtook signs nothing, and a refusal since the last checkpoint stands (`seen`, `#standingRefusal`) | a checkpoint signed after a refusal for a tamper the vault can find (`StaysUnsignedOnceFound`) | |
| Under the head, while a refusal stands, a call whose walk began after the entry it names checks that entry again: its hash, its link, the vault's MAC (`#entryHolds`) | three checkpoints at once: one signs past an entry edited after it walked it, another refuses for that entry, and a third resumes from the first's checkpoint and signs, never reading the entry (`StaysUnsignedOnceFound`, in `Overtaking`) | this model, T104 |
| The scrub recomputes the signed prefix's hashes (`#scrub`, `relink`) | an entry edited in place, signed over again and again (`EditFoundByNextScrub`) | |
| Readiness checks that the log still holds the anchor's prefix (`readiness`, `holds`) | green after a rewrite behind the anchor, until the next beat (`GreenIsReal`) | |
| A beat writes the anchor over the record it read, by compare-and-set (`AnchorStore.write`, `admits`) | two beats at once: the one that checkpointed first writes last, and moves the anchor back (`AnchorNeverBack`); or the one that walked before an edit writes a clean anchor over the finding of the one that found it (`FoundEditStaysRed`, in `Overtaking`); a walk between beats writes how far it got over a beat's later checkpoint (`AnchorNeverBack`, in `Walking`) | this model |

Three protections the code keeps are not needed in the model: the beat's
walk checking that the anchor's prefix is still there, that the entry
it goes on from still has its hash, and that each batch links to the
hash it computed last (`AnchorHeld`, `WalkChecksFrom`, `AppLinksWalk`).
Turned off, alone or together, every scenario still holds: the vault's
own check refuses to sign over a rewrite of the prefix it signed last,
readiness reads the anchor's hash, and a walk ends at the hash the vault
signed, after the app's MACs of every entry it read. They matter where the model does
not go: a vault started again after the log was cut back below its
newest checkpoint, which then resumes from an older one still in the log
and signs the shorter log afresh (`audit-watch.test.ts`, "a log cut back
below the anchor").

What it does not claim, as the code does not:

- **The vault signs over app entries it cannot check.** A rewrite of the
  app's entries alone, past the last vault entry, is signed. The beat's
  walk finds it and the anchor keeps the finding (`FoundEditStaysRed`).
- **A refusal of the vault's stands only until it signs again.** A call
  whose walk began after the entry a refusal names checks that entry again
  under the head, as the walk checks each, and refuses while it is broken
  (T104). Two refusals this holds no further: one that names no entry, a
  prefix not the one signed or a head not naming the last entry, which a
  call's own checks find again only where they reach (the hash of the
  prefix it resumes from, and the head); and a lap of the scrub ending on
  a hash other than the one signed, whose entry, on its own, holds. The
  next signature clears either, and the scrub finds the change again
  within two laps.
- **A rewrite that stops short of the anchor's checkpoint.** The model's
  rewrite hashes the chain again to the head. One of entries 400 to 499,
  each hashed again, under a checkpoint at 500, leaves 500's hash, which
  readiness reads, and breaks 500's link to 499, which no beat walks
  again: the scrub, which links each entry to the one before, finds it
  within two laps, as it does an edit in place.
- **An edit made between a checkpoint's walk and its signature is signed
  over.** The scrub finds it: here, with a scrub of the whole prefix a
  call, at the next checkpoint; in the code, with `walks.scrub` entries a
  call, within two laps.
- **A walk cut short.** A walk reads at most `CHAIN_WALK` entries; one cut
  short keeps how far it got in the anchor, which readiness reads as red,
  and the next goes on from there. The model's walks are four entries, six
  in `Repair`, where the beats must outrun the two entries each adds.
- **Cutting the log.** The model's attacker edits and rewrites, and does
  not delete: a cut is the tests' (`audit-watch.test.ts`, "a cut tail is red
  at once", "a log cut back below the anchor"). The entries written since
  the last beat are a window a cut takes unseen.
- **An empty store, and an Owner's acceptance.** The scenarios start
  from an anchor. A store found empty is re-anchored by a walk of the
  whole log, readiness green meanwhile (Erwin, 2026-10-24): over that
  window `GreenIsReal` does not hold by design, since nothing yet vouches
  for the prefix, and a cut made before the store emptied is never seen.
  An Owner's acceptance of lost entries moves the anchor back in a new
  epoch. Neither is modelled; both are the tests' (`audit-watch.test.ts`).
- **The anchor's own store.** Its compare-and-set is one step here; a
  store with weak access control is tamper-evident by the app's MAC and
  the vault's signature, and only its own compare-and-set and monotonic
  rule (`admits`) keep an older record from being put back.

### Tunnel.tla

How long a revoked handle's tunnel session lives
(`credential-proxy.ts`, `watch`). One group's timer asks again every
`recheckSeconds`, R, one check at a time, and a check that has not
answered by its deadline, D = min(R, 10 s), is a no. A watchdog ends the
sessions once the newest check that answered yes, or the admission,
started R + D ago. Timers due at the same tick fire in any order, and a
check may take any time or never answer.

| Protection, in the code | Turned off, TLC finds | Found by |
|---|---|---|
| A check that has not answered by its deadline is a no (`late`), and the watchdog (`arm`): each covers for the other | a session open forever behind a check that never answers (`EndsWithinBound`) | |
| The deadline | without it, a yes that comes late, the timer skipped meanwhile, and the watchdog ends a session whose handle stands (`StandingStaysOpen`, in `TunnelShort`) | |

The bound is R + D, and no shorter. With the deadline alone, TLC finds a
session still open R + D ticks after its revocation, none later: the
handle is revoked just after a check, the next comes R later and takes
its whole deadline. With a bound of R + D − 1 that run fails. A watchdog
shorter than R + D ends sessions whose handle stands. Both hold with
R = 4 and D = 2 (`Tunnel`) and R = D = 3 (`TunnelShort`). By default
that is 70 seconds, not the minute the proxy's documentation said, which
now says so.

A check that is under way when the timer fires skips that tick. #296
first kept it (`due`), when a tick skipped at the deadline could leave a
session open 2R + D. Since #308 a check's deadline is at most its
interval, and the watchdog bounds the session on its own: a tick falls
during a check only as that check times out, which ends the group. TLC,
which puts the deadline and the next tick on one tick, finds nothing that
keeping it changes, so the code does not. In the code the deadline's timer
starts just after the check does, so with D = R a yes inside that gap
skips a tick, and the watchdog can end a session whose handle stands: an
availability edge, not a bound, which `StandingStaysOpen` does not see.

### AppKey.tla

The app key's rotation (`key-rotation.ts`). Starts under the new key B
step it, each step one transaction under the log's head that reads where
the rotation stands, signs the next row again under B if the old key A
signed it, and appends its `key.reseal`; once no row is left, a step of
its own appends `key.rotate` (`finishRotation`).
Beside them, an instance still under A writes a row and its entry under
the head, as during a deploy, and someone who holds A and can write the
database writes rows and entries under A past every check, at any moment.
A row is its MAC's key and who wrote what it says; one row a step.

| Protection, in the code | Turned off, TLC finds |
|---|---|
| A step reads where the rotation stands under the head (`rotateStep` and `finishRotation`, `keyState(tx)` after `lockLogHead`) | two starts that each read the last row before the other's step write `key.rotate` twice (`OneRotate`); and a start that read the rotation under way signs under B, after `key.rotate`, a row someone wrote under A since (`NoLaunderingAfterRotate`) |
| An append under a key the log names as moved from refuses (`appendEntries`, `KeyRetired`) | the instance under A writes an entry after the first step (`OldKeyWritesNothingAfter`), and a row the step had passed, left under A once rotated (`RotationComplete`) |
| A verification takes A's entries only before the first step (`appVerifier`) | an entry forged under A after the first step verifies (`NothingForgedAccepted`) |

What it does not cover: a row forged under A before `key.rotate` is
signed again with the rest, as the rotation cannot tell it from the
instance's own, so a leaked key's window for rows closes at `key.rotate`,
and for entries at the first step; an instance under A that changes a
row without the head, as no audited write does, may lose that change. The
anchor, outside the database, is sealed again by compare-and-set before
`key.rotate`, as `Audit.tla` models its writes, and not modelled here.

### Their invariants

| Invariant | What must hold in every state |
|---|---|
| `OneRotate` | However many starts step the rotation at once, the log holds one `key.rotate` |
| `NoLaunderingAfterRotate` | No row written under the old key after `key.rotate` is ever signed under the new one |
| `OldKeyWritesNothingAfter` | An instance under the old key appends no entry from the rotation's first step on |
| `RotationComplete` | Once rotated, a row under the old key alone is one someone forged past the checks |
| `NothingForgedAccepted` | No entry forged under the old key from the first step on verifies |
| `SignsNoForgedVault` | The vault never signs a prefix holding an entry of its own rewritten, or chained after a rewrite |
| `StaysUnsignedOnceFound` | Once a checkpoint was refused for a broken log, none is signed while the vault could find the tamper |
| `FoundEditStaysRed` | Against someone who edits, reverts and edits again, any entry, heartbeat rows among them: while an edit a beat wrote to the anchor is still in place, readiness is red. Edited again after a revert, it is a new edit behind the anchor, which the scrub finds (`EditFoundByNextScrub`) |
| `EditFoundByNextScrub` | An entry edited in place is signed over by one checkpoint in flight at most, with a scrub of the whole prefix a call, as in `Tampering` |
| `GreenIsReal` | Readiness, read as a monitor asks it, the anchor then the log, never vouches for a prefix holding an entry rewritten or chained after a rewrite |
| `AnchorNeverBack` | The anchor's checkpoint and the app's progress never move back |
| `RepairGoesGreen` | In `Repair`, once the edit is put back and five beats have walked with no edit in place, readiness is green |
| `EndsWithinBound` | A revoked handle's tunnel session ends within R + D of its revocation |
| `StandingStaysOpen` | A session whose handle stands stays open while every check answers before its deadline |

### Their scenarios

| Scenario | Who runs what | States |
|---|---|---|
| `Tampering` | From an entry of each author, a beat, a checkpoint and the anchor: a request appends, two heartbeats run at once with their checkpoints, someone edits an entry in place or rewrites the chain from one, and a monitor asks | 16.6 million |
| `Readiness` | Requests append while two heartbeats, whose walks cover less than the log, run at once, and a monitor asks | 249 thousand |
| `Overtaking` | Three heartbeats at once while someone edits an entry past the anchor, the first beat's row or its checkpoint's, with a scrub of one entry a call | 4.6 million |
| `Rows` | Someone edits and puts back any entry, heartbeat rows among them, twice, at any step, while two beats run and a monitor asks | 2.0 million |
| `Walking` | From a checkpoint past a backlog of four entries: walks between beats go on with it, two entries a walk, while two beats run at once, someone edits an entry in the backlog, and a monitor asks | 2.4 million |
| `Repair` | From the anchor's finding of an edited entry, more than a walk behind the head: someone puts it back when they like, while beats run one after another | 1,063 |
| `Tunnel` | A check every 4 ticks, each with 2 to answer, the handle revoked at any tick | 1 thousand |
| `TunnelShort` | The same, with as long to answer as between checks | 2 thousand |
| `AppKeyRotation` | Two starts under the new key step a rotation of two rows at once, while an instance under the old key writes a row, and someone who holds it writes rows and an entry under it | 146 thousand |

## 0.15: the hot path, sealing and the cutover

0.15 rewrites the vault, its access decisions and the audit log (R35). Under
R45 the spec comes first: these three models are written before the code,
which follows them PR by PR ([0.15-plan.md](design/0.15-plan.md)). The design and
its measurements are in [hot-path-one.md](design/hot-path-one.md) and
[merkle-checkpoints.md](design/merkle-checkpoints.md).

Three things in `scripts/formal.sh` came with them:

- **A removal may set a constant to a value.** A token `Name=Value` (no
  spaces) sets the constant to that value instead of turning a protection
  from TRUE to FALSE. `Unsealed={"credential"}`, for example, leaves one of
  HotPathOne's inputs unsealed.
- **A removal may break a temporal property** that the scenario lists under
  `PROPERTIES`. That property is then checked alone, and TLC must report it
  violated.
- **`EXPECTED` lists what a design leaves open.** TLC must find each of these
  broken with every protection on: the window the design documents.

### HotPathOne.tla

W208's one call per use, with W211's round 2 and review r1, in one module
(the plan's PRs 3 to 5).

**The protocol.**
- **A use** takes the fence shared, then, in one statement, reads its inputs
  and each input's newest change, and inserts its entry, numbered under the
  lock.
- **A change** takes the fence exclusive. It writes only if its object's row
  is still what it read (a CAS); refused, it reads again.
- **The model also covers:**
  - per-isolate covers and the seal cache;
  - Postgres crashes and restores;
  - a database writer who puts back earlier, validly sealed rows;
  - the checkpointer's barrier and the floor of `at`;
  - the deadline, with Hyperdrive holding calls;
  - the bulk cap, its count from a sealed policy input.

Each scenario switches on what it needs. `Inputs` is any set, and `Unsealed`
(normally `{}`) names inputs left unsealed, so a removal can unseal one.

| protection | turned off, TLC finds |
|---|---|
| uses take the fence shared; their reads are a statement after the lock (never a bare CTE) | `TotalOrder`, `ReplayAgrees`, `NothingAllowedAfterAnswer` |
| numbers taken under the lock; the lock goes with the commit | `TotalOrder`, `CheckpointsHold`, `NothingAllowedAfterAnswer` |
| changes take the fence exclusive and answer once committed | `TotalOrder`, `NothingAllowedAfterAnswer` |
| a value leaves only after its entry commits, durably | `DurableBeforeRelease`, `NothingAllowedAfterAnswer` |
| the barrier under the fence exclusive; the floor of `at` | `CheckpointsHold` |
| the barrier checks the floor is the one it last wrote (BarrierChecksFloor), against a writer who lowers it. The model shows the barrier signing nothing past a lowered floor; the alarm PR 6 raises is not modelled | `CheckpointsHold` |
| each input sealed (`Unsealed={"credential"}` …) | `ReplaySound`: allowed live, refused by the replay |
| seals checked before what the rows say (StaleFirst) | `TamperVisible` |
| the seal cache valid only while the newest change is the one it was read at (CacheChecked, CacheSameChange) | `ReplaySound`, `RepeatsAreTheirCover`, after a restore |
| covers see a change to any input; and need their entry (CoverExists) | `RepeatsAreTheirCover`, `DurableBeforeRelease` |
| a change's CAS on its object's seal (ChangeCAS) | `EachChangeFlips` |
| a change refuses a base row that is not its object's newest change (ChangeChecksSeal): a CAS alone passes a row a writer put back, and the change would re-seal the rollback | `EachChangeFlips`, `ReplaySound` |
| the deadline checked in Postgres; the Worker's answer at it | `NoLateWork`, `ReleaseByDeadline` |
| new and stale keys under the principal's lock; refresh on use; covers only while fresh; the refresh's and the deadline's slack | `BulkCapHolds`, `BulkReplayAgrees` |
| the cap's count and window from the policy read in the use's snapshot (CapFromPolicy), and from its newest change, not its row (CapSealed); HotPathOnePolicyWindow flips the window alone | `BulkReplayAgrees` |

**HotPathOneStaleBulk** checks the two halves together: a use refused
`stale` still moves the cap's row exactly as the replay does, and a repeat
after a change is logged again and counted.

**Liveness** (`HotPathOneLive`, `FairSpec`: weak fairness on every protocol
step and on the clock; failures, crashes, tampering and restores are
bounded):
- `UseAnswered`: every use that arrives is answered (a value, a refusal or
  a 503). Without the Worker's answer at its deadline, a call Hyperdrive
  holds is never answered.
- `ChangeAnswered`: every change that starts is answered. Without re-reading
  after a refused CAS, it retries the same stale read forever.

**Left to benches, not TLC:**
- latencies;
- how fast a 503 comes;
- a change's wait for the uses in flight;
- sealing within a tick;
- that an endless stream of uses never starves a change. Postgres queues
  an exclusive lock ahead of later shared ones; the model does not.

**What it abstracts.**
- One principal and one isolate (covers and the seal cache are each checked
  against the log, so more isolates add no new interleaving), and two or
  three uses.
- A writer that forges no seal. The rows that are not decision inputs
  (`bulk`, the floor) are unsigned. A writer who lowers the floor is caught
  by the barrier's check. One who resets the cap's rows is seen only by the
  replay: no invariant holds the live `bulk` rows against a writer.
- The tree reduced to sets of numbers (Seal.tla checks the tree).
- **Request ids:** each use is a distinct request. A retry that repeats its
  request id, the unique `(at, request id)` index, and "a retry never
  decides again" are not in the model. PRs 4 and 5 test them on Postgres.
- **Time in covers:** a cover is ended only by a change, a missing entry or
  a stale bulk row. Its window and the credential's expiry are not in the
  model, and are tested on Postgres.
- **A use's `at` from above:** the model bounds a Worker's skew to a tick,
  so no use is stamped past where a proof looks for it. On Postgres,
  `use_credential` refuses one stamped over a minute past the database's
  clock (`ahead`, 0022_log_015), tested in `packages/db/test/log-guarantees.sql`.
  A refused request is not logged, so no invariant over entries sees it.

### Seal.tla

W209's sealing of the log into Merkle checkpoints, with W212's shape: two
growing trees, changes (kept for good) and uses (dropped by day), signed at
one `upto` by each tick, as one pair.

**The parties.**
- **Appends** take their number under the fence's shared lock.
- **The checkpointer** takes the lock exclusively to close a window, seals it
  into both trees, remembers the pair outside the database (the signer's
  memory), writes both rows, and queues the pair for a witness.
- **A crash** can fall between any two steps.
- **An attacker** with write access to the database and no key can delete,
  forge, replay, swap or move entries (a change into the uses partition),
  and delete one tree's row or a whole pair.

| protection | turned off, TLC finds |
|---|---|
| the number taken under the lock; the window closed under it exclusively | `Complete` |
| the signer remembers a pair before writing it (RememberFirst) | `SealedDeletionDetected`, `SplitViewDetected` |
| the signer's memory, outside the database | `SealedDeletionDetected`, `SplitViewDetected`, `AnsweredChangeKept` |
| each tick checks the database's newest rows against its memory (RowChecked) | `SealedDeletionDetected` |
| MACs checked before sealing; request IDs checked by the verifier | `NoForgerySealed`, `NoUndetectedReplay` |
| a change answers only once sealed and, with one, witnessed (WaitForSeal) | `AnsweredChangeKept` |
| both rows in one statement (PairWrittenTogether) | `PairConsistent`, `NoFalseAlarm` |
| both notes remembered in one record (PairRemembered) | `PairConsistent` |
| each tree's newest row checked, at each tick or by the verifier (PairChecked + PairVerified) | `SealedDeletionDetected` |
| the kind under the entry's MAC (KindInMac) | `KindKept`: a moved change is sealed into the uses tree |

`EXPECTED`:
- **The window R51 accepts.** Deleting or reordering an entry before it is
  sealed is not detected.
- **The witness without the signer's memory** (SealPlugin). A crash between
  writing a pair and publishing it leaves deletions and split views
  undetected.
- **The unwitnessed answer.** `WaitForSeal` models a change that answers only
  once sealed and witnessed. R51 lets a change answer unwitnessed after 2 s,
  recorded and alerted. An answered change can then be deleted before it is
  published, and stay undetected: the same window as SealPlugin's.
  `AnsweredChangeKept` does not cover it.

**What TLC found against W212's rules.**
- The tick's check must read each tree's newest row: one "newest row" query
  across both is unsafe.
- `open()` need not refuse rows at different `upto`s. It checks each tree
  against the one remembered pair, and can repair a half-written pair.

### Migration015.tla

The cutover from 0.14 (the plan's PR 9).

**The model.** One object (a member and its grants) with:
- 0.14's row (its MAC and `access_seq`) and chain;
- an old isolate still serving 0.14 uses and writes after the deploy;
- two 0.15 vault starts, at once or one after the other;
- a 0.15 use, a 0.15 change, and checkpointer ticks;
- in its Tamper and Drops scenarios, a writer who puts rows back, forges a
  0.14 entry, drops 0.14's newest entry, or clears a marker.

| protection | turned off, TLC finds |
|---|---|
| the cutover under the 0.15 fence (and 0.14's head) | `OneCutover` |
| the cutover marker | `OneCutover` |
| the cutover checks each row as 0.14's `#integrity` does (VerifyRows) | `NewLogFollowsOld`, `AllowedOnlyWhenGranted` |
| 0.14's chain verified up to the anchor | `AnchorHolds` |
| 0.15 changes also advance 0.14's fence (DualFence) | `NothingAllowedAfterAnswer` |
| a trigger takes the 0.15 fence for each 0.14 access change (OldWritesFence) | `NothingAllowedAfterAnswer` |
| 0.14's head before the 0.15 fence (ChangeHeadFirst) | `NoWaitCycle` |
| the object's member row before 0.14's head (RowFirst): 0.14 takes rows before its head, so the order is row, head, fence | `NoWaitCycle` |
| adoption, at every tick | `EveryOldWriteAdopted` |
| adoption verifies the entry and seals what it wrote | `NewLogFollowsOld`, `AllowedOnlyWhenGranted` |
| adoption only after the newest seal's 0.14 entry (AdoptAfterSeal) | `NewChangesStand` |
| a 0.15 use reads the object's newest 0.14 access entry (UsesSeeOldWrites) | `AllowedOnlyWhenGranted` |
| a row marker in place of that read (Migration015Marker) | `AllowedOnlyWhenGranted`, and it fails as soon as the writer clears it |

**Not modelled:** 0.14 uses after the cutover. They stay in 0.14's own chain,
which the cutover anchors.

## TLC

[TLC](https://github.com/tlaplus/tlaplus) is the TLA+ tools' explicit-state
model checker. It explores breadth first, so every counterexample is a
shortest one.

- **Version:** `tla2tools.jar` 1.7.4, released 2024-08-05, the latest
  stable release. It is one jar with no dependencies, pinned in
  `scripts/formal.sh` by SHA-256 and checked before every use.
- **Not 1.8.0:** that tag is a prerelease, rebuilt nightly, which no pin
  would hold.
- **Java:** TLC needs Java 11 or newer. CI pins an exact Temurin build with
  `actions/setup-java` (17.0.9+9, in `validate.yml`'s plan and shard jobs
  alike): the key hashes the JVM, and GitHub's `ubuntu-24.04` image rolls out
  over days, so two jobs of one run could land on images with other Java
  builds and disagree (seen on #379). Bump the version in both places.
- **Other tools considered:**
  - Apalache checks symbolically, by trace length, and is much larger.
  - Quint's simulator samples traces rather than covering every one, and
    its exhaustive mode downloads Apalache at run time.

### In CI

Before 0.15's models, run in order, the 125 TLC runs took 22 minutes, twice
the tests. As three shards they took about 11 (Tampering's), as long as the
tests do; skipped, seconds. With 0.15's models the suite is 239 TLC runs in
nine shards; the six new ones are 0.15's. On a shared host with 4 workers,
each new one takes about 5 minutes. CI's runners took about twice as long:
in its first CI run, Tampering took 10.7 minutes (6.4 here) and the bulk
shards 10.9 (5.8 and 5.5 here).

| shard | wall time here, 4 workers | CPU time | on CI |
|---|---|---|---|
| hotpath | 5.4 min | 25 min | about 11 min (estimated) |
| hotpath-policy | 5.3 min | 24 min | about 11 min (estimated) |
| hotpath-bulk | 5.8 min | 31 min | 10.9 min (measured) |
| hotpath-skew | 5.4 min | 29 min | 11.0 min (measured) |
| seal | 4.9 min | 23 min | about 10 min (estimated) |
| seal-plugin | 5.8 min | 29 min | about 12 min (estimated) |

Two things cut that, and `Formal model` is still the one job `Validate` asks about, on
every pull request that is not a version-only bump:

- **A green run of the same inputs is not run again.** TLC's answer depends
  on what it is given and nothing else, so `Formal model plan` hashes that,
  [`scripts/formal-key.sh`](../scripts/formal-key.sh): `formal/*.tla` and
  `formal/*.cfg` (all `formal.sh` copies; the Lean proofs are
  `formal-lean`'s), `formal.sh` itself, which pins TLC's jar by checksum,
  `formal-trace.mjs`, the workflow, and the job's Java (vendor and exact
  build, pinned by the workflow). A full green run saves that key, with its run id, in Actions' cache,
  only after every shard has held. The next run of a key that has one logs
  "TLC skipped" with the key and the run that held, and finishes in
  seconds. The plan reads the repository's whole cache list, not a restore,
  which would see only the pull request's own and `main`'s: a model merged
  from a pull request is a hit for the next. GitHub drops a cache a week
  after it was made, so after a quiet week the first run is a full one. To
  trust nothing, label the pull request `full-formal` and re-run the plan.
  A cache counts only if the run it names is one of
  `validate.yml`'s, at a commit whose model, script and workflow files are
  the ones hashed, and its *Formal model* job ran the step named for that
  key and run, which only happens after every shard held; each shard
  checks that its own Java gives the plan's key. Anyone who can push a
  branch could already make `Validate` pass by editing the workflow in their
  own pull request, so this guards against mistakes and stale answers, not
  against them.
- **A run is nine jobs in parallel.** `scripts/formal.sh --shard
  <name>` runs the scenarios of one
  (`shard_of`), each with its runs without a protection, balanced by what
  they took:
  - Tampering's 7 to 11 minutes (17.5 million states) alone;
  - Overtaking, Walking, Sharing, Rows and Mixed together;
  - 0.15's models in six:
    - `hotpath`;
    - `hotpath-policy` (the policy, liveness and stale-bulk scenarios);
    - `hotpath-bulk` (the bulk cap's main scenario);
    - `hotpath-skew` (its slack and clock-skew scenarios);
    - `seal` (Seal and Migration015);
    - `seal-plugin` (SealPlugin and SealCore);
  - the rest.

  A new scenario is in `rest`, unless its name starts as 0.15's do. `--list` prints
  what a run would run, without TLC; a test holds the nine to a partition
  of it. A shard that fails fails `Formal model`, and each prints its own
  counterexamples. CI gives TLC 4 GB of heap (`--heap 4g`, the script's
  default is 1g) with 4 workers: Tampering took 11 minutes at 1g and 7 at 4g
  or 8g in a benchmark on a 4-core, 16 GB runner (10.7 in its first CI run).

# Proofs in Lean

TLC explores every interleaving of a few requests; it says nothing about a
single decision being right. The rules themselves (who reads what, what a
token keeps, what a ciphertext is bound to, what the log's checks accept) are
proved in [Lean 4](https://lean-lang.org), about a model of the code, and
that model is held to the code case by case:

```sh
pnpm formal:lean               # the proofs, and about 120,000 cases, half a minute
pnpm formal:lean --long        # ten times the cases
pnpm formal:lean --seed=42     # another reproducible set
```

- [`formal/lean/Coffre/Access.lean`](../formal/lean/Coffre/Access.lean) is
  `packages/core/src/access.ts`, a definition for each function, under its
  name. [`AccessProofs.lean`](../formal/lean/Coffre/AccessProofs.lean) proves
  what the rules promise.
- [`Decide.lean`](../formal/lean/Coffre/Decide.lean) is how the vault decides
  each key of a read, and each reference one makes,
  [`packages/vault/src/decide.ts`](../packages/vault/src/decide.ts):
  personal configs, references, deleted places, sensitive values, and what
  a workload's scope lists.
- [`Use.lean`](../formal/lean/Coffre/Use.lean) is how 0.15 decides a use
  on sealed inputs (`decideChecked` in `decide.ts`), and the bulk cap's rule
  ([`packages/vault/src/bulk.ts`](../packages/vault/src/bulk.ts)): each
  input's seal first, then `Decide.lean`'s rules on the reader the inputs
  make, then the cap ([`docs/design/sealed-inputs.md`](design/sealed-inputs.md)).
- [`Envelope.lean`](../formal/lean/Coffre/Envelope.lean) is the AAD and the
  envelope, and [`Audit.lean`](../formal/lean/Coffre/Audit.lean) the chain
  and its checkpoints.
- [`Oracle.lean`](../formal/lean/Oracle.lean) runs the model on JSON cases,
  and [`scripts/formal-lean.ts`](../scripts/formal-lean.ts) generates them,
  runs each through the TypeScript and the oracle, and fails on any answer
  that differs. [`scripts/formal-lean.sh`](../scripts/formal-lean.sh) builds
  both and runs it.

CI runs it in the *Formal proofs* job of `validate.yml`.

## What is proved

Each theorem is about the model; the next section is what ties the model to
the code.

| Theorem | In plain words |
|---|---|
| `credential_within_holder` | A request on a credential holds nothing its holder does not hold now. |
| `personal_token_within_issuer` | A personal token issued by 0.10 or later holds nothing its issuer did not hold when they made it, at the place as it was named then, whatever happened since: roles widened, environments protected or unprotected or renamed, grants added. At a protected environment, it is held to what the issuer held there protected. |
| `role_edits_never_widen_credentials` | What a credential's scope leaves to its holder is the same under any edit of any role. |
| `protected_never_widens` | Under valid roles (`definitionProblem`), a person holds no more in an environment once it is protected. |
| `owner_issued_only` | A request reads a project's sensitive values only as a service, on a credential with a grant in that project whose own issuer owned the project when they issued it (R32). One from before 0.11 reads them if its own issuer owns the project when it is sealed (`sealCredentials`), which the model leaves out. |
| `no_person_reads_sensitive` | No person, Owner or not, on a session or any token of theirs, is handed back a sensitive value: directly, through a reference, in a fork or in a personal config. |
| `service_sensitive_from_owner` | A service is handed back a sensitive value only on a grant in the value's own project, the source's for a reference, whose issuer owned that project. |
| `copy_keeps_sensitive`, `copy_never_through_reference` | A fork copies a sensitive value, for anyone, only where it keeps it sensitive, and never one read through a reference: it keeps the reference. |
| `personal_owner_only`, `personal_holds_no_reference` | A personal config's key opens for its owner alone, and no reference reads into or out of one. |
| `no_laundering` | A workload is handed back a value, for any purpose but the proxy's use, a fork's copy included, only if its scope lists the key, by ID, on a grant covering where the value is held: a reference's source, a fork's parent, never the place the read names (docs/design/workload-access.md, section 6.1). |
| `reference_made_by_reader` | A reference is made only by someone who writes where it is held and reads its source, and uses the source too if it is sensitive (R24); by a workload, only to a plain source or one its scope lists. |
| `reference_shares_by_design` | A reference does let someone read what they cannot at its source: Bo, a Viewer of `web/dev`, reads `api/dev/KEY` through `web/dev/API`. That is what R20 asks; the guarantee is the one above. |
| `allowed_sealed`, `allowed_credential_sealed` | A 0.15 use is allowed only if every input it weighs (credential, principal, roles, policy, key, a reference's source, each environment) was read as its object's newest change left it, under the vault's seal. |
| `stale_credential_refused` | A credential row that is not the log's newest refuses the use `stale` or `tampered`, whatever the row says: never a refusal the replay would give too (HotPathOne's `StaleFirst`). |
| `allowed_keyread` | A 0.15 use allowed is one `KeyRead.decide`, 0.14's rules, allows on the reader its sealed inputs make. |
| `allowed_within_cap`, `bulkRule_writes_admitted` | An allowed use's key is in its principal's set, or fewer than the log's count of other keys count; the cap's rule writes a key's row only for a request it admits, at the request's time. |
| `encodeAad_injective` | No two contexts encode to the same AAD. |
| `open_only_as_sealed` | A row that opens as a context holds a key the vault wrapped as exactly that context (project, environment, key, owner, sensitivity), and opens to the value the app encrypted under that key for those ids: nothing swaps across them. A rewrap, one key wrapped again as another version, is part of the history it covers. |
| `versions_not_bound` | The version is not bound: an older version's row, put back, opens as the newer. |
| `no_person_opens_sensitive` | Even when an attacker rewrites the database's sensitivity, owner or place columns, a person is handed only a value whose key the vault wrapped not sensitive for that place, and no personal config's value but their own: the decision trusts the columns, and the wrap refuses to open what they lied about. |
| `sensitive_value_never_reaches_a_person` | So a value whose key the vault only ever wrapped sensitive reaches no person, whatever the database says. That every wrap of a sensitive value's key is sensitive is the theorem's hypothesis, which `rewrap` is written to keep (but for an Owner's loosening, R30). |
| `verify_append`, `resume_sound` | Verifying a log in batches, or going on from where a walk stopped, decides over the entries it read exactly as one walk from genesis (R25). A row edited behind where it resumes is the vault's scrub's to find. |
| `head_determines_chain` | Two runs that verify from genesis to the same head are the same entries. |
| `checkpoint_pins_prefix` | A valid checkpoint pins the log up to it, every field and MAC, as its authors wrote it (the true log). |
| `walk_from_checkpoint_extends` | What a walk from a valid checkpoint accepts is the true log up to it, then entries that chain on, each its own hash and passing the walk's MAC check: the app's walk checks its own entries' MACs, the vault's its own, each the other's by place. |

## What is assumed

Nothing is assumed in a `sorry` or an `axiom`:
[`CheckAxioms.lean`](../formal/lean/CheckAxioms.lean) has Lean list what
every declaration of the proofs depends on, and fails on anything but Lean's
own three axioms (`propext`, `Classical.choice`, `Quot.sound`), a `sorry` or
a `native_decide` included. The cryptography is assumed as hypotheses of the
theorems that need it, each the standard property, idealised:

- **AEAD integrity** (`Envelope.Assumptions`): whatever opens under the KEK
  is a wrap the vault made, of a DEK, with its AAD; whatever opens under a
  DEK the vault wrapped is the value the app encrypted under it, against
  anyone who never held the DEK. The app, which encrypts, holds every DEK:
  this assumes it encrypts under each only the value it made it for. Each
  DEK encrypts one value; it may be wrapped several times, once a version,
  as a rewrap does. We do not prove AES-256-GCM has this property.
- **Collision resistance** (`Audit.Injective`): the entry hash is injective
  and never the genesis hash. This is the symbolic idealisation, stronger
  than collision resistance: a proof under it says an attacker must find a
  SHA-256 collision.
- **Unforgeability** (`Audit.Signed`): a checkpoint that verifies is one the
  vault signed, over a prefix of the log as it was.
- **MACs**: the chain's proofs take each entry's MAC check as given
  (`macOk`): whichever the walk makes, the app's of its own entries or the
  vault's of its own, each author checking its own over the same stretch.
  Who can make one is HMAC's property.
- **About the data**: an environment's id is never `""` (`NoBlankEnv`), and
  contexts are well formed, as `checkContext` makes them.

## How the model is tied to the code

`scripts/formal-lean.ts` draws cases from a seeded generator over a small
world (two projects, their environments, a fork, a personal config, ids no
row has) that meets every branch: edited and invalid roles, custom roles,
protected environments and `*`, credentials of 0.10 and of before, services,
deleted places, lapsed grants, every member status, tampered chains, holders
with no policy, scope grants with no project, and names a plain object
already holds (`constructor`, `__proto__`). Each case runs through the
TypeScript and through the oracle, which runs the very definitions the
proofs are about. A case without a field the code needs is an error to the
oracle, never an answer, so it cannot pass for one the code would refuse.
They run a batch of 20,000 at a time.

| Compared | Cases | From |
|---|---|---|
| `allows`, `withinCredential` | 20,000 each | `@coffre/core/access` |
| `givesService`, `managesService`, `issuesCredential` | about 6,500, 6,000, 6,000 | `@coffre/core/access` |
| `heldColumns`, `issuedGrant`, `readsSensitive`, `ownsProject`, `mayManageAccess`, `runsInstance`, `readsWholeLog`, `makesProjects` | 4,000 each | `@coffre/core/access` |
| `useOnly` | 6,000 | `@coffre/core/access` |
| `keyRefusals`, `sensitiveRefusals`, `useOnlyRefusals`, `referenceRefusal` | 13,000, 10,000, 10,000, 6,000 | `packages/vault/src/decide.ts` |
| `decideUse` (0.15), `bulkRule` | 20,000, 6,000 | `packages/vault/src/decide.ts` (`decideChecked`), `bulk.ts`; each input's seal as checked (valid, current), half the cases with every seal holding; only views a use's statement reads (`decideChecked` throws on others, which the model answers `unread`) |
| `encodeAad` | 2,000 | `@coffre/core/envelope` |
| `verifyEntries` | 2,000 | `@coffre/core/audit`, real keys and hashes |

The run prints how often each yes-or-no function says yes, so a generator
that stopped meeting one answer shows. And the comparison was itself tested:
each of these changes to the code makes the run fail, by 4 to 519 cases or
by throwing: `holds` ignoring protection, `heldColumns` asking at the
project, `readsSensitive` across projects, `ownsProject` for a service, a
personal config's owner past their credential, a person handed a sensitive
value, a reference made to a sensitive source without using it there,
a workload's copy let through, a workload's reference to a plain source refused,
`verifyEntries` letting a gap through, a lookup by an inherited name,
the 0.15 decision checking the policy's seal before the roles' (146 cases),
the cap counting other keys without the deadline's margin (650 cases).
Changing the model the same way breaks the proofs first.

The vault's per-key decision and its check of each reference made live in
`decide.ts`, pure, so that they can be compared: `#keys` and `reference`
read, lock and log around them. It tells a personal
config's own key from a reference into it by the environments' ids, as the
model does, where it compared their rows as objects: the same on every map
the store builds, one row an id.

## What it found

- **An empty list of permissions skipped the check.** `#keys` takes, for
  each key, permissions any one of which it needs besides the call's
  (`needs`). Given none, `refused[0]` was undefined, which passed for no
  refusal, and the key was released without the call's own permission
  checked. No caller passes an empty list; `keyRefusals` now refuses one.
- **The version is not bound** (`versions_not_bound`). An attacker who can
  write the database can put an older version's row in place of the newer,
  and it opens. They could as well point the key at the older version: the
  rollback coffre accepts (`docs/design/oidc.md`). Binding the version would
  be a new envelope format.
- **A lookup read names a plain object already holds.** `allows` read an
  instance role as `instanceRoles[holder.role]`, and `protectedWithin` a
  project's protected environments as `protectedIn[projectId]`: a role named
  `constructor` made `allows` throw, and a project of that id made
  `givesService` throw. Roles are checked and ids are UUIDs before they get
  there, so nothing reached it; each lookup now takes only the record's own
  keys, as `definitionOf` did.
- **References share by design** (`reference_shares_by_design`): a stronger
  claim than the code makes would be false, so the model says so.

## What it does not cover

- **The code around the decisions.** The model is the rules and the per-key
  decision, not the API, the database's reads, which `Holdings` and the
  environment rows the vault builds, or the locking (TLA+ above).
  `serviceGrant`, how `issuedScope` keeps a service's grant, is modelled and
  proved but not compared: `narrowest` is private to the server. Nor is
  `sealCredentials`, which reads a credential of before 0.11 as its issuer
  holds when it is sealed.
- **The cryptography itself**, as assumed above. KMS's encryption context
  (`kek/aws-kms.ts`) is not encoded, and needs no injectivity proof: it is a
  map, so distinct contexts are distinct by construction; KMS binds the
  ciphertext to the key, whose returned `KeyId` the code checks; and
  `kekIntegrity`'s adversary is anyone without `kms:Encrypt` on the key.
- **The rewrap rule.** `rewrap` wraps a sensitive version's key again only as
  sensitive (`LOOSER`, re-checked under the head), but for an Owner's
  loosening: what makes `sensitive_value_never_reaches_a_person`'s hypothesis
  hold. Neither is modelled or compared.
- **Freshness.** Rolling back the log and all its checkpoints together needs
  no key.
- **Bytes.** The model encodes the AAD as characters; the code, UTF-8. They
  agree on the ASCII contexts `checkContext` admits, which the cases compare.

## Lean

- **Version:** Lean 4.35.0 (`formal/lean/lean-toolchain`), released
  2026-10-12, core alone: no Mathlib, so a clean build of every proof and the
  oracle takes seconds. `scripts/formal-lean.sh` pins each platform's release
  archive by SHA-256 and uses elan's Lean instead when it is that release.
- **Adding a rule:** a definition in `Access.lean` beside the code's, an
  operation in `Oracle.lean` and its cases in `formal-lean.ts`, then the
  theorem. Workload sessions narrowed from a parent's would be one more
  `IssuedBy`, and `personal_token_within_issuer` the shape of its proof.
