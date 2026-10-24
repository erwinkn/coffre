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
pnpm formal                  # every scenario, about a minute and a half
scripts/formal.sh Deletion   # one, with its runs without a protection
```

- [`formal/Coffre.tla`](../formal/Coffre.tla) is the model of the locking
  protocol: the state, one step per SQL statement, and the invariants.
- [`formal/MC.tla`](../formal/MC.tla) holds its scenarios: who runs what, and
  from which state. Each one has a configuration, `formal/<Name>.cfg`.
- Three smaller models, each with its scenarios beside it, hold other
  protocols to the same discipline ([below](#credentials-issuing-and-the-bulk-limit)):
  - [`formal/Credentials.tla`](../formal/Credentials.tla), a CI run's ID
    token exchanged for a credential, and every way a credential ends;
  - [`formal/Issuing.tla`](../formal/Issuing.tla), who may hand a service
    account sensitive values (R32);
  - [`formal/Bulk.tla`](../formal/Bulk.tla), the vault's bulk limit (R28).

  A configuration names the module of its scenarios on its second line,
  `\* model MCCredentials`; one that names none is `MC.tla`'s.
- [`scripts/formal.sh`](../scripts/formal.sh) downloads TLC, checks its
  checksum and runs everything.
- [`scripts/formal-trace.mjs`](../scripts/formal-trace.mjs) prints a
  counterexample one step per line.

CI runs it in the *Formal model* job of `validate.yml`.

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
| A read decides under the reader's row, which a revocation or a removal locks too (`#keys`, through `#decide`) | a value released to a member after their removal committed (`NothingReleasedAfterRevocation`) | |
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
  - the vault locks the reader's row and checks their standing and the place;
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
  Foreign-key share locks are compatible with `FOR NO KEY UPDATE` and are
  left out too.
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
  the vault's count, `Bulk.tla`.
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
  2. the vault's answer;
  3. the vault's decision, under the account's row and the head;
  4. through the credential proxy, `credential.use` under the head;
  5. the value answered.
- **Ending one:**
  - revoking it (`revokeCredential`);
  - untrusting its binding or replacing the issuer's keys (`unbind`,
    `replaceKeys`, `#revoke`);
  - removing the account, the vault's step then the app's sweep
    (`removeMember`), and admitting it again.

| Protection, in the code | Turned off, TLC finds | Found by |
|---|---|---|
| The exchange spends the ID token in the transaction that issues its credential, a primary key on its hash (`consumeToken`) | one ID token bought two credentials (`SingleUse`) | |
| It reads its binding again under the head (`standingBinding`) | a credential issued after its binding's `token.unbind` (`NoExchangeAfterUnbind`) | |
| And the account (`stillMember`) | a credential at a generation a removal had moved past (`ExchangedAtCurrentGeneration`) | |
| The binding's rate is counted under the head (`exchangesSince`) | more credentials in the minute than the rate (`RateHeld`) | |
| Once the vault has released, the app reads the credential and the member's generation again before it answers (`credentialStill`), under the head through the proxy | a value released through a token revoked after it was checked (`NoReleaseAfterEnd`) | this model, fixed with it |
| And with no lock for an export, which commits nothing more | the same, by an export (`NoReleaseAfterEnd`) | this model, fixed with it |
| Untrusting or replacing a binding revokes the credentials it issued (`#revoke`) | the same, through a credential whose binding was untrusted (`NoReleaseAfterEnd`) | |
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
  8. reader    UseLock           use cred tok               -> use.head        rowLock none -> reader
 10. reader    UseDecide         use cred tok               -> use.fence       log +secret.read cred <<tok, 0>> gen 0 (reader); rowLock reader -> none; head reader -> none
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
those it would release (`snapshot.postgres.ts`).

- **With a local key**, the vault takes the head in the statement that
  counts, right after the row.
- **With a key service**, it counts under the row, opens the keys, then
  counts again in the statement that takes the head.
- **Either way**, that last count is the decision, at its statement's
  clock, which stamps the entries; the commit, and the keys handed over,
  come after it, while the clock runs on.

| Protection, in the code | Turned off, TLC finds |
|---|---|
| A read decides under the reader's row (`lockMembers`), and with a key service counts again under the head (`#keys`, `late`): each covers for the other | two reads, each counted before the other's entries, together past the limit (`CapHolds`) |
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
| `SensitiveOnlyFromOwners` | A scope reads a project's sensitive values only if whoever issued it is an Owner of the project when it commits |
| `SealedOnce` | The older release's token is sealed once, however many first uses race |
| `CapHolds` | At most the limit's keys decided for the principal in any window |

### Their scenarios

| Scenario | Who runs what | States |
|---|---|---|
| `Exchanging` | Two runs present one ID token at once, and each another of its own, while an owner untrusts the binding, replaces its keys, or removes the account and admits it again | 112 thousand |
| `Revoking` | A run reads through its token, by the proxy or an export, and through an exchanged credential, while an owner revokes, untrusts, replaces keys or removes the account, and another admits it again | 83 thousand |
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
`verifyEntries` letting a gap through, a lookup by an inherited name.
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
