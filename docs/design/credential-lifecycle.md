# 0.15: the vault owns a credential's life (T149)

Behind 0.15's switch, the vault makes and ends credentials itself, each in
one call (D146): one Postgres statement for a sign-in or a revoke, a read
and one write for a token's issue (section 3). The app reads what it needs to
check the request, names it, and passes it on. W246 mapped today's paths and
modelled two placements (the vault, or the app with the vault sealing what it
proposes); Erwin chose the vault on 2026-10-28. This page says what is built,
what comes next, and why.

Three pull requests, each leaving `main` shippable, all in 0.15:

| PR | what | Lifecycle.tla's protections it builds |
|---|---|---|
| 1 (T149, W250) | sign-in through a trust binding (`POST /api/auth/oidc` and a workload's `POST /api/workloads/session`), revoke and sign-out, by the vault; the spec | BindingLocked, MemberLocked, SpentChecked, IssueOffFence, RevokeTakesFence, RevokePolicyHeld, SweepAfterLock (as built already) |
| 2 (T149, W250) | a service token, a personal token and a handle, issued by the vault, which weighs the issuer's rights itself | IssuerLocked, IssuerCAS |
| 3a (T149, W250) | a service's trust bindings made and ended by the vault, which weighs who binds as it weighs a service token's issue; a sign-in through none it did not seal | BindingSealed; IssuerLocked, IssuerCAS, IssuePolicyHeld for a bind |
| 3b | the vault verifies the CI run's ID token (D148), against the sealed binding's keys | VaultVerifiesToken |
| 3c | each credential's token hash sealed, after W242's B1 | HashSealed |

## 1. Before: CI sign-in as 0.15 had it

With the switch on, `POST /api/auth/oidc` (`WorkloadService.#exchange`):

| # | where | what | under 0.14's head |
|---|---|---|---|
| 1 | app → Postgres | `exchangeCandidates`: the service's live bindings on the issuer, whether the token was spent, the newest policy change | |
| 2 | app | the ID token's signature, audience, times and claims | |
| 3 | app → vault | `access(member)` | |
| 4 | app → vault | `prepare`: seals the `credential.issue` the app proposes; reads nothing, weighs no right | |
| 5 | app → Postgres | `BEGIN` and the head | yes |
| 6 | app → Postgres | `exchangeStill`: member, binding, rate | yes |
| 7 | app → Postgres | `exchangeToken`: token spent, credential inserted, binding stamped | yes |
| 8 | app → Postgres | the head again, then `token.exchange` with `app_change` | yes |
| 9 | app → Postgres | `COMMIT` | yes |
| 10 | app → vault | `waitSealed` (R51) | |

8 app statements, 6 of them holding the head that every app write of the
instance waits for, and 3 to 4 vault calls. On the Debian rig at 20 ms a round
trip, one sign-in took 190 ms alone, 1.4 s at p99 with 10 at once and 3.5 s
with 30, most of it queued on the head. A revoke was the same shape and held
the fence across its `COMMIT`'s round trip. The rest of W246's map
(workload sessions, token issue, bearer checks) is in #408's history.

## 2. The sign-in, as built (PR 1)

The app verifies the proof as before (one statement: the bindings, with the
spent flag), builds the credential's row and its APP_KEY MAC, and makes one
vault call, `Vault.signIn`. The vault decides the credential's object from the
binding's columns the app names (its scope, and a workload's reads with it,
`sealedSessionScope`), seals it, MACs its change, and runs `sign_in`
(migration 0034), one statement:

1. the account's row `FOR SHARE`, active at the binding's generation; then,
   in a statement of its own, its seal its newest change's (MemberLocked: a
   removal waits for the sign-in, or the sign-in sees it; a row put back is
   none). Compared after the lock, not in its `WHERE`: a recheck there sees
   the row's new version beside the snapshot's older changes, and would refuse
   a sign-in that waited behind a grant (Fable's review);
2. the binding's row `FOR UPDATE`, as named: principal, generation, profile,
   scope, policy, not revoked (BindingLocked); and no tombstone;
3. a workload's: no freeze of the instance, the account or the binding;
4. the rate, 60 a minute, counted under the binding's row;
5. the proof's own times (`validUntil`: the ID token's `exp`, its `iat`'s
   hour) and the credential's end, by the database's clock;
6. the token spent, by the primary key of `consumed_tokens` (SpentChecked),
   once the app's key is known not to be one it rotated from (as 0.14's
   append refuses one, KeyRetired);
7. the credential inserted with its seal, the binding stamped;
8. the issue lock shared, the change numbered under it (IssueOffFence).

Then the vault waits for the seal (R51) and answers. Locks are the order every
writer takes: member row, binding row, issue lock. No head, no fence, so no use
waits on a sign-in (R58). Each function has `lock_timeout = '1s'`: a sign-in
that cannot get its binding's row within a second is refused at once as busy
(R44), and answered 429.

A CI sign-in is now **1 app statement and 1 vault call, 1 statement there**
(`packages/server/test/signin-cost.test.ts`), and each reads as many rows and
pages after the binding issued 20,000 credentials, 20,000 tokens were spent and
both logs grew a hundredfold.

A workload's session (`#signIn`) goes the same way for a proof that decides
nothing in a transaction (`oidc`, `aws`), with two app statements (its
bindings, and the places its session reaches, for its row and answer). A proof
with a `commit` (the enrollment proof, not registered yet) keeps the old path.

**Revoke and sign-out.** The app reads the row (`liveCredentialsWhere`, its
MAC checked), weighs who may as before, and calls `Vault.revokeCredential`
with the object's columns and seal, its MAC over the revoked row, and the
policy the caller's right was weighed on. The vault checks the seal is its
own (`tampered` otherwise, reported), seals the revoke, and runs
`revoke_credential`: the row `FOR UPDATE` as read (its MAC and seal, else
`moved`, and the app reads again), the fence exclusive, the row's seal its
object's newest change's (else `stale`, reported: a row put back), the policy
still the newest and its protected environments' slugs as weighed (else
`policy`, 409, as `policyStill` under 0.14's head: every policy change and
rename takes the fence before it commits, so reading it under the fence
orders the two; RevokePolicyHeld), the update, the change. The fence is held
for the statement's work, never a round trip. A row 0.14 made, with no seal,
is revoked as before, with 0.14's entry: the log holds no object of it to
change.

## 3. Token issue, as built (PR 2)

Three tokens, each made by a person or a service for an account: a service
token (`POST /api/services/<name>/tokens`), a person's personal token and a
handle. Under 0.14's head, the app weighed who may give what, then `prepare`
sealed whatever row it proposed: the vault weighed no right of the issuer's.
Behind the switch, the vault weighs it itself, with the same rules from
`@coffre/core/access` (`issuesCredential`, `managesService`, `ownsProject`
for sensitive reads, R32; `delegable` and `heldColumns` for a person's own).

The app checks the request as before, works out the scope (5 statements:
the issuer's newest policy and access entries, the places, what sensitive
values and references they hold), builds the row and its APP_KEY MAC, and
makes one vault call, `Vault.issueToken`, naming the issuer, the credential
the request came in on, the account at its generation, the issuer's access
as the app weighed it and the policy it weighed on. The vault:

1. reads, in one snapshot, both members with their grants, the newest
   policy and, for a service token, the instance's settings; beside it, the
   credential the request came in on (`issuing_credential`, migration 0036:
   the vault's login reads no credential otherwise);
2. checks each row as `access` does (its MAC, its newest access entry), the
   credential's seal its own and its object's newest change's, the policy and
   the protected environments' slugs the app named;
3. weighs the issue (`weighIssue`): what the issuer holds through that
   credential, what the account holds, the token's kind, scope and end (a
   service token at most 366 days and given by a person, a personal one a
   week, a handle no later than the scoped credential it was made on, if
   one); each grant's columns, which a use decides on, within its role as
   defined (the policy's for a service or personal token,
   `HANDLE_POLICY`'s for a handle), never its role's name alone. Only what
   the vault authenticated decides: of the credential the request came in
   on, its object's scope, end and caller, never its row's kind, which no
   seal covers (R53; reviews r1 and r2); a credential 0.14 made, which
   the log never held, authorizes nothing here: the vault answers
   `unlogged` and the app issues on it as before (review r3);
4. runs `issue_token`, one statement: the members' rows `FOR SHARE`, by
   principal (IssuerLocked), then, compared in a statement of its own, each
   active at its generation and its `access_seq` as read (IssuerCAS); the
   credential's row `FOR SHARE`, then live, the issuer's, its seal as read
   and its object's newest, its end the one the vault authenticated and
   still ahead (a seal compares bytes, never the columns it was made of;
   review r3); the issue lock shared, then the policy still the newest
   under it (IssuePolicyHeld); the app's key not one it rotated from; then
   the insert, and the change numbered under the issue lock
   (IssueOffFence);
5. waits for the seal (R51) and answers.

Nothing is held between the read and the write, so no lock waits on the
vault's round trip (`IssuesHoldNoLockBetween`). A write that finds a row
moved writes nothing, and the vault reads and weighs again, at most three
times (the model's IssueCheck); a demotion that commits meanwhile is seen,
and the issue refused on what the issuer holds now
(`packages/vault/test/issue.test.ts`). When the app weighed the scope on
the issuer's access as it was, the vault answers `access` and the app asks
again (409, as `issuerStill` did).

**Not one statement.** D146 asked for one. A sign-in is one because the
app names everything the statement can hold to the binding's row. An
issue's decision is on the issuer's rights, which the vault has to read and
check, MACs included, before it can weigh them; the app's `Access` answer
carries no MAC the vault could take back. So it is one call: reads on two
round trips (the snapshot, with the credential beside it, then the places
the account's grants name), then the one write.

The app's 0.14 entry is gone here too (D147): the change records the issue,
`issue: {by, via, kind, label}`, and refusals are 0.14 entries as before.
Under 0.14's log, and with a vault that does not say `issues`, the app
issues as before.

## 4. Bindings, as built (PR 3a)

A trust binding was the app's row, vouched for by its APP_KEY MAC alone. The
app's code, turned hostile, holds that key: it could write a binding that
trusts its own key and sign in through it. `Lifecycle.tla` breaks
`SignInsOnValidTokens` that way, with the vault checking the ID token or
not, which is why D148 needs sealed bindings.

Behind the switch, a binding is a 0.15 object (`BindingInput`: the account,
its generation, profile, issuer, keys, claims, scope, policy, revoked), and
the vault's to change, in one call, `Vault.changeBindings`:

- **making one** is weighed as a service token's issue: on `#issuerRead`'s
  reads, by `weighService` (a person who manages the account, never more than
  it holds, sensitive reads only from an Owner, R32). An Admin's binding
  that reads sensitive values is refused, as an Admin's token would be;
- **ending one** (an unbind, or the binding a new one replaces) takes every
  live credential it issued with it. The app names them, each with its seal
  and MAC; the statement holds the set to the rows, so one a sign-in made
  meanwhile is read again. One with no seal, written around the vault, is
  ended too, with no change: a binding the log holds is always the vault's
  to end, so its object never stands past its end (review r1);
- a bind holds the account's live bindings to the set the app weighed it
  beside (an issuer's keys moved, the cap), and the keys its policy reads
  to the names they were asked by, `FOR SHARE`: what the app's transaction
  checked under 0.14's head, now under the account's row (review r1);
- one statement, `change_bindings` (migration 0037): the account's row
  (its update lock, so that two binds take turns over the 16-binding cap)
  and the maker's (shared), compared; the credential the request came in
  on; the bindings it ends and their credentials, `FOR UPDATE`, compared;
  the issue lock shared, then the policy under it; the fence exclusive only
  when it ends something; the writes; a change per object.

A sign-in names its binding's columns and seal. The vault takes it only
when the seal is its own over those columns (`unsealed` otherwise, 401 with
"bind it again"), and `sign_in` holds the row to them and the seal to the
binding's newest change, so a row put back after its end is none.

A binding 0.14 made, which the log never held, signs nobody in under the
switch (fail closed): 0.15 is unreleased, nobody runs it, and a fallback to
the app's own check would be the hole sealed bindings close. Plan PR 9's
cutover can adopt them; until then a manager binds again. Ending one is the
vault's too, its row revoked with no change: the statement holds a row with
no seal to having no change in the log, so a binding of the log's whose
seal a writer cleared is `stale`, never ended quietly (review r2).

Bindings keep 0.14's `token.bind` and `token.unbind` entries, written once
the vault's change has committed, following through on its decision. The
app's own credential checks read `token.unbind` as a binding's tombstone,
so a row put back stays dead to them too, and the 0.14 audit page keeps
showing bindings until T156. D147 asked only that no `token.exchange` be
written; binds are rare admin acts.

A sign-in is still 1 app statement and 1 vault statement. On the Debian rig
at 20 ms a round trip, beside 1,000 uses a second: 65 ms alone, 72 / 180 ms
(p50 / p99) with 10 at once, 128 / 264 ms with 30; PR 1 measured 64,
83 / 211 and 127 / 303. Uses beside stay at 25 ms p99.

## 5. The model: `formal/Lifecycle.tla`

W246's model compared both placements. It now models the vault's alone, and
more of it: issue, sign-in, unbind, revoke and the seal wait beside uses, a
database writer, and the app's code turned hostile. Every invariant holds with
every protection on; each protection removed breaks the invariant beside it
(`scripts/formal.sh`, `REMOVALS`):

| invariant | says | broken without |
|---|---|---|
| `RevokeOrdersUses`, `NothingAfterRevokeAnswered` | no use allowed is numbered after a revoke; none begun after its answer serves | RevokeTakesFence |
| `RevokesOnStandingRight` | a revoke by a right the policy gives is numbered before that right is taken away | RevokePolicyHeld |
| `SignInsTakeNoHead` (R44), `IssuesHoldNoLockBetween` | no sign-in takes 0.14's head; an issue holds nothing between its two statements | (by construction) |
| `SensitiveOnlyFromOwners`, `IssuedByLiveCredential` | rights never widen: a token is numbered before its issuer's demotion, a policy change that takes the right from her role, and her credential's revoke | IssuerLocked, IssuerCAS (each); IssuePolicyHeld (the policy change) |
| `UsesNeverWaitOnIssues`, `UsesTakeNoIssueLock` (R58) | a use never waits on an issue, nor behind a change that waits for one, and never takes the issue lock | IssueOffFence; PolicyIssueFirst |
| `RateHeld`, `SpentOnce` | a binding's rate holds; an ID token buys one credential | BindingLocked; SpentChecked |
| `AllowedAtCurrentGeneration` | removed, an account's credentials end | MemberLocked and UseChecksGeneration (each covers the other) |
| `EndedBindingEndsCredentials` | unbound, a binding's credentials serve nothing after | BindingLocked; SweepAfterLock |
| `AllowedOnSealed` | a row a writer put back, forged or edited serves nothing | SealChecked |
| `AllowedAsPresented` | a use serves the credential whose token was presented | HashSealed and AppChecksMac (each suffices) |
| `SignInsOnValidTokens` | the app's code, hostile, mints no run's credential | VaultVerifiesToken; BindingSealed |

Scenarios: `LifecycleIssue`, `LifecyclePolicy`, `LifecycleBind` (Ada binds svc's CI
through the vault while she is demoted), `LifecycleSignIn`, `LifecycleReplay`,
`LifecycleUnbind`, `LifecycleRevoke`, `LifecycleForge`, `LifecycleCompromised`, each a few
seconds. `docs/formal.md` says what each abstracts.

Two results drove the design:

- **The unbind race.** A sign-in no longer takes the head, so the unbind's
  re-read under the head no longer excludes it. It is still safe because the
  unbind updates the binding's row before it sweeps what the binding issued
  (`#revoke`), and the sign-in holds that row. TLC finds a live credential of
  an ended binding with either removed, and 0.15's use reads no binding.
- **D148 needs sealed bindings.** With the vault checking the ID token but
  taking any binding row, the hostile app writes a binding that trusts its own
  key (it holds `coffre_app` and APP_KEY) and signs a token for it. TLC breaks
  `SignInsOnValidTokens` that way. So PR 3a makes a binding a 0.15 object,
  sealed when a manager makes it, and the sign-in takes only a sealed one.
  The model's bind is an issue that commits a binding (its maker held as an
  issuer is), and its unbind is the vault's statement, no 0.14 head.

## 6. Decisions

| decision | instead of | why |
|---|---|---|
| the vault decides the credential's object from the binding's columns the app names (its profile, scope and policy), and the statement holds them to the row under its lock | the vault reading the binding first | one statement, one round trip; a binding changed meanwhile is refused (`unbound`, 400), and the run signs in again. Only the one-time sealing of a 0.4 binding's scope changes a binding in place, so this is rare |
| the app computes the row's APP_KEY MAC, the vault writes it verbatim | the vault holding APP_KEY | the vault never holds the app's key; the MAC covers id, hash, kind, principal, generation, identity, expiry and revoke, all of which the vault checks or decides |
| the vault's own scope rule (`sealedSessionScope`, `storedScope`, `readScope`) moved to `@coffre/core/access` | the vault trusting the app's scope | one rule on both sides; the app's scope must equal the vault's, or the call fails |
| `validUntil`, the proof's own times, held to in the statement | trusting the app's check before the call | 0.14 checked the token's times again after its wait under the head; the vault does the same, by the database's clock. PR 3 computes it itself |
| `lock_timeout = '1s'` on both functions, refused as busy | `NOWAIT` (review r1) | R44: overload refused fast. The binding's row lock is what holds its rate (BindingLocked); `NOWAIT` would refuse every sign-in of a burst on one binding but the first, which R44 asks to serve. Each holder keeps the row for its statement's work, a few ms, and a backend waits only behind those; one second bounds the rare long holder (an unbind's transaction) |
| no 0.14 `token.exchange` entry (D147), and, extending it, no 0.14 `token.revoke` or `sign_out` allow entry: the change records it | the app appending 0.14's entry after the call | the same reason as D147; the change carries who, the binding, the proof, the issuer, the run, a session's key and end, and for a revoke why, the credential it came in on, and whose credential of what kind. Refusals are still 0.14 entries. **For Erwin: reversible** |
| seal the token hash in the credential's object (option (a)), in PR 3 | the app's MAC check alone (option (b)) | with W242's B1 the vault finds a use's credential by its hash, so the hash is a decision input (R53). The model shows each stops a writer who moves a hash; only (a) holds when the app's check does not run. It lands after B1 |
| a workload proof with a `commit` keeps the old path | moving the enrollment's capacity into SQL | no such proof is registered yet |
| every sign-in through a binding goes through the vault, one 0.4 made sealed first | the old path for those | a binding's rate is counted under its row; a sign-in that counted it under the head beside one under the row could pass it by one (review r2) |
| the app's key checked in the statement, not under the fence | the fence, or nothing | a credential the app signed under a key it rotated from is refused, as 0.14 refuses its entry. A rotation that commits during the statement leaves a row its new key refuses at once: a dead credential, never a live one, and R41's rotation signs every session out anyway. The model leaves this out for that reason: no outcome of it widens anything |
| an issue is one call, a read and one write, holding nothing between (PR 2) | one statement, as D146 asked | the vault weighs the issuer's rights, which it has to read and check first: the app's `Access` answer carries no MAC the vault could take back. The write holds what the read decided on (IssuerLocked, IssuerCAS), which the model shows enough. **For Erwin: a deviation from D146** |
| a row moved under the write: the vault reads and weighs again, up to three times, then `moved` (409) | answering `moved` at once, for the app to ask again | the vault reads everything it weighs, so it can weigh again itself, as the model's IssueCheck does; the app reads nothing more |
| an issue compares the policy under the issue lock shared, which a policy change, or a write that moves an environment's slug, takes exclusive after its rows and before the fence (`holdIssues`; IssuePolicyHeld, PolicyIssueFirst) | the fence, as a revoke takes it (RevokePolicyHeld); or nothing, which PR 2 first did | a use waits on the fence, and never on the issue lock (R58). With no lock, a policy change that narrows the issuer alone (Developer loses `secret.read`; the account's own Viewer grant still reads) could commit between the issue's check and its number (review r3): a use's check of the account does not catch it. The change waits for the issues in flight, a few ms each; an issue behind a change waits for it, bounded by `lock_timeout` |
| the app still weighs the scope, and names the issuer's access it weighed on; the vault refuses `access` when it moved | the vault alone | the app's scope reads what the vault does not hold (sensitive values, references); a demotion between the two is refused, 409, as `issuerStill` did |

## 7. Numbers

Debian `postgres:16.14` (R62), local, a compose project of its own, 20 ms
added to every round trip, 1,000 uses a second beside, 3 rounds a level
(`packages/server/test/bench/ci.ts --log 0.15 --signin-only --uses 1000
--rtt 20`; 100 at once with `--bindings 2`, a binding taking 60 a minute).
Before: W246's run of the same bench on 0.15 as it was.

| sign-ins at once | before: p50 / p99 | after: p50 / p99 | uses beside, p99 | refused |
|---|---|---|---|---|
| 1 | 190 / 192 ms | 64 / 68 ms | 40.9 ms | none |
| 10 | 763 / 1,374 ms | 83 / 211 ms | 30.7 ms | none |
| 30 | 1,795 / 3,451 ms | 127 / 303 ms | 31.0 ms | none |
| 60, one binding | did not finish | 178 / 301 ms | 45.4 ms | none |
| 100, two bindings | | 235 / 555 ms | 26.9 ms | none |

Uses alone: p99 26.6 ms. Each sign-in is 1 app statement and 1 vault call,
1 statement there, at every level; what it waits for is the binding's row,
behind the other sign-ins through it (at 30, 53 ms of its 127). R58 holds:
uses beside 100 sign-ins read as uses beside none.

Two things the bench needed. Its vault, a proxy made new for each request,
was asked `about` on every one, which a deployment's runtime asks once; it now
answers once. And an isolate takes 32 sign-ins at once (then 429, at once):
W246's level of 60 hung there, its error swallowed. The bench raises that
limit (`exchangeLimit`), its one process standing in for the isolates a burst
spreads over, which share only the database; their CPU is this process's, so
these numbers are, if anything, high. A cold JWKS fetch is unchanged by this
PR (the app's, as before); the vault's own comes with PR 3.

**Token issue (PR 2).** The same rig, 5 rounds a level, a service token's
issue by the Owner (`ci.ts --log 0.15 --issue --uses 1000 --rtt 20`).
Before: the same bench with `--legacy`, whose vault hides from the app that
it issues tokens, so that the app issues as before T149.

| issues at once | before: p50 / p99 | after: p50 / p99 | uses beside, p99: before / after | refused |
|---|---|---|---|---|
| 1 | 360 / 417 ms | 233 / 246 ms | 40.6 / 25.3 ms | none |
| 10 | 1,176 / 2,039 ms | 239 / 569 ms | 42.7 / 25.5 ms | none |
| 30 | 2,839 / 5,433 ms | 297 / 634 ms | 43.1 / 25.0 ms | none |
| 100 | 9,125 / 17,593 ms | 473 / 880 ms | 43.5 / 25.3 ms | none |

Uses alone: p99 25.5 ms, 25.9 before. Each issue is 5 app statements, all
reads, and 3 vault calls (the app's two `access` and the issue); before, 15
app statements, most under 0.14's head, and 4 calls. The uses beside an issue
waited on the fence before; now none does (R58). Past one at once, a call
averages 6.3 to 6.8 vault statements rather than 5: the bench's new vault
isolates read their keys on their first call, as a cold isolate does. The
write is never among the statements that wait longest: the rows it locks it
shares with the other issues.

## 8. Still open

- **A hostile app.** In 0.15 the app names the caller to the vault, so it can
  act as anyone whose credential hash it reads. PR 3 stops it minting run
  credentials from nothing; closing the rest means the vault taking the raw
  bearer token and hashing it itself. Not decided.
- **The 0.14 audit page under the switch** shows no sign-in, revoke,
  sign-out or token issue of the vault's, no run beside the entries a run's
  credential caused, and no label beside those a personal token the vault
  issued caused (`withCredentials` reads `token.exchange` and
  `personalTokensOf` `token.create`). T156 reads them from the changes,
  whose payloads carry both.
- **Environment rows an issue decides on** (T159, a 0.15 ship gate): their
  project, slug and tombstone are read without their objects' seals, as in
  the vault's `access` and `#account`. T159 checks them for all three. The
  protected ones' slugs are held to the policy under the issue lock.
- **Still the app's, with `prepare`:** browser and device sign-ins, renewal,
  a member's removal sweep, unbinding, the key rotation's sign-outs.
