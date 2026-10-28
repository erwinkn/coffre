# 0.15: the vault owns a credential's life (T149)

Behind 0.15's switch, the vault makes and ends credentials itself, each in
one call and one Postgres statement (D146). The app reads what it needs to
check the request, names it, and passes it on. W246 mapped today's paths and
modelled two placements (the vault, or the app with the vault sealing what it
proposes); Erwin chose the vault on 2026-10-28. This page says what is built,
what comes next, and why.

Three pull requests, each leaving `main` shippable, all in 0.15:

| PR | what | Lifecycle.tla's protections it builds |
|---|---|---|
| 1 (T149, W250) | sign-in through a trust binding (`POST /api/auth/oidc` and a workload's `POST /api/workloads/session`), revoke and sign-out, by the vault; the spec | BindingLocked, MemberLocked, SpentChecked, IssueOffFence, RevokeTakesFence, SweepAfterLock (as built already) |
| 2 | a service token, a personal token and a handle, issued by the vault, which weighs the issuer's rights itself | IssuerLocked, IssuerCAS |
| 3 | the vault verifies the CI run's ID token (D148), takes only bindings it sealed, and seals each credential's token hash | VaultVerifiesToken, BindingSealed, HashSealed |

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

1. a retry by request id answers the change it made;
2. the account's row `FOR SHARE`, active at the binding's generation
   (MemberLocked: a removal waits for the sign-in, or the sign-in sees it);
3. the binding's row `FOR UPDATE`, as named: principal, generation, scope,
   policy, not revoked (BindingLocked); and no tombstone;
4. a workload's: no freeze of the instance, the account or the binding;
5. the rate, 60 a minute, counted under the binding's row;
6. the proof's own times (`validUntil`: the ID token's `exp`, its `iat`'s
   hour) and the credential's end, by the database's clock;
7. the token spent, by the primary key of `consumed_tokens` (SpentChecked);
8. the credential inserted with its seal, the binding stamped;
9. the issue lock shared, the change numbered under it (IssueOffFence).

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
with the object's columns and seal and its MAC over the revoked row. The vault
checks the seal is its own (`tampered` otherwise, reported), seals the revoke,
and runs `revoke_credential`: the row `FOR UPDATE` as read (its MAC and seal,
else `moved`, and the app reads again), the fence exclusive, the row's seal its
object's newest change's (else `stale`, reported: a row put back), the update,
the change. The fence is held for the statement's work, never a round trip.

## 3. The model: `formal/Lifecycle.tla`

W246's model compared both placements. It now models the vault's alone, and
more of it: issue, sign-in, unbind, revoke and the seal wait beside uses, a
database writer, and the app's code turned hostile. Every invariant holds with
every protection on; each protection removed breaks the invariant beside it
(`scripts/formal.sh`, `REMOVALS`):

| invariant | says | broken without |
|---|---|---|
| `RevokeOrdersUses`, `NothingAfterRevokeAnswered` | no use allowed is numbered after a revoke; none begun after its answer serves | RevokeTakesFence |
| `UsesNeverWaitOnIssues` (R58) | a use never waits on an issue or a sign-in | IssueOffFence |
| `SignInsTakeNoHead` (R44), `IssuesHoldNoLockBetween` | no sign-in takes 0.14's head; an issue holds nothing between its two statements | (by construction) |
| `SensitiveOnlyFromOwners`, `IssuedByLiveCredential` | rights never widen: a token is numbered before its issuer's demotion and her credential's revoke | IssuerLocked, IssuerCAS (each) |
| `RateHeld`, `SpentOnce` | a binding's rate holds; an ID token buys one credential | BindingLocked; SpentChecked |
| `AllowedAtCurrentGeneration` | removed, an account's credentials end | MemberLocked and UseChecksGeneration (each covers the other) |
| `EndedBindingEndsCredentials` | unbound, a binding's credentials serve nothing after | BindingLocked; SweepAfterLock |
| `AllowedOnSealed` | a row a writer put back, forged or edited serves nothing | SealChecked |
| `AllowedAsPresented` | a use serves the credential whose token was presented | HashSealed and AppChecksMac (each suffices) |
| `SignInsOnValidTokens` | the app's code, hostile, mints no run's credential | VaultVerifiesToken; BindingSealed |

Scenarios: `LifecycleIssue`, `LifecycleSignIn`, `LifecycleReplay`,
`LifecycleUnbind`, `LifecycleForge`, `LifecycleCompromised`, each a few
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
  `SignInsOnValidTokens` that way. So PR 3 also makes a binding a 0.15 object,
  sealed when a manager makes it, and the sign-in takes only a sealed one.

## 4. Decisions

| decision | instead of | why |
|---|---|---|
| the vault decides the credential's object from the binding's columns the app names, and the statement holds them to the row under its lock | the vault reading the binding first | one statement, one round trip; a binding moved meanwhile is refused (`unbound`), and the app asks again |
| the app computes the row's APP_KEY MAC, the vault writes it verbatim | the vault holding APP_KEY | the vault never holds the app's key; the MAC covers id, hash, kind, principal, generation, identity, expiry and revoke, all of which the vault checks or decides |
| the vault's own scope rule (`sealedSessionScope`, `storedScope`, `readScope`) moved to `@coffre/core/access` | the vault trusting the app's scope | one rule on both sides; the app's scope must equal the vault's, or the call fails |
| `validUntil`, the proof's own times, held to in the statement | trusting the app's check before the call | 0.14 checked the token's times again after its wait under the head; the vault does the same, by the database's clock. PR 3 computes it itself |
| `lock_timeout = '1s'` on both functions, refused as busy | waiting | R44: overload refused fast; a burst on one binding waits on its row about 1 to 3 ms a sign-in |
| no 0.14 `token.exchange` entry (D147), and, extending it, no 0.14 `token.revoke` or `sign_out` allow entry: the change records it | the app appending 0.14's entry after the call | the same reason as D147; the change carries who, the binding, the proof, the issuer, the run, a session's key and end, and for a revoke why, the credential it came in on, and whose credential of what kind. Refusals are still 0.14 entries. **For Erwin: reversible** |
| seal the token hash in the credential's object (option (a)), in PR 3 | the app's MAC check alone (option (b)) | with W242's B1 the vault finds a use's credential by its hash, so the hash is a decision input (R53). The model shows each stops a writer who moves a hash; only (a) holds when the app's check does not run. It lands after B1 |
| a workload proof with a `commit` keeps the old path | moving the enrollment's capacity into SQL | no such proof is registered yet |

## 5. Numbers

Debian `postgres:16.14` (R62), local, a compose project of its own, 20 ms
added to every round trip, 1,000 uses a second beside
(`packages/server/test/bench/ci.ts --log 0.15 --signin-only --uses 1000 --rtt 20`).
Before: W246's run of the same bench.

| sign-ins at once | before: p50 / p99 | after: p50 / p99 | uses p99, after | refused |
|---|---|---|---|---|
| 1 | 190 / 192 ms | | | |
| 10 | 763 / 1,374 ms | | | |
| 30 | 1,795 / 3,451 ms | | | |
| 100 | | | | |

## 6. Still open

- **A hostile app.** In 0.15 the app names the caller to the vault, so it can
  act as anyone whose credential hash it reads. PR 3 stops it minting run
  credentials from nothing; closing the rest means the vault taking the raw
  bearer token and hashing it itself. Not decided.
- **The 0.14 audit page under the switch** shows no sign-in, revoke or
  sign-out of the vault's, and no run beside the entries a run's credential
  caused (`withCredentials` reads `token.exchange`). T156 reads them from the
  changes.
- **Still the app's, with `prepare`:** browser and device sign-ins, renewal,
  a member's removal sweep, unbinding, the key rotation's sign-outs.
