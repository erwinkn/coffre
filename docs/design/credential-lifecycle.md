# The vault owns a credential's life

## 1. What the vault makes and ends

The vault makes and ends these credentials itself, each in one call to it:

- a sign-in through a trust binding: a CI run's (`POST /api/auth/oidc`) or a workload's (`POST
  /api/auth/workload`) for a proof that decides nothing in a transaction (`oidc`, `aws`),
  `Vault.signIn`;
- a revoke or a sign-out, `Vault.revokeCredential`;
- a token's issue, a service token, a personal token or a handle, `Vault.issueToken`;
- making and ending a service's trust bindings, `Vault.changeBindings`.

The app checks the request, builds the row and its APP_KEY MAC (`auth_mac`), names what it read,
and passes it on. The vault weighs it on rows it checks itself, seals the credential's object, and
writes it in one Postgres statement. Why: the app's code, turned hostile, holds APP_KEY and the
app's login, so were these its transactions it could mint any credential. And none of these
statements takes the log's head, which every app write waits for, so a burst of CI sign-ins queues
nothing behind it.

Other credential changes (a browser, device or passkey sign-in, a workload's enrollment session, whose
proof decides its capacity in the transaction, a passkey reset, the key rotation's sign-outs) stay the app's transactions, each change sealed by the vault first
(`AppChanges.prepare`). A vault mid-deploy that does not say it makes, issues or binds (`about()`)
gets those paths too. `formal/Lifecycle.tla` models it all (section 5).

## 2. The sign-in

For a binding of keys its issuer publishes, the app verifies the ID token (one statement: the
service's live bindings, with whether the token was spent); for one of uploaded keys, the vault
does (section 4b). The vault decides the credential's object from the binding's columns the app
names (its scope, and a workload's reads with it: `sealedSessionScope`), seals it, and runs
`sign_in`, one statement:

1. the account's row `FOR SHARE`, active at the binding's generation, its seal its object's newest
   change's (MemberLocked: a removal waits for the sign-in, or the sign-in sees it);
2. the binding's row `FOR KEY SHARE`, exactly as named, not revoked, not closed (BindingLocked).
   Sign-ins through one binding share it and run together; an unbind's `FOR UPDATE` waits for them,
   or they for it (UnbindExclusive);
3. for a workload, no freeze of the instance, the account or the binding;
4. the proof's own times (`validUntil`: the token's `exp`, its `iat`'s hour) and the credential's
   end, by the database's clock;
5. the token spent, by the primary key of `spent_id_tokens` (SpentChecked): each ID token buys one
   credential, and nothing else counts sign-ins; the app's key not one it rotated from;
6. the credential inserted with its seal; the binding's `last_used_at` stamped when a minute old,
   skipped when another sign-in holds that lock (`SKIP LOCKED`, TouchSkipsLocked);
7. the issue lock shared, and the change numbered under it (IssueOffFence).

Then the vault waits for the seal and answers. Every writer takes locks in one order: member row,
binding row, issue lock. `lock_timeout` is 1 s: a sign-in that cannot get its rows by then is
refused as `busy`, 429, at once.

**Revoke and sign-out.** The app reads the row (`liveCredentialsWhere`, its MAC checked), weighs who
may, and calls the vault with the object's columns and seal, its MAC over the revoked row, and the
policy it weighed on. The vault checks the seal is its own (`tampered` otherwise, reported) and runs
`revoke_credential`: the row `FOR UPDATE` as read (else `moved`, and the app reads again), the fence
exclusive, the row's seal its object's newest change's (else `stale`: a row put back), the policy
still the newest and its protected environments' slugs as weighed (else `policy`, 409;
RevokePolicyHeld), the update, the change. The fence is held for the statement's work, never a
round trip. `lock_timeout` is 500 ms here.

## 3. Token issue

Three tokens, each made by a person for an account: a service token (`POST
/api/members/<service>/tokens`), a person's personal token and a handle. The vault weighs the
issuer's rights itself, with `@coffre/core/access`'s rules (`issuesCredential`, `managesService`,
`ownsProject` for sensitive reads; `delegable` and `heldColumns` for a person's own).

The app checks the request, works out the scope (its reads see sensitive values and references,
which the vault does not hold), builds the row and MAC, and makes one call naming the issuer, the
credential the request came in on, the account at its generation, the issuer's access as it weighed
it, and the policy. The vault:

1. reads, in one snapshot, both members with their grants, the newest policy, the instance's
   settings, and the credential the request came in on (`issuing_credential`);
2. checks each row as `access` does (its MAC, its newest access entry), and the credential's seal its
   own and its object's newest;
3. weighs the issue (`weighIssue`). Only what the vault authenticated decides: of the credential the
   request came in on, its object's scope, end and caller, never its row's `kind`, which no seal
   covers. A service token is given by a person, for at most the deployment's
   `services.tokenMaxDays`, a year at most (`MAX_SERVICE_TOKEN_DAYS`). A personal token is made on a
   session, a week at most, with no role that manages access. A handle is `viewer` or `contributor`
   on named environments, a week at most and never past the scoped credential it came in on. Every
   grant's permissions stay within its role as the policy defines it;
4. runs `issue_token`, one statement: the members' rows `FOR SHARE` (IssuerLocked), each still at
   its generation and `access_seq` as read (IssuerCAS); the credential's row `FOR SHARE`, live, its
   seal as read; the issue lock shared, then the policy still the newest (IssuePolicyHeld); the
   app's key not retired; the insert and its change;
5. waits for the seal and answers.

Nothing is held between the read and the write. A write that finds a row moved writes nothing, and
the vault reads and weighs again, three times at most, so a demotion that commits meanwhile is seen.
When the issuer's access moved since the app weighed the scope, the vault answers `access` and the
app answers 409.

## 4. Bindings

A binding is an object of the vault's log (`BindingInput`: the account, its generation, profile,
issuer, keys, claims, scope, policy, `origin`, revoked), which only the vault changes,
`Vault.changeBindings`. Were it the app's row under its MAC alone, a hostile app could write one that
trusts its own key and sign in through it.

- **Making one** is weighed as a service token's issue (`weighService`): a person who manages the
  account, never more than it holds, sensitive reads only from an Owner of the project.
- **Ending one** (an unbind, or the bindings a new one replaces) ends every live credential it
  issued. The app names them, each with its seal and MAC, and the statement holds that set to the
  rows, so one a sign-in made meanwhile is read again.
- **Past `UNBIND_BATCH` (125) live credentials**, the app first closes the binding (`closed_at`,
  which `sign_in` refuses) and revokes them in batches, then ends it. 125 because each revoke holds
  the fence about 0.08 ms and a batch holds it 10 ms at most, so no use waits long behind it; and a
  batch fits half the vault's 8 MiB message. On Workers a request makes at most two such calls of
  114 (`packages/server/src/removal.ts`: 32 invocations a request, 10 ms of CPU a call), then answers
  202 `{ "removing": { "left": … } }`; the client asks again until done, and the scheduled run goes
  on with any binding left closed, as `system:schedule`.
- **A bind holds the account's other bindings** to the set the app weighed it beside (keys moved,
  the `MAX_BINDINGS` cap of 16), under the account's row. One statement, `change_bindings`.

A sign-in takes a binding only when the seal is the vault's own over the columns named (`unsealed`
otherwise, 401 "bind it again"), and `sign_in` holds the row to them and the seal to the binding's
newest change, so a row put back after its end is none. The app still writes `token.bind` and
`token.unbind` entries once the vault's change commits; its own checks read `token.unbind` as a
binding's tombstone.

## 4b. The ID token, verified by the vault where it holds the keys

The vault makes no call to an issuer: a deployment's vault reaches Postgres and, if its KEK is
remote, AWS KMS, nothing else. So who verifies a run's ID token depends on where the binding's keys
come from, which its seal says (`jwks_uri`):

- **Keys uploaded with the binding** (a Kubernetes cluster's, `sha256:<digest>`): the sign-in
  carries the token, and the vault verifies it against the key set whose digest the seal covers
  (`verifyRunToken` in `@coffre/core/identity`). A forged set is refused (`keys`, 401 "bind it
  again"); a key the set lacks, `unknown_key`. The audience, times, claims and the profile's rules
  are held as the app holds them, and what the credential is held to (spend, `exp`, a session's
  end) comes from the token. A compromised app mints nothing through such a binding without a
  genuine token its issuer signed for this instance.
- **Keys the issuer publishes** (GitHub, GitLab, generic OIDC, and other platforms unless their keys
  were uploaded) and AWS signed requests: the app verifies the proof, fetching the issuer's keys
  itself (`packages/server/src/workloads`), and the vault takes its word for it. Everything else the vault
  still decides: the binding is one it sealed and not ended, the account's standing and
  generation, the scope the binding seals, the token spent once.

So the boundary: **a compromised app can mint CI credentials and sessions for an account bound to
GitHub, GitLab, a generic OIDC issuer or AWS, within those bindings' scopes, and for no account the
vault never bound.** Through uploaded keys it needs a genuine token. One it receives that names no
key it can spend for itself: once for a CI run's or a Kubernetes pod's, which are spent once (the
run's own sign-in then fails), and as often as it likes until `exp` for Azure's, which its platform
hands out again (`REPEATING_PROFILES`). A token that names the session's key
(`<origin>#jkt=<thumbprint>`) is useless to any other key.

What stays sealed, whoever verifies:

- **The audience** (AudienceSealed). The binding's `origin` is the instance's public URL when it was
  made (`service_bindings.origin`). The vault verifies a token of uploaded keys against it, and a
  binding made before the instance moved takes no token for the new URL (`audience`: bind again).
  A token for several audiences is refused.
- **The session's key.** A workload's DPoP proof goes to the vault, which verifies it (for
  `<origin>/api/auth/workload`, within a minute) and binds the session to that key, never one the
  app names.

## 5. The model: `formal/Lifecycle.tla`

It models issue, sign-in, unbind, revoke and the seal wait beside uses, a database writer, and the
app's code turned hostile. Every invariant holds with every protection on, and each protection
removed breaks the invariant beside it (`scripts/formal.sh`, `REMOVALS`):

| invariant | says | broken without |
|---|---|---|
| `RevokeOrdersUses`, `NothingAfterRevokeAnswered` | no use allowed is numbered after a revoke | RevokeTakesFence |
| `RevokesOnStandingRight` | a revoke by a right is numbered before that right is taken away | RevokePolicyHeld |
| `SensitiveOnlyFromOwners`, `IssuedByLiveCredential` | an issue is numbered before its issuer's demotion, a policy change against her, her credential's revoke | IssuerLocked, IssuerCAS; IssuePolicyHeld |
| `UsesNeverWaitOnIssues`, `UsesTakeNoIssueLock` | a use never waits on an issue | IssueOffFence; PolicyIssueFirst |
| `SpentOnce` | an ID token buys one credential | SpentChecked |
| `SignInsRunTogether` | a sign-in never waits for another through its binding | SignInsShare; TouchSkipsLocked |
| `AllowedAtCurrentGeneration` | a removed account's credentials end | MemberLocked and UseChecksGeneration (each covers the other) |
| `EndedBindingEndsCredentials` | an unbound binding's credentials serve nothing after | BindingLocked; UnbindExclusive; SweepAfterLock |
| `AllowedOnSealed` | a row put back, forged or edited serves nothing | SealChecked |
| `AllowedAsPresented` | a use serves the credential whose token was presented | HashSealed or AppChecksMac (each suffices) |
| `SignInsOnValidTokens` | the hostile app mints nothing through a binding whose keys the vault holds | VaultVerifiesToken; AudienceSealed; BindingSealed |
| `EverySignInOnValidToken` | ... nor through one of published keys | none: `LifecycleFetched` breaks it with every protection on, the gap section 4b accepts |

A sign-in takes no head, so what keeps an ended binding's credentials dead is the unbind updating
the binding's row before it sweeps, while each sign-in holds that row.

## 6. Decisions

- **The vault takes the binding's columns from the app, and the statement holds them to the row**,
  rather than reading the binding first: one round trip. A binding changed meanwhile is refused
  (`unbound`), and the run signs in again.
- **The app computes the row's APP_KEY MAC, the vault writes it verbatim**: the vault never holds the
  app's key. One scope rule (`sealedSessionScope`, in `@coffre/core/access`) serves both sides, and
  the app's scope must equal the vault's.
- **An issue is a read and one write, not one statement**: the vault must check the issuer's rows,
  MACs included, before it weighs them, and the app's `Access` answer carries no MAC it could take
  back. The write holds what the read decided on (IssuerLocked, IssuerCAS).
- **The issue holds the policy by the issue lock, not the fence**: a use waits on the fence, never on
  the issue lock. A policy change, or a write that moves an environment's slug, takes the issue
  lock exclusive after its rows and before the fence (`holdIssues`).
- **`lock_timeout`, not `NOWAIT`**: overload is refused fast, and `NOWAIT` would refuse a sign-in for
  every unbind in flight. The app's key is checked in the statement, not under the fence: a rotation
  that commits meanwhile leaves a dead credential, never a live one.
- **No app entry for a sign-in, an issue or a revoke**: the vault's change records who, the binding,
  the proof, the run, a session's key and end. Refusals are still app entries.

## 7. Cost

A CI sign-in is 1 app statement and 1 vault statement, reading as many rows however large the
instance grows (`packages/server/test/signin-cost.test.ts`). An isolate takes 32 sign-ins in flight
(`exchangeLimit`), then answers 429 at once. Measured at 20 ms a round trip beside 1,000 uses a
second: 65 ms alone, 128 / 264 ms (p50 / p99) with 30 at once, the uses beside at 25 ms p99.

## 8. Still open

- **The app names the caller to the vault**, so a hostile app can act as anyone whose credential it
  holds. Closing that means the vault taking the raw bearer token and hashing it itself.
- **The token hash is under the app's MAC, not the vault's seal.** The model shows either stops a
  writer who moves a hash (`AllowedAsPresented`), but only sealing it holds if the app's check does
  not run.
- **Published-key and AWS bindings** stay the app's word, the gap of section 4b.
