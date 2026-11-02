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
             app    one statement: head, fence, hold, write   1 round trip
             vault  waitSealed                                the seal
member add   vault  read                                      1 round trip
                    the Worker decides, builds the rows, their MACs and seals
             app    checks the caller's auth_mac              no round trip
             vault  write, holding the read                   1 round trip
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
  (`levelsAt`): `write_inputs` reads each key's row and current version,
  and `write_request` answers *not served*, and the write takes today's path;
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
   It holds the plaintext. Everything else the front door and the router
   do without the database stays, before any DEK is made: the same-origin
   check on a change a cookie carries (CSRF), the body's and the entries'
   caps, the route's input validation. A new key's insert that meets
   another's (`unique_violation`) asks again, as today. The front door
   answers no refusal of its own that writes a denial today (a token kind
   a route refuses, `token.use`'s denied entry): it sends that request down
   today's path, which writes it, as a named use answers `served: false`.
   An app and a vault of different versions are not served: while both
   Workers deploy, the app answers 503 `deploying` with a short
   `Retry-After` (Erwin, 2026-11-02).
2. **The vault's statement** (`write_request`, a SECURITY DEFINER function
   beside `use_credential`, shaped like it) takes the fence shared and
   then, in one statement after the lock, calls **`write_inputs`** (below,
   "The read and its hold") and records the request, numbered (below, "The
   request and its refusals"). Under READ COMMITTED a statement after the
   lock reads afresh, so the read sees every change committed before the
   fence was held (HotPathOne's "reads are a statement after the lock"),
   and no change is numbered between the read and the request. It commits
   and answers `write_inputs`' answer as it read it. One round trip, and
   nothing held after it.
3. **The Worker** takes the answer's SHA-256 (the read's **digest**),
   which `write_request` returns beside the text, computed by Postgres
   (`sha256` of its UTF-8 bytes), and checks that the text it parses
   hashes to it. `write_inputs` is declared `SET bytea_output = hex`, as
   `use_credential` is, so its text is the same bytes whichever login
   and session settings call it: the vault's request and the app's hold
   hash one rendering. Then it parses the text into one `WriteInputs` value and
   holds each object in it to its newest change (StaleFirst: a row put
   back is refused). It refuses first everything the app would
   (AcceptedFirst, as a named use): the config's `accepts`, the token's
   kind, an ended or expired session, an earlier generation, all at the
   vault's clock. It builds the caller's `Reader` from `WriteInputs`
   (`readerOf`: the account, the credential, the roles object, the places)
   and decides with `decide.ts` (unchanged, still tied to the Lean model),
   the route's checks among its inputs; wraps each DEK, bound to its key's
   owner and decided sensitivity; and prepares each key's change from its
   object as read (`prepareChanges`, in memory, with keys only the vault
   holds), the request and the digest in its MAC'd payload. It answers the
   app: the caller (credential and identity rows, with their `auth_mac`,
   and for an exchanged token its issuing binding's row, with its own),
   each key's id and sensitivity, the envelopes, the prepared changes, and
   the arguments `write_inputs` was called with. Not the read: the app
   never sees the vault's rows.
4. **The app** checks the rows' `auth_mac` in memory (as `named-use.ts`
   does), and for a credential a binding issued (`created_by`
   `binding:<id>`), that binding as `findCredential` does today
   (`standingBinding`: its `auth_mac`, its principal and generation, no
   revocation, no tombstone). Today's `verify` also awaits an UPDATE of
   the credential's `last_used_at`, once every five minutes per
   credential: here it goes into the Sync below, left to `later`, so it
   costs no round trip of its own. Only then it encrypts: the AAD binds `project|environment|key` by
   id (`envelope.ts`), which it learns from the answer. No round trip. Then
   it sends **one Sync**: BEGIN, 0.14's head `FOR UPDATE` (its first
   statement, and kept after PR 6 as a lock alone: see "Locks"), **the
   hold** (`hold_inputs`: the issue lock shared, the fence exclusive, then
   `write_inputs` again, its digest against the changes'), the new rows
   and the key's update, each change through `app_change_strict`, then
   COMMIT. A hold that fails raises `CF001`, Postgres skips the COMMIT, and
   the write asks again from 2 (`ObjectMoved`), carrying the keys it learnt
   are sensitive into the new request: at most three tries in all, then
   409 `changed` (below, "Retries").
5. `waitSealed`, then the answer (R51).

## The read and its hold

Four review rounds of this design each found an input the decision weighed
and the commit did not hold: the fork chain and a reference's source, the
roles, a rename, the environments a whole-project grant weighs as
protected. Each was one more guard on a list kept by hand. So there is no
list. **One function reads what the decision weighs, and the commit holds
that same read.**

### `write_inputs`

`write_inputs(token_hash, project, environment, keys)`, one SQL statement
(a STABLE function: one snapshot), answers one `text`, the canonical JSON
(`jsonb` rendered as text) of:

- **every object the decision weighs**, its row's decision columns and its
  newest change in `log_changes` (number, seal, MAC): the credential by
  its token's hash and its identity, each with every column its app
  `auth_mac` covers (`auth-rows.ts`: the token's hash among them) and the
  `auth_mac` itself, and for an exchanged token the binding that issued
  it, with its tombstone and the columns and MAC `standingBinding` checks
  (its scope is the credential's), the member row and grants, the roles
  and the policy (two objects: a role's definition is `roles`, the
  instance's policy `policy`), the project, the environment and each one
  of its fork chain (an environment's protection is its own object's
  change), each key's row and current version, and the parent keys
  weighed (each a value `replaces`; each inherited key whose level the
  write takes, `levelsAt`);
- **every name and set the decision resolves, as resolved**: the slugs to
  their project and environment, the fork chain, each key's name in each
  environment of the chain to its row or to none, and the dismissals that
  stand. `dev@me` resolves relative to the caller, to their personal
  config of dev by its parent and owner, as 0051's `resolveRead` does; a
  write never lands on dev for it. With no personal config, `write_inputs`
  answers *not served*, and the write takes today's path, which makes one.

Columns nobody decides on (a `last_used_at`) are not in it, so a use
moves nothing the hold compares.

### Why the read is complete by construction

- **The decision takes nothing else.** `decide.ts` (and, for a member add,
  `#standing`, `#setsUp`, `givesService`) gets one `WriteInputs` value as
  its only data. Its other arguments are the request as asked and the
  deployment's config, which no change moves. The type is made only by
  parsing `write_inputs`' answer, so no other query and no isolate state
  (the use path's seal cache, a warm actor) can reach the decision. An
  input a later change needs goes into `write_inputs`, or the decision
  cannot see it.
- **The digest is of the bytes the decision parsed.** Every row, number
  and name in `WriteInputs` is in it. Nothing is left to list.
- **The hold is the read.** `hold_inputs` calls `write_inputs` with the
  same arguments and compares the SHA-256 of its answer to the digest the
  vault MAC'd. One function, two callers: the hold cannot read less than
  the decision did. `hold_names` (round 3) did this for names alone; this
  does it for everything.

The rounds' cases, each now a change of the read:

- **A revoke, a demotion, a role redefined, a policy change** (rounds 1, 2):
  the credential's, the member's, the roles' or the policy's newest
  change moves.
- **The fork chain** (round 1): Ada regenerates `API_KEY` in fork `dev-ada`,
  replacing `dev`'s version 7; meanwhile `dev`'s `API_KEY` is written
  (version 8). `dev`'s key is in the read as a parent key weighed; its
  newest change moves.
- **A rename** (round 3): Ada writes `dev { API_KEY: "new" }`; the vault
  reads `API_KEY` as key S. A maintainer renames it `OLD_KEY`. No object
  changes, but `API_KEY` in dev now resolves to none: the digest differs.
  Without the hold, "API_KEY written" would land on `OLD_KEY`.
- **A key that appears** (round 3): neither `dev` nor `dev-ada` holds
  `API_KEY`; Ada writes it in the fork, weighed at secret. Meanwhile `dev`
  gains `API_KEY`, sensitive. `API_KEY` in dev resolved to none, now to a
  row: the digest differs, and the write asks again, now sensitive.
- **`dev@me`** (round 4): the name resolves to Ada's personal config; a
  maintainer deletes it. It resolves to none: the digest differs.
- **The protected set** (round 5): see the member add below.

### Numbers, not values; the log, not the row

Each object's part of the read carries its newest change's number, from
`log_changes`:

- **No ABA.** Numbers only grow. Ada's grant taken and given back leaves the
  same row and a newer number, so the hold fails and the write asks again.
  Committing on equal values would be right at that instant, but the log
  could not show it: replayed at the write's commit, the member's newest
  change would not be the one its change binds. With numbers, every
  committed write's inputs are, at its commit, at exactly the numbers its
  MAC'd change names.
- **The log, not the row** (R64). A database writer who puts a revoked
  session's row back puts back its columns and its `seal` column, not the
  log's newest change of it, which is the revoke. The hold's read differs
  in the number, and the vault's next read refuses the row (StaleFirst).
  The checkpointer checks each change's MAC before sealing it.

A name has no number. Renamed and renamed back, it resolves as read, and
the write lands where it decided: the AAD binds each value to its key by
id.

### Where the hold runs

BEGIN, 0.14's head, **then the fence, then the hold, then the write's own
rows**:

- **After the head.** Every write that moves a name, a fork chain, a key's
  row or a dismissal (`patchSecret`, `setSecrets`, `missing.ts`'s
  dismissals, a project's or environment's rename) is `audited`, and takes
  0.14's head first. One that committed before ours took the head is in
  the hold's read; one after waits for our COMMIT. One more reason the head
  stays a lock after PR 6.
- **After the fence.** `hold_inputs` takes the issue lock shared and then
  the fence exclusive, as `app_change` does; `app_change_strict` takes them
  again later in the transaction, which an advisory lock allows. Once 0.16
  drops 0047's head from `revoke_credential`, a session's revoke takes the
  fence and not the head: a hold before the fence could pass, the revoke
  commit, and our write after it.
- **In a statement after the locks.** `hold_inputs` takes them, then calls
  `write_inputs` in its next statement: READ COMMITTED reads afresh at each
  statement, so the read sees every change that committed before the locks
  were held. Folded into the lock's own statement, it would read that
  statement's snapshot, taken before.
- **Before the write's own rows.** After them, it would read our new
  version and change, and fail every time.
- **Holding no row.** It reads; it takes no `FOR SHARE`.

### Who may call what

- `write_inputs` reads the vault's rows and the app's: owned by the owner,
  `SET search_path` fixed, `REVOKE ALL … FROM PUBLIC`, granted to no
  login. Its callers are SECURITY DEFINER and run it as the owner:
  `write_request`, granted to `coffre_vault` alone, answers the rows to the
  vault; `hold_inputs` answers nothing.
- `hold_inputs(args, expected)` is the app's: SECURITY DEFINER, `SET
  search_path` fixed, `REVOKE ALL … FROM PUBLIC`, `GRANT EXECUTE … TO
  coffre_app` alone, as 0052's strict wrappers. It answers nothing: it
  returns, or raises `CF001`. The app login reads no row of the vault's
  through it.
- `expected` is the digest the vault MAC'd into each prepared change's
  payload (`inputs`). `hold_inputs` records it for its transaction (a
  transaction-local setting), and `app_change_strict` refuses a change that
  carries `inputs` this transaction's hold did not match. A code path that
  forgot the hold would fail every write, in the suites. This guards
  against our own code. An app login that skips it is a database writer
  (R64), which could write the rows without coffre at all. What it cannot
  do is make a change the vault did not decide: the change and its digest
  carry the vault's MAC, which the checkpointer checks before sealing.

### Cost, flat as the log grows (R48)

`write_inputs` reads the request's objects and names by id and slug, and
each object's newest change by one probe of `log_changes_object_idx`
(`object, number`). No history: an object's past changes are never read. It
costs the same at a thousand changes and at ten million. The hold is one
more such read inside the app's Sync, under the fence. That costs no round
trip; uses wait for it as they wait for `app_change` now, a fraction of a
millisecond. `request-cost.test.ts` holds `write_request` and `hold_inputs`,
like the hot paths, to the same statements and pages however long the log
grows.

### Retries

A hold that fails asks again from step 2: a new request, nothing held
between tries, no lock waited on but the statement's own. At most three
tries in all, as `retrying` gives moved rows now; then 409 `changed`, with
`Retry-After: 1`. A churn that moves a write's read three times in a row
fails fast (R44); it never queues. Each try is two round trips, and each
committed try made exactly two.

## The request and its refusals

The statement records the request, not its outcome (R53), as a use does:
one row per request, naming all its keys, numbered from `log_number`, in a
table of its own beside `log_uses`. Not `log_uses` itself: its row names
one key (`secret`), and `(at, request_id)` is unique there, so a row per
key under the request's one id would collide. The Worker can only MAC what
it knows before the call, and it does not know the ids: it has the token's
hash, not the credential. So the row's MAC covers the request id, the
Worker's clock, the token's hash, and the path and keys **by name, as
asked**. Beside them the row keeps the read itself, as `write_inputs`
answered it, unsealed. Nothing proves from it until a MAC'd record names
its digest: then the replay hashes the stored read, and a match
authenticates every id, number and name in it.

What binds a request to ids is a record the Worker MACs once it has the
statement's answer, as a use's second call writes its MAC'd row:

- allowed and committed: **the change** in `log_changes`. Its MAC (the
  vault's, made by `prepareChanges`) covers every column but the change's
  own number (`log-entry.ts`), so what it binds must sit in one: the key's
  id is its `object`; the request's id and number, the credential's id,
  the identity's and the read's digest ride its payload, as `request` and
  `inputs`, beside `old` (today's `actor` names the principal alone, and a
  session and an API token of one person carry different scopes). Each
  change has a `request_id` of its own: the column is unique, and
  `app_change` refuses a second change under one id (0046, "request %
  names another change"), so one id for a whole patch would abort every
  write of two keys. Each change's id is derived from the request's id and
  the key's (a UUIDv5), not drawn at random as `prepareChanges` does today,
  so that the app can find its own changes again. No extra trip;
- refused, or not done for any other reason (out of time, the key service
  failing): **an outcome record**, the request id, its number, the read's
  digest, the credential's and the identity's ids and the refusal's code, MAC'd by the Worker and written by a
  second vault statement (`write_outcome`). One more round trip, on a
  refusal only: a refusal is not a change, and today `Refusal` pays a 0.14
  deny entry for it;
- allowed but asked again (the hold failed): nothing more; the next try is
  a request of its own.

**A COMMIT whose answer is lost.** The app cannot tell whether it landed.
It does not send the write again: a resend's hold would fail anyway, since
the key's newest change is then our own. It reads the log back by its
changes' ids (`newestCommitted`, as PR 2 does today): found, the write
committed and waits for its seal; not found, it asks again as a new
request. Not found is not proof: the dropped connection's backend may
still be working through the Sync, and commit after the read. Then the
retry's vault read waits on that COMMIT's fence, sees the change, and
writes a second version of the same value under a request of its own. No
guarantee moves (each change was decided and held on its own read, and
each is sealed), and today's path does the same; the cost is a duplicate
version, not a lost or a wrong one.

A request with neither record (the app's statement never ran, the Worker
died) binds no ids: the log says it was asked, by that token's hash, and
nothing more. The replay decides from the bound record, at the request's
number. Example: a database writer edits the credential id in a refused
write's stored read. The read no longer hashes to the digest the outcome
record's MAC names, so the replay refuses it; and an edited outcome record
fails its MAC at the checkpointer.

## A member add

`PUT /members/svc`, Bob's session, with svc's role, its scope and its first
grants or none (`admit` and `setAccess(…, admit)` alike).

**What takes it.** The first add of a principal with no member row, by a
caller with a session or an API token of a member; by a caller who does not
run the instance (no admin, setting up a service account as the services
setting lets them), only with first grants. Such a caller's standing is
`#setsUp`: may they give access at some live place? With a first grant,
that grant's place answers it, and the read holds that place. With none,
only every live place would. Everything else keeps today's path: a
re-admit (an earlier generation, whose end the app writes,
`endPriorMembership`), a role or grant change on an existing member
(`member.role`, the last-Owner checks), a caller through a way in with no
token, a dry run, and a services setting whose newest entry fails its MAC
(today's path pages back, as `#settingsAt` does; the two-trip read takes
the newest entry only).

**The front door** is the write's: served before `authenticate` and the
router, the app reads the token's kind from the token, checks the origin
and the body, and calls the vault with the token's hash, the config's
`accepts`, svc, its role, the role's scope **by slug** (`PUT
/members/:member`'s `scope`, which today the app turns into project ids,
`scopeIds`) and its grants by place name. The vault resolves Bob from the
token's hash and refuses first what the app would (AcceptedFirst). Like the
write's, the front door answers no refusal of its own that writes a denial
today: a personal token on `PUT /members/:member` gets a committed
`token.use` `personal_token` entry from the router (`router.ts`), so the
front door sends it down today's path, which writes that entry. Today
`vault.admit` trusts the `actor` the app authenticated; here nothing the
app says names the actor: the vault resolves Bob from the token's hash, and
the app authenticates that resolution (step 3) before anything is written.

1. **The vault's read** (`admit_read`) calls **`admit_inputs`**, the add's
   `write_inputs`, with the same discipline: the session by its token's
   hash, Bob's member row and grants, the roles and the policy, the
   services setting's newest entry, svc's row (none), each first grant's
   place by its slugs with its environment's object, for a grant on a
   whole project every environment of that project with its object, and
   the scope's projects by slug. Each object with its newest change, each
   name and set as resolved. No lock, nothing written (Lifecycle's issue,
   statement 1).
2. **The Worker** takes the digest, parses `AdmitInputs`, holds each row to
   its newest change (StaleFirst), decides on it alone (`#standing`,
   `#setsUp`, `givesService`), and builds svc's new row and its grants,
   their MACs and seals, and their changes from the rows as read (none),
   the digest in each change's payload. It answers the app the caller's
   credential and identity rows as read, with their `auth_mac` (and an
   exchanged token's binding, as a key write's step 3), and the
   prepared add under one MAC of the vault's own, which the vault checks
   when the add comes back: the app carries it, and can neither change it
   nor make one.
3. **The app** checks the rows' `auth_mac` in memory, and an exchanged
   token's binding, as a key write's step 4 does, and only then hands the prepared add back. A row that
   fails is refused as `authenticate` refuses it today, and nothing is
   written. This is a second call of the vault's Worker (a service
   binding), not of the database: no round trip. The add has no app
   statement to carry `verify`'s `last_used_at` touch, so this path skips
   it: the credential's next use or key write sets it.
4. **The vault's write** (`admit_write`), one statement: both members'
   queue locks and rows in principal order (`lockMembers`), 0.14's head,
   the issue lock shared, then the fence; then, in a statement of its own,
   `admit_inputs` again, its
   digest against the changes'; then the rows, `change_input_strict`,
   COMMIT, the read stored beside the changes as a key write's request row
   keeps it. A mismatch writes nothing and answers `moved`, and the vault
   reads again: three tries in all, then 409 `changed`. svc's row is in
   the read (none): an add that committed first makes it a row, and the
   digest differs. The members' primary key backs it.
5. `waitSealed`, then the answer.

Why step 3 (round 6). The vault holds no key of the app's, and the
credential's seal does not cover its token's hash: only the app's
`auth_mac` binds a token to its credential. Without the check, a database
writer copies the hash of a CLI token they hold onto a live Owner's
credential row, then asks to add their own account as Owner. The vault
resolves the token to the Owner; its read and its hold agree on the
substituted row, so the hold passes, and the vault writes a new Owner,
sealed and MAC'd by its own keys: a forged admin the log vouches for. With
it, the app finds the row's `auth_mac` wrong and nothing is written. A key
write had this check from round 1; the add's two vault statements left the
app out of the path, and the check with it.

**Who the change is by** (round 7). The check vouches for the rows as read,
not for what the token resolves to later, and nothing can make it: a
database writer takes no lock, so they can copy the hash onto an Owner's
row after the hold and before the COMMIT, which the hold, already passed,
cannot see. So nothing after the check resolves the token again: the
prepared changes (a key write's and an add's alike) name the caller by its
credential and identity ids, under the vault's MAC, and the write takes its
actor from them. A substitution after the check changes whom the hash
finds, not whom the change is by. One before the hold moves the digest (the
hold calls `write_inputs` with the hash again), and the request asks again,
where the check refuses it.

**The issue lock before the fence** (round 6). Until PR 6 the add still
appends 0.14's `member.add` entry, and `audit_log_fence`, the trigger on
that append, takes the issue lock shared. Taken after the fence, it could
wait on a barrier holding the issue lock exclusive, which waits for the
fence the add holds. So `admit_write` takes the issue lock shared before
the fence, as `app_change` and `hold_inputs` do.

Example (round 5). Bob, a Developer on all of `market` and no admin, sets
up svc with a developer grant on `market` while the services setting lets
him. `market/prod` is unprotected, so `givesService` holds: Bob has a
developer's rights in every protected environment of `market`
(`protectedWithin`). An Owner then protects `market/prod`. The protected
set is no column of the policy: `readerOf` builds it from the environment
rows (`protectedIn`), and protecting stages `environment.protect` on
prod's own object. Prod is in the read, as every environment of `market`
is for a whole-project grant, so its newest change moves, the digest
differs, nothing is written, and the read again refuses Bob. A fork of a
protected environment made under `market` meanwhile (protected at its
making) adds a row to the set: the digest differs too.

Example. Bob, no admin, sets up svc with a grant at `market/dev` while the
services setting is open; an Owner closes it between the read and the
write. The setting's newest entry is in the read; the write's read
differs; the read again refuses Bob.

**A refused add** writes an outcome record, as a refused key write does:
the request id, the read's digest, the actor's ids and the refusal's code,
MAC'd by the Worker and written, the read stored beside, by a second vault
statement (`admit_outcome`). The read
writes nothing, so without it a refused add would leave no record once
0.14's `member.add` deny entry stops (PR 6). Two trips on a refusal, off
the budget.

A warm vault could skip step 1: the isolate keeps the actor's inputs, as
the use path keeps its seal cache, and the write's hold refuses them if
they moved. That would be one round trip when warm. It is not the design:
it puts isolate state in the decision, the one thing `AdmitInputs` rules
out, and Cloudflare may send the next request to another isolate anyway.

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

formal/Writing.tla checks it (docs/formal.md, "Writing.tla"). Each
protection is a constant; turned off, TLC finds a counterexample:

| protection | turned off, TLC finds |
|---|---|
| the vault's statement reads and numbers in one statement under the fence shared (RequestUnderFence) | `RequestsReplay`: the session read, then revoked, then the rest read and numbered; the Worker allows what the log at the number denies |
| the commit holds the whole read (ReadHeld): the app's statement for a write, `admit_write` for an add | `WritesStandAtCommit`, `AddsStandAtCommit`, `KeyChangesFlip`, `AddsFlip`: every adversary of the scenarios below commits past |
| ... every part of it (`Unheld`, each part left out in turn: the model's stand-in for a `write_inputs` that missed one) | the adversary that moves that part: a revoke, a session's end, a role redefined, a policy change, an archive or protection of the environment or its fork parent, a write of the key a regenerate replaces, a new level on an inherited key, a rename, a key appearing in the parent, `dev@me` deleted, a second write of the key; for an add, a demotion, the setting closed, the grant's place archived or its slug moved, an environment of the project protected, a protected fork made, the scope's project renamed, a second add |
| the decision takes only the read (DecideOnRead) | `WritesStandAtCommit`: the Worker weighs the roles from its isolate's cache; the read and its hold agree, and the role redefined before both is missed |
| the hold runs once the fence is held (HoldAfterFence) | `WritesStandAtCommit`: a session's revoke, which takes the fence and not the head, between the hold and the write |
| the read's objects by the log's newest change, not the row's column (ReadOnLog) | `WritesStandAtCommit`: a revoked session's row put back, live, by a database writer |
| by number, not value (ReadByNumber) | `CommitsReplay`: Ada's grant taken and given back; the write commits on equal values, and the log, replayed at its commit, shows the member changed after the read its change binds |
| the app checks the caller's `auth_mac` on the rows the vault read before anything commits (AuthChecked): a key write's step 4, an add's step 3 | `CommitsAuthentic`: a database writer copies a token hash they hold onto a live Owner's credential; the vault resolves the token to the Owner, its read and hold agree, and a write or an add commits as the Owner (round 6) |
| the change's actor is the checked read's, by id under the vault's MAC; nothing after the check resolves the token again (ActorFromRead) | `CommitsAuthentic`: a database writer, who takes no lock, copies the hash onto the Owner's row after the hold and before the COMMIT (round 7). The model splits the hold from the write's rows and COMMIT for this: nothing that takes the head or the fence comes between, a database writer may |
| a change answers once sealed (WaitForSeal, R51) | `AnsweredSealed` |

Two properties hold besides: `TwoTrips` (a write or an add that committed
at its first try made two round trips; it says what the steps are, it
proves nothing else) and `EveryRequestEnds` (each write and add ends,
committed or refused, within its tries: no retry loops).

**One guarantee is new.** `WritesStandAtCommit` is stronger than today's
code. Today a write decided by the vault before a revoke can still commit
after the revoke has answered: the app's transaction checks the policy
(`policyStill`), not the writer's standing. With the hold under the fence,
a write stands at its commit, not only at its decision, against every
change of what it read. A session's expiry changes nothing in the read: it
is judged at the vault's clock, at the decision, as today. The hold costs
no round trip: it is a statement of the same Sync.

**Locks, in the order Migration015's `NoWaitCycle` already checks:**
- the app's statement: 0.14's head, then the issue lock shared, then the
  fence, then the hold, then its rows. `audited` takes its rows before the
  issue lock and the fence; here they come after, as `app_change` and
  `change_input` already update a key's row (`secrets.seal`) after the
  fence. That waits for nobody: every statement that locks a key's row
  holds 0.14's head first (`audited`, `app_change`, `change_input`), and
  the vault and the uses lock none. The head stays its first statement
  after 0.16 stops the appends, a lock and nothing read: `app_change`
  takes the head again inside, so without it a two-trip write (rows, then
  head) and a route still head-first (`patchSecret`: head, then rows)
  would wait on each other until Postgres kills one. Neither Writing (its
  locks one owner, `head` and `held`, with no row locks) nor Migration015
  (the head first, assumed) would see it;
- the vault's request: the fence shared alone, as a use;
- a member add's write: both members' queues and rows in principal order,
  then 0.14's head, then the issue lock shared, then the fence, then the
  hold, as `change_input` and `lockMembers` lock now (the issue lock before
  the fence: while 0.14's `member.add` append stays, its trigger takes the
  issue lock, and after the fence that could wait on a barrier).

The fence is held from the hold to COMMIT: one read of the request's
objects and names more than `app_change` holds it for now, inside the same
Sync. No round trip is spent while it is held.

**A session's revoke takes 0.14's head too, today.** 0047 put the head first
in `revoke_credential`, to order it against 0.14's checks on isolates still
serving them (Migration015's `EntryLessHead`). The model leaves it out, as
0.16 will once 0.14's path is gone: a revoke that takes the fence alone is
the stronger adversary, and the hold after the fence is what holds then.
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
- **Old isolates' changes, new holds.** Every 0.15 release logs each change
  of a credential, a member, the policy, an environment and a key in
  `log_changes` (through `app_change` and `change_input`). So a revoke or a
  policy change made by an old isolate moves exactly the newest change a
  new hold reads. And its renames and dismissals take 0.14's head, as the
  hold needs.
- **An app and a vault of different versions** are not served together:
  while both Workers deploy, the app answers 503 `deploying` with a short
  `Retry-After` (Erwin, 2026-11-02). Nothing here handles the skew, and the
  model leaves it out.
- **SQLite** holds the whole file per transaction: the same steps run in
  TypeScript inside one transaction, with no round trip to save.

## The PRs

Each with what the key write and the first member add then cost:

1. This design and formal/Writing.tla.
2. **The vault's decisions on seals**, not 0.14's access entries (the
   compatibility step above), so that one statement can read what a
   decision needs. No route's cost moves. Built: `#onLog` in vault.ts
   checks a member as a use does, its row's seal, its newest change's and
   the 0.14 entries that change accounts for (`memberLogs`, read with the
   decision's snapshot); a tampered member is no longer started over under
   0.15's log, which could not seal the row it writes (a reseal does, plan
   PR 9).
3. **The key write's front door, `write_inputs`, `write_request`,
   `write_outcome`, `hold_inputs` and the app's held statement**, with the
   0.14 entries still written. The vault's `key.wrap` entry needs its head
   (a transaction of two trips); the app's statement keeps its head read
   for its own entry's MAC (two). With it: `WriteInputs` as `decide.ts`'s
   only data, `request-cost.test.ts` holding `write_request` and
   `hold_inputs` flat as the log grows, and a regression case per
   adversary of formal/Writing.tla's scenarios (each review round's P1
   among them), each failing with its part of the read left out.
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
5. **The member add's front door, `admit_inputs`, read, write and
   `admit_outcome`**, the scope carried by slug, the app's `auth_mac`
   check between the read and the write (a test puts a known token's hash
   on an Owner's credential row and expects no add; another corrupts only
   an exchanged token's binding's `auth_mac` and expects no write and no
   add, as `authenticate` refuses it today), with the same
   regression cases. Its 0.14 `member.add` entry still needs the head read before its
   MAC: read, head, write, 3 round trips (14 today).
6. **0.16, the contraction.** The two routes stop writing 0.14's entries;
   `revoke_credential` drops the head (a migration); the app's statement
   keeps it as a lock (above). The services setting's changes move into
   `log_changes` with §11's other vault changes, and `admit_inputs` reads
   the setting's newest change there. `change-cost.test.ts` holds a key write to `{ app: 1, vault: 1 }`
   and a first member add to `{ app: 0, vault: 2 }`.
7. **The other change routes**, each in the same shape; references join the
   key write once `write_request` seals their making and their end, and a
   remote key-encryption key once the request and outcome records stand
   for its intent and outcome.

Each PR that changes what a statement reads or holds changes
formal/Writing.tla in the same PR.
