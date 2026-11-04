# A change in two round trips (T179)

Status: design and model (formal/Writing.tla). The key write's path is built (PR 3, below, "As built: PR 3"), an
admin's first member add (PR 5, "As built: PR 5"), the contraction, in 0.16.0 ("As built: the contraction"), each
now two round trips, and their refusals' records (PR 6, "As built: PR 6"), two round trips too. First grants and a
set-up by someone who runs no instance (PR 5b) follow; the stored request row waits for a replay of writes.

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
   hash one rendering. Then it parses the text into one `WriteInputs` value,
   holds each object's newest change in it to its MAC (`changeHolds`, T190:
   a database writer can write any seal into that change's column, not a
   MAC over it; one that fails is refused `tampered`), and only then holds
   each object to that change's seal (StaleFirst: a row put back is
   refused). The read carries each newest change's every column for this,
   as `memberLogs` does, so the check costs no round trip. It refuses first everything the app would
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
   costs no round trip of its own (a write that then goes down today's
   path writes it on its own first, as `verify` would have). Only then it encrypts: the AAD binds `project|environment|key` by
   id (`envelope.ts`), which it learns from the answer. No round trip. Then
   it sends **one Sync**: BEGIN, 0.14's head `FOR UPDATE` (its first
   statement, a lock alone since the contraction: see "Locks"), the
   credential's `last_used_at`, when due (its row before the issue lock,
   as `issue_token` takes it: see "Locks"), **the
   hold** (`hold_inputs`: the issue lock shared, the fence exclusive, then
   `write_inputs` again, its digest against the changes'), the new rows
   and the key's update, each change through `app_change_strict`, then
   COMMIT. A hold that fails raises `CF001`, Postgres skips the COMMIT, and
   the write asks again from 2 (`ObjectMoved`): at most three tries in
   all, then 409 `changed` (below, "Retries"). A key a try found sensitive
   stays so: a later try that finds it a secret goes down today's path,
   which keeps it sensitive (its `sticky` set; review r1 of #469).
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
  stays a lock after the contraction.
- **After the fence.** `hold_inputs` takes the issue lock shared and then
  the fence exclusive, as `app_change` does; `app_change_strict` takes them
  again later in the transaction, which an advisory lock allows. Were
  0047's head gone from `revoke_credential` (it stays in 0.16.0, below), a
  session's revoke would take the fence and not the head: a hold before the
  fence could pass, the revoke commit, and our write after it. The model's
  revoke takes the fence alone, the stronger adversary.
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

As built in PR 3, and kept as it is by the contraction, PR 6b and PR 7: a hold that fails
(`hold_inputs` raises `coffre_moved`, or a new key's name is taken first)
rolls the app's transaction back and asks the vault again, three tries in
all, then 409 `changed` with `Retry-After: 1`. A try the vault no longer
serves takes today's path instead of a fourth trip, as a first read it does
not serve does: a refusal, an object other than the caller's credential
not as its log has it (StaleFirst, `stale`; a newest change whose MAC fails,
`tampered`), a key this path does not write (`shape`). So does a try whose
read found the place's slugs at another environment than the first's (a
rename, and another environment made under the old name: a try asks by
slugs, and the route writes to the first's ids), and a try that finds a
key a secret that an earlier one found sensitive (review r1 of #469). That
path decides at the vault, as it always has, and its transaction commits
on that decision, weighing again only the policy the caller was loaded
with (`policyStill`: a role redefined or the policy changed since, 409
`policy_changed`), the environment and the key's row; it answers and logs
as it always has (formal/Writing.tla, `WToday` and `WTodayCommit`). A
grant revoked or a session ended between its decision and its commit does
not stop it, the window every write has had since 0.14
(`TodayStandsAtCommit`, an expected gap in `scripts/formal.sh`), which this
path closes for the writes it serves. PR 6b's outcome record moves only
the refusals off it; what the two-trip path does not serve (forks until
PR 3b, references and a key service until PR 7, SQLite) keeps it.

The caller's own credential never goes down today's path. Not as its log
has it (a row put back, its newest change's MAC broken: `forged`), or
revoked or expired at the vault's clock (`ended`): 401, as today's path
answers a credential it finds ended, there and then. Today's path reads
the row again and holds it to its `auth_mac` alone, so a session revoked,
then put back by a database writer between the two reads, would pass it.
Both come before every other refusal, a missing environment's too: one
the vault refused for its place first would go down today's path, which
answers 404 for that session put back.

Once a request has gone down today's path, nothing rechecks the caller's
session: the path goes on with the caller the request authenticated (the
first try's read, or the credential's own check when the first try was not
served), and the vault's wrap weighs the caller's member and grants, not
the session. So a session revoked after that check still writes. Example
(review r2 of #469): the first try is served; Ada's grant is taken, so the
hold fails; the retry is refused; her grant is given back and her session
revoked; today's path then writes version 2, 200. Today's front door has
the same window between its check and its wrap; after a served try it
spans those tries too, a few round trips. `write-held.test.ts` pins this
(it flips once no write goes down today's path), and formal/Writing.tla's
`TodayCallerStandsAtDecision` is an expected gap (`WritingCaller`).

What an abandoned try leaves behind, with nothing waiting on it:

- **its number**, drawn from `log_number` by `write_request`: a gap in the
  log, which a checkpoint seals past as it does a rolled-back change's;
- **before the contraction, its 0.14 `key.wrap` entries**, one per key, committed by the vault
  before it answered (0.16.0 writes none): records of wraps that were
  made, each an allowed key operation with no intent left open, which no
  `secret.write` names. The committed try's `secret.write` names its own
  try's wrap (`relatedSeq`), and a request writes once whichever path
  commits it (`WritesNameTheirWrap`, `OneWritePerRequest`). Today's path
  leaves the same: one `key.wrap` per try of its sixteen, and one for any
  write that fails after its wrap;
- **its changes, prepared and MAC'd, never written**: the app's
  transaction rolled back, and they name a request no record binds;
- nothing else: the vault's statement reads and numbers, it writes nothing,
  and a try it does not serve wraps nothing and appends nothing.

`write-held.test.ts` holds each case against a vault that serves no
`writeKeys`: a refusal the read finds (a forged change, a row put back) is
answered with today's status and body and adds exactly today's entries; a
served try abandoned at its hold, then refused StaleFirst, adds its one
`key.wrap` and then exactly today's entries; one abandoned, then not served
(the key made a reference meanwhile), writes once down today's path, its
`secret.write` naming that path's wrap, and the audit verifies.

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
  deny entry for it. As built (PR 6, "As built: PR 6"): for a refusal of the decision's, a row of `log_changes`
  of the request's own object, written by `log_refusal` once the app has checked the caller's rows; the request
  row it would bind is not stored yet;
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
2. **The Worker** takes the digest, parses `AdmitInputs`, holds each newest
   change to its MAC (`changeHolds`, T190, as a key write's step 3) and each
   row to its newest change's seal (StaleFirst), decides on it alone (`#standing`,
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

**The issue lock before the fence** (round 6). Until the contraction the add
appended 0.14's `member.add` entry, and `audit_log_fence`, the trigger on
that append, takes the issue lock shared. Taken after the fence, it could
wait on a barrier holding the issue lock exclusive, which waits for the
fence the add holds. So `admit_write` takes the issue lock shared before
the fence, as `app_change` and `hold_inputs` do, and keeps that order with
no append.

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
0.14's `member.add` deny entry stops (PR 6b; until then a refusal goes down
today's path, which appends it). Two trips on a refusal, off the budget.

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
contract the 0.15 plan already planned (0.15-plan.md, "11. The contract, in 0.16"), made by the contraction in
0.16.0 for these two routes ("As built: the contraction"); the request's own record is PR 6b's.

**The audit pages have to read them first.** Today the sealed pages render
sign-ins only (`sealedPage`), a place-filtered page never reaches the log,
and an offboarding report's "wrote" side reads `secret.write` entries
(`queries.ts`). Stopping the appends before that changes would lose records:
a removed member's report would stop naming the values they wrote. So the
pages render writes and member adds from the log, place filters included,
and the offboarding report reads its "wrote" from the log, in the same
change that stops the appends (§11's own precondition: readers leave
`audit_log` first, at the latest with the writers; D169 put both in
0.16.0). Refusals keep today's path and its 0.14 entries until PR 6b's
outcome records.

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
| the Worker holds each newest change it read to its MAC before StaleFirst weighs its seal (ChangeMacChecked, T190) | `WritesStandAtCommit`, `AddsStandAtCommit`: a revoked session's row, or a demoted adder's, put back with its seal written into the log's newest change of it; row and log agree, the hold agrees, and the write or the add commits |
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
- the app's statement: 0.14's head, then (as built in PR 3) its
  credential's row, the last use's UPDATE when due, then the issue lock
  shared, then the fence, then the hold, then its rows. The credential's
  row before the issue lock, as `issue_token` (its row shared, then the
  issue lock) and `revoke_credential` take it: after them, the write would
  hold the issue lock and wait for an issue's share of the row, that issue
  queued for the issue lock behind the checkpointer's barrier, which waits
  for the write's: a cycle Postgres breaks after `deadlock_timeout`, the
  fence held and every use waiting meanwhile (review r1 of #469;
  formal/WriteLocks.tla, which models the lock queue). `audited` takes its rows before the
  issue lock and the fence; here they come after, as `app_change` and
  `change_input` already update a key's row (`secrets.seal`) after the
  fence. That waits for nobody: every statement that locks a key's row
  holds 0.14's head first (`audited`, `app_change`, `change_input`), and
  the vault and the uses lock none. The head stays its first statement
  now the contraction has stopped the appends, a lock and nothing read: `app_change`
  takes the head again inside, so without it a two-trip write (rows, then
  head) and a route still head-first (`patchSecret`: head, then rows)
  would wait on each other until Postgres kills one. Neither Writing (its
  locks one owner, `head` and `held`, with no row locks) nor Migration015
  (the head first, assumed) would see it;
- the vault's request: the fence shared alone, as a use;
- a member add's write: both members' queues and rows in principal order,
  then 0.14's head, then the issue lock shared, then the fence, then the
  hold, as `change_input` and `lockMembers` lock now (the issue lock before
  the fence: while 0.14's `member.add` append stayed, its trigger took the
  issue lock, and after the fence that could wait on a barrier; the order
  stays, the head a lock alone).

The fence is held from the hold to COMMIT: one read of the request's
objects and names more than `app_change` holds it for now, inside the same
Sync. No round trip is spent while it is held.

**A session's revoke takes 0.14's head too, in 0.16.0 still.** 0047 put the
head first in `revoke_credential`, to order it against 0.14's checks on
isolates still serving them (Migration015's `EntryLessHead`). 0.14.5's
isolates may serve beside 0.16.0: an upgrade straight from 0.14.5 rolls out
over them, and a rollback to 0.14.5 serves reads and uses. So the revoke
keeps the head, as the two-trip write and add keep it as a lock
(formal/WriteLocks.tla's revoke: the head, the row, the fence). It may go
once no release that meets 0.14.5 is supported. The model's revoke leaves it
out: one that takes the fence alone is the stronger adversary, and the hold
after the fence is what holds against it.

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
  release that still writes 0.14's entries. AGENTS.md would stop the
  appends one release later; 0.16.0 stops them in the same release (D169,
  Erwin's call). Isolates of an earlier release still serve beside it,
  while it rolls out (each app with a vault of its own release: the app
  answers 503 `deploying` to another's, below) and after a rollback: they
  serve the members they knew, and refuse, failing closed, a member 0.16.0
  added. That is the price (docs/deploy.md, "From 0.14.5 to 0.16"); and why
  0.16.0's changes still take 0.14's head ("A session's revoke takes 0.14's
  head too"). That move comes before `write_request` too (PR 2, below): the
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
   the 0.14 entries that change accounts for, and that change's MAC too,
   as a use does since T190 (`memberLogs`, read with the
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
   Key write: 1 + 2 + 2 = 5 round trips (16 today). Built without
   `write_outcome` and the request row, which come with PR 6b: a refusal
   takes today's path meanwhile ("Retries"). See "As built: PR 3" below,
   for what it serves and what it leaves to later PRs.
4. **The audit pages, the offboarding report and the members' watermark
   read the log**: writes, their refusals and member changes, place
   filters included; and `memberAccess`, `missingMembers` and
   `tamperedMembers`, which take a member's newest 0.14 access entry
   (`ACCESS_ACTIONS`: `member.add`, `access.grant`, …) as the newest
   legitimate change against a `vault.tampered` finding, take the
   principal's newest change in the log instead. Otherwise, once the adds
   stop appending, the watermark freezes, and a member added later with any
   later finding reads tampered for good. After it, nothing reads these
   routes' 0.14 entries. Split in two (D166): PR 4a, the members' watermark
   ("As built: PR 4a"); PR 4b, the audit pages and the offboarding report
   on the log, landed with the contraction (6, "As built: the
   contraction"); the refusals of outcome records with PR 6b.
5. **The member add's front door, `admit_inputs`, read, write and
   `admit_outcome`**, the scope carried by slug, the app's `auth_mac`
   check between the read and the write (a test puts a known token's hash
   on an Owner's credential row and expects no add; another corrupts only
   an exchanged token's binding's `auth_mac` and expects no write and no
   add, as `authenticate` refuses it today), with the same
   regression cases. Its 0.14 `member.add` entry still needs the head read before its
   MAC: read, head, write, 3 round trips (14 today). Built for an admin's first add, a
   person's or a service account's, with no first grants and without `admit_outcome`
   (a refusal takes today's path, as PR 3's): "As built: PR 5". First grants and a
   set-up by someone who runs no instance (the read holding the places, the protected
   set and the services setting, as the steps above have it) are PR 5b, with
   the services setting's changes moved into `log_changes` beside §11's
   other vault changes, `admit_inputs` reading its newest change there.
6. **The contraction, in 0.16.0, with PR 4b.** The two routes stop writing
   0.14's entries; the app's statement, the add's write and
   `revoke_credential` keep 0.14's head as a lock (above).
   `change-cost.test.ts` holds a key write to `{ app: 1, vault: 1 }` and a
   first member add to `{ app: 0, vault: 2 }`. The audit pages, the
   offboarding report and the list of everyone read the two routes'
   changes in the same PR. The retry loop stays as PR 3 built it. AGENTS.md
   would ship it a release after one that still writes 0.14's entries;
   Erwin put it in 0.16.0 itself (D169), and a rollback to an earlier
   release refuses the members it added. "As built: the contraction".
6b. **The request row and the outcome records.** `write_request` stores
   the request ("The request and its refusals"), and a refusal is answered
   and logged by the vault's outcome record (`write_outcome`,
   `admit_outcome`), no longer by today's path and its 0.14 deny entries;
   the audit pages list those refusals. Built as PR 6, the outcome records alone, for the refusals of the
   decision's: "As built: PR 6". The request row waits for a replay of writes, which would read it.
7. **The other change routes**, each in the same shape; references join the
   key write once `write_request` seals their making and their end, and a
   remote key-encryption key once the request and outcome records stand
   for its intent and outcome.

Each PR that changes what a statement reads or holds changes
formal/Writing.tla in the same PR.

## As built: PR 3

The key write's path, on Postgres (`write_inputs`, `write_request` and `hold_inputs`, migration 0061; the vault's
`writeKeys`, packages/vault/src/write.ts; the app's front door, packages/server/src/write-ahead.ts, and its held
statement, `heldWrite` in api/secrets.ts). `change-cost.test.ts` holds a key write, one key or five, new or not, to
`{ app: 2, vault: 3 }` (16 and 20 before):

```
vault  write_request: the fence shared, then the read, app_read's rows and the number       1
       the Worker: each newest change's MAC, each row's seal, the decision; wraps, prepares
       0.14's key.wrap entries: BEGIN + the head | the append + COMMIT                    2
app    the rows' auth_mac, in memory; each value encrypted
       BEGIN + 0.14's head and its read                                                   1
       hold_inputs | the rows | the versions | 0.14's entries + the changes | COMMIT     1
vault  waitSealed                                                                         the seal
```

What it serves, and what keeps today's path, `served: false` (the app writes as before, which answers and logs it):

- **The patch**: values, given or generated (no key pair), saying nothing of who sees them. Not a marking, a
  reference, an archive, a plain or sensitive value asked for, a dry run.
- **The place**: an environment of its own. Not a fork, nor `dev@me` (PR 3b: `write_inputs` reads the fork chain,
  its parents' keys and the personal config by its owner, as round 1 and 4 have it). Not an archived or deleted one.
- **The keys**: none yet, or a live value of the place's own, secret or sensitive. Not an archived key, a
  reference, a plain value (its object binds its text, which the read leaves out), or a regenerate whose version
  moved since it was listed.
- **The caller**: a session, a CLI login, a personal or a service token, its config accepting it, not ended at the
  vault's clock. Not a token a trust binding issued (its binding is the app's to check, a read of its own), a
  workload's, a handle's, an MCP connection's or Cloudflare Access's.
- **The vault**: 0.15's log, cut over, on Postgres, its key-encryption key in memory (`about().writes`). SQLite's
  writes keep today's path: one transaction, with no round trip to save.

What it does not build yet, and why that is sound meanwhile:

- **No request row, no outcome record.** The statement numbers the request from `log_number`, in the read's own
  statement under the fence (RequestUnderFence), and each change carries that number, the credential and identity
  it was decided for and the read's digest in its payload, under the vault's MAC. The stored read and the outcome
  record (`write_outcome`) are for the replay of a decision and for the audit pages' refusals, which read 0.14's
  entries until PR 4 and PR 6b. So every refusal, a vault's, a seal's or a MAC's, goes down today's path, which
  refuses and logs it as now: a refusal costs today's trips, and the vault's `writeKeys` call before them (R64
  allows a refused request's extra trips). Its status and body are today's, pinned by `write-held.test.ts`. A
  forged change's refusal relies on today's path checking MACs too: T190 (#466), which this PR builds on
  (formal/Writing.tla, `TodayChangeMacChecked`).
- **A caller's credential revoked or expired is refused 401 there and then** (`ended`), as today's path answers
  it: sent down that path, its second read would take a row put back meanwhile.
- **A caller's credential not as its log has it is refused, never sent down today's path** (`forged`, 401): a
  session revoked and its row put back whole carries its `auth_mac`, which `findCredential` alone would take. So
  the two-trip write refuses it where today's path would not, on both engines (reported with T179 PR 3).
- **A retry that finds the credential ended answers 401** rather than going down today's path, which would go on
  with the caller the first try checked.
- **A retry whose read found the place elsewhere, or a key less sensitive, goes down today's path**: its read and
  decision are of another environment than the one the route writes to, by its ids, or it would write a key looser
  than an earlier try found it (review r1 of #469). A regenerate whose `replaces` is no version's id goes there
  from the front door, which today's path answers 409 `stale`.

The regressions (packages/server/test/write-held.test.ts) make each adversary of Writing.tla between the vault's read
and the app's hold, through the real front door: a revoke, an end, a rename, a key appearing sensitive, an archive, a
second write, a grant taken and given back, a hold that keeps failing (409 after three tries), a forged seal
(WritingForge), a row put back (dbw), a token hash moved (sub), the environment renamed and another made under its
name, a key sensitive at the first try and a secret at the next; and one that the read's digest moves with each.
packages/vault/test/write-cost.test.ts holds both statements' buffers flat from 10k entries to 1M.

## As built: PR 5

An admin's first member add, on Postgres (`admit_inputs`, `admit_read` and `admit_hold`, migration 0062; the vault's
`admitRead` and `admitWrite`, packages/vault/src/admit.ts; the app's front door, packages/server/src/admit-ahead.ts,
and `admitHeld` in api/members.ts). `change-cost.test.ts` holds a first add, of a person with or without a role and of
a service account, to `{ app: 0, vault: 3 }` (14 before; at 20 ms a round trip, the seal apart, about 80 ms against
320):

```
vault  admit_read: the read, and app_read's rows of the caller, one snapshot, no lock          1
       the Worker: each newest change's MAC, each row's seal, the decision; the add prepared
app    the rows' auth_mac, in memory; the prepared add handed back
vault  BEGIN + the members' rows + 0.14's head and its read                                    1
       admit_hold | 0.14's member.add | the row | the change | COMMIT                         1
       waitSealed                                                                              the seal
```

What it serves, and what keeps today's path (`served: false`: the app adds as before, which answers and logs it):

- **The add**: the first of a principal no row names, a person with an instance role and its scope or none, or a
  service account with neither. Not first grants (`access`, PR 5b); not a re-admit, a role change, a member the
  deployment's config names (its Owners'), a `member` role with a scope (whose projects the route still resolves,
  404 on one it does not find).
- **The caller**: someone who runs the instance (`runsInstance`: an admin or an Owner of all of it, no credential
  scope), by a browser session or a CLI login, its config accepting it, not ended at the vault's clock. Not someone
  who sets a service account up as the services setting lets them (PR 5b); not a personal token (the router refuses
  it this route, logged), a service's token (no instance role), a token a trust binding issued, Cloudflare Access.
- **The vault**: 0.15's log, cut over, on Postgres (`about().admits`). SQLite adds as before: one transaction.

How it holds, and what it leaves to later PRs:

- **The read holds the caller's session**, as a key write's does (formal/Writing.tla, the add's `cred`): a session
  revoked between the read and the write moves the digest, and the read again answers 401, as does one revoked or
  put back before the read (`ended`, `forged`), never sent down today's path. So is a session of the caller's
  membership before a removal, its generation not the row's (`credentialEnded`), whose own row says live until the
  app's sweep revokes it: Bob removed and restored as an admin between two tries adds nothing with his old session
  (`WritingRejoin`, review r1 of #474).
- **The caller's row is held to its 0.4 MAC too**, before its seal, as today's path holds it (`#integrity`): the MAC
  covers columns the 0.15 object does not (`created_by`, `status_changed_by`), so a row edited in those alone is
  `tampered` and goes down today's path, which answers 401. A key write's read (PR 3) checks it the same way, through
  the same caller helpers (review r1 of #474).
- **The prepared add is a ticket**: the vault's MAC (its change key's, domain-separated from every log MAC) over
  what the write writes, the read it holds (its arguments and digest) and who the add is by, by ids, the credential
  and identity the checked read resolved (ActorFromRead). The app carries it from the read to the write and can
  neither change it nor make one; the write takes it for 30 seconds. The writing isolate may not be the reading
  one, nor run the same config (a rollout between the calls, the same keys): it settles its keys as `admitRead` does,
  and leaves an add of a member its own config names an Owner to today's path (`unserved`), whatever the ticket says
  (review r1 of #474).
- **The write's locks**: the members' rows, then 0.14's head, in the write's first statement, as every flow that
  takes both takes them (formal/WriteLocks.tla, `AddLocks`, MembersFirst: the head first waits in a circle with a
  demotion); then `admit_hold` takes the issue lock shared and the fence, as `change_input` does, and holds the read
  after them. A hold that fails writes nothing (CF001, the transaction rolled back); the app reads again, three
  tries in all, then 409 `changed` with `Retry-After: 1`. The head held by another, the write waits for it within
  the lock bound, as today's add does, not in one of the reads' places in line (`READ_HEAD_WAITERS`), which a burst
  of reads may all hold, and which would refuse it at once, 503. So does a key write's `key.wrap` append (PR 3)
  (Fable's review of #474).
- **Two adds of one member**: the second's hold finds the first's row, its change and its 0.14 entry; read again, it
  is no first add, and today's path answers it as it answers an add of a member (`created: false`). The members'
  primary key backs it: a unique violation is read again too.
- **No outcome record** (`admit_outcome`, with PR 6b's `write_outcome`): every refusal goes down today's path, which
  refuses and logs it as now, after the vault's read (R64 allows a refusal's extra trip). Its status and body are
  today's, pinned by `admit-held.test.ts`.
- **No last use**: the add has no app statement to carry the credential's `last_used_at`; its next use or key write
  sets it, and an add that goes down today's path writes it on its own first, as `verify` would have.

The regressions (packages/server/test/admit-held.test.ts) make each adversary of Writing.tla's add between the vault's
read and its write, through the real front door: the adder demoted, their session revoked, the roles redefined,
another add of the member first, a hold that keeps failing (409 after three tries); before the add, a session revoked
and its row put back (dbw), the adder's row put back and its seal written into the demotion's change (WritingForge),
a token hash copied onto an Owner's session (sub), the adder's row edited in its `created_by` alone; the head held,
with every place in the reads' line, when the write comes (and when a key write's wrap does); the adder removed
and restored between the tries, his session's row not yet revoked (WritingRejoin); a ticket edited, or written by a
vault whose config names the member an Owner; a change naming a read its transaction did not hold; and one that the
read's digest moves with each. Each fails with its protection taken out. The refusals (a
caller who runs no instance, a project no slug names, an Owner asked of an admin) answer as a vault that serves no
`admitRead` answers them. packages/vault/test/write-cost.test.ts holds both statements' buffers flat as the log grows
by a million entries (R48).

## As built: PR 4a

The members' watermark, without 0.14's entries (packages/db/src/grants.ts; formal/Findings.tla). Under 0.15's log a
`vault.tampered` about a member's row (`mac`, `stale`) names, in its metadata, the member's newest change its check
weighed, by the change's MAC: `{"change": "<32 hex digits>"}`, "none" for none (`changeName`). A check that read the
member's log (`#onLog`, and `#integrity`, whose 0.4 MAC's finding now reads the log first, the read `#onLog` makes
anyway) passes the change it read; one that read none (a grant written in during a decision, `#seal`; a change
refused, `#notLogged`) has the newest read as the finding appends (`#weigh`), one statement for all of them, and only
then: no route's cost moves.

The rule (`findingStands`): a member's findings stand while one of them names their newest change, or while their
newest finding of 0.14's (none named) is newer than their newest access entry. Any finding, not the newest alone: two
checks commit in an order of their own (Findings.tla, EveryFinding). A change after the one it names is one the vault
made only once its own check passed the row: what clears it, as 0.14's access entry did, and what the contraction still writes.

By the change's MAC, not its number (review r1 of #476). A change's MAC covers every column but its number, which a
database writer can change (`changeHolds`; rotations name theirs in their payload for that reason). Weighed by number,
as this PR first did, a finding about Ada naming change 52 would settle once the writer renumbered that same change to
1,000,000, with no change since; or, renumbered up before the check and back after, would name 1,000,000 and stand
past every change she will ever have, removal included. Named by MAC, renumbering moves nothing: the finding stands
until her newest change is another one. A name no change of hers bears (forged, or a JSON number) never names her
newest, so it settles at once, or, not a JSON string, is 0.14's to the keyless readers. What a name cannot see is an
older change of hers put back above the newest, whole, its MAC intact: the vault's check then finds her row stale and
refuses, and a finding naming it settles once the log is put right; the checkpoints catch such an entry
(docs/design/merkle-checkpoints.md, (a) and (f)).

Read by:

- **`tamperedMembers`**, the list's and `coffre migrate`'s: the findings grouped by member and the change they name,
  the newest of 0.14's by seq, then for those named the newest access entry and the newest change's MAC, one probe each
  (`newestChangeNames`, `log_changes_object_idx`, R48).
- **`memberAccess`**, the member page's one statement: the same, as subqueries beside the row.
- **`reportStands`**, the vault's conversion, each finding as the vault's MAC tells it from one forged in its name:
  those of 0.15's naming the change the decision just checked the member's row against (`#standing`'s log: its MAC,
  and the row's seal against it), not a newest read again, then those of 0.14's after the newest access entry. The rule
  is the same as `coffre migrate`'s so that the two never disagree.
- **`missingMembers` of one member**: no row, and a change of theirs in 0.15's log or an access entry of 0.14's, as
  `#onLog` weighs both. Nothing asked it of one member: the member's report (`memberReport`) now does, when the list
  of everyone has no such member, so that a member added after the contraction, their row gone, reads tampered there, not 404.
  The list of everyone finds the rowless by 0.14's entries still: a change's object names its member by a hash alone,
  which a scan cannot turn back into a principal (PR 4b).

The same row found again after a change is another finding: the vault's once-per-process key includes the change
weighed, where it had left the second unlogged. A finding of 0.14's that stands when a deployment takes the contraction is
settled as before by the member's next change: 0.16.0 stops the access entry of a first add alone, of someone with no
row, and every other change of a member still writes one (docs/formal.md, "Findings.tla").

The regressions: packages/vault/test/vault.test.ts (a finding names the change its check weighed and stands until a
change after it, the same row then found again; settled by a change whose 0.14 entries are taken out, as the contraction
writes none; two findings committed out of the order they read in, and one forged naming the next change, which only the
vault passes over; forged names, a number and a JSON number, none of which stands past the next change; the change a
finding names renumbered up for its check and back, and up after it, the finding standing until the next change, then
settled), packages/vault/test/bindings.test.ts (a finding from `#notLogged`, named as it appends), and
packages/server/test/tamper-watermark.test.ts (the list, the member page and the report agree, through a renumbering
of the change named, a change settling them with its 0.14 entries gone; a member with a change and no row reads
tampered in their report). Each fails with its protection taken out.

## As built: the contraction

In 0.16.0 (D169), with PR 4b's readers. On Postgres with 0.15's log, the two-trip key write and the two-trip first add
append no 0.14 entry: the vault's `key.wrap` and `member.add` and the app's `secret.write` are gone from those paths,
and their changes in `log_changes` are their record. `change-cost.test.ts` holds a key write, one key or five, to
`{ app: 1, vault: 1 }` (2 + 3 in PR 3, 16 before) and a first add to `{ app: 0, vault: 2 }` (3 in PR 5, 14 before):

```
key write   vault  write_request: the fence shared, then the read and the number            1
                   the Worker: MACs, seals, the decision; wraps, prepares the changes
            app    the rows' auth_mac, in memory; each value encrypted
                   BEGIN, 0.14's head (a lock alone), the last use when due, hold_inputs,
                   the rows, the versions, the changes, COMMIT                            1
            vault  waitSealed                                                              the seal
first add   vault  admit_read                                                              1
            app    the rows' auth_mac, in memory; the prepared add handed back
            vault  BEGIN, the bound, the members' rows, 0.14's head (a lock alone),
                   admit_hold, the row, the change, COMMIT                                 1
                   waitSealed                                                              the seal
```

**What a change records now.** Its payload names, under the vault's MAC, the request it was decided on: for a key
write its number, the credential and identity, the app's operation and request ids (`operationId`, `requestId`,
which 0.14's entries carried) and the read's digest; for an add the same but the number (its read numbers nothing),
and no `old`, as no 0.14 entry accounts for it. The add's row stores `access_seq` 0: under 0.15's log nothing weighs
the column against an entry (`#onLog` weighs the member's newest access entry against their newest change, and a
first add has neither); a later change down today's path writes its entry and moves the column, as before.

**Who reads them.** Each reader of the two routes' 0.14 entries now reads the changes, every other route's entries
as before:

- **The audit pages** (`sealedPage`, asked with `sealed`): a key write where its `secret.write` stood, on the whole
  log, its project's, its environment's (deleted ones among a project's), its key's and its writer's pages, and to a
  reader of some places at those places (`writtenAt`: the page's place met with the reader's `within`); a first add
  where its `member.add` stood, on the instance's pages alone, as every record of no place. Each is the vault's,
  vouched for as every record of 0.15's log a page lists (`vouched`), and named after it is read: the key, its place
  and its version's number by id (`withNames`), so a key renamed since shows its name now, and one deleted its id
  alone. Two record kinds of change-records.ts tell them apart from every other change by how their payload starts and
  the read it names (`written`, `admitted`); eight partial indexes over them (migration 0065: every one, one actor's, one
  environment's by the payload's `environmentId`, one key's, one actor's at one environment or key; and the adds', every
  one and one actor's) keep a page to as many index entries as it lists, however long the log grows (R48;
  `request-cost.alone.ts`). Of some members at a place, a read of each one's there (review r1 of #490): one of the
  place's, others' passed over, grew with their writes there. And statistics on the conditions' `strpos(…)`
  (`log_changes_records_stats`), which ANALYZE measures: Postgres's guess for them made a key with 50,000 writes look
  like 80, and read them all to sort a page (3,680 pages) rather than walk its index; statistics, not a planner
  setting (R69).
- **The offboarding report** (`memberActivity`): a member's key writes from the log beside their entries and reads,
  one more statement beside its first reads, no round trip.
- **The list of everyone's missing members** (`missingMembers`): those a two-trip add named in its payload, their
  row gone, beside those 0.14's entries name.
- **`coffre verify`** (`verifyLog`, `#partlyReplayed`): with no two-trip add in 0.15's log, as before. With some
  (`fastAdded`, `log_changes_admitted_idx`), every row still names the newest 0.14 access entry about the member (0
  for one added so and changed no further); everyone else is replayed from 0.14's access entries as before; those
  added so are held to 0.15's log, as `#sweep` holds them (`#integrity`: the 0.4 MAC, the row's seal against its
  newest change, that change's MAC, no 0.14 access entry past the one it accounts for), a deleted row included. A
  later change of one of them down today's path (a removal, a role change) is a change 0.14's replay never saw the
  member admitted for: the walk stops there (`unadmitted-change`, which a checkpoint's tally keeps, as it follows from
  0.14's log alone), and past it every row, and everyone the walk saw an entry about, is held to 0.15's log instead.
- **Conformance**: a version's record is its app entry or its key's change, never both (`writesAgree`); an add is a
  vault entry or the vault's change (`accessAuthorship`); an access change commits nothing while either log refuses
  its writes (`noAuditNoAccess`).

`revoke_credential` keeps 0.14's head (EntryLessHead), since 0.14.5's isolates may still serve beside 0.16.0
(above, "A session's revoke takes 0.14's head too").

**What stays.** Every other change appends its 0.14 entry, and so does every refusal of these two routes, which goes
down today's path until PR 6b's outcome records. A finding of 0.14's still settles at the member's next such change.
A release before 0.16.0, rolled back to, refuses a member the two-trip add made: it checks a member against their
newest 0.14 access entry, finds none, reads the row as tampered, and can neither add nor remove them again (0.15.0's
start-over replays 0.14's entries, which never admitted them). Going forward to 0.16.0 again serves them; restoring
the backup taken before the upgrade loses them. docs/deploy.md has the upgrade hold member changes during its watch
for this. Keys written by the two-trip path open on such a release as any other; its audit page lists none of them.

The regressions: packages/server/test/write-held.test.ts (a write's change names its request, its operation and its
request id, and no 0.14 entry stands beside it; an abandoned try leaves no entry in either log; the write listed on
the whole log, its project's, environment's and key's pages, its writer's, a reader of its environment's, and none of
another place's, another member's or the refusals'; its value in the writer's offboarding report; its change edited
around coffre listed as forged), packages/server/test/admit-held.test.ts (an add's change with its ids and no `old`,
no entry; listed on the instance's pages alone; the log verifying through a role change down today's path after it,
and not with the row forged; the row deleted, the member missing), packages/server/test/change-cost.test.ts (the two
budgets), packages/server/test/request-cost.alone.ts (the pages' reads flat as others' writes and adds grow), and the
conformance checks above.

## As built: PR 6

The refusals of the two two-trip routes, on Postgres with 0.15's log (`log_refusal`, migration 0067; the vault's
`recordRefusal`, packages/vault/src/refusal.ts; the app's packages/server/src/refused.ts and `refuse` in
api/context.ts). A key write or a first add the vault's decision refuses on its read is answered as today's path
answers it and recorded by the vault in 0.15's log, in place of the 0.14 deny entry that path appends.
`change-cost.test.ts` holds a refused key write and a refused add each to `{ app: 0, vault: 2 }` (a dozen before):

```
vault  write_request (or admit_read): the read, the number                                 1
       the Worker: MACs, seals, the decision: refused; the record prepared (its ticket)
app    the rows' auth_mac, in memory; the route's check, or its handler, refuses as today's path,
       the caller as the vault's read decided it, the place as it found it, reading nothing
vault  log_refusal: the record, under the fence shared                                      1
       waitSealed                                                                           the seal
```

Example: Ada, a Viewer of market/dev, `PATCH /secrets/market/dev { API_KEY: "sk-…" }`. The vault's read finds her
grant, the rules refuse `no_grant`; the app's router, its caller her standing as the read decided it, refuses as it
always has, 403 "you need secret.write on market/dev"; where it would append the app's deny entry, the vault writes:

```
log_changes  number 4211, object log_object('request', <its id>), actor user:ada@acme.example, seal NULL,
             payload {"code":"no_grant","credential":"<her session>","environmentId":"<dev>","identity":"<id>",
                      "keys":["API_KEY"],"op":"write.refused","path":"market/dev","projectId":"<market>",
                      "read":"<the read's digest>","ref":{"id":"<its id>","kind":"request"},
                      "request":{"number":"4209","operationId":"…","requestId":"…"}}
```

What it serves: the refusals the rules make on a read whose every object stood (its MACs, its seals, the caller's
credential): a key write's `keyRefusals` (`no_grant`, a protected place, a credential scope), a first add asked of
a person or with a role by someone who runs no instance, an Owner asked by an admin. What keeps today's path: a read
not as its log has it (`tampered`, `stale`: that path's check records its finding, which the members' watermark reads,
PR 4a), a caller not active, a service account set up by someone who runs no instance (`#setsUp`, which the read does
not hold: PR 5b), and everything the two-trip path does not serve.

How it holds (formal/Writing.tla, `Refuse`; the scenarios Refuse, Caller and Add):

- **A change of nothing.** The record is a row of `log_changes`, so that the checkpointer MACs it, seals it in its
  window and its tiles, and retention keeps it, as every change. Its object is the request's own,
  `log_object('request', id)`, which no other row's is: every reader that asks an object's newest change (a use, a
  hold, `write_inputs`, the members' watermark, `missingMembers` of one) never meets it. Its payload starts
  `{"code":"`, as no other change's does, so no record kind of change-records.ts but its own takes it
  (`refusedWrite`, `refusedAdd`); the replay passes over it as the log's own (`LOGS_OWN`), and the verifier finds it
  well formed (its `ref` names its object). Its request id is drawn for it alone, never a change's (a key write's are
  derived from the request's number and each key's object), so no idempotency check of a change's ever meets it.
- **Recorded as the caller its token is** (RefusalAfterAuth): the vault prepares the record at its decision, under its
  change MAC key, domain-separated (a ticket, 30 s, as an add's), and writes it only when the app hands it back,
  once the app has checked the caller's rows that read answered. A token hash copied onto an Owner's credential never
  puts a refusal in the Owner's name: the app's check answers 401, and nothing is recorded. Without, TLC finds it
  (WritingAdd, `RefusalsAuthentic`).
- **It ends the request** (RefusalEnds). Before PR 6 a refusal went down today's path, which, after a try the vault
  served and a hold that failed, went on with the caller the first try checked: Ada's grant taken (the hold fails),
  the retry refused, her grant given back and her session revoked, today's path wrote (review r2 of #469). Now the
  refusal is answered there (WritingCaller, `TodayCallerStandsAtDecision` holds; without RefusalLogged it breaks).
  What the two-trip path no longer serves on a retry (the key made a reference) still goes there, and keeps that
  window (WritingCallerShape, an expected gap; PR 3b, PR 7).
- **Under the fence shared**, as a use: it waits for a change's hold to its COMMIT and the checkpointer's barrier waits
  for it, so its number is sealed in order; it holds up no use, and moves no object a use or a hold reads. A use's
  cached cover asks again once (it compares the log's newest change, which the record moves, as a sign-in does).
- **Sealed before the answer** (R51; D165 kept for refusals): `recordRefusal` waits for the record's seal, as a change
  does. A refusal answered is in a signed checkpoint. A seal that does not come in time answers 503, as a change's
  does, but in words of its own (`REFUSAL_UNSEALED_MESSAGE`, refused.ts): "coffre did not make this change", where a
  change's says it made it (review r2 of PR 6). The record stands, and the next checkpointer seals it.
- **Forged or copied.** The record's MAC covers every column but its number, its object and its request id among them.
  Copied by a database writer as the newest change of Ada's member object, her row put back to match, it is a change
  whose MAC fails: the vault refuses the member `tampered`, as any forged change (WritingRefuse, ChangeMacChecked).
  Copied whole under another request id, it is listed and marked forged on the audit pages.

Its answer: the app's caller is the vault's read's (`standing`, its rows checked), the place the read's, so the
router's check refuses as it would on today's path, its message and its status; one the app's check lets through (a
later try, or the app's check and the vault's apart: an Owner asked by an admin) is answered as that path answers the
vault's own refusal (`vaultRefused`). `refuse` records it where it would append a deny entry of the action the vault
refused (`secret.write`, `member.add`); a ticket expired meanwhile (the app took more than 30 s) appends the entry as
before. No credential's last use is written on a refusal: no app statement carries it, as an add's carries none.

The audit pages list the records where the deny entries stood: a key write's on the whole log, its place's and its
environment's pages, the refused member's, a reader of its environment's, and `decision=deny`; an add's on the
instance's pages; neither on `decision=allow`, nor at a key (the route's refusal named none). Six partial indexes
(every one, one member's, one environment's and one member's there; an add's every one and one member's), and
statistics on their markers, keep a page to as many entries as it lists (R48).

**What it leaves out: the request row.** The design stores, beside each request, the read `write_inputs` answered and
the request as asked, MAC'd (above, "The request and its refusals"), so that a replay of writes could decide each
again. Nothing reads it yet: no verifier replays a write's decision. It waits for one; the record names the read's
digest and the request's number, which such a row would be held to.

The regressions: packages/server/test/write-held.test.ts (a refusal answered as today's path answers it, status and
body, the record in place of the deny entry; every reader as it was after a refusal, the audit pages listing it where
0.14's entry stood and nowhere else; the record sealed by a checkpointer before the answer, the trees verifying, the
replay without a fault; a record copied onto Ada's member object refused as forged, and one copied whole marked
forged; a refused retry ending the request, and a retry not served still going down today's path),
packages/server/test/admit-held.test.ts (an add refused for someone who runs no instance, and an Owner asked by an
admin, answered as today's path, the list of everyone as it was), and packages/server/test/change-cost.test.ts (both
at two round trips).
