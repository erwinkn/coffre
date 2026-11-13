# Sealed inputs, decisions and replay

Every row a vault decision reads is one **object** of the log, and carries a **seal** the vault made.
A database writer without the vault's key can change rows, but every decision then refuses them as
`tampered` or `stale`, and a replay of the log decides every use the way the vault did. This page
says what the objects are, how a use is decided on them, what the bulk cap counts, and what the
replay checks.

- [`packages/vault/src/inputs.ts`](../../packages/vault/src/inputs.ts): the objects, their keys,
  their seals, the changes (`Op`) and `applyOp`.
- [`packages/vault/src/objects.ts`](../../packages/vault/src/objects.ts): each object built from its
  row's columns.
- [`packages/vault/src/decide.ts`](../../packages/vault/src/decide.ts): `decideUse` (its seals
  checked by `checkSeals`, then `decideChecked`), and `readerOf`.
- [`packages/vault/src/bulk.ts`](../../packages/vault/src/bulk.ts): the bulk cap's rule.
- [`packages/vault/src/log-replay.ts`](../../packages/vault/src/log-replay.ts): `readUse` (the use's
  statement, over maps) and `replay`.
- [`formal/lean/Coffre/Use.lean`](../../formal/lean/Coffre/Use.lean): the model, held to the code by
  `pnpm formal:lean` ([`docs/formal.md`](../formal.md)).

## The objects

Every input a decision reads is one object of the log. Its row carries a **seal**, and every change
records the seal it leaves.

| object | id | what it holds |
|---|---|---|
| principal | `user:ada@acme.example` | status, its generation (moved on by each removal), instance role and scope, every grant with its end |
| credential | uuid | whose, what kind (person, bearer, workload), its scope, its end, revoked, its account's generation when issued |
| connection | uuid | an MCP client a person connected: whose, at which generation, its end, revoked |
| binding | uuid | a trust binding: whose, at which generation, its issuer, keys and claims, its scope, revoked |
| secret | the key's uuid | where it is, its current version, its nature, its wrapped data key or a plain value's digest, or a reference's source |
| environment | uuid | project, slug (renamed by its own change: a scoped role's filters read it), protected, a fork's parent, a personal config's owner, deleted, archived |
| roles | one, `instance` | an Owner's edits of the roles, and the roles they made |
| role | `project/<name>` or `instance/<name>` | one role's edit, or null for one as it ships; written with every change of the roles, read by no decision yet |
| policy | one, `instance` | the bulk cap's count and window |
| proxy | the environment's uuid | its proxy definitions written in the UI, each item with who saved it and what that save froze of them; its seal covers the index of their digests, names included, not their bodies ([proxy-ui.md](proxy-ui.md), section 2) |
| proxy-reserved | one, `instance` | every name the deployment's code reserved and no instance Owner released |

A seal covers the **object**, never the row's other columns: bookkeeping the app updates outside any
change (a credential's `last_used_at` and `last_used_ip`, a binding's) is no part of one. The change
path and the use path build each object from its fields alone.

Every decision of the vault, not only a use, checks each environment row it reads against its seal
and its newest change's (`access`, issues and grants included), and fails closed on one that does
not hold.

Every change to the policy carries the **whole policy as its `value`**
(`genesis` or `bulk.limit`): schema 0022's `use_credential` reads the cap
from the newest one at `value.bulk.count` and `value.bulk.windowMs`.

- **Protection moved onto the environment.** 0.14 kept the protected
  environments in its policy. Here each environment says whether it is
  protected. The 0.14 `Policy` that `allows` takes is rebuilt from the roles
  object and the environments a use reads (`readerOf`). At an environment
  that is exact: `allows` asks the policy only `protects(environmentId)`, and
  every place a use checks is an environment it read.
- **The roles object holds edits only**: a role defined as it ships, or put back, is no edit. A
  decision merges the edits over the running release's tables (`readerOf`), so a release that
  changes a role as it ships changes it wherever nobody edited it, and the log replays the same
  under any release: it never holds the shipped tables.
- **The policy object is the cap's configuration.** With roles and
  protection elsewhere, what is left is what the deployment sets that every
  decision reads: `bulkLimit`.

**The object's key** in the log is the first 16 bytes of
`SHA-256("coffre.object.v1\0" + kind + "\0" + id)`, as a uuid (`log_object` in SQL, `logObject` in
TypeScript). It is fixed-width, so a probe of the changes by object is cheaper than on text. Vectors:
[`packages/vault/test/object-keys.json`](../../packages/vault/test/object-keys.json).

**The seal** is HMAC-SHA256, cut to 16 bytes, under a key derived from the vault's signing key (HKDF
label `coffre.vault.seals.v1`, so seals never share a key with anything else). It covers the kind
and id the row is **filed under** and the object's canonical JSON (sorted keys; grants as a set).
Because the id is the key's and not the row's, Ada's valid row copied under Bo's key is not Bo's:
`tampered`.

## A use

The log records the request, not its outcome. A use's row in `log_uses`:

| column | example |
|---|---|
| `credential` | `c1`'s uuid |
| `secret` | `DFNS_KEY`'s uuid |
| `place` | the environment it was asked at, when not the key's own (a fork it inherits into, a reference); null otherwise |
| `purpose` | one smallint (`useCode`): the purpose (0 reveal, 1 run, 2 compare, 3 copy, 4 use, 5 expose), plus 256 when a copy keeps values sensitive, plus 512 × the way in (0 credential, 1 connection, 2 binding, 3 access) |
| `route` | the UI proxy route it was a use of, or null |
| `at`, `request_id`, `number`, `mac` | 14:02:01.300; its request; its place in the log; the vault's MAC |

Purpose and place are in the row because the outcome depends on them: a person's `reveal` of a
sensitive value is refused, its `use` allowed.

`decideChecked` decides it in four steps:

1. **Every input's seal, before anything its rows say.** Credential, principal, roles, policy, key,
   a reference's source, then each environment the decision weighs (where it is read, where its
   value is, a personal config's parent). A row whose seal is not the vault's is `tampered`; one
   whose seal is not its object's newest change's is `stale`. That covers a row put back from before
   a change, a row deleted outright, and a row written with no change at all.
2. **The credential and the key:** missing, revoked or ended at the request's time, or issued at an
   earlier generation than its active account's (`credential`); no such key (`missing`); a reference
   whose source is gone (`ended`); a reference to a reference, a value with no wrapped key, or a
   place `throughOk` refuses (`bad_claim`); no policy in the log (`no_policy`). The place a key is
   read through **decides nothing**: it must be a live, unarchived environment of the key's project
   other than the key's own, and the key is decided where it is held (a reference's holder).
   Example: Bo, a Viewer of `market/dev` alone, reads dev's key through `market/fork`: allowed. Bo,
   a Viewer of the fork alone: `no_grant` (inherited values take read on the parent,
   [forking.md](forking.md)).
3. **The access rules:** `keyRefusals`, `useOnlyRefusals`, `sensitiveRefusals`, on the reader
   `readerOf` makes.
4. **The bulk cap,** with the policy's count.

A plain value is refused at the door (`bad_claim`): the app hands it back without a use. Its text is
under its seal all the same (the secret object holds its digest), so an edited text is `tampered`.

**Example.** Bo is a Viewer of `market/dev`. Ada revokes him (seal S0 after S1). An attacker with
database access puts back Bo's row with his grant (seal S1, validly the vault's, once). Bo's next use
reads the row (S1) and his newest change (S0): `stale`. The replay of the log, which has Bo revoked,
says `no_grant`. They differ, and only as `stale`: that is the property the tests hold.

**All seals first.** Checking each input's seal just before its own content would also be sound.
Checking all of them first is simpler to state and to model, and gives `stale` whenever any input is
not the log's. A mutation test holds it: with the credential's revoked flag read before the seals,
the property tests fail.

## The newest change's MAC

A row is held to the seal its object's **newest change** records, and that seal is a column of
`log_changes` like any other, which a database writer can edit. Example: Ada revokes Bo (seal S0
after S1). Mallory puts back Bo's row and grant with S1, then runs `UPDATE log_changes SET seal = S1`
on the revoke. The row's seal is the vault's, and equals the newest change's.

What the writer cannot write is the change's **MAC** (`entryMac`): it covers every column but the
number, the seal included. So nothing holds a row to a newest change's seal before that change's MAC
holds:

- **A use.** Each probe of an input's newest change (the way in, the principal, the roles, the
  policy, the key, a reference's source, each place) reads the change's other MAC'd columns too: its
  time, request, actor, payload and MAC, answered in `changes`. The vault checks each MAC over them,
  the object and the seal (`lastsHeld`, `changeHolds`). An input whose change does not hold is
  `stale`: nothing opened, nothing served. The payload is under the MAC too, so the 0.14 entry a member's
  change accounts for (`old`, UsesSeeOldWrites) and the policy's cap
  cannot be edited either. Every way a use is asked goes through it: by
  ids, as a batch, by name, as a named batch, by route.
- **A route use** (`use_route`) reads three more newest changes: each fork level's definitions and
  its environment, and the route's editor's principal. The vault checks them (`newestHolds`) before
  it holds a level or the editor to that seal: a level that fails makes the chain `stale`
  (`chainFault`), an editor that fails is `stale` (`editorOf`).
- **The isolate's seal cache** keeps a key's seals only when every one of their changes' MACs held.
  Kept, they are not checked again: they are the isolate's memory, which no database writer reaches,
  and any change since moves the log's newest change, which sends the next use back to its probes.
- **A write the vault seals** checks the MAC of the newest change its statement holds the base row
  to, before the statement runs: SQL compares that seal under the fence and holds no key to check
  its MAC. Without the check the put-back row would be laundered, not merely served: the next
  legitimate change would apply its op to it and seal the result under a new, authentic change.
  Refused `tampered` otherwise:
  - the vault's own changes (`newestChange`): a member, a grant, roles, the policy, proxy
    definitions;
  - the app's changes (`Vault.prepare` before `app_change`): one statement reads every object's
    newest change (`loggedChanges`), and for an unarchive the change before it (`keptFrom`), so that
    a write's seal blanked cannot make an older one look the newest sealed. `prepare` also holds the
    row the app read to the seal of the change it checked, and answers `moved` when they differ,
    which an honest write in between makes too: the app reads again (`ObjectMoved`, `retrying`);
  - a key write in two round trips (`write_inputs`, `hold_inputs`) holds its whole read, each
    object's newest change in it, by digest ([two-trips.md](two-trips.md));
  - an issue, and a binding made, on the credential the request came in on (`issue_token`,
    `change_bindings`): read in the same statement as that credential (`issuingCredential`);
  - a sign-in through a binding (`sign_in`): below.

  A revoke (`revoke_credential`) and a binding's end, with the credentials it sweeps, do not check
  it, on purpose: they only end, so a forged seal gets the writer a credential revoked; refusing
  them would let a forged log keep a credential live.

  `app_change` and `issue_token` then compare the seal alone, as bytes. So one gap stays: a writer
  who forges the newest change's seal column after the vault's check and before the statement, over
  an honest change landing in that gap. Closing it takes the statement holding the newest change to
  what the vault checked, under the lock, as `sign_in` does.

**A sign-in holds the change whole.** `sign_in` takes the member's and the binding's newest changes
as the vault checked them: each one's number, every column its MAC covers (`at`, `request_id`,
`actor`, `payload`, `seal`) and the MAC (`p_member_*`, `p_binding_*`). Under each row's lock it holds
the object's newest change to them (another is `moved`, and the vault reads them again itself), then
the row to that seal. The app reads those changes in the statement that already reads the bindings
(`exchangeCandidates`, `workloadCandidates`), and the vault checks their MACs (`givenPins`), so a
sign-in stays one vault statement. The app's word refuses nothing: a change missing, whose MAC
fails, of another object, or no longer the newest, sends the vault to read them itself.

Number and seal alone are not enough, because the app chooses what it hands back and no MAC covers a
number. Example: Ada removes `token:ci` (seal S1 after S0). Mallory, with the app and a database
writer, puts back the account's row with S0, writes S0 into the removal's seal column, and hands the
change before the removal (seal S0, MAC valid) under the removal's number. Its MAC holds, and the
number and seal column match. Only the rest of the row (its `at`, request id, payload, MAC) tells it
from the removal, so the pin compares all of it: `moved`, then the vault's own read finds the MAC
broken, `tampered`, and nobody signs in (`packages/vault/test/bindings.test.ts`;
`formal/HotPathOne.tla`'s ChangePinsChecked and ChangePinsWhole).

What the pin does not check is the account's row against what its newest change sealed. Example:
Ada removes `token:ci` (seal S1); its binding stays live at generation 0. Mallory sets the row back
to `active`, generation 0, with seal S1. The pinned change is the honest removal, the row's seal is
its seal, and `sign_in` makes a credential. Nothing honours it: every decision that reads the
account checks its row against its seal (`viewOf` in `packages/vault/src/use.ts`) and finds it
tampered. It fails closed; the test names it open.

**Retired keys.** A change's MAC is checked under the key its tag names, among every signing key the
vault holds, as seals are (`sealed`). A retired key included: its holder can forge a row's seal and
re-MAC the change under that key's tag, and `checkpoint_fence.retired`, which stops them inserting
entries, does not stop them editing one. Refusing that takes accepting a retired key only for
changes numbered at or before its rotation, which the keyring knows and the hot path does not load:
a known limit.

**What it does not see:** an entry deleted, or replayed whole under another number. With Bo's revoke
deleted outright, the grant before it is the newest change, authentic, with seal S1. No check of one
use can tell; the Merkle checkpoints do ([audit-tree.md](audit-tree.md),
[merkle-checkpoints.md](merkle-checkpoints.md)), and so does the whole-log verifier.

**The decision path** holds each environment's row to its newest change the same way: `snapshot` and
`environmentsById` read that change whole, in the same probe, and `#placeFault` refuses the row
`tampered` when its MAC does not hold, before the seal comparison. Example: an archived place put
back, its archive's seal column forged, would otherwise have grants on it hold and an issue on it
made. A place whose row is gone carries no seal, which no check passes
(`packages/vault/test/places-sealed.test.ts`).

## The bulk cap

**Both numbers come from the policy's newest change** (the spec's `CapSealed`,
`CapFromPolicy`), read in the use's own snapshot, never passed in. During a
deploy, two vaults with different `bulkLimit` configurations can serve at
once; with the numbers passed in, live would count with one and the replay
with the other. Not from the policy's row either: the statement moves the
cap before anyone checks the row's seal, so a row put back would move it
otherwise than the replay (`BulkReplayAgrees`). A vault starting with a new
configuration writes a `bulk.limit` change first (`limitChange`).

At most `count` distinct keys per principal in any rolling `windowMs`. One row per principal and key
holds `last`, the start of the refresh period in which the key was last counted.

- A key counts at `t` while its row's `last > t − window − refresh`.
- Other keys count over `window + refresh + deadline + ahead` (`USE_DEADLINE_MS`, 3 s;
  `USE_AHEAD_MS`, 60 s): uses are decided in number order, not by time, up to the deadline after
  their `at` or, a Worker's clock ahead, a minute before it.
- `refresh` is a minute, or a tenth of a shorter window.
- Each principal's key has refresh periods of its own: they start at a phase, the first 6 bytes of
  SHA-256 of `<principal>/<key>` modulo `refresh` (`phaseOf`, `bulk_period`). With one phase for
  every row, every hot key's row went stale at the same instant, and the uses just after it each
  took a second call, two locks and two writes: at 1,000 uses a second, a burst of busy answers
  every period. Whatever the phase, a period starts less than a `refresh` before its use, never after
  it.
- The replay moves a key on as the statement that decided each use did. `log_uses.phased` says
  which: true from the phased statement, null from the one before it, whose periods all start at 0.
  It is outside the entry's MAC and the checkpoints' leaves: who could change it could change the
  cap's rows, and it moves only the replay's, by up to a `refresh`.
- Every request counts, whatever else refuses it, but those the cap refuses: the use's statement
  writes the row before the vault decides.
- A key is the key asked for: two references to one source count twice (more counted, never fewer).
- Every request the cap admits moves it, `stale` ones included; the replay counts them the same way.

**The bulk rows are outside the seals.** A use writes them in its one statement, at most once a
`refresh` per key, and the replay rebuilds them; sealing them would put the vault's key, or a change
entry, on that write. So a database writer who erases a principal's rows resets its cap, and the use
that follows is allowed where the replay says `bulk_limit`, with no input `stale`. The cap is a rate,
not a right: nothing it lets through is anything the principal may not read. No check holds the bulk
rows to the replay's. The property tests state exactly this: bulk rows moved change a decision only
between allowed and `bulk_limit`.

## Replay

`replay` applies each change with the same `applyOp`, checks the seal it logged is the vault's over
the object the replay has, and decides each use with `readUse` over the replay's rows. It names what
does not hold: a change that does nothing, a seal that is not its object's, numbers out of order.
`readUse` is the use's statement written over maps (which rows it reads, in which order, how it moves
the cap), so `use_credential` must read the same.

**Under whose rules.** The log names no release, so `replay` decides every use under the rules of
the release running it. When a release changes a rule, uses logged before the change replay under
the new one. Example: a reference is read by its holder's permissions alone. A service token issued
by an Owner of `landing` alone, using `landing/prod`'s reference to `backend/prod`'s sensitive
`CLERK_SECRET_KEY`, was refused `not_owner_issued` under the rule before, and is allowed in replay.
No production path replays decisions, and the verifier (`verifier.ts`) does not either: only the
tests call `replayStored`. A verifier that relied on replayed outcomes would first need the log to
name each interval's rules.

## What the tests hold

- **Unit** ([`use-decide.test.ts`](../../packages/vault/test/use-decide.test.ts)): the rules on the
  objects (grants, protection, sensitivity, personal configs, references, forks); each input put
  back (member, credential, key, environment), edited, deleted or written with no change; the cap, a
  stale use moving it, and its count changed at a restart, live equal to replay across the change.
- **Properties** ([`use-replay-properties.test.ts`](../../packages/vault/test/use-replay-properties.test.ts),
  hegel, 200 cases each):
  - random runs of changes and uses: every live decision equals the replay's, and the replay ends on
    the same rows, newest seals and cap rows;
  - rows perturbed (put back, edited, deleted, written with no change, moved from another object,
    sealed with another key): a decision differs from the replay's only as `stale` or `tampered`,
    and always is one when it weighs a perturbed input; bulk rows moved change it only between
    allowed and `bulk_limit`;
  - the cap: requests decided in number order, stamped up to the deadline apart, never release more
    than `count` keys in a window.
  - Each fails with the stale check removed, or with a row read before the seals.
- **Forged log** ([`use-forged.test.ts`](../../packages/vault/test/use-forged.test.ts)): for each
  input a use reads, the change's seal column forged over a row put back, refused on a warm isolate
  and a fresh one, and by every way a use is asked; and a change on such a row refused
  ([`change-path.test.ts`](../../packages/vault/test/change-path.test.ts)). The decision path's the
  same, for a place
  ([`places-sealed.test.ts`](../../packages/vault/test/places-sealed.test.ts)) and a member
  (`vault.test.ts`).
- **Lean** (`pnpm formal:lean`): `decideUse` and `bulkRule` against the model on generated cases,
  and the theorems in [`docs/formal.md`](../formal.md).

## Decisions

| # | decision | alternatives | numbers | tradeoff |
|---|---|---|---|---|
| 1 | Protection on each environment; the policy object holds the cap | protection in the policy object, as 0.14 | `allows` at an environment asks only `protects(id)`: exact on the environments a use reads | the 0.14 `Policy` is rebuilt per use (a few objects) |
| 2 | The cap's count and window from the policy's newest change (`CapSealed`) | passed per call, as the prototype; the policy's row | live equals replay across a deploy with two configurations, and with the row put back | the statement reads the newest policy change (cached with the seals) |

The other choices, each with its reason above: a reference is the holder's own secret object, its
`source` sealed (one object fewer per reference; a use through one reads one more input); object
keys are hashes cut to a uuid (a fixed-width probe); every seal before any row; seals under a key of
their own; the roles object holds edits only; the bulk rows outside the seals.
