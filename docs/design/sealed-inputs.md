# Sealed inputs, decisions and replay (0.15, plan PR 3)

Pure code that the 0.15 log will run on. It is not wired in yet: 0.14's
behaviour is unchanged, and the later pull requests of the 0.15 plan (the
change path, the use path, the verifier, the cutover) call it.

- [`packages/vault/src/inputs.ts`](../../packages/vault/src/inputs.ts): the
  objects, their keys, their seals, the changes (`Op`) and `applyOp`.
- [`packages/vault/src/decide.ts`](../../packages/vault/src/decide.ts):
  `decideUse` (its seals checked by `checkSeals`, then `decideChecked`), and
  `readerOf`, beside 0.14's rules, which it calls unchanged.
- [`packages/vault/src/bulk.ts`](../../packages/vault/src/bulk.ts): the bulk
  cap's rule.
- [`packages/vault/src/log-replay.ts`](../../packages/vault/src/log-replay.ts):
  `readUse` (the use's statement, over maps) and `replay`.
- [`formal/lean/Coffre/Use.lean`](../../formal/lean/Coffre/Use.lean): the
  model, held to the code by `pnpm formal:lean` ([`docs/formal.md`](../formal.md)).

## The objects

Every input a decision reads is one object of the log. Its row carries a
**seal**, and every change records the seal it leaves.

| object | id | what it holds |
|---|---|---|
| principal | `user:ada@acme.example` | status, its generation (moved on by each removal, T145), instance role and scope, every grant with its end |
| credential | uuid | whose, what kind (person, bearer, workload), its scope, its end, revoked, its account's generation when issued |
| secret | the key's uuid | where it is, its current version, its nature, its wrapped data key, or a reference's source |
| environment | uuid | project, slug (renamed by its own change: a scoped role's filters read it), protected, a fork's parent, a personal config's owner, deleted, archived |
| roles | one, `instance` | an Owner's edits of the roles, and the roles they made |
| policy | one, `instance` | the bulk cap's count and window (R52) |
| proxy | the environment's uuid | its proxy definitions written in the UI (0.16), each item with who saved it and what that save froze of them; its seal covers the index of their digests, names included, not their bodies ([proxy-ui.md](proxy-ui.md), section 2) |
| proxy-reserved | one, `instance` | every name the deployment's code reserved and no instance Owner released |

A seal covers the **object**, never the row's other columns: bookkeeping
the app updates outside any change (a credential's `last_used_at` and
`last_used_ip`, a binding's) is no part of one, so 0.14 stamping it during
the overlap never stales a credential. The change path and the use path
build each object from its fields alone.

Not only a use: every decision of the vault's checks each environment row
it reads against its seal and its newest change's, `access`, issues and
grants included, and fails closed on one that does not hold (T159;
[0.15-plan.md](0.15-plan.md), "As built: T159").

Every change to the policy carries the **whole policy as its `value`**
(`genesis` or `bulk.limit`): schema 0022's `use_credential` reads the cap
from the newest one at `value.bulk.count` and `value.bulk.windowMs`.

Two choices differ from 0.14's shapes:

- **Protection moved onto the environment.** 0.14 kept the protected
  environments in its policy. Here each environment says whether it is
  protected. The 0.14 `Policy` that `allows` takes is rebuilt from the roles
  object and the environments a use reads (`readerOf`). At an environment
  that is exact: `allows` asks the policy only `protects(environmentId)`, and
  every place a use checks is an environment it read.
- **The roles object holds edits only,** as 0.14's policy entries do: a
  role defined as it ships, or put back, is no edit. A decision merges the
  edits over the running release's tables (`readerOf`), so a release that
  changes a role as it ships changes it wherever nobody edited it, and the
  log replays the same under any release: it never held the shipped tables.
- **The policy object is the cap's configuration.** With roles and
  protection elsewhere, what is left is what the deployment sets that every
  decision reads: `bulkLimit`.

**The object's key** in the log is the first 16 bytes of
`SHA-256("coffre.object.v1\0" + kind + "\0" + id)`, as a uuid. It is
fixed-width, so a probe of the changes by object is cheaper than on text,
and SQL computes the same with `sha256()`. Vectors for the SQL of the
schema and use path:
[`packages/vault/test/object-keys.json`](../../packages/vault/test/object-keys.json).

**The seal** is HMAC-SHA256, cut to 16 bytes (R53), under a key derived from
the vault's signing key (`coffre.vault.seals.v1`). It covers the kind and id
the row is **filed under** and the object's canonical JSON (sorted keys;
grants as a set). Because the id is the key's and not the row's, Ada's
valid row copied under Bo's key is not Bo's: `tampered`.

## A use

The log records the request, not its outcome (R53). A use's entry carries:

| field | example |
|---|---|
| credential | `c1` |
| key | `DFNS_KEY`'s uuid |
| place | 0.14's `through`: the fork an inherited value is read in; null when read in the key's own environment |
| purpose, keepsSensitive | `reveal`, false: one smallint, the purpose's code (0 reveal, 1 run, 2 compare, 3 copy, 4 use, 5 expose) plus 256 when a copy keeps values sensitive (`purposeCode`) |
| time | 14:02:01.300 |

Purpose and place are new against the prototype's slim row: the outcome
depends on them (a person's `reveal` of a sensitive value is refused, its
`use` allowed). **Measured** on Postgres 16, 1M rows, heap and index: the
flags byte and a null place cost nothing (140.8 B per use, as the
prototype's 140.8 B: they fit in alignment padding). A place on 20% of
uses: 143.8 B. On every use: 157.6 B. (Measured with a one-byte column;
schema 0022 stores a smallint, and PR 2 reports its size.)

`decideChecked` decides it in four steps:

1. **Every input's seal, before anything its rows say.** Credential,
   principal, roles, policy, key, a reference's source, then each
   environment the decision weighs (where it is read, where its value is,
   a personal config's parent). A row whose seal is not the vault's is
   `tampered`; one whose seal is not its object's newest change's is
   `stale`. That covers a row put back from before a change, a row deleted
   outright, and a row written with no change at all.
2. **The credential and the key:** missing, revoked or ended at the
   request's time, or issued at an earlier generation than its active
   account's, a removal's before its sweep revokes it (`credential`); no such key (`missing`); a reference
   whose source is gone (`ended`); a reference to a reference, a value with
   no wrapped key, or a place 0.14's `throughOk` refuses (`bad_claim`); no
   policy in the log
   (`no_policy`). The place a key is read through **decides nothing**, as
   in 0.14: it must be a live, unarchived environment of the key's project
   other than the key's own, and the key is decided where it is held (a
   reference's holder). Example: Bo, a Viewer of `market/dev` alone, reads
   dev's key through `market/fork`: allowed. Bo, a Viewer of the fork
   alone: `no_grant`, as forking.md says (inherited values take read on the
   parent).
3. **0.14's rules, unchanged:** `keyRefusals`, `useOnlyRefusals`,
   `sensitiveRefusals`, on the reader `readerOf` makes.
4. **The bulk cap,** with the policy's count (its row, checked current by
   then).

Example: Bo is a Viewer of `market/dev`. Ada revokes him (seal S0 after
S1). An attacker with database access puts back Bo's row with his grant
(seal S1, validly the vault's, once). Bo's next use reads the row (S1) and
his newest change (S0): `stale`. The replay of the log, which has Bo
revoked, says `no_grant`. They differ, and only as `stale`. That is the
property the tests hold (below).

**Seals before rows, all of them.** Checking each input's seal just before
its own content would also be sound (a content refusal then rests only on
rows already checked). Checking all of them first is simpler to state and
to model, and it gives `stale` whenever any input is not the log's. A
mutation test holds it: with the credential's revoked flag read before the
seals, the property tests fail.

## The newest change's MAC (T190)

A row is held to the seal its object's **newest change** records, and that
seal is a column of `log_changes` like any other. A database writer can
write it. Example (Fable's, on #461): Ada revokes Bo (seal S0 after S1).
Mallory puts back Bo's row and grant with S1, then runs `UPDATE log_changes
SET seal = S1` on the revoke. The row's seal is the vault's, and it equals
the newest change's. Before T190 every use served Bo the value, while
`access` called him tampered.

What the writer cannot write is the change's **MAC**: it covers every
column but the number, the seal included (`entryMac`). So nothing holds a
row to a newest change's seal before that change's MAC holds:

- **A use.** Each probe of an input's newest change (the way in, the
  principal, the roles, the policy, the key, a reference's source, each
  place) reads the change's other MAC'd columns too: its time, request,
  actor and payload, and its MAC. The statement answers them in `changes`
  (0059; SQLite's twin the same). The Worker checks each MAC over them, the
  object the input is of and the seal (`lastsHeld`, `changeHolds`). An
  input whose change does not hold has a newest seal equal to none, and
  the use is `stale`, as a row put back is: nothing opened, nothing
  served. The payload is under the MAC too, so the 0.14 entry a member's
  change accounts for (`old`, UsesSeeOldWrites) and the policy's cap
  cannot be edited either. Every way a use is asked goes through it: by
  ids, as a batch, by name, as a named batch, by route.
- **A route use** (`use_route`, 0059 too) reads three newest changes
  beside its caller's and its keys' inputs: each fork level's definitions
  and its environment, and the route's editor's principal. Each answers
  its MAC'd columns the same way (`change`), and the vault checks them
  (`newestHolds`) before it holds a level or the editor to that seal: a
  level that fails makes the chain `stale` (`chainFault`), an editor that
  fails is `stale` (`editorOf`). The chain's is the only check on a level
  above the key's place: neither the gate nor the key's own use reads it.
- **The isolate's seal cache** keeps a key's seals only when every one of
  their changes' MACs held (CacheVerified). Kept, they are not checked
  again: they are the isolate's memory, which no database writer reaches,
  and any change since moves the log's newest change, which sends the next
  use back to its probes (CacheSameChange).
- **A write the vault seals** checks the MAC of the newest change its
  statement holds the base row to, before the statement runs: SQL compares
  that seal under the fence and holds no key to check its MAC. Without the
  check the writer's row is laundered, not merely served: the next
  legitimate change applies its op to the put-back row and seals the
  result under a new, authentic change, and the revoke is undone for good.
  Every such write checks it, refused `tampered` (or as its statement
  refuses a stale row) otherwise:
  - the vault's own changes (`Changes`, `newestChange`, ChangeChecksMac):
    a member, a grant, roles, the policy, proxy definitions;
  - the app's changes (`Vault.prepare` before `app_change`): one
    statement reads every object's newest change (`loggedChanges`), and
    for an unarchive the change before it, the write its archive ended
    (`keptFrom`), so that a write's seal blanked cannot make an older one
    look the newest sealed. Reviewer r1 found this route open: a credential
    revoked, put back, its revoke's seal forged, then renewed by a minute,
    and served again;
  - a sign-in through a binding (`sign_in`): the member and the binding,
    one statement before it;
  - an issue, and a binding made, on the credential the request came in on
    (`issue_token`, `change_bindings`): read in the same statement as that
    credential (`issuingCredential`), no round trip more.

  A revoke (`revoke_credential`) and a binding's end, with the credentials
  it sweeps, do not check it, on purpose: they only end, so a forged seal
  gets the writer a credential revoked from the row it put back, revoked
  all the same; refusing them would let a forged log keep a credential
  live.

  Each check is a read before the statement, which then compares the seal
  alone (ChangeCAS, ChangeChecksSeal): bytes, which SQL cannot tell from a
  forgery. `prepare` also holds the row the app read to the seal of the
  change it checked (each object's first call from it, each later call
  from the seal the one before leaves: the calls, not the app's entries,
  so that an entry changing nothing cannot stand in for the one that
  writes, review r3), and answers `moved` when they differ, which is also
  what an honest write between the app's read and `prepare` makes: nothing
  is reported, and the app reads again (`ObjectMoved`, `retrying`), as it
  does when `app_change` finds a row moved. Without that, a writer would
  put the revoked row back with its old seal, let the app read it, and make
  the revoke's seal column the old one after `prepare` checked the revoke's
  MAC: the renewal then passes `app_change` and seals the put-back row
  under an authentic entry (review Fable). With it, a writer must forge a
  change the vault has already checked, after its read and before the
  statement, and that change must be an honest one landing in that gap
  (row and seal put back, its seal forged). An issue holds the credential
  it came in on to its checked change's seal the same way, and so does a
  sign-in its binding (review r3: without it, an ended binding put back,
  its end's seal column forged once the vault read the end, signed a run
  in), and both statements take that seal as a parameter: the same gap.
  A sign-in's member is wider: `sign_in` reads the member's row itself,
  and the vault, which never sees it, pins nothing, so a member removed,
  its row put back and the removal's seal forged after the MAC check,
  takes no honest change, only the timing (a writer holding the member's
  row locked widens it to `lock_timeout`). Closing both takes the statement
  holding the newest
  change's seal column to the seal the vault checked (a number alone is not
  enough: the forgery edits the seal in place and keeps the number), under
  the lock: a parameter of `app_change`, `sign_in` (the member's) and
  `issue_token`.
  T179's two-trip writes, which check their read set there (#458), take it
  on. The model checks the MAC as the code does, of the change read at
  `ChangeStart`, and its scenarios, one tamper each (`MaxTampers = 1`),
  cannot reach the gap.

A change's MAC is checked under the key its tag names, among every
signing key the vault holds, as seals are (`sealed`): this check guards
the seal check and trusts no more keys than it. A retired key
included: its holder can forge a row's seal and re-MAC the change to match
under that key's tag, and `log_fence.retired`, which stops them inserting
entries, does not stop them editing one. Refusing that takes accepting a
retired key only for changes numbered at or before its rotation, which the
keyring knows and the hot path does not load: a known limit, not a
guarantee of T190's.

**What it does not see:** an entry deleted, or replayed whole under
another number (the MAC does not cover the number). With Bo's revoke
deleted outright, the grant before it is the newest change, authentic,
and its seal is S1. No check of one use can tell; the Merkle checkpoints
do (merkle-checkpoints.md, attacks (a) and (f)), and so does the
whole-log verifier. That is the same boundary as `access` and every other
reader of the log.

**The decision path** (T159) holds each environment's row to its newest
change the same way: `snapshot` and `environmentsById` read that change
whole, in the same probe, and `#placeFault` refuses the row `tampered`
when its MAC does not hold, before the seal comparison (review r3: an
archived place put back, the archive's seal column forged, otherwise had
grants on it hold, its old protection weighed and an issue on it made).
Every reader that hands a decision an environment row carries that change
(`snapshot` and `environmentsById`, on each engine), and a place whose row
is gone carries no seal, which no check passes. T191, filed for this hole,
found it closed and added the tests: a place put back after an archive or
a rename, its change's seal column forged, is refused by every decision
on it (`access`, a kept answer, a grant, an issue, a service account's
manager, a key's wrap, a read through it, a scoped person's setup of a
service account), and each of those tests fails with the MAC check
removed, from either reader (measured, both engines).
The route use reads proxy definitions through the same check (above).

## The bulk cap

As W211 built it ([hot-path-one.md](hot-path-one.md), "The bulk cap"; decisions 16 to 21 there are this PR's), with **both numbers
from the policy's newest change** (the spec's `CapSealed`,
`CapFromPolicy`), read in the use's own snapshot, never passed in. During a
deploy, two vaults with different `bulkLimit` configurations can serve at
once; with the numbers passed in, live would count with one and the replay
with the other. Not from the policy's row either: the statement moves the
cap before anyone checks the row's seal, so a row put back would move it
otherwise than the replay (`BulkReplayAgrees`). A vault starting with a new
configuration writes a `bulk.limit` change first (`limitChange`).

- A key counts at `t` while its row's `last > t − window − refresh`.
- Other keys count over `window + refresh + deadline + ahead`
  (`USE_DEADLINE_MS`, 3 s; `USE_AHEAD_MS`, 60 s): uses are decided in
  number order, not by time (TLC's finding), up to the deadline after their
  `at` or, a Worker's clock ahead, a minute before it (W228, migration 0028).
- `refresh` is a minute, or a tenth of a shorter window.
- Every request counts, whatever else refuses it, but those the cap
  refuses: the use's statement writes the row before the vault decides.
- A key is the key asked for: two references to one source count twice.
  That is conservative (more counted, never fewer).
- Every request the cap admits moves it, `stale` ones included
  (`HotPathOneStaleBulk`): the replay counts them the same way.

**The bulk rows are outside the seals.** A use writes them in its one
statement, at most once a `refresh` per key, and the replay rebuilds them;
sealing them would put the vault's key, or a change entry, on that write.
So a database writer who erases a principal's rows resets its cap, and the
use that follows is allowed where the replay says `bulk_limit`, with no
input `stale`. The cap is a rate, not a right: nothing it lets through is
anything the principal may not read. Nothing holds the bulk rows to the
replay's yet: PR 8 has no row audit (D145), and T138 models the agreement
first. The property tests state exactly this: bulk rows moved change a
decision only between allowed and `bulk_limit`.

## Replay

`replay` applies each change with the same `applyOp`, checks the seal it
logged is the vault's over the object the replay has, and decides each use
with `readUse` over the replay's rows. It names what does not hold: a
change that does nothing, a seal that is not its object's, numbers out of
order. PR 8's verifier checks the checkpoints and the entries above the
newest; it replays nothing and reads no row (D145).

`readUse` is the use's statement, written over maps: which rows it reads,
in which order, and how it moves the cap. PR 5's `use_credential` must read
the same.

## What the tests hold

- **Unit** ([`use-decide.test.ts`](../../packages/vault/test/use-decide.test.ts)):
  the rules on the objects (grants, protection, sensitivity, personal
  configs, references, forks); each input put back (member, credential, key,
  environment), edited, deleted or written with no change; the cap, a stale
  use moving it, and its count changed at a restart, live equal to replay
  across the change.
- **Properties** ([`use-replay-properties.test.ts`](../../packages/vault/test/use-replay-properties.test.ts),
  hegel, 200 cases each):
  - random runs of changes and uses: every live decision equals the replay's,
    and the replay ends on the same rows, newest seals and cap rows;
  - rows perturbed (put back, edited, deleted, written with no change, moved
    from another object, sealed with another key): a decision differs from
    the replay's only as `stale` or `tampered`, and always is one when it
    weighs a perturbed input; bulk rows moved change it only between
    allowed and `bulk_limit`;
  - the cap: requests decided in number order, stamped up to the deadline
    apart, never release more than `count` keys in a window.
  - Each fails with the stale check removed, or with a row read before the
    seals (measured).
- **Forged log** ([`use-forged.test.ts`](../../packages/vault/test/use-forged.test.ts),
  both engines): for each input a use reads, the change's seal column
  forged over a row put back, refused on a warm isolate and a fresh one,
  and by every way a use is asked; and a change on such a row refused
  ([`change-path.test.ts`](../../packages/vault/test/change-path.test.ts)).
  Each serves the value on 0.15.0. The decision path's the same, for a
  place ([`places-sealed.test.ts`](../../packages/vault/test/places-sealed.test.ts),
  `putBack`) and a member (`vault.test.ts`, T179 PR 2).
- **Lean** (`pnpm formal:lean`): `decideUse` and `bulkRule` against the
  model on 26,000 cases, and the theorems in [`docs/formal.md`](../formal.md).

## Decisions

| # | decision | alternatives | numbers | tradeoff |
|---|---|---|---|---|
| 1 | Protection on each environment; the policy object holds the cap | protection in the policy object, as 0.14 | `allows` at an environment asks only `protects(id)`: exact on the environments a use reads | the 0.14 `Policy` is rebuilt per use (a few objects) |
| 2 | The cap's count and window from the policy's newest change (`CapSealed`) | passed per call, as the prototype; the policy's row | live equals replay across a deploy with two configurations, and with the row put back | the statement reads the newest policy change (cached with the seals) |
| 3 | The use row carries purpose and keepsSensitive (one smallint, schema 0022) and the place (null when the key's own) | the prototype's row (credential, key) | 140.8 B per use unchanged; 143.8 B with a place on 20% of uses | the replay can decide every purpose |
| 4 | A reference is the holder's own secret object, its `source` sealed | a reference object of its own | one object fewer per reference | a use through one reads one more input |
| 5 | Object keys: SHA-256 of kind and id, cut to a uuid | text keys (`member:<id>`) | about 20% cheaper per probe (W211's estimate, open decision 2) | the SQL hashes the principal's id once per use |
| 6 | Every seal before any row | each input's seal before its own row | both sound; the first gives `stale` for any input not the log's | none measured |
| 7 | Seals under a key of their own (HKDF label `coffre.vault.seals.v1`) | 0.14's row key | separates 0.15's seals from 0.14's member MACs | none |
| 8 | The roles object holds edits only, merged over the release's tables | the whole tables, sealed | a release that changes a shipped role replays the same log the same way (review r1: whole tables made the replay fault) | a decision merges two small tables |
| 9 | The bulk rows outside the seals; T138 holds them to the log once modelled | sealed per principal | no seal, no key, on the use's statement's bulk write | an erased row resets one principal's cap, and no check names it yet (T138) |

## Open

- **Probes on a cache miss:** up to 9 (credential, principal, roles,
  policy, key, source, three environments) against the plan's "about six".
  PR 5 measures it against the 30-buffer budget; grouping roles and policy
  is the plan's cut.
- **A project's deletion** reaches a decision as each of its environments'
  `deleted`: the decision reads no project object (schema 0022 has none).
  PR 4's change path writes one change per environment when a project goes.
- **For PR 4:** every write to an input is one of `Op`'s changes, an
  environment's rename (0.14's `environment.update`) included; a write with
  no op of its own would leave its object's seal stale, or, worse, its old
  content current.
- **For PR 5:** a use opens a wrapped key. A plain value, which 0.14's
  vault never decides either, is refused at the door (`bad_claim`): the
  app hands it back without a use. Its text is under its seal all the
  same: its object holds the text's digest (0029), so an edited text is
  `tampered`, not `bad_claim`.
- **For PR 4 and PR 5, from the spec (W211):** a change writes only over
  a row whose seal is its object's newest change's (`ChangeChecksSeal`,
  else `stale`), and only from the seal it read (`ChangeCAS`); one refused
  by that compare-and-set reads the row again before it retries
  (`ChangeRereads`); the Worker answers 503 at the deadline even if its call
  never returns, and a value whose call returns late never leaves
  (`WorkerGivesUp`). Neither is in this pure code.
