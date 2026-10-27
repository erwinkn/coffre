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
| principal | `user:ada@acme.example` | status, instance role and scope, every grant with its end |
| credential | uuid | whose, what kind (person, bearer, workload), its scope, its end, revoked |
| secret | the key's uuid | where it is, its current version, its nature, its wrapped data key, or a reference's source |
| environment | uuid | project, slug (renamed by its own change: a scoped role's filters read it), protected, a fork's parent, a personal config's owner, deleted, archived |
| roles | one, `instance` | an Owner's edits of the roles, and the roles they made |
| policy | one, `instance` | the bulk cap's count and window (R52) |

A seal covers the **object**, never the row's other columns: bookkeeping
the app updates outside any change (a credential's `last_used_at` and
`last_used_ip`, a binding's) is no part of one, so 0.14 stamping it during
the overlap never stales a credential. The change path and the use path
build each object from its fields alone.

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
   request's time (`credential`); no such key (`missing`); a reference
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

## The bulk cap

As W211 built it (hot-path-one.md, "The bulk cap"), with **both numbers
from the policy's newest change** (the spec's `CapSealed`,
`CapFromPolicy`), read in the use's own snapshot, never passed in. During a
deploy, two vaults with different `bulkLimit` configurations can serve at
once; with the numbers passed in, live would count with one and the replay
with the other. Not from the policy's row either: the statement moves the
cap before anyone checks the row's seal, so a row put back would move it
otherwise than the replay (`BulkReplayAgrees`). A vault starting with a new
configuration writes a `bulk.limit` change first (`limitChange`).

- A key counts at `t` while its row's `last > t − window − refresh`.
- Other keys count over `window + refresh + deadline` (`USE_DEADLINE_MS`,
  3 s): uses are decided in number order, not by time (TLC's finding).
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
anything the principal may not read. PR 8's row audit holds every bulk row
to the replay's, as W211's verifier does, and names the drift. The
property tests state exactly this: bulk rows moved change a decision only
between allowed and `bulk_limit`.

## Replay

`replay` applies each change with the same `applyOp`, checks the seal it
logged is the vault's over the object the replay has, and decides each use
with `readUse` over the replay's rows. It names what does not hold: a
change that does nothing, a seal that is not its object's, numbers out of
order. PR 8's verifier adds the row audit (every row is the replay's) and
the checkpoints.

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
| 9 | The bulk rows outside the seals; the row audit (PR 8) checks them | sealed per principal | no seal, no key, on the use's statement's bulk write | an erased row resets one principal's cap until the audit names it |

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
  app hands it back without a use.
- **For PR 4 and PR 5, from the spec (W211):** a change refused by its
  seal's compare-and-set reads the row again before it retries
  (`ChangeRereads`); the Worker answers 503 at the deadline even if its call
  never returns, and a value whose call returns late never leaves
  (`WorkerGivesUp`). Neither is in this pure code.
