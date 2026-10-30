# 0.15's hot path, in TLA+

0.15 answers uses from shards: actors that keep each principal's standing
in memory and write each decision to a lane of the audit log of their own.
A change to anything a use decides on fences every shard before it commits.
These models check that design before it is built, as `formal/Workload*.tla`
did for workload access. TLC runs them like the rest:

```sh
scripts/formal-shards.sh                  # every scenario but the long ones, about 2 minutes with --workers 4
scripts/formal-shards.sh --long           # and ShardsCombined, about 5 minutes more
scripts/formal-shards.sh ShardsRevoking   # one, with its runs without a protection
```

`scripts/formal.sh` runs the `Shards*` scenarios too, since it runs every
`formal/*.cfg`. It does not run their removals: those are in
`scripts/formal-shards.sh` until its `REMOVALS` are folded into `formal.sh`'s.

## The modules

- [`Shards.tla`](Shards.tla) models the fence. Postgres holds the grant and the
  revision. A changer takes the revision's row, fences every shard at
  R = revision + 1, commits, and answers. It can roll back at any step
  before the commit, and the answer to its COMMIT can be lost. Shards keep a
  standing and a floor, and their instances stop and start. Two instances
  can run at once, and the storage takes only the newer one's writes. Uses
  are answered from the kept standing, or read it again, or probe the
  revision's row. Fences and unfences are lost, duplicated, delayed and sent
  again: a changer resends a fence not yet acknowledged, any number of
  times, and may roll back between any two tries, which covers "retry a
  bounded number of times, then roll back". The revision is (epoch, n).
  Postgres can be restored from an earlier backup: `coffre restore`
  goes through the changer, fencing every shard at the backup's revision in
  a new epoch before it puts the backup in place.
- [`ShardsLanes.tla`](ShardsLanes.tla) models a shard's lane, copied to
  Postgres by a flusher that compares and swaps the lane's head (seq and
  hash). Instances restart, and a stale instance can still flush. An
  instance can start with its storage lost while Postgres holds what the old
  storage flushed. Postgres can be restored from any earlier backup of
  itself.
- [`ShardsCredentials.tla`](ShardsCredentials.tla) models credentials at
  two shards. A sign-in writes the credential's row without a fence, then
  answers. A shard that meets a credential it doesn't know reads the
  standing again, and revoking a credential is a fenced change.
- [`ShardsExchange.tla`](ShardsExchange.tla) models a CI token exchange
  arriving again and again, at a principal served by two shards that restart.
- [`ShardsCutover.tla`](ShardsCutover.tla) models the cutover from 0.14,
  two ways, each its own spec. B, close and carry (`Spec`): 0.14 instances
  still append, read and revoke while `coffre migrate` copies, closes the old
  chain and revokes INSERT on it. A, the chain continued (`ContinueSpec`):
  no copy and no closing checkpoint. One migration transaction installs the
  revision row and the `FencedWritesOnly` trigger on the shared tables. 0.14
  readers keep deciding under the head and appending to the chain, now the
  control lane. 0.14 writes to decision inputs fail on the trigger. 0.15
  changes take the head and the revision's row, fence a shard, and commit,
  while the shard serves uses.

| Scenario | What runs | Distinct states | Depth | Time (4 workers) |
|---|---|---|---|---|
| `ShardsRevoking` | 1 shard, 2 uses, 2 changes; losses, duplicates, rollbacks, lost COMMIT answers, a writer that does not fence | 1,281,733 | 24 | 20 s |
| `ShardsRollback` | as Revoking, with no duplicates and every COMMIT answered: the revision reused after a rollback | 24,335 | 21 | 1 s |
| `ShardsRestore` | as Rollback, with a backup and one restore among the 2 changes | 142,390 | 22 | 3 s |
| `ShardsFanout` | 2 shards serve the principal, 1 change | 26,956 | 23 | 1 s |
| `ShardsRestarting` | 1 shard, 2 instances, 2 starts, 2 changes | 867,878 | 31 | 9 s |
| `ShardsCombined` (`--long`) | 2 instances and 1 start (a restart, or a second instance), losses, duplicates, resends, rollbacks, lost COMMIT answers; one client sending use after use | 13,716,778 | 39 | 3 min on 8 workers |
| `ShardsLive` | as Revoking without duplicates, with fairness | 106,951 | 25 | 21 s |
| `ShardsLanes` | 2 instances, 3 starts, 4 entries, 1 restore of Postgres | 138,361 | 23 | 2 s |
| `ShardsLanesLost` | 2 instances, 2 starts, one with the storage lost, 3 entries, 2 restores of Postgres | 55,707 | 19 | 1 s |
| `ShardsLanesLive` | as Lanes without restores, with fairness | 820 | 12 | 1 s |
| `ShardsCredentials` | 2 shards, 2 credentials (one issued during the run), 2 uses, 2 revocations | 58,986 | 19 | 2 s |
| `ShardsCredentialsLive` | the second credential issued and kept, with fairness | 6,686 | 14 | 1 s |
| `ShardsExchange` | 2 shards, 2 instances each, 3 attempts, 2 starts | 344 | 9 | 1 s |
| `ShardsCutover` | B: 3 actions by 0.14 instances, then the migration and 0.15 | 170 | 6 | 1 s |
| `ShardsContinue` | A: 2 actions by 0.14 instances, 2 changes by 0.15, 2 uses at its shard | 48,888 | 20 | 2 s |

## What must hold

| Name | Kind | Says |
|---|---|---|
| `NothingReleasedAfterRevocation` | invariant | (In `ShardsContinue`, this covers 0.14 readers and the 0.15 shard together.) A use that arrives after a revocation's answer is never allowed on a grant read before that revocation. A ghost generation of the grant checks this, not the revision label: content read before a change but labelled after it is caught. |
| `UsesOrderedAgainstChanges` | invariant | A use's entry names (e, r), the committed revision when it was decided. Change r committed before it, and change r + 1 after it. In `ShardsRestore`, this also orders uses against the restore. |
| `EveryReplyAudited` | invariant | A reply with a value has its entry in the shard's storage, or one about to be written by a live instance whose writes the storage takes. |
| `FloorsAtMostNext` | invariant | Every floor in the current epoch, in memory or in storage, is at most revision + 1. |
| `LanesHold` | invariant | (In `ShardsContinue`: the control lane, appended by both versions, is chained.) Postgres's copy of a lane is numbered without gap or repeat, each entry is sealed from the one before it, and it holds nothing the shard did not write. No flusher takes for flushed what Postgres does not hold. |
| `RewindStops` | invariant | While Postgres lacks entries the shard recorded as flushed, nothing more is written to that lane. A rewind from before a storage loss is outside it: the shard kept no record of it, and the signed checkpoints find it. |
| `NoUseAfterCredentialRevoked` | invariant | No use with a credential whose revocation was answered before the use arrived is allowed. |
| `SingleUseExchange` | invariant | A jti is spent once. |
| `NothingAfterClose` | invariant | Nothing lands in the old chain after its closing checkpoint. |
| `EveryReleaseAudited` | invariant | Every value 0.14 released has its entry in the old chain, before the closing checkpoint. |
| `RevocationCarried` | invariant | B: no value is released, by either version, after a 0.14 revocation was answered. A: no change writes over a revocation it has not seen. |
| `ChangesEnd` | property | A change that begins ends, answered or rolled back. |
| `UsesAnswered` | property | With finitely many changes, every use is answered, with a value or a refusal. No fence refuses forever, a rolled-back one's included, even when its unfence is lost. |
| `EveryEntryFlushed` | property | Every entry in a shard's storage reaches Postgres. |
| `IssuedUsable` | property | A credential just issued, and never revoked, is usable at either shard. |

## Protections, and what TLC finds without each

| Protection | Turned off, TLC finds |
|---|---|
| `FloorChecked`: kept standing is used only if read at the floor or later | The read happens before the fence, the revocation commits and answers, and the next use is served from the stale standing (`NothingReleasedAfterRevocation`). |
| `NowaitProbe`: only the NOWAIT probe lowers a floor | A timer lowers the floor to the committed revision while the change is still in flight. A read lands below the change and is kept, and it is served after the answer. |
| `ProbeKeepsFence`: the probe lowers a floor only if no fence came while it was out (a count, not the floor's value) | Change A at R=1 rolls back. A probe finds the row free at 0. Change B fences at R=1, which leaves the floor value unchanged, so a value comparison passes. The probe lowers the floor to 0, B commits and answers, and the standing read at 0 is served. |
| `UnfenceProbes`: an unfence only starts a probe | Two routes. (1) A rolls back at R=1, B fences at R=1, then A's late UNFENCE(1) sees floor = 1 and lowers it to 0 (`ShardsRollback`). (2) A COMMIT's answer is lost, the changer unfences as if it had rolled back, then its retry by change id answers. The floor is back at 0 after the revocation committed (`ShardsRevoking`). |
| `OneSnapshot`: the standing and its revision come from one statement | The rows are read before the commit and the revision after it. The old grant is labelled with the new revision and passes the floor. |
| `FencedWritesOnly`: Postgres refuses a write to a decision input from a transaction that did not fence | A writer that does not fence (a 0.14 instance, or a path that forgot) revokes and answers. The shard keeps serving its kept standing, whose revision never moved. |
| `FenceBeforeCommit`: every shard is fenced before the commit | Commit first, then fence, then answer: a use decided between the commit and the fence names revision 0 after change 1 committed (`UsesOrderedAgainstChanges`). It does not break `NothingReleasedAfterRevocation`, because the answer still waits for every fence. |
| `EpochChecked`: the revision is (epoch, n); the migration and a restore write a new epoch; a shard meeting a newer epoch in a fence or a read drops its floor and standing, adopts it, and reads again | A revocation at 1 commits and is answered, and a use's read at revision 0 from before it is still out. Postgres is restored to its backup at revision 0. A probe finds the row free at 0, below the floor of 1, takes it for a rollback, and lowers the floor. The old read, also labelled 0, passes and is served after the revocation (`NothingReleasedAfterRevocation`). Without the epoch, the two revision 0s are the same. |
| `AllAcked`: commit only once every shard acknowledged | s1 acknowledges and s2's fence is still in flight. The change commits and answers, and s2 serves its kept standing. |
| `FencePersisted`: the floor is in storage before the acknowledgement | The fence reaches instance 1 in memory only. Instance 2 starts from storage with floor 0, reads below the change, and serves after the answer. |
| `StorageArbiter`: storage takes only the newest instance's writes | Instance 2 starts, and the fence reaches the old instance 1, which persists and acknowledges. Instance 2 never saw the fence and serves after the answer. On Node this is a lease epoch checked in every write; a lease timeout alone is not enough. |
| `DurableBeforeReply`: the entry is durable before the reply leaves | The reply leaves, then the instance loses the storage before its write (`EveryReplyAudited`). |
| `HeadCAS`: the flush writes only where Postgres's head is | A new instance, whose recorded `flushed` lags, flushes entry 1 again (`LanesHold`). |
| `CasComparesHash`: the flush's CAS compares the head's hash as well as its seq | Entry 1 is flushed, and a backup holds it. The storage is lost, and the new instance writes its own entries 1 and 2. Postgres is restored to empty, the new entry 1 is flushed, then Postgres is restored to the backup. Its head is at seq 1, where the instance expects it, so without the hash the new entry 2 is appended after the old entry 1 (`LanesHold`). |
| `AdoptOnlyOwnPrefix`: Postgres ahead is adopted only up to the shard's own head, and only if the hash at that seq is its own | Entry 1 is flushed, and the storage is lost. The new instance writes its own entry 1, finds Postgres ahead, and adopts it by seq, taking the old entry for its own (`LanesHold`). |
| `RewindChecked`: Postgres behind what was flushed raises the alarm | Postgres is rewound below the recorded head, and the flusher adopts the shorter head and fills it again (`RewindStops`). |
| `FlushGated`: a flush leaves only once a storage write commits | The stale instance, which last flushed nothing, finds the rewound lane empty, where it expects it, and refills it. The alarm the owner would raise never comes. |
| `CredentialRevokeFenced`: revoking a credential is a fenced change | The revocation is an UPDATE that answers at once. A shard serves the credential from its kept standing (`NoUseAfterCredentialRevoked`). |
| `UnknownCredentialRereads`: a shard reads again for a credential it does not know | A shard keeps a standing from before the second credential was issued, and refuses it, every time (`IssuedUsable`). |
| `JtiSpentInShard`: the spent jti is in storage before the answer | The jti is spent in memory only. A second instance starts and accepts it again. |
| `JtiAtHome`: an exchange goes to the principal's home shard | s1 and s2 each spend the same jti in their own storage. |
| `OldLoginRevoked` | A 0.14 vault instance appends after the closing checkpoint (`NothingAfterClose`). |
| `AppLoginRevoked` | The same for the 0.14 app login, which the baseline also grants INSERT on `audit_log` (and UPDATE on `audit_chain_head`). |
| `CutoverInOneTransaction`: copy, close and revoke run as one transaction under the old head's lock | With copy, close and revoke as three steps, a 0.14 instance appends between close and revoke (`NothingAfterClose`). A 0.14 read released there has its entry after the checkpoint (`EveryReleaseAudited`). |
| `CutoverInOneTransaction` + `FencedWritesOnly` | A 0.14 revocation lands between the copy and the revoke and is answered. 0.15 serves the copied grant (`RevocationCarried`). Either protection alone prevents this. |
| A: `TriggerInstalledWithRevision` | The revision row is installed and 0.15 starts. The shard reads the grant. A 0.14 vault revokes and answers, without a fence, before the trigger's later step. The shard keeps the standing and serves the next use with it (`NothingReleasedAfterRevocation`). A split install is safe only if both steps land before 0.15 starts: TLC holds when the start waits for the trigger. |
| A: `FencedWritesOnly` | The same race, with no trigger at all. |
| A: `ChangeTakesHead`: a 0.15 change holds the head from before its fences to its commit | A 0.15 change reads head 0. A 0.14 app entry lands at 0, and the change's control entry is also sealed from 0, so the chain forks (`LanesHold`). |
| A: `ChangeTakesHead` + `FencedWritesOnly` | A 0.15 revocation fences. A 0.14 revocation lands and is answered meanwhile, and the 0.15 commit writes over it unseen (`RevocationCarried`). |

## What the model changed in the design

1. **The probe must compare a fence count, not the floor.** A rollback
   leaves the revision where it was, so the next change fences at the same
   R. "Lower only if the floor has not moved" passes when the floor moved
   from R to R. The shard needs an in-memory count of fences received. A
   probe records it when sent and lowers the floor only if the count is
   unchanged.
2. **UNFENCE must not lower the floor itself.** `experiments/lanes` does
   `if (floor === R) floor = R - 1`. That breaks in two ways: a late
   UNFENCE(R) from a rolled-back change arriving after the next change's
   FENCE(R), and the UNFENCE a changer sends when it cannot tell whether its
   COMMIT landed. Make UNFENCE a hint that runs the probe, or drop it: the
   probe on the next use already lifts a rolled-back fence (`UsesAnswered`
   holds with unfences lost).
3. **The probe can tell a rollback from a rewound database.** Floors never
   pass revision + 1 (`FloorsAtMostNext`). A probe that finds the revision
   more than one below its floor has found Postgres restored from an older
   backup, not a rollback. It should raise the alarm, not lower the floor.
4. **A flush must start with a storage write.** As Cloudflare describes its output
   gate, it holds outgoing I/O only while a write is pending. An instance the storage
   no longer takes, with nothing pending, can still write to Postgres. That
   is harmless for the lane itself, because the head's compare-and-swap
   holds, but it lets a stale instance refill a rewound lane before the
   owner notices.
5. **The cutover revokes both logins, in one transaction.** The 0.14 app
   login can append to `audit_log` too. Copy, close and revoke as three
   steps leave two windows: an append after the checkpoint, and a revocation
   answered by 0.14 that 0.15 never sees. Run them as one transaction that
   takes the old head's row first (REVOKE is transactional in Postgres), or
   order them revoke, copy, close. The `FencedWritesOnly` trigger, installed
   on the old tables at the copy, also closes the second window.
6. **A restore fences, as a change does.** The epoch alone is not enough. A
   shard with a kept standing reads nothing, so it would answer from before
   the restore until the first change after it. `coffre restore` must fence
   every shard at (new epoch, the backup's revision) before it puts the
   backup in place. TLC found that with the epoch checked and the restore
   not fenced: a use read before the restore and decided after it names the
   old epoch (`UsesOrderedAgainstChanges`). A restore that fails after
   fencing leaves shards refusing until it completes. The model does not
   roll restores back.
7. **The lane's CAS and adoption compare hashes.** A shard whose storage is
   lost starts a second history at seq 1. Adopting Postgres's head by seq
   takes the old history for its own; a CAS by seq alone appends after it.
   With both comparing the hash, the flusher raises the alarm and the shard
   stops flushing and serving. That is the simplest correct rule. The
   alternative, a new lane epoch for the shard (a new lane, chained from
   genesis, that the checkpoints link), keeps it serving. Entries written
   between the loss and the alarm stay in the storage until an operator
   moves them; a new lane epoch would carry them.
8. **A credential is issued without a fence; its revocation is fenced.** The
   `FencedWritesOnly` trigger must let a new credential's INSERT through
   without a fence, while refusing unfenced revocations. A shard meeting an
   unknown, authentic credential reads again.
9. **The jti is spent at the home shard,** never at another shard serving
   the same principal. The home must not move while a token can still be
   presented: resharding has to carry the spent set, or the spent set lives
   in Postgres.

## What is abstracted

- One principal and one grant. Any change fences every shard, so a global
  revocation and a per-principal one take the same path. The standing is
  one grant plus a ghost generation.
- In the lanes, an entry is (seq, hash, previous hash), with a new hash for
  each write. MACs and hashes are assumed collision-free.
  Checkpoints, apart from the closing one, and verification from the last
  checkpoint (R25) are not modelled.
- Storage arbitration is an assumption, Cloudflare's: of two live
  instances, the storage takes only the newer one's writes. Turning it off
  shows the design needs it. On Node it has to be built: an epoch checked
  in every write.
- The NOWAIT probe and its read are one step. Separate steps would only add
  behaviours where the row is found taken, which refuse.
- A decision, its entry and caching its standing are one step, as one turn
  of a Durable Object's actor with synchronous SQL is.
- An RPC's acknowledgement is the delivery step. A lost acknowledgement is a
  rollback or a resend.
- A storage loss in `Shards.tla` (the floor gone with it) is not modelled.
  A shard starting on an empty storage should take its floor as unknown,
  and probe before it answers.
- The bounds are small: 1 or 2 shards, 2 instances, 2 uses (or one client
  repeating), 2 changes, 1 to 3 starts, 4 entries, 2 restores of the lane, 1
  restore of the revision, 3 actions by 0.14 instances. Node's group commit,
  the bulk cap (R28) and R16/R32 are not modelled.

## Where TLC stops, and Apalache or TLAPS would go further

- **Any number of shards, uses and revisions.** The safety argument is an
  inductive invariant. Every instance's floor is at most revision + 1, and
  its storage floor is at least the floor of any fence it acknowledged to
  the change in flight. A kept standing at or above the floor was read at
  the committed revision or at one below a change still in flight. TLAPS can
  prove that for all N. Apalache's `--inductive` mode can check it with
  revisions as unbounded integers, which is where ABA races like (1) live.
- **Liveness under endless changes.** `UsesAnswered` holds because changes
  are finite. With a change always in flight, a use can be refused forever:
  each read lands below the next floor. That needs an unbounded model, or a
  proof of the bound "changes at most k per window ⇒ a use is answered
  within k + 1 tries".
- **The fan-out's counters.** A per-principal cap counted per shard allows
  K times the cap with fan-out K. The model has no counters, and that needs
  arithmetic over K, which Apalache handles symbolically.
