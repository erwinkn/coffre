----------------------------- MODULE HotPathOne -----------------------------
(***************************************************************************)
(* 0.15's hot path: one round trip per use, no revision (W208, W211;       *)
(* docs/design/hot-path-one.md). Uses and changes on one Postgres, under   *)
(* READ COMMITTED.                                                         *)
(*                                                                         *)
(* A use is one call, `use_credential`, a plpgsql function, one            *)
(* transaction (autocommit):                                               *)
(*   it reads, before any lock, the ids of the objects it will read: its   *)
(*   credential's member, its key's environment and, if the key is a       *)
(*   reference, its source (the call names only the credential, the key    *)
(*   and the place);                                                       *)
(*   it takes the fence lock (an advisory lock) shared, then each of those *)
(*   objects' locks (L1, T282: an advisory lock an object), shared, in key *)
(*   order, and refuses an `at` below the floor;                           *)
(*   statement A reads the principal's bulk row for its key and, if the    *)
(*   key must enter the cap's set, takes the principal's lock exclusive,   *)
(*   or, if it is in the set and must be moved on, shared (T127);          *)
(*   statement B, a snapshot of its own after every lock: past its         *)
(*   deadline it writes nothing (`late`); if its rows name an object the   *)
(*   call did not lock, it writes nothing either (`moved`, and the vault   *)
(*   asks again); else it reads every decision input, the seals of their   *)
(*   newest changes, applies the cap's rule and inserts the use's entry,   *)
(*   numbered from a sequence (or, a repeat on a cover, writes nothing);   *)
(*   it commits, which lets the locks go.                                  *)
(* The Worker decides on what statement B read, and the value leaves only  *)
(* after the commit and before the use's deadline. The entry is the        *)
(* request, not the outcome: the outcome is recomputed from the log.       *)
(*                                                                         *)
(* A change (one input revoked or restored) is one call too: the vault     *)
(* reads the row outside any lock; then the fence shared and the lock of   *)
(* the object it writes, exclusive, the write if the row is still the one  *)
(* it read, its entry numbered from the same sequence, the commit; then it *)
(* answers. The checkpointer's barrier takes the fence exclusive for one   *)
(* statement, as it alone does: it raises the floor of `at` to its clock   *)
(* less D and closes every number handed out so far. The next checkpoint   *)
(* reads that window, its uses through the `at` index from the floor the   *)
(* previous barrier set, and signs it.                                     *)
(*                                                                         *)
(* The claim at the core: since a use holds the lock of each object it     *)
(* reads shared and a change the lock of the one it writes exclusive, and  *)
(* each takes its number under its locks and keeps them until its commit   *)
(* is visible, no use overlaps a change of what it reads, so the number    *)
(* alone orders every use against every change of what it reads            *)
(* (TotalOrder). Nothing is left for a revision counter to do. Until L1    *)
(* the fence was that lock for every object at once, every change taking   *)
(* it exclusive: a change of one key made every use wait. Changes are      *)
(* ordered against each other by the change lock (Coffre.tla,              *)
(* WriteLocks.tla), which this module leaves out: its changers may run     *)
(* side by side, on two objects, and nothing here relies on their order.   *)
(*                                                                         *)
(* A statement is several steps here where something can come between     *)
(* them in Postgres: it takes its snapshot when it starts, then waits for  *)
(* its lock, then reads and writes, then commits; the commit is flushed to *)
(* disk at once (synchronous_commit on) or later; Postgres can crash.      *)
(*                                                                         *)
(* The inputs: every decision reads several rows (Inputs), each sealed by  *)
(* the vault (a MAC over it): in coffre the member with its grants, the    *)
(* credential, the secret with its wrapped key, the environment. Each      *)
(* change writes exactly one and its entry records the seal it leaves. An  *)
(* input here allows (TRUE) or refuses (FALSE); a change flips one. A seal *)
(* is the row's content, so putting back an identical row passes,          *)
(* harmlessly. An input in Unsealed is read without its seal checked (a    *)
(* removal: normally {}). A database writer with no key (MaxTampers) can   *)
(* only put back a row the vault once sealed: an earlier value of that     *)
(* input; with LogTampers (T190), it also writes that row's seal into the  *)
(* seal column of the input's newest change, which the vault compares rows *)
(* with, and that entry's MAC, which covers the seal, then no longer       *)
(* holds. It cannot make a MAC, nor delete or move an entry here: those    *)
(* the checkpoints catch (merkle-checkpoints.md). The log stores no        *)
(* outcome; each entry's decision here is a ghost, for the invariants.     *)
(*                                                                         *)
(* Covers (fewer rows): once an allowed use's entry #k has committed, the  *)
(* isolate passes k with the next uses of the same key. Under the same     *)
(* shared lock, the call writes nothing if its cover's entry is still in   *)
(* the log, no change was numbered after it, and the key is fresh in the   *)
(* cap's set: the use is a repeat of #k, which the log already has. It     *)
(* still reads, and the Worker still decides on what it read.              *)
(*                                                                         *)
(* The seal cache (SealCache): the isolate keeps, per key, the seals of    *)
(* the inputs' newest changes as a use read them, with the log's newest    *)
(* change then (its number and MAC). A later use passes it; its statement  *)
(* reads the log's newest change and, if it is that one, skips the probes  *)
(* and the Worker holds the rows to the cached seals (a cover is then      *)
(* checked against the cached number). Otherwise it probes, and the        *)
(* isolate keeps what it read.                                             *)
(*                                                                         *)
(* Issues (Issuers, T123, R58): a sign-in issues a new credential, one    *)
(* change of the log (`credential.issue`), in the app's transaction. It    *)
(* never takes the fence: nobody can name a credential before its issue    *)
(* commits (its token is handed out after), so no use overlaps it, and    *)
(* it changes no input any other use reads. It takes a lock of its own,    *)
(* the issue lock, shared, and its number under it; the lock goes with    *)
(* the commit. The barrier waits for the issues in flight on that lock,    *)
(* exclusive, before it takes the fence: so a use never waits on an issue, *)
(* directly or behind the barrier (Postgres queues a shared request behind *)
(* a waiting exclusive one: a barrier queued on the fence while it waited  *)
(* for an issue would hold every use up for the issue's commit). A use     *)
(* that names a new credential (`fresh`) finds it only once its issue has  *)
(* committed, in its snapshot; the replay, once its issue is numbered      *)
(* below the use. Covers and the seal cache are per credential and key.    *)
(* The issue lock's order against 0.14's head and the other locks, and     *)
(* that no wait cycle comes of it, are Migration015.tla's (Migration015Issue).*)
(*                                                                         *)
(* One isolate: each cover and cache entry is checked against the log and  *)
(* the bulk rows on its own, never against another isolate's, so more      *)
(* isolates only add more of the same kind.                                *)
(*                                                                         *)
(* A restore (MaxRestores): the database goes back to an earlier point, a  *)
(* backup's, its log, rows and sequence with it, while no call is in       *)
(* flight; the isolates keep their caches and covers. Changes made after   *)
(* it take the numbers again. A change's MAC covers its request id, so two *)
(* changes are never the same: here, each change has an id of its own      *)
(* (`made`). The history before a restore is gone, and so are the ghosts   *)
(* about it (`released`, `repeats`, the signed checkpoints).               *)
(*                                                                         *)
(* Changers: the change processes, each one change at a time. Two can race *)
(* on one input: each reads the row outside the lock and works out the     *)
(* next state from what it read. A change stands for every write that      *)
(* holds a row to its object's newest seal (`newestChange`, `prepare`,     *)
(* sign-in, issue). Those of PinnedChangers are sign-ins (T192): their     *)
(* statement holds the newest change to the one whose MAC the vault        *)
(* checked. With AppPins, the app hands that change over, read beside the  *)
(* binding, and may hand back any authentic change of the object, under    *)
(* any number: no MAC covers a number. The vault reads it itself after a   *)
(* `moved`. The others pin nothing here: T179's two-trip writes hold their *)
(* read set whole (Writing.tla, ReadByNumber), and the rest do not yet.    *)
(*                                                                         *)
(* Clocks. Postgres's clock `pnow` moves on (to MaxTime), and may step     *)
(* back. A use is stamped `at` by the Worker's clock (pnow, give or take   *)
(* MaxSkew) when it arrives (at pnow <= MaxStart), and its deadline is     *)
(* at + D (D: the 3 s bound, scaled down). Deadlines are checked by        *)
(* Postgres's clock against the Worker's `at`.                             *)
(*                                                                         *)
(* The bulk cap (R52): at most BulkCount distinct keys per principal in    *)
(* any BulkWindow (W), both parameters; Keys = {} leaves it out. With a    *)
(* `policy` input (W216), the count and the window are the deployment's,  *)
(* sealed and changed like any input: TRUE stands for (BulkCount,          *)
(* BulkWindow), FALSE for (BulkCountAlt, BulkWindowAlt), and a change      *)
(* flips it; it allows every use itself. Each request is decided on the    *)
(* policy in force at its number, live and in the replay. One row          *)
(* per key the principal asked for, `last`: when the key last entered the *)
(* set or was moved on, as the start of that use's refresh period (the     *)
(* periods are Refresh, delta, long, each key's from a phase of its own:   *)
(* t - (t - phase) % delta, T204). A key is in the set                     *)
(* at time t while last > t - W - delta. A key that is not in the set      *)
(* enters it if fewer than BulkCount others count at t, else the request   *)
(* is refused `bulk`; another key counts while last > t - W - delta - D - *)
(* MaxSkew: a use is decided up to D after its `at`, and one stamped by a  *)
(* Worker running ahead up to MaxSkew before its own, so it can be decided *)
(* after a use stamped up to D + MaxSkew later, which must have counted    *)
(* its key. A key in the set is moved on only once its `last` is from an  *)
(* earlier period than the use's, so that a hot key does not write its row *)
(* on every use. Uses that move one key on at once each write their      *)
(* period, the greatest one kept: the rows end where the replay's do,      *)
(* whichever commits first, so moves need not wait for one another        *)
(* (T127). Every request counts but the ones the cap refuses, whatever the *)
(* decision on the inputs: the SQL that moves the row cannot know it, the  *)
(* log stores requests, and the replay recomputes the cap from them in     *)
(* number order.                                                           *)
(*                                                                         *)
(* Hyperdrive may hold a call (Holds) and never run it; the Worker answers *)
(* 503 at the deadline all the same. That answer is a step of its own only *)
(* with Holds: without, every call returns, and the deadline check on its  *)
(* return stands for it. A call may also fail before its commit, or its   *)
(* Worker die after it (Failures); the bulk scenarios leave both out.      *)
(*                                                                         *)
(* The protections, each a constant, so that TLC can show each necessary   *)
(* (scripts/formal.sh):                                                    *)
(*   UseLocks              a use takes its locks shared: the fence, and    *)
(*                         the lock of each object it reads;               *)
(*   Unlocked = {}         ... of every one: an object it reads unlocked   *)
(*                         (the member, whom the call does not name) is    *)
(*                         one a change may write under it;                *)
(*   LockedAsRead          ... and a use whose rows name an object it did  *)
(*                         not lock (its key made a reference since the    *)
(*                         call read the ids) writes nothing, and never    *)
(*                         takes a lock after its first read;              *)
(*   StatementSnapshot     its reads take their snapshot after its locks:  *)
(*                         a statement of its own inside the function,     *)
(*                         FALSE for a bare CTE, `WITH l AS (SELECT        *)
(*                         pg_advisory_xact_lock_shared(…)) …`, whose one  *)
(*                         snapshot predates the wait (and for a row's     *)
(*                         lock, FOR SHARE, which a statement takes after  *)
(*                         its snapshot);                                  *)
(*   UseNumberUnderLock    a use's number is taken under the lock, not     *)
(*                         passed in (`use_credential(nextval(…), …)`);    *)
(*   ChangeLocks           a change takes the lock of the object it        *)
(*                         writes, exclusive;                              *)
(*   ChangeSharesFence     ... and the fence, shared, so that the barrier  *)
(*                         waits for its number;                           *)
(*   ChangeNumberUnderLock a change's number is taken under the lock, not  *)
(*                         in a read before it;                            *)
(*   LockToCommit          the locks go with the commit (xact locks), not  *)
(*                         at the end of the statement before it (session  *)
(*                         locks unlocked in the function);                *)
(*   CommitBeforeAnswer    a change answers only once committed;           *)
(*   ReleaseAfterCommit    a use's value leaves only once its entry has    *)
(*                         committed;                                      *)
(*   SyncCommit            a commit returns once flushed                   *)
(*                         (synchronous_commit on);                        *)
(*   CheckpointLocks       the barrier closes its numbers under the fence  *)
(*                         exclusive;                                      *)
(*   CoverChecksChanges    a covered use writes nothing only if no change  *)
(*                         was numbered after its cover;                   *)
(*   CoverChecksAllInputs  ... a change to any of its inputs, not only to  *)
(*                         the member (W208's first scope);                *)
(*   CoverExists           ... its cover's entry is still in the log (its  *)
(*                         number, time and request id: a restore may have *)
(*                         taken it out);                                  *)
(*   Unsealed = {}         every input's seal is checked: a use refuses    *)
(*                         (`stale`) a row whose seal is not the one its   *)
(*                         newest change wrote (R53);                      *)
(*   StaleFirst            `decide` checks the seals before what the rows  *)
(*                         say, so that a row put back shows as `stale`;   *)
(*   CacheChecked          a use skips the probes of the newest changes    *)
(*                         only if the log's newest change is the one the  *)
(*                         isolate's cache was read at;                    *)
(*   CacheSameChange       ... the same change (its number and MAC), not   *)
(*                         only a number no higher: a log restored from a  *)
(*                         backup has other changes under the same         *)
(*                         numbers;                                        *)
(*   ChangeCAS             a change writes only if the row is still the    *)
(*                         one it read (`WHERE seal = p_seal_from`);       *)
(*   ChangeRereads         ... and else reads it again (not the same read, *)
(*                         retried);                                       *)
(*   ChangeChecksSeal      ... and only if the row is the one its object's *)
(*                         newest change wrote (its seal is that change's: *)
(*                         change_input probes the newest change as a use  *)
(*                         does), else it reads again: a row put back      *)
(*                         carries a valid older seal, so the check on     *)
(*                         what was read passes, and the change would      *)
(*                         apply its payload to the rolled-back row and    *)
(*                         seal the result;                                *)
(*   DeadlineChecked       a call that decides past its deadline writes    *)
(*                         nothing: checked with clock_timestamp() after   *)
(*                         its last lock wait, in the statement that       *)
(*                         decides (now() is the transaction's start,      *)
(*                         before any lock wait, and passes a late use);   *)
(*   AheadChecked          a use whose `at` is more than MaxSkew past      *)
(*                         Postgres's clock writes nothing (`ahead`, 60 s  *)
(*                         in the code): with DeadlineChecked, a use takes *)
(*                         its number within [at - MaxSkew, at + D] by     *)
(*                         Postgres's clock, which reads both, so a later  *)
(*                         number's `at` is never more than D + MaxSkew    *)
(*                         below an earlier one's (CeilingHolds);          *)
(*   ChunkFloor            a checkpoint that seals only a prefix of its    *)
(*                         barrier's window (T169: a tick's window is      *)
(*                         capped) signs as its floor the lowest `at` of   *)
(*                         the uses the window holds above it, if below    *)
(*                         the barrier's, never the barrier's: the next    *)
(*                         window is read from it, and the rest of the     *)
(*                         backlog may be stamped long before the barrier; *)
(*   FloorChecked          a use whose `at` is below the floor writes      *)
(*                         nothing;                                        *)
(*   BarrierChecksFloor    the floor is an unsigned row: the barrier       *)
(*                         finds it at the value it last wrote, which the  *)
(*                         signer remembers, or raises the alarm and signs *)
(*                         nothing (a floor a writer lowered would let a   *)
(*                         use in below it, which the next checkpoint's    *)
(*                         `at` scan misses);                              *)
(*   BarrierAcceptsLate    ... or above it, but no higher than this        *)
(*                         barrier's own clock less D: what a barrier of a *)
(*                         signer given up on (T169) leaves when it lands  *)
(*                         late, which the next barrier raises past anyway *)
(*                         (LateBarrier); without, one such barrier stops  *)
(*                         every checkpoint after it (CheckpointsGoOn);    *)
(*   WorkerHonoursDeadline the Worker answers 503 at the deadline, and a   *)
(*                         value whose call returns later never leaves;    *)
(*   PrincipalLocks        a key that enters the cap's set takes the       *)
(*                         principal's lock exclusive;                     *)
(*   RefreshLocks          ... and a key moved on takes it too (shared     *)
(*                         with RefreshShared), so that a key entering the *)
(*                         set counts every move numbered before it;       *)
(*   RefreshPeriods        a key moved on writes the start of its use's    *)
(*                         refresh period, not its time, so that two moves *)
(*                         at once write what the replay's one does;       *)
(*   RefreshShared         a move takes the lock shared, not exclusive: so *)
(*                         a hot key's uses never queue behind one another *)
(*                         (RefreshesNeverQueue; T127);                    *)
(*   RefreshOnUse          a use moves its key on once `last` is from an   *)
(*                         earlier period (delta old, without periods);    *)
(*   CoverFresh            a repeat rides a cover only while its key's     *)
(*                         `last` is from its own period;                  *)
(*   ReplayPhases          the replay starts each key's periods where the  *)
(*                         statement does, at its phase (T204);            *)
(*   ReplayPhased          it phases a use's key only if the statement     *)
(*                         that decided it did, as its entry records: the  *)
(*                         previous release's phases none (T204);          *)
(*   Slack                 the set keeps a key delta longer than W (its    *)
(*                         last use may be up to delta after `last`);      *)
(*   DeadlineSlack         another key counts against a new one D longer   *)
(*                         than it stays in the set;                       *)
(*   AheadSlack            ... and MaxSkew longer again: a use stamped by  *)
(*                         a Worker whose clock runs ahead is decided up   *)
(*                         to D + MaxSkew before one stamped earlier (in   *)
(*                         Postgres, 60 s, the most `ahead` lets by);      *)
(*   CapFromPolicy         the statement takes the cap's count from the    *)
(*                         policy in its own snapshot, not a count the     *)
(*                         caller passes from its config, which may lag    *)
(*                         the logged one;                                 *)
(*   CapSealed             ... from the policy's newest change (probed, or *)
(*                         the isolate's cache when it holds), not from    *)
(*                         the policy row, which a writer may have put     *)
(*                         back: the SQL cannot check a MAC, and the cap's *)
(*                         row moves whatever the Worker then decides;     *)
(*   ChangeMacChecked      a use holds a row to the seal its newest change *)
(*                         records only once that change's MAC holds over  *)
(*                         it, the seal included (T190): the statement     *)
(*                         answers each newest change's MAC'd columns, and *)
(*                         the Worker checks them; a change whose MAC does *)
(*                         not hold leaves the row `stale`;                *)
(*   CacheVerified         the isolate's seal cache keeps only seals whose *)
(*                         changes' MACs held: one kept unchecked would be *)
(*                         trusted, unprobed, by every use while the log's *)
(*                         newest change stays the same;                   *)
(*   ChangeChecksMac       a write checks the MAC of the newest change it  *)
(*                         holds the row to (`newestChange`, `prepare`,    *)
(*                         sign-in, issue), as a use does; else a change   *)
(*                         to a row put back so seals the writer's row     *)
(*                         under a new, authentic entry (EachChangeFlips). *)
(*                         The code checks it before its statement, and so *)
(*                         does the model: of the change read at           *)
(*                         ChangeStart;                                    *)
(*   ChangePinsChecked     ... and a sign-in's statement (PinnedChangers)  *)
(*                         holds the object's newest change, under the     *)
(*                         lock, to the one whose MAC it checked (T192):   *)
(*                         else a second tamper, the seal column forged    *)
(*                         once the check is done, passes the statement's  *)
(*                         seal comparison (HotPathOneForgedGap: the row   *)
(*                         put back, then the forgery, MaxTampers = 2).    *)
(*                         Writes that pin nothing (`app_change`,          *)
(*                         `issue_token` outside T179's two trips) keep    *)
(*                         that gap: the scenario without the pin is       *)
(*                         theirs;                                         *)
(*   ChangePinsWhole       ... whole: its number, every column its MAC     *)
(*                         covers (`made`, `value`) and the seal, not its  *)
(*                         number and seal alone, which an old, authentic  *)
(*                         change handed back under the newest's number    *)
(*                         shares with the newest once a writer sets its   *)
(*                         seal to the old one's (AppPins, review r2);     *)
(*   IssueOwnLock          an issue takes the issue lock shared, not the   *)
(*                         fence shared (which a barrier or a change       *)
(*                         queued behind it would make every use wait on); *)
(*   IssueNumberUnderLock  its number is taken under that lock;            *)
(*   BarrierWaitsIssues    the barrier takes the issue lock exclusive, so  *)
(*                         that every issue numbered so far has committed  *)
(*                         or rolled back when it closes;                  *)
(*   BarrierIssueFirst     ... before the fence, not holding the fence     *)
(*                         while it waits for an issue;                    *)
(*   NamedAfterIssue       a credential is named by a use only once its    *)
(*                         issue has committed (its token handed out).     *)
(*                                                                         *)
(* What it abstracts. A row's seal is its content, and a writer can only  *)
(* put back what the vault once sealed. A change flips its input; the      *)
(* replay applies the changes' operations (each a flip) in number order,   *)
(* and a change's entry records the value it sealed, so a change applied   *)
(* to a row put back shows as an entry that is not the flip of the one     *)
(* before it (EachChangeFlips), and as uses the replay refuses. The bulk   *)
(* rows and the floor of `at` are unsigned: a writer can reset the live    *)
(* cap (a key let in again early), which only the replay shows (no         *)
(* invariant here holds the live rows to a writer), and can lower the      *)
(* floor (TamperFloor), which the barrier checks (BarrierChecksFloor).     *)
(*                                                                         *)
(* Liveness (UseAnswered, ChangeAnswered): under weak fairness of the      *)
(* protocol's steps, with crashes, aborts, holds, tampering and restores   *)
(* bounded and not fair. A change that keeps finding its row put back      *)
(* never answers (it fails closed, ChangeChecksSeal): HotPathOneLive has   *)
(* no writer. Left to the benchmarks instead: how long any of   *)
(* it takes (latencies, the 503's speed, a change's wait for the uses in   *)
(* flight, sealing within a tick), and that an unending stream of uses     *)
(* never starves a change (Postgres queues an exclusive lock request ahead *)
(* of later shared ones; the model's uses are finite).                     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Uses,            \* the uses, each one request, one call
    Changers,        \* the change processes
    PinnedChangers,  \* ... of them, the sign-ins, whose statement pins the change checked (T192)
    AppPins,         \* the app hands a sign-in that change, any authentic one of the object, under any number
    MaxChanges,      \* changes each changer makes in a behaviour
    MaxAborts,       \* change statements that fail after taking the lock
    MaxCheckpoints,  \* checkpoints signed in a behaviour
    MaxCrashes,      \* Postgres crashes in a behaviour
    Covers,          \* uses pass the isolate's cover
    Inputs,          \* the rows a decision reads
    Unsealed,        \* the inputs read without their seal checked: {} (a removal sets some)
    SealCache,       \* the isolate keeps the seals a use read, and later uses may pass them
    MaxTampers,      \* rows a database writer puts back in a behaviour
    LogTampers,      \* ... and may write the row's seal into its newest change's `seal` column too (T190)
    MaxRestores,     \* restores from a backup in a behaviour
    Holds,           \* Hyperdrive may hold a call and never run it
    FloorTampers,    \* the writer's tampering (MaxTampers) may lower the floor of `at` instead of a row
    LateBarriers,    \* a barrier of a checkpointer given up on may land late, any number of times (T169)
    Chunks,          \* a checkpoint may seal a prefix of its barrier's window (T169: the window is capped)
    Ahead,           \* how much further than MaxSkew a Worker's clock may run ahead (`ahead` refuses its uses)
    Failures,        \* a call may fail before its commit, or its Worker die after it
    Keys,            \* the keys one principal asks for; {}: no bulk cap
    MaxTime,         \* Postgres's clock runs 0..MaxTime
    MaxStart,        \* uses arrive while Postgres's clock is at most this
    MaxClockBacks,   \* times it steps back by one in a behaviour
    MaxSkew,         \* how far a Worker's clock is from Postgres's
    D,               \* a use's deadline after its `at`
    BulkCount, BulkCountAlt, BulkWindow, BulkWindowAlt, Refresh,
    UseLocks, StatementSnapshot, UseNumberUnderLock, ChangeLocks, ChangeNumberUnderLock,
    LockToCommit, CommitBeforeAnswer, ReleaseAfterCommit, SyncCommit, CheckpointLocks,
    CoverChecksChanges, CoverChecksAllInputs, CoverExists, StaleFirst, CacheChecked, CacheSameChange,
    ChangeCAS, ChangeRereads, ChangeChecksSeal, BarrierChecksFloor, BarrierAcceptsLate, ChunkFloor, AheadChecked, DeadlineChecked, FloorChecked, WorkerHonoursDeadline,
    PrincipalLocks, RefreshLocks, RefreshPeriods, RefreshShared, RefreshOnUse, CoverFresh, ReplayPhases, ReplayPhased, Slack, DeadlineSlack,
    AheadSlack, CapFromPolicy, CapSealed, ChangeMacChecked, CacheVerified, ChangeChecksMac, ChangePinsChecked, ChangePinsWhole,
    Issuers,         \* the sign-ins, each issuing one new credential: {} for none
    IssueOwnLock, IssueNumberUnderLock, BarrierWaitsIssues, BarrierIssueFirst, NamedAfterIssue,
    DecideBeforeLock,
    ReadSets,        \* the sets of inputs a use may read, each a key's and its caller's objects: {} for all of them
    Extra,           \* the inputs a use reads only while its key is a reference (its source): {} for none
    Unlocked,        \* the inputs a use reads without their lock: {} (a removal sets some)
    ChangeSharesFence, LockedAsRead

ASSUME /\ ReadSets \subseteq SUBSET Inputs /\ Extra \subseteq Inputs /\ Unlocked \subseteq Inputs
       /\ Extra = {} \/ "secret" \in Inputs
       /\ \A R \in ReadSets : "policy" \in Inputs => "policy" \in R
       \* A key's source is read through its link alone: the replay takes every Extra input off a use's reads
       \* and puts back the one the log links (ReplayReads), which is wrong for a read set that holds one.
       /\ Extra = {} \/ (ReadSets # {} /\ \A R \in ReadSets : R \cap Extra = {})

None == "none"
Change == "change"
NoTime == -1000   \* a key never asked for

VARIABLES
    log,       \* the committed entries; `durable` once flushed
    nextSeq,   \* the sequence's next value
    holder,    \* the fence held exclusive: the barrier, or None
    shared,    \* the uses holding their locks, the fence and their objects', shared
    plock,     \* the principal's lock: the use holding it exclusive (ex), or None, and those holding it shared (sh)
    u,         \* each use's state
    c,         \* each changer's state
    answered,  \* of each input: how many of its changes had committed when the last of them answered
    released,  \* the values that left: the use, its key, its at and deadline, the time
    cp,        \* the checkpointer: a window closed and not yet signed
    lastUpto,  \* where the last checkpoint ended
    lastFloor, \* the floor its barrier set: where the next one reads uses from
    signed,    \* the checkpoints signed: their range and the numbers they read
    floor,     \* the floor of `at`
    crashes,   \* Postgres crashes so far
    cover,     \* the isolate's cover per key: the number (0: none) and use of the last allowed entry it wrote
    repeats,   \* the values released on a cover: the use, its cover, what it saw, the changes answered
    tamper,    \* each input's row as a database writer put it back (`on`), else the row its newest change wrote
    tampers,   \* rows put back so far
    cache,     \* the isolate's seal cache per key: the seals a use read and the log's newest change then
    restores,  \* restores so far
    bulk,      \* the principal's bulk rows, committed: each key's `last`, or NoTime
    pnow,      \* Postgres's clock
    backs,     \* its steps back so far
    iss,       \* each issuer's state
    iholder,   \* the issue lock held exclusive: the barrier, or None
    ishared,   \* ... held shared: the issuers
    bar        \* the locks the barrier holds while it waits for its next

issueVars == <<iss, iholder, ishared, bar>>
vars == <<log, nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
          cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iss, iholder, ishared, bar>>

Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b

NoPlock == [ex |-> None, sh |-> {}]
\* The principal's lock without use x: what its commit, or its end, leaves.
PlockWithout(x) == [ex |-> IF plock.ex = x THEN None ELSE plock.ex, sh |-> plock.sh \ {x}]

-----------------------------------------------------------------------------
(* What a statement sees. `SeenIn`, the number of changes of each input committed, orders it      *)
(* against the changes of what it reads (TotalOrder). Each input's row is what its newest         *)
(* committed change wrote, unless a database writer put back an earlier one; the seal of the      *)
(* input's newest change is read from the log in the same statement.                              *)
ChangesIn(L) == {e \in L : e.kind = "change"}
\* An issue is a row of the change table too (`credential.issue`), of an object no input names.
IssuesIn(L) == {e \in L : e.kind = "issue"}
\* Whether issuer i's credential is in L: committed, or below a number.
IssuedIn(L, i) == \E e \in IssuesIn(L) : e.id = i
UsesIn(L) == {e \in L : e.kind = "use"}
\* How many changes of each input L holds: what a statement has seen of each object.
SeenIn(L) == [i \in Inputs |-> Cardinality({e \in ChangesIn(L) : e.input = i})]
NoSeen == [i \in Inputs |-> 0]

\* The objects a use reads (L1). Each use is of one key by one caller: it reads that key's and that caller's objects,
\* one of ReadSets (all the inputs, with none given), and, while the key is a reference, its source's too (Extra). The
\* key's row says which: here, the newest change of the secret, whose entry records the link it leaves (none: plain).
ReadSetsOr == IF ReadSets = {} THEN {Inputs} ELSE ReadSets
\* A reference names one source, one of Extra, and a later change of the key may name another (the reference ended and
\* made again, re-pointed): the link is which, NoLink for a plain key.
NoLink == "-"
LinkIn(L) ==
    LET cs == {e \in ChangesIn(L) : e.input = "secret"}
    IN IF cs = {} THEN NoLink ELSE (CHOOSE e \in cs : \A d \in cs : d.seq <= e.seq).link
ReadsWith(base, link) == base \cup (IF link /= NoLink /\ "secret" \in base THEN {link} ELSE {})

\* An input's value as the newest change to it in L left it (all start allowing; the policy at
\* BulkCount).
NewestIn(L, i) ==
    LET cs == {e \in ChangesIn(L) : e.input = i}
    IN IF cs = {} THEN TRUE ELSE (CHOOSE e \in cs : \A d \in cs : d.seq <= e.seq).value
\* The seal its newest change's row in L records (`log_changes.seal`), which a use's probe and the change
\* path's check read: the value the vault sealed (`value`, under the entry's MAC) unless a writer
\* wrote another (LogTampers); and the inputs whose newest change's MAC no longer holds over it.
NewestEntriesIn(L, i) ==
    LET cs == {e \in ChangesIn(L) : e.input = i}
    IN {e \in cs : \A d \in cs : d.seq <= e.seq}
LoggedIn(L, i) == IF NewestEntriesIn(L, i) = {} THEN TRUE ELSE (CHOOSE e \in NewestEntriesIn(L, i) : TRUE).seal
ForgedIn(L) == {i \in Inputs : \E e \in NewestEntriesIn(L, i) : e.seal /= e.value}
\* Its newest change as a statement reads it: its number, the seal its row records, and what its MAC
\* covers, the seal the vault logged (`value`) and the change's own columns (`made`: its request id,
\* time, actor, payload). None: 0, TRUE.
NoPin == [seq |-> 0, seal |-> TRUE, value |-> TRUE, made |-> <<>>]
PinIn(L, i) == IF NewestEntriesIn(L, i) = {} THEN NoPin
               ELSE LET e == CHOOSE e \in NewestEntriesIn(L, i) : TRUE IN [seq |-> e.seq, seal |-> e.seal, value |-> e.value, made |-> e.made]
\* What an app may hand a sign-in as input i's newest change (AppPins): any change of i's, as the vault
\* wrote it (its MAC holds: its seal is its value), under any change's number.
AppPinsIn(L, i) == {[seq |-> s, seal |-> d.value, value |-> d.value, made |-> d.made] :
                      d \in {d \in ChangesIn(L) : d.input = i}, s \in {e.seq : e \in ChangesIn(L)}}
Newest == [i \in Inputs |-> LoggedIn(log, i)]
Forged == ForgedIn(log)
Rows == [i \in Inputs |-> IF tamper[i].on THEN tamper[i].value ELSE NewestIn(log, i)]

\* The log's newest change, as its number and MAC (here, its id) say it, or none.
NoChange == [seq |-> 0, made |-> <<>>]
NewestChange ==
    LET cs == ChangesIn(log) \cup IssuesIn(log)
    IN IF cs = {} THEN NoChange
       ELSE LET e == CHOOSE e \in cs : \A d \in cs : d.seq <= e.seq IN [seq |-> e.seq, made |-> e.made]

\* `decide`, on the rows a use read and the seals of their newest changes: `stale` when a sealed
\* row is not its newest change's, or (ChangeMacChecked) that change's MAC does not hold over the
\* seal it records (`forged`: none to hold the row to), then allowed only if every row allows.
\* Without StaleFirst, what the rows say is checked first, and a row put back that refuses shows as
\* a plain refusal.
\* Of the objects R the use reads.
Stale(R, read, newest, forged) == \E i \in R \ Unsealed : read[i] /= newest[i] \/ (ChangeMacChecked /\ i \in forged)
Content(R, read) == \A i \in R \ {"policy"} : read[i]
Code(R, read, newest, forged) ==
    IF Stale(R, read, newest, forged) /\ (StaleFirst \/ Content(R, read)) THEN "stale"
    ELSE IF Content(R, read) THEN "allow" ELSE "refused"

AllTrue == [i \in Inputs |-> TRUE]
NoCover == [seq |-> 0, id |-> None]
NoCache == [on |-> FALSE, seals |-> AllTrue, change |-> NoChange]
\* The credentials a use may name: an old one (None), or issuer i's.
Credentials == {None} \cup Issuers
\* The truth, for the invariants: whether the log allows the use's caller, as its changes left every
\* input and, for a new credential, once its issue is in.
Stands(R, f) == Content(R, Newest) /\ (f = None \/ IssuedIn(log, f))
\* No step, invariant or constant names one use over another, nor one key, and no CHOOSE breaks a
\* tie between them (each picks an entry by its number, which NumbersUnique holds unique): a scenario
\* whose uses and keys are model values checks each set of states alike but for those names once
\* (SYMMETRY Alike), and lists NumbersUnique. Not one with PROPERTIES: TLC's liveness checking is
\* unsound under symmetry.
Alike == Permutations(Uses) \cup Permutations(Keys)
\* The uses alone alike: a scenario whose keys' periods start apart (Phase <- Staggered) tells its keys
\* apart by their phases.
UsesAlike == Permutations(Uses)
\* The keys a use may ask for: with no bulk cap, one, which no bulk row tracks.
KeysOr == IF Keys = {} THEN {None} ELSE Keys

(* The bulk cap. *)
\* The cap a policy value stands for, (count, window); the one in force as of the log L.
PolicyOf(v) == IF v THEN [n |-> BulkCount, w |-> BulkWindow] ELSE [n |-> BulkCountAlt, w |-> BulkWindowAlt]
PolicyIn(L) == IF "policy" \in Inputs THEN PolicyOf(NewestIn(L, "policy")) ELSE PolicyOf(TRUE)
\* An input as the replay has it from the log L: its changes' operations applied in turn, each a
\* flip, from the first value (whatever values their entries sealed).
ReplayValue(L, i) == Cardinality({e \in ChangesIn(L) : e.input = i}) % 2 = 0
ReplayPolicyIn(L) == IF "policy" \in Inputs THEN PolicyOf(ReplayValue(L, "policy")) ELSE PolicyOf(TRUE)
CountIn(L) == PolicyIn(L).n
WindowIn(L) == PolicyIn(L).w
Margin == IF Slack THEN Refresh ELSE 0
CountMargin == Margin + (IF DeadlineSlack THEN D ELSE 0) + (IF AheadSlack THEN MaxSkew ELSE 0)

\* The cap's set at time t under window w, on rows L; the other keys that count against a new one.
InSet(L, k, t, w) == L[k] > t - w - Margin
Counts(L, k, t, w) == L[k] > t - w - CountMargin
\* Each key's phase (T204): its refresh periods start at Phase(k) + n * Refresh. In code it is a hash of
\* the principal and the key, so that a principal's keys, and one key's principals, do not all move on at
\* the same instant; here 0, every key's periods together, but in HotPathOneBulkPhases, which replaces it
\* with Staggered: each key a phase of its own in turn (KeyOrder, a constant, is evaluated once).
Phase(k) == 0
KeyOrder == CHOOSE f \in [Keys -> 0..Cardinality(Keys) - 1] : \A a, b \in Keys : f[a] = f[b] => a = b
Staggered(k) == KeyOrder[k] % Refresh
\* The start of k's refresh period at t, whatever its phase (% is never negative for a positive divisor),
\* or, without periods, t.
PeriodFrom(ph, t) == IF RefreshPeriods THEN t - ((t - ph) % Refresh) ELSE t
FreshFrom(L, k, t, ph) == IF RefreshPeriods THEN L[k] >= PeriodFrom(ph, t) ELSE L[k] > t - Refresh
\* The uses the previous release's statement decides, the one 0074 replaced, every key's phase 0: none
\* here, but in HotPathOneBulkSwitch, one, which runs beside the others, at any time (T204, r1). Each
\* use's entry records whether the statement that decided it phased its key (`phased`, 0074's
\* `log_uses.phased`, which only the new statement writes).
OldUses == {}
\* HotPathOneBulkSwitch's: one use the previous release's.
OneOld == {CHOOSE x \in Uses : TRUE}
\* The new release's uses alone alike: HotPathOneBulkSwitch tells its old one apart.
NewUsesAlike == Permutations(Uses \ OldUses)
\* Whether use x's statement phases its key.
Phased(x) == x \notin OldUses
\* The phase use x's statement moves k on by.
LivePhase(x, k) == IF k = None \/ ~Phased(x) THEN 0 ELSE Phase(k)
\* The phase the replay moves entry e's key on by: the statement's, as e records it (ReplayPhased;
\* without, every use's phased, as r1 found it), or, without ReplayPhases, every key's 0.
ReplayPhase(e) == IF ~ReplayPhases THEN 0 ELSE IF ReplayPhased /\ ~e.phased THEN 0 ELSE Phase(e.key)

\* The cap's rule for a request for k at t under the policy p, on rows L, k's periods from phase ph:
\* admitted or not, and the `last` it writes (NoTime: none). The live statement B and the replay apply
\* the same rule.
RuleFrom(L, k, t, p, ph) ==
    IF k = None THEN [admitted |-> TRUE, write |-> NoTime]
    ELSE IF InSet(L, k, t, p.w)
    THEN [admitted |-> TRUE, write |-> IF RefreshOnUse /\ ~FreshFrom(L, k, t, ph) THEN PeriodFrom(ph, t) ELSE NoTime]
    ELSE IF Cardinality({k2 \in Keys \ {k} : Counts(L, k2, t, p.w)}) >= p.n
         THEN [admitted |-> FALSE, write |-> NoTime]
         ELSE [admitted |-> TRUE, write |-> PeriodFrom(ph, t)]
Rule(x, L, k, t, p) == RuleFrom(L, k, t, p, LivePhase(x, k))

\* The replay of the cap: the use entries of the log G in number order, the rule applied to each on
\* the rows the ones before it left, under the policy the changes numbered before it left.
RECURSIVE ReplayFrom(_, _, _, _)
ReplayFrom(es, L, decided, G) ==
    IF es = {} THEN [rows |-> L, decided |-> decided]
    ELSE LET e == CHOOSE e \in es : \A d \in es : e.seq <= d.seq
             r == RuleFrom(L, e.key, e.at, ReplayPolicyIn({d \in G : d.seq < e.seq}), ReplayPhase(e))
         IN ReplayFrom(es \ {e}, IF r.write = NoTime THEN L ELSE [L EXCEPT ![e.key] = Max(@, r.write)],
                       decided \cup {<<e.seq, r.admitted>>}, G)
BulkReplay(G) == ReplayFrom({e \in UsesIn(G) : e.key /= None}, [k \in Keys |-> NoTime], {}, G)

\* What the log says of a use entry: every input as the changes numbered below it left it, and
\* the cap's decision as the replay makes it.
\* The objects the replay reads for it: the ones the use read, and its key's source if and only if the log, below
\* the use's number, says the key is a reference.
ReplayReads(e) == ReadsWith(e.reads \ Extra, LinkIn({d \in log : d.seq < e.seq}))
InputsAllowed(e) == \A i \in ReplayReads(e) \ {"policy"} : ReplayValue({d \in log : d.seq < e.seq}, i)
ReplayAllows(e) ==
    /\ InputsAllowed(e)
    /\ e.fresh /= None => IssuedIn({d \in log : d.seq < e.seq}, e.fresh)
    /\ e.key = None \/ <<e.seq, TRUE>> \in BulkReplay(log).decided

\* Entries: a use's is its request (number, key, at, deadline) with ghosts: the objects it read, the
\* changes of each it saw, its decision and code, when decided, the cap's decision, the changes answered when it committed. A
\* change's: its number, its input, the value it leaves (under its MAC), the seal its row records
\* (`seal`: the same, unless a writer wrote another), its id. Both: flushed yet.
UseEntry(x, durable) ==
    [seq |-> u[x].seq, kind |-> "use", id |-> x, seen |-> u[x].seen, allow |-> u[x].allow, code |-> u[x].code,
     answeredAt |-> answered, key |-> u[x].key, at |-> u[x].at, deadline |-> u[x].deadline, decidedAt |-> u[x].decidedAt,
     admitted |-> u[x].admitted, input |-> None, value |-> FALSE, seal |-> FALSE, made |-> <<>>, fresh |-> u[x].fresh, durable |-> durable,
     phased |-> Phased(x), reads |-> u[x].reads, link |-> NoLink]
ChangeEntry(seq, input, value, link, made, durable) ==
    [seq |-> seq, kind |-> "change", id |-> Change, seen |-> NoSeen, allow |-> FALSE, code |-> None, answeredAt |-> NoSeen,
     key |-> None, at |-> 0, deadline |-> 0, decidedAt |-> 0, admitted |-> FALSE,
     input |-> input, value |-> value, seal |-> value, made |-> made, fresh |-> None, durable |-> durable, phased |-> FALSE,
     reads |-> {}, link |-> link]
\* An issue's: its number, its issuer (whose credential it makes).
IssueEntry(seq, i, durable) ==
    [seq |-> seq, kind |-> "issue", id |-> i, seen |-> NoSeen, allow |-> FALSE, code |-> None, answeredAt |-> NoSeen,
     key |-> None, at |-> 0, deadline |-> 0, decidedAt |-> 0, admitted |-> FALSE,
     input |-> None, value |-> FALSE, seal |-> FALSE, made |-> <<i>>, fresh |-> None, durable |-> durable, phased |-> FALSE,
     reads |-> {}, link |-> NoLink]

IdleUse == [pc |-> "idle", seq |-> 0, seen |-> NoSeen, snap |-> NoSeen, base |-> {}, resolved |-> {}, reads |-> {}, snapLink |-> NoLink,
            snapRows |-> AllTrue, snapNewest |-> AllTrue,
            snapForged |-> {}, forged |-> {}, snapNewestChange |-> NoChange, covered |-> 0, coverId |-> None, allow |-> FALSE, code |-> None,
            probed |-> FALSE, newest |-> AllTrue, newestChange |-> NoChange,
            key |-> None, at |-> 0, deadline |-> 0, decidedAt |-> 0, admitted |-> FALSE, write |-> NoTime,
            replied |-> FALSE, gaveUp |-> FALSE, fresh |-> None, snapIssued |-> FALSE, mode |-> None, enters |-> FALSE,
            second |-> FALSE, standing |-> FALSE, firstAllows |-> FALSE]
\* A cover or a cache entry is the isolate's for one credential and key, whose objects its uses read: a use's slot.
Slots == KeysOr \X ({None} \cup Issuers) \X ReadSetsOr
Slot(x) == <<u[x].key, u[x].fresh, u[x].base>>

Init ==
    /\ log = {}
    /\ nextSeq = 1
    /\ holder = None
    /\ shared = {}
    /\ plock = NoPlock
    /\ u = [x \in Uses |-> IdleUse]
    /\ c = [h \in Changers |-> [pc |-> "idle", n |-> 0, seq |-> 0, aborts |-> 0, input |-> None, read |-> TRUE, forged |-> FALSE, pin |-> NoPin, value |-> FALSE,
                                link |-> NoLink]]
    /\ answered = NoSeen
    /\ released = {}
    /\ cp = [open |-> FALSE, from |-> 0, upto |-> 0, readFloor |-> 0, floor |-> 0 - D]
    /\ lastUpto = 0
    /\ lastFloor = 0 - D
    /\ signed = {}
    /\ floor = 0 - D   \* the schema's: below every use to come
    /\ crashes = 0
    /\ cover = [s \in Slots |-> NoCover]
    /\ repeats = {}
    /\ tamper = [i \in Inputs |-> [on |-> FALSE, value |-> TRUE]]
    /\ tampers = 0
    /\ cache = [s \in Slots |-> NoCache]
    /\ restores = 0
    /\ bulk = [k \in Keys |-> NoTime]
    /\ pnow = 0
    /\ backs = 0
    /\ iss = [i \in Issuers |-> [pc |-> "idle", seq |-> 0]]
    /\ iholder = None
    /\ ishared = {}
    /\ bar = 0

(* The locks (L1). The fence: a use and a change's statement take it shared, the checkpointer's barrier exclusive      *)
(* (`holder`). An object's lock: a use takes each one it will read, shared; a change the one it writes, exclusive. A   *)
(* use takes them all in one step here, and a change its two: what Postgres grants one at a time, in key order, is as  *)
(* if granted together when the last one is (until then the transaction has read nothing under them), and the order,  *)
(* with what waits on what meanwhile, is WriteLocks.tla's (ObjectLocks). A use holds them while it is in `shared`; a   *)
(* change from its lock to its commit, or, without LockToCommit, to its statement's end.                               *)
ChangerIn(h) == c[h].pc = "locked" \/ (c[h].pc = "ran" /\ LockToCommit)
\* The objects use x locks: the ones whose ids it read before any lock, but those it leaves unlocked (a removal).
Locked(x) == u[x].resolved \ Unlocked
Readers(o) == {x \in shared \cap Uses : o \in Locked(x)}
Writers(o) == {h \in Changers : ChangeLocks /\ ChangerIn(h) /\ c[h].input = o}
\* The fence free of every holder: what the barrier waits for.
LockFree == holder = None /\ shared = {} /\ (ChangeSharesFence => \A h \in Changers : ~ChangerIn(h))

-----------------------------------------------------------------------------
(* Clocks. *)

Tick ==
    /\ pnow < MaxTime
    /\ pnow' = pnow + 1
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor,
                   crashes, cover, repeats, tamper, tampers, cache, restores, bulk, backs, issueVars>>

ClockBack ==
    /\ backs < MaxClockBacks
    /\ pnow > 0
    /\ pnow' = pnow - 1
    /\ backs' = backs + 1
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor,
                   crashes, cover, repeats, tamper, tampers, cache, restores, bulk, issueVars>>

-----------------------------------------------------------------------------
(* A use: one call. *)

\* It arrives, for a key, stamped by the Worker's clock, its deadline set; the call's outer
\* statement starts, with its snapshot, and reads, before any lock, the ids of the objects it will
\* read (`resolved`: its key's source among them if the key is a reference now), whose locks it will
\* take. Passed a number taken before (without UseNumberUnderLock), it takes it now.
\* It names an old credential (None) or a new one, issuer i's: with NamedAfterIssue, once its issue
\* has answered.
UseStart(x) ==
    /\ u[x].pc = "idle"
    /\ pnow <= MaxStart
    /\ \E k \in KeysOr, s \in -MaxSkew..(MaxSkew + Ahead), R \in ReadSetsOr,
          f \in {None} \cup {i \in Issuers : NamedAfterIssue => iss[i].pc = "answered"} :
          u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "started", !.key = k, !.at = pnow + s, !.deadline = pnow + s + D,
                                          !.base = R, !.resolved = ReadsWith(R, LinkIn(log)), !.snapLink = LinkIn(log),
                                          !.snap = SeenIn(log), !.snapRows = Rows, !.snapNewest = Newest, !.snapForged = Forged,
                                          !.snapNewestChange = NewestChange, !.fresh = f,
                                          !.snapIssued = f /= None /\ IssuedIn(log, f),
                                          !.seq = IF UseNumberUnderLock THEN 0 ELSE nextSeq]]
    /\ nextSeq' = IF UseNumberUnderLock THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<log, holder, shared, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Hyperdrive holds the call; it may run it later, or never.
UseHold(x) ==
    /\ Holds
    /\ u[x].pc = "started"
    /\ u' = [u EXCEPT ![x].pc = "held"]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

UseResume(x) ==
    /\ u[x].pc = "held"
    /\ u' = [u EXCEPT ![x].pc = "started"]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* It gets its locks shared, the fence and each object's: the barrier does not hold the first, and no
\* change any of the others. Below the floor, it lets them go having written nothing (503 `late`).
\* With a bulk cap, statement A comes next; without, statement B.
UseLock(x) ==
    /\ u[x].pc = "started"
    /\ UseLocks => holder = None /\ \A o \in Locked(x) : Writers(o) = {}
    /\ LET late == \/ FloorChecked /\ u[x].at < floor
                   \/ AheadChecked /\ u[x].at > pnow + MaxSkew
       IN /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = IF late THEN "done" ELSE IF Keys = {} THEN "read" ELSE "locked",
                                             !.replied = @ \/ late]]
          /\ shared' = IF UseLocks /\ ~late THEN shared \cup {x} ELSE shared
    /\ UNCHANGED <<log, nextSeq, holder, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Statement A: the key's bulk row, as committed, and the policy's window (which no change can move
\* while the use holds the policy's lock shared). A key that must enter the set asks for the principal's lock
\* exclusive; one in the set that must be moved on, shared (or exclusive, without RefreshShared).
\* With DecideBeforeLock (T158, D153), a use that would ask for the principal's lock asks for it
\* only once the Worker decided the use, in its second call: no decision is kept for a later use to
\* take the lock on. Otherwise the call takes no lock, writes nothing and ends, answering the rows it
\* read, which the Worker decides on (UseDecide). `standing` is the truth when the use asks for the
\* lock, or, for a second call, when its first read what the Worker decided on: whether the log allows
\* its caller.
UseRead(x) ==
    /\ u[x].pc = "locked"
    /\ LET k == u[x].key
           t == u[x].at
           f == u[x].fresh
           reads == ReadsWith(u[x].base, LinkIn(log))
           enters == k /= None /\ ~InSet(bulk, k, t, WindowIn(log))
           moves == k /= None /\ ~enters /\ ~FreshFrom(bulk, k, t, LivePhase(x, k))
           waits == PrincipalLocks /\ (enters \/ (moves /\ RefreshLocks))
           decides == DecideBeforeLock /\ waits /\ ~u[x].second
       IN /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = IF decides THEN "deciding" ELSE IF waits THEN "waiting" ELSE "read",
                                             !.enters = enters,
                                             !.mode = IF ~waits THEN None ELSE IF moves /\ RefreshShared THEN "s" ELSE "x",
                                             \* Asking for the lock in its second call, the truth when the Worker decided its first.
                                             !.standing = waits /\ IF u[x].second THEN @ ELSE Stands(reads, f),
                                             \* What the Worker will decide on the rows this first call read.
                                             !.firstAllows = decides /\ (f = None \/ IssuedIn(log, f)) /\ Code(reads, Rows, Newest, Forged) = "allow",
                                             !.second = FALSE]]
          /\ shared' = IF decides THEN shared \ {x} ELSE shared
    /\ UNCHANGED <<log, nextSeq, holder, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* The Worker decides the first call's rows (T158): a caller refused there is answered so, nothing
\* written, no lock taken; one allowed makes the use, a second call, which asks for the lock whatever
\* it finds then (a revoke since waits, then refuses).
UseDecide(x) ==
    /\ u[x].pc = "deciding"
    /\ LET allow == u[x].firstAllows
           f == u[x].fresh
       IN /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = IF allow THEN "started" ELSE "done", !.replied = @ \/ ~allow,
                                             !.second = allow, !.standing = @ /\ allow, !.firstAllows = FALSE,
                                             !.resolved = ReadsWith(u[x].base, LinkIn(log)), !.snapLink = LinkIn(log),
                                             !.snap = SeenIn(log), !.snapRows = Rows, !.snapNewest = Newest, !.snapForged = Forged,
                                             !.snapNewestChange = NewestChange, !.snapIssued = f /= None /\ IssuedIn(log, f)]]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* As Postgres grants a lock: exclusive once no one holds it; shared once no one holds it exclusive or
\* waits for it so (a shared request queues behind a waiting exclusive one).
UsePrincipalLock(x) ==
    /\ u[x].pc = "waiting"
    /\ plock.ex = None
    /\ IF u[x].mode = "x"
       THEN /\ plock.sh = {}
            /\ plock' = [plock EXCEPT !.ex = x]
       ELSE /\ \A y \in Uses : ~(u[y].pc = "waiting" /\ u[y].mode = "x")
            /\ plock' = [plock EXCEPT !.sh = @ \cup {x}]
    /\ u' = [u EXCEPT ![x].pc = "read"]
    /\ UNCHANGED <<log, nextSeq, holder, shared, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Statement B past its deadline: nothing written, the call ends, its locks go (503 `late`).
UseLate(x) ==
    /\ u[x].pc = "read"
    /\ DeadlineChecked /\ pnow > u[x].deadline
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "done", !.replied = TRUE]]
    /\ shared' = shared \ {x}
    /\ plock' = PlockWithout(x)
    /\ UNCHANGED <<log, nextSeq, holder, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* With a cover and the isolate's cache for its key passed (a use may pass the cache or not), the
\* probes are skipped if the log's newest change is the cached one (without CacheSameChange: if its
\* number is no higher; without CacheChecked: always): the rows are held to the cached seals, and the
\* cover to the cached number. Without CoverExists, the cover's entry is not looked for; without
\* CoverChecksAllInputs, only changes to the member count.
CacheHolds(sl, newestChange) ==
    IF CacheSameChange THEN newestChange = cache[sl].change ELSE newestChange.seq <= cache[sl].change.seq
CoverThere(sl) ==
    /\ cover[sl].seq /= 0
    /\ CoverExists => \E e \in UsesIn(log) : e.seq = cover[sl].seq /\ e.id = cover[sl].id
CoverNoChange(sl) ==
    CoverChecksChanges => \A d \in ChangesIn(log) : (CoverChecksAllInputs \/ d.input = "member") => d.seq < cover[sl].seq
CoverInSet(x, k, t, w) == k /= None => InSet(bulk, k, t, w) /\ (CoverFresh => FreshFrom(bulk, k, t, LivePhase(x, k)))

\* The caps a caller may pass from its own config (without CapFromPolicy): any the policy has had.
CallerPolicies ==
    IF "policy" \in Inputs /\ ~CapFromPolicy
    THEN {PolicyOf(v) : v \in {TRUE} \cup {e.value : e \in {d \in ChangesIn(log) : d.input = "policy"}}}
    ELSE {PolicyOf(TRUE)}

\* What statement B reads: the key's and the caller's objects and, if the key's row says it is a
\* reference in the statement's snapshot, its source's.
ReadsNow(x) == ReadsWith(u[x].base, IF StatementSnapshot THEN LinkIn(log) ELSE u[x].snapLink)

\* The rows name an object whose id the call had not read before its locks, so did not lock (the key
\* was made a reference in between): with LockedAsRead, the call ends there, nothing written, its
\* locks let go (`moved`), and the vault asks again. It never takes a lock after its first read.
UseMoved(x) ==
    /\ u[x].pc = "read"
    /\ LockedAsRead /\ ~(ReadsNow(x) \subseteq u[x].resolved)
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "done", !.replied = TRUE]]
    /\ shared' = shared \ {x}
    /\ plock' = PlockWithout(x)
    /\ UNCHANGED <<log, nextSeq, holder, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Statement B, its snapshot taken now (or, as a bare CTE, at the call's start): everything the
\* decision reads, the cap's rule (its count and window from the policy's newest change), the entry's
\* number, from the sequence unless passed in; or, a repeat on its cover, nothing written. Without
\* LockToCommit its locks go here, before the commit. Without ReleaseAfterCommit the value
\* leaves on what was read.
UseRun(x) ==
    /\ u[x].pc = "read"
    /\ DeadlineChecked => pnow <= u[x].deadline
    /\ LockedAsRead => ReadsNow(x) \subseteq u[x].resolved
    /\ \E passed \in IF SealCache /\ cache[Slot(x)].on THEN BOOLEAN ELSE {FALSE}, callerPolicy \in CallerPolicies :
       LET k == u[x].key
           sl == Slot(x)
           t == u[x].at
           reads == ReadsNow(x)
           seen == IF StatementSnapshot THEN SeenIn(log) ELSE u[x].snap
           read == IF StatementSnapshot THEN Rows ELSE u[x].snapRows
           probes == IF StatementSnapshot THEN Newest ELSE u[x].snapNewest
           probedForged == IF StatementSnapshot THEN Forged ELSE u[x].snapForged
           newestChange == IF StatementSnapshot THEN NewestChange ELSE u[x].snapNewestChange
           skip == passed /\ (CacheChecked => CacheHolds(sl, newestChange))
           newest == IF skip THEN cache[sl].seals ELSE probes
           \* The cache's seals were checked when a use probed them (CacheVerified): none is forged.
           forged == IF skip THEN {} ELSE probedForged
           p == IF "policy" \notin Inputs THEN PolicyOf(TRUE)
                ELSE IF ~CapFromPolicy THEN callerPolicy
                ELSE PolicyOf(IF CapSealed THEN newest["policy"] ELSE read["policy"])
           covered == /\ Covers /\ CoverThere(sl) /\ CoverInSet(x, k, t, p.w)
                      /\ IF skip THEN cover[sl].seq > cache[sl].change.seq ELSE CoverNoChange(sl)
           r == Rule(x, bulk, k, t, p)
           admitted == covered \/ r.admitted
           \* A new credential is found only once its issue has committed, in the statement's snapshot (its row).
           found == u[x].fresh = None \/ IF StatementSnapshot THEN IssuedIn(log, u[x].fresh) ELSE u[x].snapIssued
           base == IF found THEN Code(reads, read, newest, forged) ELSE "refused"
           code == IF base = "allow" /\ ~admitted THEN "bulk" ELSE base
       IN /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "ran", !.seen = seen, !.reads = reads, !.decidedAt = pnow,
                                     !.covered = IF covered THEN cover[sl].seq ELSE 0, !.coverId = IF covered THEN cover[sl].id ELSE None,
                                     !.allow = (code = "allow"), !.code = code, !.admitted = admitted,
                                     !.write = IF covered THEN NoTime ELSE r.write,
                                     !.probed = ~skip, !.newest = newest, !.newestChange = newestChange, !.forged = forged,
                                     !.seq = IF UseNumberUnderLock /\ ~covered THEN nextSeq ELSE @]]
          /\ released' = IF ~ReleaseAfterCommit /\ code = "allow"
                         THEN released \cup {[id |-> x, key |-> k, at |-> t, deadline |-> u[x].deadline, t |-> pnow]}
                         ELSE released
          /\ nextSeq' = IF UseNumberUnderLock /\ ~covered THEN nextSeq + 1 ELSE nextSeq
    /\ shared' = IF LockToCommit THEN shared ELSE shared \ {x}
    /\ UNCHANGED <<log, holder, plock, c, answered, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* The commit: the entry and the bulk row (the greater of the two times, as an upsert would), then
\* the locks go (Postgres makes a commit visible before it releases the transaction's locks). A
\* covered use commits nothing, and is a repeat of its cover.
UseCommit(x) ==
    /\ u[x].pc = "ran"
    /\ IF u[x].covered = 0
       THEN /\ log' = log \cup {UseEntry(x, SyncCommit)}
            /\ UNCHANGED repeats
       ELSE /\ repeats' = repeats \cup {[id |-> x, cover |-> u[x].covered, coverId |-> u[x].coverId, seen |-> u[x].seen,
                                          reads |-> u[x].reads, allow |-> u[x].allow, answeredAt |-> answered]}
            /\ UNCHANGED log
    /\ bulk' = IF u[x].write = NoTime THEN bulk ELSE [bulk EXCEPT ![u[x].key] = Max(@, u[x].write)]
    /\ shared' = shared \ {x}
    /\ plock' = PlockWithout(x)
    /\ u' = [u EXCEPT ![x].pc = "committed"]
    /\ UNCHANGED <<nextSeq, holder, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, tamper, tampers, cache, restores, pnow, backs, issueVars>>

\* The call fails before its commit (a lost connection): rolled back, nothing written, the Worker
\* answers 503. Its number is a gap.
UseFail(x) ==
    /\ Failures
    /\ u[x].pc = "ran"
    /\ shared' = shared \ {x}
    /\ plock' = PlockWithout(x)
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "done", !.replied = TRUE]]
    /\ UNCHANGED <<log, nextSeq, holder, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* The Worker, at the deadline, its call not back: 503, and it gives up on the call.
WorkerGivesUp(x) ==
    /\ Holds
    /\ WorkerHonoursDeadline
    /\ u[x].pc \notin {"idle", "done"}
    /\ ~u[x].replied
    /\ pnow > u[x].deadline
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.replied = TRUE, !.gaveUp = TRUE]]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* The call returns: the Worker answers on what it decided, and an allowed value leaves, unless the
\* Worker gave up on the call (or its deadline has passed). An allowed entry of its own the Worker
\* answered becomes the isolate's cover; a refusal ends it. A use that probed leaves what it read in
\* the isolate's cache.
UseRelease(x) ==
    /\ u[x].pc = "committed"
    /\ LET k == u[x].key
           sl == Slot(x)
           answers == ~u[x].gaveUp /\ (WorkerHonoursDeadline => pnow <= u[x].deadline)
       IN /\ released' = IF ReleaseAfterCommit /\ u[x].allow /\ answers
                         THEN released \cup {[id |-> x, key |-> k, at |-> u[x].at, deadline |-> u[x].deadline, t |-> pnow]}
                         ELSE released
          /\ cover' = IF ~u[x].allow THEN [cover EXCEPT ![sl] = NoCover]
                      ELSE IF answers /\ u[x].covered = 0 THEN [cover EXCEPT ![sl] = [seq |-> u[x].seq, id |-> x]] ELSE cover
          \* With CacheVerified, only seals whose changes' MACs held: a use that read a forged one leaves the cache as it was.
          /\ cache' = IF SealCache /\ u[x].probed /\ (CacheVerified => u[x].forged = {})
                      THEN [cache EXCEPT ![sl] = [on |-> TRUE, seals |-> u[x].newest, change |-> u[x].newestChange]]
                      ELSE cache
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "done", !.replied = TRUE]]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, c, answered, cp, lastUpto, lastFloor, signed, floor, crashes,
                   repeats, tamper, tampers, restores, bulk, pnow, backs, issueVars>>

\* The Worker dies between the commit and its answer: the log holds a request whose value never
\* left, the safe side. The client sees the connection fail.
UseCrash(x) ==
    /\ Failures
    /\ u[x].pc = "committed"
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "done", !.replied = TRUE]]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

-----------------------------------------------------------------------------
(* A change: one input revoked, or restored, by one of the changers. *)

\* The call starts, for one input: the vault reads its row, outside any lock, and works out the
\* next state from it; and its newest change's, whose MAC it checks (ChangeChecksMac, T190), and which
\* a sign-in pins (ChangePinsChecked, T192). With AppPins, a sign-in may take the change the app
\* handed it instead, whose MAC holds over what the app handed, under whatever number it says. Without
\* ChangeNumberUnderLock, its number was taken by a read before it.
ChangeStart(h) ==
    /\ c[h].pc = "idle"
    /\ c[h].n < MaxChanges
    /\ \E i \in Inputs :
       \E r \in {[pin |-> PinIn(log, i), forged |-> i \in Forged]}
               \cup (IF AppPins /\ h \in PinnedChangers THEN {[pin |-> p, forged |-> FALSE] : p \in AppPinsIn(log, i)} ELSE {}) :
          c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "started", !.input = i, !.read = Rows[i], !.forged = r.forged, !.pin = r.pin,
                                          !.seq = IF ChangeNumberUnderLock THEN 0 ELSE nextSeq]]
    /\ nextSeq' = IF ChangeNumberUnderLock THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<log, holder, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* After a refused write, the vault reads the row again, and the newest change itself (a sign-in's `moved`).
ChangeReread(h) ==
    /\ c[h].pc = "refused"
    /\ c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "started", !.read = Rows[c[h].input], !.forged = c[h].input \in Forged,
                                            !.pin = PinIn(log, c[h].input)]]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* It gets its locks: the fence shared, which the barrier does not hold, and its object's exclusive, which
\* no use holds and no other change.
ChangeLock(h) ==
    /\ c[h].pc = "started"
    /\ ChangeSharesFence => holder = None
    /\ ChangeLocks => Readers(c[h].input) = {} /\ Writers(c[h].input) = {}
    /\ c' = [c EXCEPT ![h].pc = "locked"]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Its statement: if the row is no longer the one it read (ChangeCAS), or not the one its object's
\* newest change wrote (ChangeChecksSeal), or that change's MAC did not hold over its seal when the
\* vault read it (ChangeChecksMac: SQL cannot check a MAC; the CAS holds the row to that read), or,
\* for a sign-in, that change is no longer the one checked (ChangePinsChecked: a seal column forged
\* since keeps its number), whole (ChangePinsWhole: else by number and seal), nothing is written, the locks go and the vault reads
\* again (without ChangeRereads, it tries the same read again). Else the write (the flip of what it
\* read) and its entry's number. Without LockToCommit the locks go here; without CommitBeforeAnswer
\* it answers here.
\* A sign-in's pin, under the lock: the newest change is not the one checked.
PinMoved(h) ==
    LET now == PinIn(log, c[h].input)
    IN IF ChangePinsWhole THEN now /= c[h].pin ELSE now.seq /= c[h].pin.seq \/ now.seal /= c[h].pin.seal

ChangeRun(h) ==
    /\ c[h].pc = "locked"
    /\ IF \/ ChangeCAS /\ Rows[c[h].input] /= c[h].read
          \/ ChangeChecksSeal /\ Rows[c[h].input] /= LoggedIn(log, c[h].input)
          \/ ChangeChecksMac /\ c[h].forged
          \/ ChangePinsChecked /\ h \in PinnedChangers /\ PinMoved(h)
       THEN /\ c' = [c EXCEPT ![h].pc = IF ChangeRereads THEN "refused" ELSE "started"]
            /\ UNCHANGED <<nextSeq, answered, issueVars>>
       \* A change of the key may make it a reference to any of its sources (Extra), the one it was or another, or plain
       \* again: the link its row then says.
       ELSE /\ \E l \in IF c[h].input = "secret" THEN {NoLink} \cup Extra ELSE {NoLink} :
                  c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "ran", !.value = ~c[h].read, !.link = l,
                                                  !.seq = IF ChangeNumberUnderLock THEN nextSeq ELSE @]]
            /\ nextSeq' = IF ChangeNumberUnderLock THEN nextSeq + 1 ELSE nextSeq
            /\ answered' = IF CommitBeforeAnswer THEN answered ELSE [answered EXCEPT ![c[h].input] = SeenIn(log)[c[h].input] + 1]
    /\ UNCHANGED <<log, holder, shared, plock, u, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* The commit: its entry, and the row it wrote, in place of whatever was there.
ChangeCommit(h) ==
    /\ c[h].pc = "ran"
    /\ log' = log \cup {ChangeEntry(c[h].seq, c[h].input, c[h].value, c[h].link, <<h, c[h].n + 1>>, SyncCommit)}
    /\ c' = [c EXCEPT ![h].pc = "committed"]
    /\ tamper' = [tamper EXCEPT ![c[h].input] = [on |-> FALSE, value |-> TRUE]]
    /\ UNCHANGED <<nextSeq, holder, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Its statement fails instead (a deadline, a lost connection): rolled back, the lock let go; it
\* starts over. Its number is a gap.
ChangeAbort(h) ==
    /\ c[h].pc = "ran"
    /\ c[h].aborts < MaxAborts
    /\ c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "idle", !.aborts = @ + 1]]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

ChangeAnswer(h) ==
    /\ c[h].pc = "committed"
    /\ answered' = [answered EXCEPT ![c[h].input] = Max(@, SeenIn(log)[c[h].input])]
    /\ c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

-----------------------------------------------------------------------------
(* An issue: a new credential, one change of the log, by one of the issuers, once. *)

\* Its transaction starts. Without IssueNumberUnderLock, its number was taken before its lock.
IssueStart(i) ==
    /\ iss[i].pc = "idle"
    /\ iss' = [iss EXCEPT ![i] = [pc |-> "started", seq |-> IF IssueNumberUnderLock THEN 0 ELSE nextSeq]]
    /\ nextSeq' = IF IssueNumberUnderLock THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<log, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iholder, ishared, bar>>

\* The issue lock shared, unless the barrier holds it; without IssueOwnLock, the fence shared.
IssueLock(i) ==
    /\ iss[i].pc = "started"
    /\ IF IssueOwnLock
       THEN /\ iholder = None
            /\ ishared' = ishared \cup {i}
            /\ UNCHANGED shared
       ELSE /\ holder = None
            /\ shared' = shared \cup {i}
            /\ UNCHANGED ishared
    /\ iss' = [iss EXCEPT ![i].pc = "locked"]
    /\ UNCHANGED <<log, nextSeq, holder, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iholder, bar>>

\* The credential's row and its change, numbered now.
IssueRun(i) ==
    /\ iss[i].pc = "locked"
    /\ iss' = [iss EXCEPT ![i] = [pc |-> "ran", seq |-> IF IssueNumberUnderLock THEN nextSeq ELSE @.seq]]
    /\ nextSeq' = IF IssueNumberUnderLock THEN nextSeq + 1 ELSE nextSeq
    /\ UNCHANGED <<log, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iholder, ishared, bar>>

\* The commit; its lock goes with it.
IssueCommit(i) ==
    /\ iss[i].pc = "ran"
    /\ log' = log \cup {IssueEntry(iss[i].seq, i, SyncCommit)}
    /\ ishared' = ishared \ {i}
    /\ shared' = shared \ {i}
    /\ iss' = [iss EXCEPT ![i].pc = "committed"]
    /\ UNCHANGED <<nextSeq, holder, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iholder, bar>>

\* It fails before its commit: rolled back, its number a gap; the sign-in is refused (asked again, it is another).
IssueFail(i) ==
    /\ Failures
    /\ iss[i].pc = "ran"
    /\ ishared' = ishared \ {i}
    /\ shared' = shared \ {i}
    /\ iss' = [iss EXCEPT ![i].pc = "failed"]
    /\ UNCHANGED <<log, nextSeq, holder, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iholder, bar>>

\* The sign-in answers: the credential's token is handed out, and uses may name it.
IssueAnswer(i) ==
    /\ iss[i].pc = "committed"
    /\ iss' = [iss EXCEPT ![i].pc = "answered"]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iholder, ishared, bar>>

IssueStep(i) == IssueStart(i) \/ IssueLock(i) \/ IssueRun(i) \/ IssueCommit(i) \/ IssueAnswer(i)

-----------------------------------------------------------------------------
(* The checkpointer. *)

\* The barrier, under the lock exclusive for one statement: the floor raised to its clock less D,
\* never lowered; every number handed out so far closed. No lag: with every number taken under
\* the lock, none is still in flight. With BarrierChecksFloor, a floor not at the value the signer
\* last wrote is an alarm, and nothing more is closed or signed.
\* With issues, the barrier waits for them on the issue lock exclusive, then the fence (or, without
\* BarrierIssueFirst, the other way round); it takes them one at a time, holding the first while it
\* waits for the second, and closes with the last. With no issuer the issue lock is always free:
\* taken in the same step.
BarrierLocks ==
    LET fence == IF CheckpointLocks THEN <<"fence">> ELSE <<>>
        issue == IF BarrierWaitsIssues /\ Issuers /= {} THEN <<"issue">> ELSE <<>>
    IN IF BarrierIssueFirst THEN issue \o fence ELSE fence \o issue
LockOpen(l) == IF l = "fence" THEN LockFree ELSE iholder = None /\ ishared = {}

BarrierLock ==
    /\ ~cp.open
    /\ Cardinality(signed) < MaxCheckpoints
    /\ bar + 1 < Len(BarrierLocks)
    /\ LockOpen(BarrierLocks[bar + 1])
    /\ holder' = IF BarrierLocks[bar + 1] = "fence" THEN "barrier" ELSE holder
    /\ iholder' = IF BarrierLocks[bar + 1] = "issue" THEN "barrier" ELSE iholder
    /\ bar' = bar + 1
    /\ UNCHANGED <<log, nextSeq, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iss, ishared>>

CheckpointClose ==
    /\ ~cp.open
    /\ Cardinality(signed) < MaxCheckpoints
    /\ bar + 1 >= Len(BarrierLocks)
    /\ Len(BarrierLocks) > 0 => LockOpen(BarrierLocks[Len(BarrierLocks)])
    /\ BarrierChecksFloor => \/ floor = cp.floor
                             \/ BarrierAcceptsLate /\ cp.floor < floor /\ floor <= pnow - D
    /\ floor' = Max(floor, pnow - D)
    /\ cp' = [open |-> TRUE, from |-> lastUpto, upto |-> nextSeq - 1, readFloor |-> lastFloor, floor |-> Max(floor, pnow - D)]
    /\ holder' = IF holder = "barrier" THEN None ELSE holder
    /\ iholder' = None
    /\ bar' = 0
    /\ UNCHANGED <<log, nextSeq, shared, plock, u, c, answered, released, lastUpto, lastFloor, signed, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iss, ishared>>

\* A barrier of a checkpointer given up on (T169): its statement was in flight when the host stopped waiting for it, and
\* runs when its locks are free, as late as it likes, raising the floor as any barrier does. Nothing reads its window
\* or signs it. As many times as it likes: the floor only follows the clock.
LateBarrier ==
    /\ LateBarriers
    /\ LockFree /\ iholder = None /\ ishared = {}
    /\ floor' = Max(floor, pnow - D)
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Later, outside any lock: it reads the window (the changes by number, the uses through the `at`
\* index from the previous barrier's floor) and signs their numbers.
\* With Chunks, only a prefix of it, up to k (T169): the next barrier closes the rest, read from the
\* floor this one signs (ChunkFloor), the lowest `at` of the uses left above it if below the
\* barrier's; or, without, the barrier's.
Above(k) == {d.at : d \in {e \in UsesIn(log) : k < e.seq /\ e.seq <= cp.upto /\ e.at >= cp.readFloor}}
ChunkFloorOf(k) ==
    IF k = cp.upto \/ ~ChunkFloor THEN cp.floor
    ELSE Max(cp.readFloor, IF Above(k) = {} THEN cp.floor ELSE Min(cp.floor, CHOOSE a \in Above(k) : \A b \in Above(k) : a <= b))
CheckpointSign ==
    /\ cp.open
    /\ \E k \in {cp.upto} \cup (IF Chunks THEN (cp.from + 1)..(cp.upto - 1) ELSE {}) :
        /\ signed' = signed \cup {[from |-> cp.from, upto |-> k, floor |-> ChunkFloorOf(k),
                                   seqs |-> {e.seq : e \in {d \in log : cp.from < d.seq /\ d.seq <= k
                                                                        /\ (d.kind = "change" \/ d.at >= cp.readFloor)}}]}
        /\ lastUpto' = k
        /\ lastFloor' = ChunkFloorOf(k)
    /\ cp' = [cp EXCEPT !.open = FALSE]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, c, answered, released, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

-----------------------------------------------------------------------------
(* Postgres: the WAL flushed; a crash. *)

\* Without SyncCommit, commits are flushed later, all at once (the WAL is flushed in order).
Flush ==
    /\ \E e \in log : ~e.durable
    /\ log' = {[e EXCEPT !.durable = TRUE] : e \in log}
    /\ UNCHANGED <<nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Postgres crashes and restarts: what was not flushed is gone, every statement in flight is
\* rolled back, every lock let go (the Workers answer 503). The sequence never goes back below a
\* flushed number.
Crash ==
    /\ crashes < MaxCrashes
    /\ crashes' = crashes + 1
    /\ log' = {e \in log : e.durable}
    /\ holder' = None
    /\ shared' = {}
    /\ plock' = NoPlock
    /\ u' = [x \in Uses |-> IF u[x].pc \in {"started", "held", "locked", "waiting", "read", "ran"}
                            THEN [u[x] EXCEPT !.pc = "done", !.replied = TRUE] ELSE u[x]]
    /\ c' = [h \in Changers |-> IF c[h].pc \in {"started", "refused", "locked", "ran"} THEN [c[h] EXCEPT !.pc = "idle"] ELSE c[h]]
    /\ iss' = [i \in Issuers |-> IF iss[i].pc \in {"started", "locked", "ran"} THEN [iss[i] EXCEPT !.pc = "idle"] ELSE iss[i]]
    /\ iholder' = None
    /\ ishared' = {}
    /\ bar' = 0
    /\ UNCHANGED <<nextSeq, answered, released, cp, lastUpto, lastFloor, signed, floor, cover, repeats, tamper, tampers,
                   cache, restores, bulk, pnow, backs>>

-----------------------------------------------------------------------------
(* Attacks and accidents. *)

\* A database writer with no key: it puts back a row of an input as the vault once sealed it, the
\* first one or one an earlier change wrote. Outside any lock.
Tamper ==
    /\ tampers < MaxTampers
    /\ \E i \in Inputs :
          \E v \in {TRUE} \cup {e.value : e \in {d \in ChangesIn(log) : d.input = i}} :
             tamper' = [tamper EXCEPT ![i] = [on |-> TRUE, value |-> v]]
    /\ tampers' = tampers + 1
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, cache, restores, bulk, pnow, backs, issueVars>>

\* With LogTampers (T190), the writer also writes the seal of the row it puts back into the input's
\* newest change, its `seal` column, which the use's probe and the change path's check compare the
\* row with: that entry's MAC, over the seal the vault logged (`value`), no longer holds.
TamperLog ==
    /\ LogTampers
    /\ tampers < MaxTampers
    /\ \E i \in Inputs :
          \E e \in NewestEntriesIn(log, i), v \in {TRUE} \cup {d.value : d \in {d \in ChangesIn(log) : d.input = i}} :
             /\ tamper' = [tamper EXCEPT ![i] = [on |-> TRUE, value |-> v]]
             /\ log' = (log \ {e}) \cup {[e EXCEPT !.seal = v]}
    /\ tampers' = tampers + 1
    /\ UNCHANGED <<nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, cache, restores, bulk, pnow, backs, issueVars>>

\* The writer lowers the floor of `at`, an unsigned row.
TamperFloor ==
    /\ FloorTampers
    /\ tampers < MaxTampers
    /\ floor' = floor - 1
    /\ tampers' = tampers + 1
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, c, answered, released, cp, lastUpto, lastFloor, signed, crashes,
                   cover, repeats, tamper, cache, restores, bulk, pnow, backs, issueVars>>

\* A restore from a backup, while no call is in flight: the log back to an earlier point, the rows
\* (the bulk rows as that log made them) and the sequence with it. What changes had answered is now
\* what the restored log holds; the ghosts of what happened before it go with the history.
Restore ==
    /\ restores < MaxRestores
    /\ \A x \in Uses : u[x].pc \in {"idle", "done"}
    /\ \A h \in Changers : c[h].pc = "idle"
    /\ \A i \in Issuers : iss[i].pc \in {"idle", "answered", "failed"}
    /\ bar = 0
    /\ ~cp.open
    /\ \E k \in 0..(nextSeq - 1) :
          LET kept == {e \in log : e.seq <= k}
          IN /\ log' = kept
             /\ nextSeq' = k + 1
             /\ answered' = SeenIn(kept)
             /\ bulk' = IF Keys = {} THEN bulk ELSE BulkReplay(kept).rows
    /\ tamper' = [i \in Inputs |-> [on |-> FALSE, value |-> TRUE]]
    /\ released' = {}
    /\ repeats' = {}
    /\ signed' = {}
    /\ lastUpto' = 0
    /\ restores' = restores + 1
    /\ UNCHANGED <<holder, shared, plock, u, c, cp, lastFloor, floor, crashes, cover, tampers, cache, pnow, backs, issueVars>>

-----------------------------------------------------------------------------

UseStep(x) ==
    \/ UseLock(x) \/ UseRead(x) \/ UseDecide(x) \/ UsePrincipalLock(x) \/ UseLate(x) \/ UseMoved(x) \/ UseRun(x) \/ UseCommit(x) \/ UseRelease(x)
    \/ WorkerGivesUp(x)
ChangeStep(h) ==
    ChangeStart(h) \/ ChangeReread(h) \/ ChangeLock(h) \/ ChangeRun(h) \/ ChangeCommit(h) \/ ChangeAnswer(h)

Next ==
    \/ Tick \/ ClockBack
    \/ \E x \in Uses : UseStart(x) \/ UseHold(x) \/ UseResume(x) \/ UseStep(x) \/ UseFail(x) \/ UseCrash(x)
    \/ \E h \in Changers : ChangeStep(h) \/ ChangeAbort(h)
    \/ \E i \in Issuers : IssueStep(i) \/ IssueFail(i)
    \/ BarrierLock \/ CheckpointClose \/ CheckpointSign \/ LateBarrier
    \/ Flush \/ Crash \/ Tamper \/ TamperLog \/ TamperFloor \/ Restore

Spec == Init /\ [][Next]_vars

\* For the liveness properties: every step of the protocol weakly fair (the clock too), none of
\* the bounded accidents and attacks (a held call's resumption, failures, crashes, tampering,
\* restores, the clock stepping back, a use's arrival).
FairSpec ==
    /\ Spec
    /\ WF_vars(Tick)
    /\ \A x \in Uses : WF_vars(UseStep(x))
    /\ \A h \in Changers : WF_vars(ChangeStep(h))
    /\ \A i \in Issuers : WF_vars(IssueStep(i))
    /\ WF_vars(BarrierLock) /\ WF_vars(CheckpointClose) /\ WF_vars(CheckpointSign) /\ WF_vars(Flush)

-----------------------------------------------------------------------------
(* What must hold. *)

\* The number alone orders a use against the changes of what it reads: of each object it read, every
\* use saw exactly the changes numbered before it. No revision needed. (Of an object it does not
\* read, a change numbered below it may commit after it: nothing it decided on.)
TotalOrder ==
    \A e \in UsesIn(log) : \A i \in e.reads :
        e.seen[i] = Cardinality({d \in ChangesIn(log) : d.input = i /\ d.seq < e.seq})

\* The outcome is not stored: it is recomputed from the log, and the recomputation is what the
\* Worker decided. (With no database writer.)
ReplayAgrees ==
    \A e \in UsesIn(log) : e.allow = ReplayAllows(e)

\* With a database writer: nothing is allowed that the log refuses...
ReplaySound ==
    \A e \in UsesIn(log) : e.allow => ReplayAllows(e)

\* ...and a use refused where the log allows was refused for a row put back, and says so.
TamperVisible ==
    \A e \in UsesIn(log) : (~e.allow /\ ReplayAllows(e)) => e.code = "stale"

\* "Revoke returned => the next use is refused", in its strongest form: no use allowed on a state
\* from before a change of what it reads commits after that change has answered.
NothingAllowedAfterAnswer ==
    \A e \in UsesIn(log) : e.allow => \A i \in e.reads : e.answeredAt[i] <= e.seen[i]

\* A value leaves only once its entry is in the log, flushed: its own, or its cover's.
Logged(seq, x) == \E e \in UsesIn(log) : e.seq = seq /\ e.allow /\ e.durable /\ (x = None \/ e.id = x)
DurableBeforeRelease ==
    \A r \in released : (\E e \in UsesIn(log) : e.id = r.id /\ e.allow /\ e.durable)
                        \/ (\E q \in repeats : q.id = r.id /\ q.allow /\ Logged(q.cover, q.coverId))

\* A repeat is its cover again: allowed on the state its cover was decided on (no change to any of
\* its inputs numbered after the cover), and after no change it did not see had answered. So the
\* log, which has only the cover, says the truth about it: a use after a change is never a repeat
\* of one before.
RepeatsAreTheirCover ==
    \A r \in repeats : r.allow =>
        /\ Logged(r.cover, r.coverId)
        /\ \A i \in r.reads : /\ r.seen[i] = Cardinality({d \in ChangesIn(log) : d.input = i /\ d.seq < r.cover})
                               /\ r.answeredAt[i] <= r.seen[i]

\* Each checkpoint signed exactly the entries numbered in its range: none committed there later,
\* none missed by its `at`.
CheckpointsHold ==
    \A k \in signed : {e.seq : e \in {d \in log : k.from < d.seq /\ d.seq <= k.upto}} = k.seqs

\* The ceiling the verifier, locate and retention read a checkpoint's uses up to (T169): no use it
\* seals is stamped more than D + MaxSkew past its floor (63 s in the code). Both ends of a use's
\* numbering read Postgres's clock (AheadChecked, DeadlineChecked); a clock that steps back breaks it
\* (HotPathOneChunksClock, EXPECTED), and the verifier's bounded read then misses the use and alarms.
CeilingHolds ==
    \A k \in signed : \A d \in UsesIn(log) : k.from < d.seq /\ d.seq <= k.upto => d.at <= k.floor + D + MaxSkew

NumbersUnique ==
    \A d, e \in log : d.seq = e.seq => d = e

\* With no database writer, each change leaves the flip of what the change before it on its input
\* left: the log says what was done to the row, and the row is what the log says (a change that
\* worked from a row another one had moved since would log a second revoke over a revoke).
EachChangeFlips ==
    \A e \in ChangesIn(log) : e.value = ~NewestIn({d \in log : d.seq < e.seq}, e.input)

\* No entry was decided past its deadline.
NoLateWork ==
    \A e \in UsesIn(log) : e.decidedAt <= e.deadline

\* No value left past its deadline.
ReleaseByDeadline ==
    \A r \in released : r.t <= r.deadline

\* In any window of BulkWindow, by the requests' `at`, the values released to the principal are of
\* BulkCount distinct keys at most. With a policy that changes the cap, what holds across a change is
\* the weaker bound: in any window as long as the smaller of the two, the larger of the two counts.
\* (Each request is decided exactly on the policy in force at its number: BulkReplayAgrees.)
Times == (0 - MaxSkew)..(MaxTime + MaxSkew)
CapWindow == IF "policy" \in Inputs /\ BulkWindowAlt < BulkWindow THEN BulkWindowAlt ELSE BulkWindow
CapCount == IF "policy" \in Inputs THEN Max(BulkCount, BulkCountAlt) ELSE BulkCount
BulkCapHolds ==
    \A t \in Times : Cardinality({r.key : r \in {q \in released : q.key /= None /\ t - CapWindow < q.at /\ q.at <= t}}) <= CapCount

\* The replay of the cap decides each entry as live did, and leaves the bulk rows live left.
BulkReplayAgrees ==
    LET R == BulkReplay(log)
    IN /\ \A e \in UsesIn(log) : e.key /= None => <<e.seq, e.admitted>> \in R.decided
       /\ R.rows = bulk

\* T127, R44: a use whose key is in its principal's set waits on the principal's lock only for a use
\* entering a key (once per key and window), never for another use moving a key on: one principal's
\* hot keys never queue their uses one behind the other.
RefreshesNeverQueue ==
    \A x \in Uses : (u[x].pc = "waiting" /\ ~u[x].enters) =>
        \A y \in Uses \ {x} : (plock.ex = y \/ (u[y].pc = "waiting" /\ u[y].mode = "x")) => u[y].enters

\* T158: a use asks for its principal's lock, and holds it, only for a caller the log allowed when it
\* asked: a caller with no standing, which a key never made never makes wait, never waits for one held
\* (formal/Probing.tla says what that would tell her). A revoke after the ask may still find it waiting.
NoLockWithoutStanding ==
    \A x \in Uses : (u[x].pc = "waiting" \/ plock.ex = x \/ x \in plock.sh) => u[x].standing

\* A use holding the principal's lock shared finds its key still in the set at its statement: a key
\* only ever moves later, and the window cannot change under the policy's lock. So the statement never needs
\* the lock exclusive once it holds it shared.
SharedStaysInSet ==
    \A x \in plock.sh : u[x].pc = "read" => InSet(bulk, u[x].key, u[x].at, WindowIn(log))

\* R58: a use never waits on an issue. No issue holds the fence, and the barrier never holds the
\* fence while an issue holds the issue lock: a use waits only on changes and the barrier, the
\* barrier on the fence only once every issue numbered before it has ended (BarrierWaitsIssues).
UsesNeverWaitOnIssues ==
    /\ \A i \in Issuers : i \notin shared /\ holder /= i
    /\ holder = "barrier" => ishared = {}

\* Not a protection but what L1 is for, which TLC must find broken (EXPECTED in scripts/formal.sh): a
\* use reads beside a change in flight, of an object it does not read. Under the fence none did.
NeverSideBySide ==
    ~\E x \in Uses, h \in Changers : x \in shared /\ u[x].pc \in {"read", "ran"} /\ ChangeLocks /\ ChangerIn(h)

(* Liveness. *)

\* Every use that arrives is answered: its value, a refusal, or 503 (late, failed, given up).
UseAnswered ==
    \A x \in Uses : u[x].pc /= "idle" ~> u[x].replied

\* Every change that starts is answered.
ChangeAnswered ==
    \A h \in Changers : \A n \in 0..(MaxChanges - 1) : (c[h].pc = "started" /\ c[h].n = n) ~> c[h].n > n

MaxSeq == Cardinality(Uses) + Cardinality(Changers) * MaxChanges + Cardinality(Issuers)

\* Every number handed out is closed by a checkpoint, while the scenario has checkpoints left to sign.
CheckpointsGoOn ==
    \A n \in 1..MaxSeq : nextSeq > n ~> (lastUpto >= n \/ Cardinality(signed) >= MaxCheckpoints)

=============================================================================
