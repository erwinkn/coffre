----------------------------- MODULE HotPathOne -----------------------------
(***************************************************************************)
(* 0.15's hot path: one round trip per use, no revision (W208, W211;       *)
(* docs/design/hot-path-one.md). Uses and changes on one Postgres, under   *)
(* READ COMMITTED.                                                         *)
(*                                                                         *)
(* A use is one call, `use_credential`, a plpgsql function, one            *)
(* transaction (autocommit):                                               *)
(*   it takes the fence lock (an advisory lock) shared, and refuses an     *)
(*   `at` below the floor;                                                 *)
(*   statement A reads the principal's bulk row for its key and, if the    *)
(*   key must enter the cap's set, takes the principal's lock exclusive,   *)
(*   or, if it is in the set and must be moved on, shared (T127);          *)
(*   statement B, a snapshot of its own after every lock: past its         *)
(*   deadline it writes nothing (`late`); else it reads every decision     *)
(*   input, the seals of their newest changes, applies the cap's rule and  *)
(*   inserts the use's entry, numbered from a sequence (or, a repeat on a  *)
(*   cover, writes nothing);                                               *)
(*   it commits, which lets the locks go.                                  *)
(* The Worker decides on what statement B read, and the value leaves only  *)
(* after the commit and before the use's deadline. The entry is the        *)
(* request, not the outcome: the outcome is recomputed from the log.       *)
(*                                                                         *)
(* A change (one input revoked or restored) is one call too: the vault     *)
(* reads the row outside the lock; then the lock exclusive, the write if   *)
(* the row is still the one it read, its entry numbered from the same      *)
(* sequence, the commit; then it answers. The checkpointer's barrier takes *)
(* the lock exclusive for one statement: it raises the floor of `at` to    *)
(* its clock less D and closes every number handed out so far. The next    *)
(* checkpoint reads that window, its uses through the `at` index from the  *)
(* floor the previous barrier set, and signs it.                           *)
(*                                                                         *)
(* The claim at the core: since uses hold the lock shared and changes      *)
(* exclusive, and each takes its number under the lock and keeps the lock  *)
(* until its commit is visible, no use overlaps a change, so the number    *)
(* alone orders every use against every change (TotalOrder). Nothing is    *)
(* left for a revision counter to do.                                      *)
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
(* input. The log stores no outcome; each entry's decision here is a       *)
(* ghost, for the invariants.                                              *)
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
(* next state from what it read.                                           *)
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
(* periods are Refresh, delta, long: t - t % delta). A key is in the set   *)
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
(*   UseLocks              a use takes the lock shared;                    *)
(*   StatementSnapshot     its reads take their snapshot after the lock:   *)
(*                         a statement of its own inside the function,     *)
(*                         FALSE for a bare CTE, `WITH l AS (SELECT        *)
(*                         pg_advisory_xact_lock_shared(…)) …`, whose one  *)
(*                         snapshot predates the wait;                     *)
(*   UseNumberUnderLock    a use's number is taken under the lock, not     *)
(*                         passed in (`use_credential(nextval(…), …)`);    *)
(*   ChangeLocks           a change takes the lock exclusive;              *)
(*   ChangeNumberUnderLock a change's number is taken under the lock, not  *)
(*                         in a read before it;                            *)
(*   LockToCommit          the lock goes with the commit (an xact lock),   *)
(*                         not at the end of the statement before it (a    *)
(*                         session lock unlocked in the function);         *)
(*   CommitBeforeAnswer    a change answers only once committed;           *)
(*   ReleaseAfterCommit    a use's value leaves only once its entry has    *)
(*                         committed;                                      *)
(*   SyncCommit            a commit returns once flushed                   *)
(*                         (synchronous_commit on);                        *)
(*   CheckpointLocks       the barrier closes its numbers under the lock   *)
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
(*   FloorChecked          a use whose `at` is below the floor writes      *)
(*                         nothing;                                        *)
(*   BarrierChecksFloor    the floor is an unsigned row: the barrier       *)
(*                         finds it at the value it last wrote, which the  *)
(*                         signer remembers, or raises the alarm and signs *)
(*                         nothing (a floor a writer lowered would let a   *)
(*                         use in below it, which the next checkpoint's    *)
(*                         `at` scan misses);                              *)
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
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    Uses,            \* the uses, each one request, one call
    Changers,        \* the change processes
    MaxChanges,      \* changes each changer makes in a behaviour
    MaxAborts,       \* change statements that fail after taking the lock
    MaxCheckpoints,  \* checkpoints signed in a behaviour
    MaxCrashes,      \* Postgres crashes in a behaviour
    Covers,          \* uses pass the isolate's cover
    Inputs,          \* the rows a decision reads
    Unsealed,        \* the inputs read without their seal checked: {} (a removal sets some)
    SealCache,       \* the isolate keeps the seals a use read, and later uses may pass them
    MaxTampers,      \* rows a database writer puts back in a behaviour
    MaxRestores,     \* restores from a backup in a behaviour
    Holds,           \* Hyperdrive may hold a call and never run it
    FloorTampers,    \* the writer's tampering (MaxTampers) may lower the floor of `at` instead of a row
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
    ChangeCAS, ChangeRereads, ChangeChecksSeal, BarrierChecksFloor, DeadlineChecked, FloorChecked, WorkerHonoursDeadline,
    PrincipalLocks, RefreshLocks, RefreshPeriods, RefreshShared, RefreshOnUse, CoverFresh, Slack, DeadlineSlack,
    AheadSlack, CapFromPolicy, CapSealed,
    Issuers,         \* the sign-ins, each issuing one new credential: {} for none
    IssueOwnLock, IssueNumberUnderLock, BarrierWaitsIssues, BarrierIssueFirst, NamedAfterIssue

None == "none"
Change == "change"
NoTime == -1000   \* a key never asked for

VARIABLES
    log,       \* the committed entries; `durable` once flushed
    nextSeq,   \* the sequence's next value
    holder,    \* the changer holding the lock exclusive, or None
    shared,    \* the uses holding it shared
    plock,     \* the principal's lock: the use holding it exclusive (ex), or None, and those holding it shared (sh)
    u,         \* each use's state
    c,         \* each changer's state
    answered,  \* how many changes had committed when the last change answered
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

NoPlock == [ex |-> None, sh |-> {}]
\* The principal's lock without use x: what its commit, or its end, leaves.
PlockWithout(x) == [ex |-> IF plock.ex = x THEN None ELSE plock.ex, sh |-> plock.sh \ {x}]

-----------------------------------------------------------------------------
(* What a statement sees. `Committed`, the number of changes committed, orders it against the   *)
(* changes (TotalOrder). Each input's row is what its newest committed change wrote, unless a     *)
(* database writer put back an earlier one; the seal of the input's newest change is read from    *)
(* the log in the same statement.                                                                 *)
ChangesIn(L) == {e \in L : e.kind = "change"}
\* An issue is a row of the change table too (`credential.issue`), of an object no input names.
IssuesIn(L) == {e \in L : e.kind = "issue"}
\* Whether issuer i's credential is in L: committed, or below a number.
IssuedIn(L, i) == \E e \in IssuesIn(L) : e.id = i
UsesIn(L) == {e \in L : e.kind = "use"}
Committed == Cardinality(ChangesIn(log))

\* An input's value as the newest change to it in L left it (all start allowing; the policy at
\* BulkCount).
NewestIn(L, i) ==
    LET cs == {e \in ChangesIn(L) : e.input = i}
    IN IF cs = {} THEN TRUE ELSE (CHOOSE e \in cs : \A d \in cs : d.seq <= e.seq).value
Newest == [i \in Inputs |-> NewestIn(log, i)]
Rows == [i \in Inputs |-> IF tamper[i].on THEN tamper[i].value ELSE NewestIn(log, i)]

\* The log's newest change, as its number and MAC (here, its id) say it, or none.
NoChange == [seq |-> 0, made |-> <<>>]
NewestChange ==
    LET cs == ChangesIn(log) \cup IssuesIn(log)
    IN IF cs = {} THEN NoChange
       ELSE LET e == CHOOSE e \in cs : \A d \in cs : d.seq <= e.seq IN [seq |-> e.seq, made |-> e.made]

\* `decide`, on the rows a use read and the seals of their newest changes: `stale` when a sealed
\* row is not its newest change's, then allowed only if every row allows. Without StaleFirst,
\* what the rows say is checked first, and a row put back that refuses shows as a plain refusal.
Stale(read, newest) == \E i \in Inputs \ Unsealed : read[i] /= newest[i]
Content(read) == \A i \in Inputs \ {"policy"} : read[i]
Code(read, newest) ==
    IF Stale(read, newest) /\ (StaleFirst \/ Content(read)) THEN "stale"
    ELSE IF Content(read) THEN "allow" ELSE "refused"

AllTrue == [i \in Inputs |-> TRUE]
NoCover == [seq |-> 0, id |-> None]
NoCache == [on |-> FALSE, seals |-> AllTrue, change |-> NoChange]
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
\* The start of t's refresh period (% is never negative for a positive divisor), or, without periods, t.
Period(t) == IF RefreshPeriods THEN t - (t % Refresh) ELSE t
Fresh(L, k, t) == IF RefreshPeriods THEN L[k] >= Period(t) ELSE L[k] > t - Refresh

\* The cap's rule for a request for k at t under the policy p, on rows L: admitted or not, and the
\* `last` it writes (NoTime: none). The live statement B and the replay apply the same rule.
Rule(L, k, t, p) ==
    IF k = None THEN [admitted |-> TRUE, write |-> NoTime]
    ELSE IF InSet(L, k, t, p.w)
    THEN [admitted |-> TRUE, write |-> IF RefreshOnUse /\ ~Fresh(L, k, t) THEN Period(t) ELSE NoTime]
    ELSE IF Cardinality({k2 \in Keys \ {k} : Counts(L, k2, t, p.w)}) >= p.n
         THEN [admitted |-> FALSE, write |-> NoTime]
         ELSE [admitted |-> TRUE, write |-> Period(t)]

\* The replay of the cap: the use entries of the log G in number order, the rule applied to each on
\* the rows the ones before it left, under the policy the changes numbered before it left.
RECURSIVE ReplayFrom(_, _, _, _)
ReplayFrom(es, L, decided, G) ==
    IF es = {} THEN [rows |-> L, decided |-> decided]
    ELSE LET e == CHOOSE e \in es : \A d \in es : e.seq <= d.seq
             r == Rule(L, e.key, e.at, ReplayPolicyIn({d \in G : d.seq < e.seq}))
         IN ReplayFrom(es \ {e}, IF r.write = NoTime THEN L ELSE [L EXCEPT ![e.key] = Max(@, r.write)],
                       decided \cup {<<e.seq, r.admitted>>}, G)
BulkReplay(G) == ReplayFrom({e \in UsesIn(G) : e.key /= None}, [k \in Keys |-> NoTime], {}, G)

\* What the log says of a use entry: every input as the changes numbered below it left it, and
\* the cap's decision as the replay makes it.
InputsAllowed(seq) == \A i \in Inputs \ {"policy"} : ReplayValue({d \in log : d.seq < seq}, i)
ReplayAllows(e) ==
    /\ InputsAllowed(e.seq)
    /\ e.fresh /= None => IssuedIn({d \in log : d.seq < e.seq}, e.fresh)
    /\ e.key = None \/ <<e.seq, TRUE>> \in BulkReplay(log).decided

\* Entries: a use's is its request (number, key, at, deadline) with ghosts: the changes it saw, its
\* decision and code, when decided, the cap's decision, the changes answered when it committed. A
\* change's: its number, its input, the value it leaves, its id. Both: flushed yet.
UseEntry(x, durable) ==
    [seq |-> u[x].seq, kind |-> "use", id |-> x, seen |-> u[x].seen, allow |-> u[x].allow, code |-> u[x].code,
     answeredAt |-> answered, key |-> u[x].key, at |-> u[x].at, deadline |-> u[x].deadline, decidedAt |-> u[x].decidedAt,
     admitted |-> u[x].admitted, input |-> None, value |-> FALSE, made |-> <<>>, fresh |-> u[x].fresh, durable |-> durable]
ChangeEntry(seq, input, value, made, durable) ==
    [seq |-> seq, kind |-> "change", id |-> Change, seen |-> 0, allow |-> FALSE, code |-> None, answeredAt |-> 0,
     key |-> None, at |-> 0, deadline |-> 0, decidedAt |-> 0, admitted |-> FALSE,
     input |-> input, value |-> value, made |-> made, fresh |-> None, durable |-> durable]
\* An issue's: its number, its issuer (whose credential it makes).
IssueEntry(seq, i, durable) ==
    [seq |-> seq, kind |-> "issue", id |-> i, seen |-> 0, allow |-> FALSE, code |-> None, answeredAt |-> 0,
     key |-> None, at |-> 0, deadline |-> 0, decidedAt |-> 0, admitted |-> FALSE,
     input |-> None, value |-> FALSE, made |-> <<i>>, fresh |-> None, durable |-> durable]

IdleUse == [pc |-> "idle", seq |-> 0, seen |-> 0, snap |-> 0, snapRows |-> AllTrue, snapNewest |-> AllTrue,
            snapNewestChange |-> NoChange, covered |-> 0, coverId |-> None, allow |-> FALSE, code |-> None,
            probed |-> FALSE, newest |-> AllTrue, newestChange |-> NoChange,
            key |-> None, at |-> 0, deadline |-> 0, decidedAt |-> 0, admitted |-> FALSE, write |-> NoTime,
            replied |-> FALSE, gaveUp |-> FALSE, fresh |-> None, snapIssued |-> FALSE, mode |-> None, enters |-> FALSE]
\* A cover or a cache entry is the isolate's for one credential and key: a use's slot.
Slots == KeysOr \X ({None} \cup Issuers)
Slot(x) == <<u[x].key, u[x].fresh>>

Init ==
    /\ log = {}
    /\ nextSeq = 1
    /\ holder = None
    /\ shared = {}
    /\ plock = NoPlock
    /\ u = [x \in Uses |-> IdleUse]
    /\ c = [h \in Changers |-> [pc |-> "idle", n |-> 0, seq |-> 0, aborts |-> 0, input |-> None, read |-> TRUE, value |-> FALSE]]
    /\ answered = 0
    /\ released = {}
    /\ cp = [open |-> FALSE, from |-> 0, upto |-> 0, readFloor |-> 0, floor |-> 0]
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

LockFree == holder = None /\ shared = {}

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
\* statement starts, with its snapshot. Passed a number taken before (without UseNumberUnderLock),
\* it takes it now.
\* It names an old credential (None) or a new one, issuer i's: with NamedAfterIssue, once its issue
\* has answered.
UseStart(x) ==
    /\ u[x].pc = "idle"
    /\ pnow <= MaxStart
    /\ \E k \in KeysOr, s \in -MaxSkew..MaxSkew,
          f \in {None} \cup {i \in Issuers : NamedAfterIssue => iss[i].pc = "answered"} :
          u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "started", !.key = k, !.at = pnow + s, !.deadline = pnow + s + D,
                                          !.snap = Committed, !.snapRows = Rows, !.snapNewest = Newest,
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

\* It gets the lock shared: no one holds it exclusive. Below the floor, it lets the lock go having
\* written nothing (503 `late`). With a bulk cap, statement A comes next; without, statement B.
UseLock(x) ==
    /\ u[x].pc = "started"
    /\ UseLocks => holder = None
    /\ LET late == FloorChecked /\ u[x].at < floor
       IN /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = IF late THEN "done" ELSE IF Keys = {} THEN "read" ELSE "locked",
                                             !.replied = @ \/ late]]
          /\ shared' = IF UseLocks /\ ~late THEN shared \cup {x} ELSE shared
    /\ UNCHANGED <<log, nextSeq, holder, plock, c, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Statement A: the key's bulk row, as committed, and the policy's window (which no change can move
\* while the use holds the lock shared). A key that must enter the set asks for the principal's lock
\* exclusive; one in the set that must be moved on, shared (or exclusive, without RefreshShared).
UseRead(x) ==
    /\ u[x].pc = "locked"
    /\ LET k == u[x].key
           t == u[x].at
           enters == k /= None /\ ~InSet(bulk, k, t, WindowIn(log))
           moves == k /= None /\ ~enters /\ ~Fresh(bulk, k, t)
           waits == PrincipalLocks /\ (enters \/ (moves /\ RefreshLocks))
       IN u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = IF waits THEN "waiting" ELSE "read", !.enters = enters,
                                          !.mode = IF ~waits THEN None ELSE IF moves /\ RefreshShared THEN "s" ELSE "x"]]
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
CoverInSet(k, t, w) == k /= None => InSet(bulk, k, t, w) /\ (CoverFresh => Fresh(bulk, k, t))

\* The caps a caller may pass from its own config (without CapFromPolicy): any the policy has had.
CallerPolicies ==
    IF "policy" \in Inputs /\ ~CapFromPolicy
    THEN {PolicyOf(v) : v \in {TRUE} \cup {e.value : e \in {d \in ChangesIn(log) : d.input = "policy"}}}
    ELSE {PolicyOf(TRUE)}

\* Statement B, its snapshot taken now (or, as a bare CTE, at the call's start): everything the
\* decision reads, the cap's rule (its count and window from the policy's newest change), the entry's
\* number, from the sequence unless passed in; or, a repeat on its cover, nothing written. Without
\* LockToCommit the fence lock goes here, before the commit. Without ReleaseAfterCommit the value
\* leaves on what was read.
UseRun(x) ==
    /\ u[x].pc = "read"
    /\ DeadlineChecked => pnow <= u[x].deadline
    /\ \E passed \in IF SealCache /\ cache[Slot(x)].on THEN BOOLEAN ELSE {FALSE}, callerPolicy \in CallerPolicies :
       LET k == u[x].key
           sl == Slot(x)
           t == u[x].at
           seen == IF StatementSnapshot THEN Committed ELSE u[x].snap
           read == IF StatementSnapshot THEN Rows ELSE u[x].snapRows
           probes == IF StatementSnapshot THEN Newest ELSE u[x].snapNewest
           newestChange == IF StatementSnapshot THEN NewestChange ELSE u[x].snapNewestChange
           skip == passed /\ (CacheChecked => CacheHolds(sl, newestChange))
           newest == IF skip THEN cache[sl].seals ELSE probes
           p == IF "policy" \notin Inputs THEN PolicyOf(TRUE)
                ELSE IF ~CapFromPolicy THEN callerPolicy
                ELSE PolicyOf(IF CapSealed THEN newest["policy"] ELSE read["policy"])
           covered == /\ Covers /\ CoverThere(sl) /\ CoverInSet(k, t, p.w)
                      /\ IF skip THEN cover[sl].seq > cache[sl].change.seq ELSE CoverNoChange(sl)
           r == Rule(bulk, k, t, p)
           admitted == covered \/ r.admitted
           \* A new credential is found only once its issue has committed, in the statement's snapshot (its row).
           found == u[x].fresh = None \/ IF StatementSnapshot THEN IssuedIn(log, u[x].fresh) ELSE u[x].snapIssued
           base == IF found THEN Code(read, newest) ELSE "refused"
           code == IF base = "allow" /\ ~admitted THEN "bulk" ELSE base
       IN /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "ran", !.seen = seen, !.decidedAt = pnow,
                                     !.covered = IF covered THEN cover[sl].seq ELSE 0, !.coverId = IF covered THEN cover[sl].id ELSE None,
                                     !.allow = (code = "allow"), !.code = code, !.admitted = admitted,
                                     !.write = IF covered THEN NoTime ELSE r.write,
                                     !.probed = ~skip, !.newest = newest, !.newestChange = newestChange,
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
                                          allow |-> u[x].allow, answeredAt |-> answered]}
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
          /\ cache' = IF SealCache /\ u[x].probed THEN [cache EXCEPT ![sl] = [on |-> TRUE, seals |-> u[x].newest, change |-> u[x].newestChange]]
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

\* The call starts, for one input: the vault reads its row, outside the lock, and works out the
\* next state from it. Without ChangeNumberUnderLock, its number was taken by a read before it.
ChangeStart(h) ==
    /\ c[h].pc = "idle"
    /\ c[h].n < MaxChanges
    /\ \E i \in Inputs :
          c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "started", !.input = i, !.read = Rows[i],
                                          !.seq = IF ChangeNumberUnderLock THEN 0 ELSE nextSeq]]
    /\ nextSeq' = IF ChangeNumberUnderLock THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<log, holder, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* After a refused write, the vault reads the row again.
ChangeReread(h) ==
    /\ c[h].pc = "refused"
    /\ c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "started", !.read = Rows[c[h].input]]]
    /\ UNCHANGED <<log, nextSeq, holder, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* It gets the lock exclusive: no one holds it at all.
ChangeLock(h) ==
    /\ c[h].pc = "started"
    /\ ChangeLocks => LockFree
    /\ holder' = IF ChangeLocks THEN h ELSE holder
    /\ c' = [c EXCEPT ![h].pc = "locked"]
    /\ UNCHANGED <<log, nextSeq, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Its statement: if the row is no longer the one it read (ChangeCAS), or not the one its object's
\* newest change wrote (ChangeChecksSeal), nothing is written, the lock goes and the vault reads
\* again (without ChangeRereads, it tries the same read again). Else the write (the flip of what it
\* read) and its entry's number. Without LockToCommit the lock goes here; without CommitBeforeAnswer
\* it answers here.
ChangeRun(h) ==
    /\ c[h].pc = "locked"
    /\ IF \/ ChangeCAS /\ Rows[c[h].input] /= c[h].read
          \/ ChangeChecksSeal /\ Rows[c[h].input] /= NewestIn(log, c[h].input)
       THEN /\ c' = [c EXCEPT ![h].pc = IF ChangeRereads THEN "refused" ELSE "started"]
            /\ holder' = IF holder = h THEN None ELSE holder
            /\ UNCHANGED <<nextSeq, answered, issueVars>>
       ELSE /\ c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "ran", !.value = ~c[h].read, !.seq = IF ChangeNumberUnderLock THEN nextSeq ELSE @]]
            /\ nextSeq' = IF ChangeNumberUnderLock THEN nextSeq + 1 ELSE nextSeq
            /\ holder' = IF LockToCommit THEN holder ELSE None
            /\ answered' = IF CommitBeforeAnswer THEN answered ELSE Committed + 1
    /\ UNCHANGED <<log, shared, plock, u, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* The commit: its entry, and the row it wrote, in place of whatever was there.
ChangeCommit(h) ==
    /\ c[h].pc = "ran"
    /\ log' = log \cup {ChangeEntry(c[h].seq, c[h].input, c[h].value, <<h, c[h].n + 1>>, SyncCommit)}
    /\ holder' = IF holder = h THEN None ELSE holder
    /\ c' = [c EXCEPT ![h].pc = "committed"]
    /\ tamper' = [tamper EXCEPT ![c[h].input] = [on |-> FALSE, value |-> TRUE]]
    /\ UNCHANGED <<nextSeq, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tampers, cache, restores, bulk, pnow, backs, issueVars>>

\* Its statement fails instead (a deadline, a lost connection): rolled back, the lock let go; it
\* starts over. Its number is a gap.
ChangeAbort(h) ==
    /\ c[h].pc = "ran"
    /\ c[h].aborts < MaxAborts
    /\ holder' = IF holder = h THEN None ELSE holder
    /\ c' = [c EXCEPT ![h] = [@ EXCEPT !.pc = "idle", !.aborts = @ + 1]]
    /\ UNCHANGED <<log, nextSeq, shared, plock, u, answered, released, cp, lastUpto, lastFloor, signed, floor, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, issueVars>>

ChangeAnswer(h) ==
    /\ c[h].pc = "committed"
    /\ answered' = IF answered > Committed THEN answered ELSE Committed
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
    /\ BarrierChecksFloor => floor = lastFloor
    /\ floor' = Max(floor, pnow - D)
    /\ cp' = [open |-> TRUE, from |-> lastUpto, upto |-> nextSeq - 1, readFloor |-> lastFloor, floor |-> Max(floor, pnow - D)]
    /\ holder' = IF holder = "barrier" THEN None ELSE holder
    /\ iholder' = None
    /\ bar' = 0
    /\ UNCHANGED <<log, nextSeq, shared, plock, u, c, answered, released, lastUpto, lastFloor, signed, crashes,
                   cover, repeats, tamper, tampers, cache, restores, bulk, pnow, backs, iss, ishared>>

\* Later, outside any lock: it reads the window (the changes by number, the uses through the `at`
\* index from the previous barrier's floor) and signs their numbers.
CheckpointSign ==
    /\ cp.open
    /\ signed' = signed \cup {[from |-> cp.from, upto |-> cp.upto,
                               seqs |-> {e.seq : e \in {d \in log : cp.from < d.seq /\ d.seq <= cp.upto
                                                                    /\ (d.kind = "change" \/ d.at >= cp.readFloor)}}]}
    /\ lastUpto' = cp.upto
    /\ lastFloor' = cp.floor
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
             /\ answered' = Cardinality(ChangesIn(kept))
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
    \/ UseLock(x) \/ UseRead(x) \/ UsePrincipalLock(x) \/ UseLate(x) \/ UseRun(x) \/ UseCommit(x) \/ UseRelease(x)
    \/ WorkerGivesUp(x)
ChangeStep(h) ==
    ChangeStart(h) \/ ChangeReread(h) \/ ChangeLock(h) \/ ChangeRun(h) \/ ChangeCommit(h) \/ ChangeAnswer(h)

Next ==
    \/ Tick \/ ClockBack
    \/ \E x \in Uses : UseStart(x) \/ UseHold(x) \/ UseResume(x) \/ UseStep(x) \/ UseFail(x) \/ UseCrash(x)
    \/ \E h \in Changers : ChangeStep(h) \/ ChangeAbort(h)
    \/ \E i \in Issuers : IssueStep(i) \/ IssueFail(i)
    \/ BarrierLock \/ CheckpointClose \/ CheckpointSign
    \/ Flush \/ Crash \/ Tamper \/ TamperFloor \/ Restore

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

\* The number alone orders uses against changes: every use saw exactly the changes numbered
\* before it. No revision needed.
TotalOrder ==
    \A e \in UsesIn(log) : e.seen = Cardinality({d \in ChangesIn(log) : d.seq < e.seq})

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
\* from before a change commits after that change has answered.
NothingAllowedAfterAnswer ==
    \A e \in UsesIn(log) : e.allow => e.answeredAt <= e.seen

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
        /\ r.seen = Cardinality({d \in ChangesIn(log) : d.seq < r.cover})
        /\ r.answeredAt <= r.seen

\* Each checkpoint signed exactly the entries numbered in its range: none committed there later,
\* none missed by its `at`.
CheckpointsHold ==
    \A k \in signed : {e.seq : e \in {d \in log : k.from < d.seq /\ d.seq <= k.upto}} = k.seqs

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

\* A use holding the principal's lock shared finds its key still in the set at its statement: a key
\* only ever moves later, and the window cannot change under the fence. So the statement never needs
\* the lock exclusive once it holds it shared.
SharedStaysInSet ==
    \A x \in plock.sh : u[x].pc = "read" => InSet(bulk, u[x].key, u[x].at, WindowIn(log))

\* R58: a use never waits on an issue. No issue holds the fence, and the barrier never holds the
\* fence while an issue holds the issue lock: a use waits only on changes and the barrier, the
\* barrier on the fence only once every issue numbered before it has ended (BarrierWaitsIssues).
UsesNeverWaitOnIssues ==
    /\ \A i \in Issuers : i \notin shared /\ holder /= i
    /\ holder = "barrier" => ishared = {}

(* Liveness. *)

\* Every use that arrives is answered: its value, a refusal, or 503 (late, failed, given up).
UseAnswered ==
    \A x \in Uses : u[x].pc /= "idle" ~> u[x].replied

\* Every change that starts is answered.
ChangeAnswered ==
    \A h \in Changers : \A n \in 0..(MaxChanges - 1) : (c[h].pc = "started" /\ c[h].n = n) ~> c[h].n > n

=============================================================================
