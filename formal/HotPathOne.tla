----------------------------- MODULE HotPathOne -----------------------------
(***************************************************************************)
(* 0.15's hot path in one round trip (W208, experiments/lanes/src/one.ts): *)
(* no revision, no fence to fail, no retry. Uses and changes on one        *)
(* Postgres, under READ COMMITTED.                                          *)
(*                                                                         *)
(* A use is one call, `use_credential`, a plpgsql function, one            *)
(* transaction (autocommit):                                               *)
(*   it takes an advisory lock shared;                                     *)
(*   then, in a statement of its own, it reads everything the decision     *)
(*   needs and inserts the use's entry, numbered from a sequence;          *)
(*   it commits, which lets the lock go.                                   *)
(* The Worker decides on what that statement read, and the value leaves    *)
(* only after the commit. The entry is the request, not the outcome: the   *)
(* outcome is recomputed from the log (the changes numbered before it).    *)
(*                                                                         *)
(* A change (one input revoked or restored) is one call too: the lock     *)
(* exclusive, the write, its entry numbered from the same sequence, the    *)
(* commit; then it answers. A checkpointer takes the lock exclusive for    *)
(* one statement to close every number handed out so far, then signs the *)
(* entries at or below it.                                                 *)
(*                                                                         *)
(* The claim checked here: since uses hold the lock shared and changes     *)
(* exclusive, and each takes its number under the lock and keeps the lock  *)
(* until its commit is visible, no use overlaps a change, so the number    *)
(* alone orders every use against every change (TotalOrder). Nothing is   *)
(* left for a revision counter to do.                                      *)
(*                                                                         *)
(* A statement is several steps here where something can come between     *)
(* them in Postgres: it takes its snapshot when it starts, then waits for  *)
(* its lock, then reads and writes, then commits; the commit is flushed to *)
(* disk at once (synchronous_commit on) or later; Postgres can crash.      *)
(*                                                                         *)
(* The protections, each a constant, so that TLC can show each necessary   *)
(* (scripts/formal-hotpath.sh):                                            *)
(*   UseLocks              a use takes the lock shared;                    *)
(*   StatementSnapshot     its reads take their snapshot after the lock:   *)
(*                         a statement of its own inside the function,     *)
(*                         FALSE for a bare CTE, `WITH l AS (SELECT        *)
(*                         pg_advisory_xact_lock_shared(…)) …`, whose one  *)
(*                         snapshot predates the wait;                     *)
(*   UseNumberUnderLock    a use's number is taken under the lock, not     *)
(*                         passed in (`use_credential(nextval(…), …)`);   *)
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
(*   CheckpointLocks       the checkpointer closes its numbers under the   *)
(*                         lock exclusive;                                 *)
(*   CoverChecksChanges    (with Covers) a covered use writes nothing only *)
(*                         if no change was numbered after its cover;      *)
(*   CoverChecksAllInputs  ... a change to any of its inputs, not only to  *)
(*                         the member (W208's first scope);                *)
(*   SealMember, SealCredential, SealSecret, SealEnvironment               *)
(*                         a use refuses (`stale`) a row of that input     *)
(*                         whose seal is not the one its newest change     *)
(*                         wrote (W211, R53);                              *)
(*   StaleFirst            `decide` checks the seals before what the rows  *)
(*                         say, so that a row put back shows as `stale`;   *)
(*   CacheChecked          (with SealCache) a use skips the probes of the  *)
(*                         newest changes only if the log's newest change  *)
(*                         is the one the isolate's cache was read at;     *)
(*   CacheSameChange       ... the same change (its number and MAC), not   *)
(*                         only a number no higher: a log restored from a  *)
(*                         backup has other changes under the same numbers.*)
(*                                                                         *)
(* The inputs (W211): every decision reads several rows, each sealed by    *)
(* the vault (a MAC over it): the member with its grants, the credential,  *)
(* the secret with its wrapped key, the environment. Each change writes    *)
(* exactly one of them and its entry records the seal it leaves. An input  *)
(* here allows (TRUE) or refuses (FALSE); a change flips one. A seal is    *)
(* the row's content, so putting back an identical row passes, harmlessly. *)
(* A database writer with no key (MaxTampers) can only put back a row      *)
(* the vault once sealed: an earlier value of that input. The log stores   *)
(* no outcome; each entry's decision here is a ghost, for the invariants.  *)
(*                                                                         *)
(* The seal cache (SealCache, W211): the isolate keeps the seals of the    *)
(* inputs' newest changes as a use read them, with the log's newest change *)
(* then (its number and MAC). A later use passes it; its statement reads   *)
(* the log's newest change and, if it is that one, skips the probes and    *)
(* the Worker holds the rows to the cached seals (a cover is then checked  *)
(* against the cached number). Otherwise it probes, and the isolate keeps  *)
(* what it read. One isolate, one cache: each cache entry is checked       *)
(* against the log on its own.                                             *)
(*                                                                         *)
(* A restore (MaxRestores): the database goes back to an earlier point, a  *)
(* backup's, its log, rows and sequence with it, while no call is in       *)
(* flight; the isolates keep their caches. Changes made after it take the  *)
(* numbers again. A change's MAC covers its request id, so two changes     *)
(* are never the same: here, each change has an id of its own (`made`).   *)
(*                                                                         *)
(* Covers (fewer rows): once an allowed use's entry #k has committed, the  *)
(* isolate passes k with the next uses of the same credential and secret.  *)
(* Under the same shared lock, the call writes nothing if no change was    *)
(* numbered after k: the use is a repeat of #k, which the log already has. *)
(* It still reads, and the Worker still decides on what it read. The       *)
(* first use after any change is a fresh entry.                            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Uses,            \* the uses, each one request, one call
    MaxChanges,      \* changes made in a behaviour: revoke, grant, revoke...
    MaxAborts,       \* change statements that fail after taking the lock
    MaxCheckpoints,  \* checkpoints signed in a behaviour
    MaxCrashes,      \* Postgres crashes in a behaviour
    Covers,          \* uses pass the isolate's cover
    Inputs,          \* the rows a decision reads: a subset of {"member", "credential", "secret", "environment"}
    SealCache,       \* the isolate keeps the seals a use read, and later uses may pass them
    MaxTampers,      \* rows a database writer puts back in a behaviour
    MaxRestores,     \* restores from a backup in a behaviour
    UseLocks, StatementSnapshot, UseNumberUnderLock, ChangeLocks, ChangeNumberUnderLock,
    LockToCommit, CommitBeforeAnswer, ReleaseAfterCommit, SyncCommit, CheckpointLocks, CoverChecksChanges,
    CoverChecksAllInputs, SealMember, SealCredential, SealSecret, SealEnvironment, StaleFirst, CacheChecked, CacheSameChange

None == "none"
Change == "change"
Checkpointer == "checkpointer"

VARIABLES
    log,       \* the committed entries; `durable` once flushed
    nextSeq,   \* the sequence's next value
    holder,    \* who holds the lock exclusive
    shared,    \* the uses holding it shared
    u,         \* each use's state
    c,         \* the change's state
    answered,  \* how many changes had committed when the last change answered
    released,  \* the uses whose value has left
    cp,        \* the checkpointer: whether it closed numbers it has not signed yet, and up to which
    signed,    \* the checkpoints signed: their floor and the numbers at or below it
    crashes,   \* Postgres crashes so far
    cover,     \* the isolate's cover: the number of the last allowed entry it wrote and saw commit, or 0
    repeats,   \* the values released on a cover: the use, its cover, what it saw, the changes answered
    tamper,    \* each input's row as a database writer put it back (`on`), else the row its newest change wrote
    tampers,   \* rows put back so far
    cache,     \* the isolate's seal cache: the seals a use read and the log's newest change then
    restores   \* restores so far

vars == <<log, nextSeq, holder, shared, u, c, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

(* What a statement sees. `Committed`, the number of changes committed, orders it against the   *)
(* changes (TotalOrder). Each input's row is what its newest committed change wrote, unless a     *)
(* database writer put back an earlier one; the seal of the input's newest change is read from    *)
(* the log in the same statement.                                                                 *)
ChangesIn(L) == {e \in L : e.kind = "change"}
Committed == Cardinality(ChangesIn(log))

\* An input's value as the newest change to it in L left it (all start allowing).
NewestIn(L, i) ==
    LET cs == {e \in ChangesIn(L) : e.input = i}
    IN IF cs = {} THEN TRUE ELSE (CHOOSE e \in cs : \A d \in cs : d.seq <= e.seq).value
Newest == [i \in Inputs |-> NewestIn(log, i)]
\* The log's newest change, as its number and MAC (here, its id) say it, or none.
NewestChange ==
    LET cs == ChangesIn(log)
    IN IF cs = {} THEN [seq |-> 0, made |-> 0]
       ELSE LET e == CHOOSE e \in cs : \A d \in cs : d.seq <= e.seq IN [seq |-> e.seq, made |-> e.made]
Rows == [i \in Inputs |-> IF tamper[i].on THEN tamper[i].value ELSE NewestIn(log, i)]

SealChecked(i) ==
    CASE i = "member" -> SealMember
      [] i = "credential" -> SealCredential
      [] i = "secret" -> SealSecret
      [] i = "environment" -> SealEnvironment

\* `decide`, on the rows a use read and the seals of their newest changes: `stale` when a checked
\* row is not its newest change's, then allowed only if every row allows. Without StaleFirst,
\* what the rows say is checked first, and a row put back that refuses shows as a plain refusal.
Stale(read, newest) == \E i \in Inputs : SealChecked(i) /\ read[i] /= newest[i]
Content(read) == \A i \in Inputs : read[i]
Code(read, newest) ==
    IF Stale(read, newest) /\ (StaleFirst \/ Content(read)) THEN "stale"
    ELSE IF Content(read) THEN "allow" ELSE "refused"

\* What the log says of entry number `seq`: every input as the changes numbered below it left it.
ReplayAllows(seq) == \A i \in Inputs : NewestIn({d \in log : d.seq < seq}, i)

\* A use's entry: its number, the changes it saw, its decision and code (ghosts), how many changes
\* had answered when it committed. A change's: its number, its input and the value it leaves. Both:
\* flushed yet.
UseEntry(seq, id, seen, allow, code, answeredAt, durable) ==
    [seq |-> seq, kind |-> "use", id |-> id, seen |-> seen, allow |-> allow, code |-> code, answeredAt |-> answeredAt,
     input |-> None, value |-> FALSE, made |-> 0, durable |-> durable]
ChangeEntry(seq, input, value, made, durable) ==
    [seq |-> seq, kind |-> "change", id |-> Change, seen |-> 0, allow |-> FALSE, code |-> None, answeredAt |-> 0,
     input |-> input, value |-> value, made |-> made, durable |-> durable]

AllTrue == [i \in Inputs |-> TRUE]

Init ==
    /\ log = {}
    /\ nextSeq = 1
    /\ holder = None
    /\ shared = {}
    /\ u = [x \in Uses |-> [pc |-> "idle", seq |-> 0, seen |-> 0, snap |-> 0, snapRows |-> AllTrue, snapNewest |-> AllTrue,
                            snapNewestChange |-> [seq |-> 0, made |-> 0], covered |-> 0, allow |-> FALSE, code |-> None,
                            probed |-> FALSE, newest |-> AllTrue, newestChange |-> [seq |-> 0, made |-> 0]]]
    /\ c = [pc |-> "idle", n |-> 0, seq |-> 0, aborts |-> 0, input |-> None, value |-> FALSE]
    /\ answered = 0
    /\ released = {}
    /\ cp = [open |-> FALSE, upto |-> 0]
    /\ signed = {}
    /\ crashes = 0
    /\ cover = 0
    /\ repeats = {}
    /\ tamper = [i \in Inputs |-> [on |-> FALSE, value |-> TRUE]]
    /\ tampers = 0
    /\ cache = [on |-> FALSE, seals |-> AllTrue, change |-> [seq |-> 0, made |-> 0]]
    /\ restores = 0

LockFree == holder = None /\ shared = {}

-----------------------------------------------------------------------------
(* A use: one call. *)

\* The call's outer statement starts, with its snapshot. Passed a number taken before (without
\* UseNumberUnderLock), it takes it now.
UseStart(x) ==
    /\ u[x].pc = "idle"
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "started", !.snap = Committed, !.snapRows = Rows, !.snapNewest = Newest, !.snapNewestChange = NewestChange,
                              !.seq = IF UseNumberUnderLock THEN 0 ELSE nextSeq]]
    /\ nextSeq' = IF UseNumberUnderLock THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<log, holder, shared, c, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* It gets the lock shared: no one holds it exclusive.
UseLock(x) ==
    /\ u[x].pc = "started"
    /\ UseLocks => holder = None
    /\ shared' = IF UseLocks THEN shared \cup {x} ELSE shared
    /\ u' = [u EXCEPT ![x].pc = "locked"]
    /\ UNCHANGED <<log, nextSeq, holder, c, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* The statement that reads and inserts: what it reads is the committed state now (a statement of
\* its own) or as of the call's start (a bare CTE). Its number, from the sequence, unless passed in.
\* Without LockToCommit the lock goes here, before the commit. Without ReleaseAfterCommit the value
\* leaves on what was read. With a cover that no change was numbered after, it writes nothing.
\* Without CoverChecksAllInputs, only changes to the member count (W208's first scope).
CoverHolds ==
    /\ cover /= 0
    /\ CoverChecksChanges => \A d \in ChangesIn(log) : (CoverChecksAllInputs \/ d.input = "member") => d.seq < cover

\* With the isolate's cache passed (a use may pass it or not), the probes are skipped if the log's
\* newest change is the cached one (without CacheSameChange: if its number is no higher; without
\* CacheChecked: always): the rows are held to the cached seals, and a cover to the cached number.
CacheHolds(newestChange) ==
    IF CacheSameChange THEN newestChange = cache.change ELSE newestChange.seq <= cache.change.seq

UseRun(x) ==
    /\ u[x].pc = "locked"
    /\ \E passed \in IF SealCache /\ cache.on THEN BOOLEAN ELSE {FALSE} :
       LET seen == IF StatementSnapshot THEN Committed ELSE u[x].snap
           read == IF StatementSnapshot THEN Rows ELSE u[x].snapRows
           probes == IF StatementSnapshot THEN Newest ELSE u[x].snapNewest
           newestChange == IF StatementSnapshot THEN NewestChange ELSE u[x].snapNewestChange
           skip == passed /\ (CacheChecked => CacheHolds(newestChange))
           newest == IF skip THEN cache.seals ELSE probes
           code == Code(read, newest)
           covered == Covers /\ (IF skip THEN cover /= 0 /\ cover > cache.change.seq ELSE CoverHolds)
       IN /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "ran", !.seen = seen, !.covered = IF covered THEN cover ELSE 0,
                                     !.allow = (code = "allow"), !.code = code,
                                     !.probed = ~skip, !.newest = newest, !.newestChange = newestChange,
                                     !.seq = IF UseNumberUnderLock /\ ~covered THEN nextSeq ELSE @]]
          /\ released' = IF ~ReleaseAfterCommit /\ code = "allow" THEN released \cup {x} ELSE released
          /\ nextSeq' = IF UseNumberUnderLock /\ ~covered THEN nextSeq + 1 ELSE nextSeq
    /\ shared' = IF LockToCommit THEN shared ELSE shared \ {x}
    /\ UNCHANGED <<log, holder, c, answered, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* The commit: the entry goes in, then the lock goes (Postgres makes a commit visible before it
\* releases the transaction's locks).
\* A covered use commits nothing, and is a repeat of its cover.
UseCommit(x) ==
    /\ u[x].pc = "ran"
    /\ IF u[x].covered = 0
       THEN /\ log' = log \cup {UseEntry(u[x].seq, x, u[x].seen, u[x].allow, u[x].code, answered, SyncCommit)}
            /\ UNCHANGED repeats
       ELSE /\ repeats' = repeats \cup {[id |-> x, cover |-> u[x].covered, seen |-> u[x].seen, allow |-> u[x].allow, answeredAt |-> answered]}
            /\ UNCHANGED log
    /\ shared' = shared \ {x}
    /\ u' = [u EXCEPT ![x].pc = "committed"]
    /\ UNCHANGED <<nextSeq, holder, c, answered, released, cp, signed, crashes, cover, tamper, tampers, cache, restores>>

\* The call fails before its commit (a lost connection, a deadline): rolled back, nothing written.
\* Its number is a gap.
UseFail(x) ==
    /\ u[x].pc = "ran"
    /\ shared' = shared \ {x}
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ UNCHANGED <<log, nextSeq, holder, c, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* The Worker decides on what it read: allowed, the value leaves. Or the Worker dies between the
\* commit and the answer: the log holds a request whose value never left, the safe side. An allowed
\* entry of its own becomes the isolate's cover; a refusal ends it. A use that probed leaves what it
\* read in the isolate's cache.
UseRelease(x) ==
    /\ u[x].pc = "committed"
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ released' = IF ReleaseAfterCommit /\ u[x].allow THEN released \cup {x} ELSE released
    /\ cover' = IF ~u[x].allow THEN 0 ELSE IF u[x].covered = 0 THEN u[x].seq ELSE cover
    /\ cache' = IF SealCache /\ u[x].probed THEN [on |-> TRUE, seals |-> u[x].newest, change |-> u[x].newestChange] ELSE cache
    /\ UNCHANGED <<log, nextSeq, holder, shared, c, answered, cp, signed, crashes, repeats, tamper, tampers, restores>>

UseCrash(x) ==
    /\ u[x].pc = "committed"
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ UNCHANGED <<log, nextSeq, holder, shared, c, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

-----------------------------------------------------------------------------
(* A change: one input revoked, or restored. *)

\* The call starts, for one input. Without ChangeNumberUnderLock, its number was taken by a read
\* before it.
ChangeStart ==
    /\ c.pc = "idle"
    /\ c.n < MaxChanges
    /\ \E i \in Inputs : c' = [c EXCEPT !.pc = "started", !.input = i, !.seq = IF ChangeNumberUnderLock THEN 0 ELSE nextSeq]
    /\ nextSeq' = IF ChangeNumberUnderLock THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<log, holder, shared, u, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* It gets the lock exclusive: no one holds it at all.
ChangeLock ==
    /\ c.pc = "started"
    /\ ChangeLocks => LockFree
    /\ holder' = IF ChangeLocks THEN Change ELSE holder
    /\ c' = [c EXCEPT !.pc = "locked"]
    /\ UNCHANGED <<log, nextSeq, shared, u, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* Its statement: the write (the input flipped from what its newest change left), and its entry's
\* number. Without LockToCommit the lock goes here; without CommitBeforeAnswer it answers here.
ChangeRun ==
    /\ c.pc = "locked"
    /\ c' = [c EXCEPT !.pc = "ran", !.value = ~NewestIn(log, c.input), !.seq = IF ChangeNumberUnderLock THEN nextSeq ELSE @]
    /\ nextSeq' = IF ChangeNumberUnderLock THEN nextSeq + 1 ELSE nextSeq
    /\ holder' = IF LockToCommit THEN holder ELSE None
    /\ answered' = IF CommitBeforeAnswer THEN answered ELSE Committed + 1
    /\ UNCHANGED <<log, shared, u, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* The commit: its entry, and the row it wrote, in place of whatever was there.
ChangeCommit ==
    /\ c.pc = "ran"
    /\ log' = log \cup {ChangeEntry(c.seq, c.input, c.value, c.n + 1, SyncCommit)}
    /\ holder' = IF holder = Change THEN None ELSE holder
    /\ c' = [c EXCEPT !.pc = "committed"]
    /\ tamper' = [tamper EXCEPT ![c.input] = [on |-> FALSE, value |-> TRUE]]
    /\ UNCHANGED <<nextSeq, shared, u, answered, released, cp, signed, crashes, cover, repeats, tampers, cache, restores>>

\* Its statement fails instead (a deadline, a lost connection): rolled back, the lock let go; it
\* starts over. Its number is a gap.
ChangeAbort ==
    /\ c.pc = "ran"
    /\ c.aborts < MaxAborts
    /\ holder' = IF holder = Change THEN None ELSE holder
    /\ c' = [c EXCEPT !.pc = "idle", !.aborts = @ + 1]
    /\ UNCHANGED <<log, nextSeq, shared, u, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

ChangeAnswer ==
    /\ c.pc = "committed"
    /\ answered' = IF answered > Committed THEN answered ELSE Committed
    /\ c' = [c EXCEPT !.pc = "idle", !.n = @ + 1]
    /\ UNCHANGED <<log, nextSeq, holder, shared, u, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

-----------------------------------------------------------------------------
(* The checkpointer. *)

\* Under the lock exclusive, for one statement: every number handed out so far is closed. No lag:
\* with every number taken under the lock, none is still in flight.
CheckpointClose ==
    /\ ~cp.open
    /\ Cardinality(signed) < MaxCheckpoints
    /\ CheckpointLocks => LockFree
    /\ cp' = [open |-> TRUE, upto |-> nextSeq - 1]
    /\ UNCHANGED <<log, nextSeq, holder, shared, u, c, answered, released, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* Later, outside any lock: it reads the entries at or below its floor, and signs their numbers.
CheckpointSign ==
    /\ cp.open
    /\ signed' = signed \cup {[upto |-> cp.upto, seqs |-> {e.seq : e \in {d \in log : d.seq <= cp.upto}}]}
    /\ cp' = [cp EXCEPT !.open = FALSE]
    /\ UNCHANGED <<log, nextSeq, holder, shared, u, c, answered, released, crashes, cover, repeats, tamper, tampers, cache, restores>>

-----------------------------------------------------------------------------
(* Postgres: the WAL flushed; a crash. *)

\* Without SyncCommit, commits are flushed later, all at once (the WAL is flushed in order).
Flush ==
    /\ \E e \in log : ~e.durable
    /\ log' = {[e EXCEPT !.durable = TRUE] : e \in log}
    /\ UNCHANGED <<nextSeq, holder, shared, u, c, answered, released, cp, signed, crashes, cover, repeats, tamper, tampers, cache, restores>>

\* Postgres crashes and restarts: what was not flushed is gone, every statement in flight is
\* rolled back, every lock let go. The sequence never goes back below a flushed number.
Crash ==
    /\ crashes < MaxCrashes
    /\ crashes' = crashes + 1
    /\ log' = {e \in log : e.durable}
    /\ holder' = None
    /\ shared' = {}
    /\ u' = [x \in Uses |-> IF u[x].pc \in {"started", "locked", "ran"} THEN [u[x] EXCEPT !.pc = "done"] ELSE u[x]]
    /\ c' = IF c.pc \in {"started", "locked", "ran"} THEN [c EXCEPT !.pc = "idle"] ELSE c
    /\ UNCHANGED <<nextSeq, answered, released, cp, signed, cover, repeats, tamper, tampers, cache, restores>>

-----------------------------------------------------------------------------
(* A database writer with no key: it puts back a row of an input as the vault once sealed it, *)
(* the first one or one an earlier change wrote. Outside any lock.                           *)

Tamper ==
    /\ tampers < MaxTampers
    /\ \E i \in Inputs :
          \E v \in {TRUE} \cup {e.value : e \in {d \in ChangesIn(log) : d.input = i}} :
             tamper' = [tamper EXCEPT ![i] = [on |-> TRUE, value |-> v]]
    /\ tampers' = tampers + 1
    /\ UNCHANGED <<log, nextSeq, holder, shared, u, c, answered, released, cp, signed, crashes, cover, repeats, cache, restores>>

\* A restore from a backup, while no call is in flight: the log back to an earlier point, the rows
\* and the sequence with it. What changes had answered is now what the restored log holds.
Restore ==
    /\ restores < MaxRestores
    /\ \A x \in Uses : u[x].pc \in {"idle", "done"}
    /\ c.pc = "idle"
    /\ ~cp.open
    /\ \E k \in 0..(nextSeq - 1) :
          /\ log' = {e \in log : e.seq <= k}
          /\ nextSeq' = k + 1
          /\ answered' = Cardinality(ChangesIn({e \in log : e.seq <= k}))
    /\ tamper' = [i \in Inputs |-> [on |-> FALSE, value |-> TRUE]]
    /\ restores' = restores + 1
    /\ UNCHANGED <<holder, shared, u, c, released, cp, signed, crashes, cover, repeats, tampers, cache>>

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Uses : UseStart(x) \/ UseLock(x) \/ UseRun(x) \/ UseCommit(x) \/ UseFail(x) \/ UseRelease(x) \/ UseCrash(x)
    \/ ChangeStart \/ ChangeLock \/ ChangeRun \/ ChangeCommit \/ ChangeAbort \/ ChangeAnswer
    \/ CheckpointClose \/ CheckpointSign
    \/ Flush \/ Crash \/ Tamper \/ Restore

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold. *)

\* The number alone orders uses against changes: every use saw exactly the changes numbered
\* before it. No revision needed.
TotalOrder ==
    \A e \in log : e.kind = "use" => e.seen = Cardinality({d \in ChangesIn(log) : d.seq < e.seq})

\* The outcome is not stored: it is recomputed from the log, and the recomputation is what the
\* Worker decided. (With no database writer.)
ReplayAgrees ==
    \A e \in log : e.kind = "use" => e.allow = ReplayAllows(e.seq)

\* With a database writer: nothing is allowed that the log refuses...
ReplaySound ==
    \A e \in log : (e.kind = "use" /\ e.allow) => ReplayAllows(e.seq)

\* ...and a use refused where the log allows was refused for a row put back, and says so.
TamperVisible ==
    \A e \in log : (e.kind = "use" /\ ~e.allow /\ ReplayAllows(e.seq)) => e.code = "stale"

\* "Revoke returned => the next use is refused", in its strongest form: no use allowed on a state
\* from before a change commits after that change has answered.
NothingAllowedAfterAnswer ==
    \A e \in log : (e.kind = "use" /\ e.allow) => e.answeredAt <= e.seen

\* A value leaves only once its entry is in the log, flushed: its own, or its cover's.
Logged(seq, x) == \E e \in log : e.kind = "use" /\ e.seq = seq /\ e.allow /\ e.durable /\ (x = None \/ e.id = x)
DurableBeforeRelease ==
    \A x \in released : (\E e \in log : e.kind = "use" /\ e.id = x /\ e.allow /\ e.durable)
                        \/ (\E r \in repeats : r.id = x /\ r.allow /\ Logged(r.cover, None))

\* A repeat is its cover again: allowed on the state its cover was decided on (no change to any of
\* its inputs numbered after the cover), and after no change it did not see had answered. So the
\* log, which has only the cover, says the truth about it: a use after a change is never a repeat of
\* one before.
RepeatsAreTheirCover ==
    \A r \in repeats : r.allow =>
        /\ Logged(r.cover, None)
        /\ r.seen = Cardinality({d \in ChangesIn(log) : d.seq < r.cover})
        /\ r.answeredAt <= r.seen

\* What a checkpoint signed stays exactly the entries at or below its floor: none commits there later.
CheckpointsHold ==
    \A k \in signed : {e.seq : e \in {d \in log : d.seq <= k.upto}} = k.seqs

NumbersUnique ==
    \A d, e \in log : d.seq = e.seq => d = e

=============================================================================
