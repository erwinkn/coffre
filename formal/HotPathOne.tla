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
(* A change (a grant taken or given) is one call too: the lock exclusive,  *)
(* the write, its entry numbered from the same sequence, the commit; then  *)
(* it answers. A checkpointer takes the lock exclusive for one statement   *)
(* to close every number handed out so far, then signs the entries at or  *)
(* below it.                                                               *)
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
(*                         if no change was numbered after its cover.      *)
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
    UseLocks, StatementSnapshot, UseNumberUnderLock, ChangeLocks, ChangeNumberUnderLock,
    LockToCommit, CommitBeforeAnswer, ReleaseAfterCommit, SyncCommit, CheckpointLocks, CoverChecksChanges

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
    repeats    \* the values released on a cover: the use, its cover, what it saw, the changes answered

vars == <<log, nextSeq, holder, shared, u, c, answered, released, cp, signed, crashes, cover, repeats>>

(* The committed state a statement sees. The principal starts granted; each change flips it   *)
(* (revoke, grant, revoke...), so the state is the number of changes committed. It stands for  *)
(* every input a decision reads (members, grants, places, secrets, credentials), each written  *)
(* only by a change.                                                                          *)
ChangesIn(L) == {e \in L : e.kind = "change"}
Committed == Cardinality(ChangesIn(log))
Allows(n) == n % 2 = 0

\* A use's entry: its number, what its decision saw (changes committed), allowed or not, and how many
\* changes had answered when it committed. A change's: its number. Both: flushed yet.
UseEntry(seq, id, seen, answeredAt, durable) ==
    [seq |-> seq, kind |-> "use", id |-> id, seen |-> seen, allow |-> Allows(seen), answeredAt |-> answeredAt, durable |-> durable]
ChangeEntry(seq, durable) ==
    [seq |-> seq, kind |-> "change", id |-> Change, seen |-> 0, allow |-> FALSE, answeredAt |-> 0, durable |-> durable]

Init ==
    /\ log = {}
    /\ nextSeq = 1
    /\ holder = None
    /\ shared = {}
    /\ u = [x \in Uses |-> [pc |-> "idle", seq |-> 0, seen |-> 0, snap |-> 0, covered |-> 0]]
    /\ c = [pc |-> "idle", n |-> 0, seq |-> 0, aborts |-> 0]
    /\ answered = 0
    /\ released = {}
    /\ cp = [open |-> FALSE, upto |-> 0]
    /\ signed = {}
    /\ crashes = 0
    /\ cover = 0
    /\ repeats = {}

LockFree == holder = None /\ shared = {}

-----------------------------------------------------------------------------
(* A use: one call. *)

\* The call's outer statement starts, with its snapshot. Passed a number taken before (without
\* UseNumberUnderLock), it takes it now.
UseStart(x) ==
    /\ u[x].pc = "idle"
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "started", !.snap = Committed,
                              !.seq = IF UseNumberUnderLock THEN 0 ELSE nextSeq]]
    /\ nextSeq' = IF UseNumberUnderLock THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<log, holder, shared, c, answered, released, cp, signed, crashes, cover, repeats>>

\* It gets the lock shared: no one holds it exclusive.
UseLock(x) ==
    /\ u[x].pc = "started"
    /\ UseLocks => holder = None
    /\ shared' = IF UseLocks THEN shared \cup {x} ELSE shared
    /\ u' = [u EXCEPT ![x].pc = "locked"]
    /\ UNCHANGED <<log, nextSeq, holder, c, answered, released, cp, signed, crashes, cover, repeats>>

\* The statement that reads and inserts: what it reads is the committed state now (a statement of
\* its own) or as of the call's start (a bare CTE). Its number, from the sequence, unless passed in.
\* Without LockToCommit the lock goes here, before the commit. Without ReleaseAfterCommit the value
\* leaves on what was read. With a cover that no change was numbered after, it writes nothing.
CoverHolds == cover /= 0 /\ (CoverChecksChanges => \A d \in ChangesIn(log) : d.seq < cover)

UseRun(x) ==
    /\ u[x].pc = "locked"
    /\ LET seen == IF StatementSnapshot THEN Committed ELSE u[x].snap
           covered == Covers /\ CoverHolds
       IN /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "ran", !.seen = seen, !.covered = IF covered THEN cover ELSE 0,
                                     !.seq = IF UseNumberUnderLock /\ ~covered THEN nextSeq ELSE @]]
          /\ released' = IF ~ReleaseAfterCommit /\ Allows(seen) THEN released \cup {x} ELSE released
          /\ nextSeq' = IF UseNumberUnderLock /\ ~covered THEN nextSeq + 1 ELSE nextSeq
    /\ shared' = IF LockToCommit THEN shared ELSE shared \ {x}
    /\ UNCHANGED <<log, holder, c, answered, cp, signed, crashes, cover, repeats>>

\* The commit: the entry goes in, then the lock goes (Postgres makes a commit visible before it
\* releases the transaction's locks).
\* A covered use commits nothing, and is a repeat of its cover.
UseCommit(x) ==
    /\ u[x].pc = "ran"
    /\ IF u[x].covered = 0
       THEN /\ log' = log \cup {UseEntry(u[x].seq, x, u[x].seen, answered, SyncCommit)}
            /\ UNCHANGED repeats
       ELSE /\ repeats' = repeats \cup {[id |-> x, cover |-> u[x].covered, seen |-> u[x].seen, answeredAt |-> answered]}
            /\ UNCHANGED log
    /\ shared' = shared \ {x}
    /\ u' = [u EXCEPT ![x].pc = "committed"]
    /\ UNCHANGED <<nextSeq, holder, c, answered, released, cp, signed, crashes, cover>>

\* The call fails before its commit (a lost connection, a deadline): rolled back, nothing written.
\* Its number is a gap.
UseFail(x) ==
    /\ u[x].pc = "ran"
    /\ shared' = shared \ {x}
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ UNCHANGED <<log, nextSeq, holder, c, answered, released, cp, signed, crashes, cover, repeats>>

\* The Worker decides on what it read: allowed, the value leaves. Or the Worker dies between the
\* commit and the answer: the log holds a request whose value never left, the safe side. An allowed
\* entry of its own becomes the isolate's cover; a refusal ends it.
UseRelease(x) ==
    /\ u[x].pc = "committed"
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ released' = IF ReleaseAfterCommit /\ Allows(u[x].seen) THEN released \cup {x} ELSE released
    /\ cover' = IF ~Allows(u[x].seen) THEN 0 ELSE IF u[x].covered = 0 THEN u[x].seq ELSE cover
    /\ UNCHANGED <<log, nextSeq, holder, shared, c, answered, cp, signed, crashes, repeats>>

UseCrash(x) ==
    /\ u[x].pc = "committed"
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ UNCHANGED <<log, nextSeq, holder, shared, c, answered, released, cp, signed, crashes, cover, repeats>>

-----------------------------------------------------------------------------
(* A change: revoke, grant, revoke... *)

\* The call starts. Without ChangeNumberUnderLock, its number was taken by a read before it.
ChangeStart ==
    /\ c.pc = "idle"
    /\ c.n < MaxChanges
    /\ c' = [c EXCEPT !.pc = "started", !.seq = IF ChangeNumberUnderLock THEN 0 ELSE nextSeq]
    /\ nextSeq' = IF ChangeNumberUnderLock THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<log, holder, shared, u, answered, released, cp, signed, crashes, cover, repeats>>

\* It gets the lock exclusive: no one holds it at all.
ChangeLock ==
    /\ c.pc = "started"
    /\ ChangeLocks => LockFree
    /\ holder' = IF ChangeLocks THEN Change ELSE holder
    /\ c' = [c EXCEPT !.pc = "locked"]
    /\ UNCHANGED <<log, nextSeq, shared, u, answered, released, cp, signed, crashes, cover, repeats>>

\* Its statement: the write, and its entry's number. Without LockToCommit the lock goes here;
\* without CommitBeforeAnswer it answers here.
ChangeRun ==
    /\ c.pc = "locked"
    /\ c' = [c EXCEPT !.pc = "ran", !.seq = IF ChangeNumberUnderLock THEN nextSeq ELSE @]
    /\ nextSeq' = IF ChangeNumberUnderLock THEN nextSeq + 1 ELSE nextSeq
    /\ holder' = IF LockToCommit THEN holder ELSE None
    /\ answered' = IF CommitBeforeAnswer THEN answered ELSE Committed + 1
    /\ UNCHANGED <<log, shared, u, released, cp, signed, crashes, cover, repeats>>

ChangeCommit ==
    /\ c.pc = "ran"
    /\ log' = log \cup {ChangeEntry(c.seq, SyncCommit)}
    /\ holder' = IF holder = Change THEN None ELSE holder
    /\ c' = [c EXCEPT !.pc = "committed"]
    /\ UNCHANGED <<nextSeq, shared, u, answered, released, cp, signed, crashes, cover, repeats>>

\* Its statement fails instead (a deadline, a lost connection): rolled back, the lock let go; it
\* starts over. Its number is a gap.
ChangeAbort ==
    /\ c.pc = "ran"
    /\ c.aborts < MaxAborts
    /\ holder' = IF holder = Change THEN None ELSE holder
    /\ c' = [c EXCEPT !.pc = "idle", !.aborts = @ + 1]
    /\ UNCHANGED <<log, nextSeq, shared, u, answered, released, cp, signed, crashes, cover, repeats>>

ChangeAnswer ==
    /\ c.pc = "committed"
    /\ answered' = IF answered > Committed THEN answered ELSE Committed
    /\ c' = [c EXCEPT !.pc = "idle", !.n = @ + 1]
    /\ UNCHANGED <<log, nextSeq, holder, shared, u, released, cp, signed, crashes, cover, repeats>>

-----------------------------------------------------------------------------
(* The checkpointer. *)

\* Under the lock exclusive, for one statement: every number handed out so far is closed. No lag:
\* with every number taken under the lock, none is still in flight.
CheckpointClose ==
    /\ ~cp.open
    /\ Cardinality(signed) < MaxCheckpoints
    /\ CheckpointLocks => LockFree
    /\ cp' = [open |-> TRUE, upto |-> nextSeq - 1]
    /\ UNCHANGED <<log, nextSeq, holder, shared, u, c, answered, released, signed, crashes, cover, repeats>>

\* Later, outside any lock: it reads the entries at or below its floor, and signs their numbers.
CheckpointSign ==
    /\ cp.open
    /\ signed' = signed \cup {[upto |-> cp.upto, seqs |-> {e.seq : e \in {d \in log : d.seq <= cp.upto}}]}
    /\ cp' = [cp EXCEPT !.open = FALSE]
    /\ UNCHANGED <<log, nextSeq, holder, shared, u, c, answered, released, crashes, cover, repeats>>

-----------------------------------------------------------------------------
(* Postgres: the WAL flushed; a crash. *)

\* Without SyncCommit, commits are flushed later, all at once (the WAL is flushed in order).
Flush ==
    /\ \E e \in log : ~e.durable
    /\ log' = {[e EXCEPT !.durable = TRUE] : e \in log}
    /\ UNCHANGED <<nextSeq, holder, shared, u, c, answered, released, cp, signed, crashes, cover, repeats>>

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
    /\ UNCHANGED <<nextSeq, answered, released, cp, signed, cover, repeats>>

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Uses : UseStart(x) \/ UseLock(x) \/ UseRun(x) \/ UseCommit(x) \/ UseFail(x) \/ UseRelease(x) \/ UseCrash(x)
    \/ ChangeStart \/ ChangeLock \/ ChangeRun \/ ChangeCommit \/ ChangeAbort \/ ChangeAnswer
    \/ CheckpointClose \/ CheckpointSign
    \/ Flush \/ Crash

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold. *)

\* The number alone orders uses against changes: every use saw exactly the changes numbered
\* before it. No revision needed.
TotalOrder ==
    \A e \in log : e.kind = "use" => e.seen = Cardinality({d \in ChangesIn(log) : d.seq < e.seq})

\* The outcome is not stored: it is recomputed from the log, and the recomputation is what the
\* Worker decided.
ReplayAgrees ==
    \A e \in log : e.kind = "use" => e.allow = Allows(Cardinality({d \in ChangesIn(log) : d.seq < e.seq}))

\* "Revoke returned => the next use is refused", in its strongest form: no use allowed on a state
\* from before a change commits after that change has answered.
NothingAllowedAfterAnswer ==
    \A e \in log : (e.kind = "use" /\ e.allow) => e.answeredAt <= e.seen

\* A value leaves only once its entry is in the log, flushed: its own, or its cover's.
Logged(seq, x) == \E e \in log : e.kind = "use" /\ e.seq = seq /\ e.allow /\ e.durable /\ (x = None \/ e.id = x)
DurableBeforeRelease ==
    \A x \in released : (\E e \in log : e.kind = "use" /\ e.id = x /\ e.allow /\ e.durable)
                        \/ (\E r \in repeats : r.id = x /\ Allows(r.seen) /\ Logged(r.cover, None))

\* A repeat is its cover again: allowed on the state its cover was decided on (no change numbered
\* after the cover), and after no change it did not see had answered. So the log, which has only the
\* cover, says the truth about it: a use after a change is never a repeat of one before.
RepeatsAreTheirCover ==
    \A r \in repeats : Allows(r.seen) =>
        /\ Logged(r.cover, None)
        /\ r.seen = Cardinality({d \in ChangesIn(log) : d.seq < r.cover})
        /\ r.answeredAt <= r.seen

\* What a checkpoint signed stays exactly the entries at or below its floor: none commits there later.
CheckpointsHold ==
    \A k \in signed : {e.seq : e \in {d \in log : d.seq <= k.upto}} = k.seqs

NumbersUnique ==
    \A d, e \in log : d.seq = e.seq => d = e

=============================================================================
