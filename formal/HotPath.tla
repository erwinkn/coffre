------------------------------ MODULE HotPath ------------------------------
(***************************************************************************)
(* 0.15's simple hot path (W201, experiments/lanes/src/simple.ts): uses    *)
(* and changes on one Postgres, under READ COMMITTED, with no lock held    *)
(* across a round trip.                                                    *)
(*                                                                         *)
(* A use is two statements, each its own transaction (autocommit):         *)
(*   the read    the principal's standing and the revision, one snapshot;  *)
(*               in `seq` mode it also takes the entry's number from a     *)
(*               sequence;                                                 *)
(*   the append  takes a lock, checks the fence (the revision the read     *)
(*               decided at is still the committed one; `seq`: and no      *)
(*               checkpoint has closed its number), inserts the entry and  *)
(*               commits. The value leaves only after that commit.         *)
(* A change (a grant taken or given) reads the revision, then in one       *)
(* statement takes the lock exclusively, checks the revision did not move, *)
(* writes, raises the revision and commits; then it answers.               *)
(*                                                                         *)
(* Mode "head": the lock is the head row's (FOR UPDATE), which uses and    *)
(* changes alike take, one at a time, for one statement; the entry's       *)
(* number is the head's. Mode "seq": uses share an advisory lock that a    *)
(* change or a checkpoint takes exclusively; the number comes from the     *)
(* sequence, in the read, and a checkpoint closes the numbers below a      *)
(* floor before it signs the entries under it.                             *)
(*                                                                         *)
(* A statement is several steps here where something else can come        *)
(* between them in Postgres: the append takes its snapshot when it starts, *)
(* then waits for its lock, then checks, then commits.                     *)
(*                                                                         *)
(* The protections, each a constant, so that TLC can show each necessary   *)
(* (scripts/formal-hotpath.sh):                                            *)
(*   FenceChecked        the append checks the revision at all;            *)
(*   FenceUnderLock      it checks the revision as committed once it holds *)
(*                       its lock, not as its statement's snapshot had it  *)
(*                       before the wait: "head" keeps the revision in the *)
(*                       head row, which a lock re-reads; "seq" checks in  *)
(*                       a statement after the lock's. The brief's literal *)
(*                       SQL, `WHERE (SELECT n FROM revision) = $rev` in   *)
(*                       the append that locks the head, has it FALSE;     *)
(*   ChangeLocks         a change takes the lock exclusively;              *)
(*   CommitBeforeAnswer  a change answers only once committed;             *)
(*   ReleaseAfterCommit  a use's value leaves only once its entry has      *)
(*                       committed;                                        *)
(*   CheckpointLocks     ("seq") a checkpoint raises its floor under the   *)
(*                       exclusive lock;                                   *)
(*   FloorChecked        ("seq") an append refuses a number at or below    *)
(*                       the floor.                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Uses,           \* the uses, each one request, retried once if its fence fails
    MaxChanges,     \* changes made in a behaviour: revoke, grant, revoke...
    MaxCheckpoints, \* checkpoints signed in a behaviour ("seq")
    MaxAborts,      \* change statements that fail after taking the lock
    Mode,           \* "head" or "seq"
    FenceChecked, FenceUnderLock, ChangeLocks, CommitBeforeAnswer, ReleaseAfterCommit,
    CheckpointLocks, FloorChecked

ASSUME Mode \in {"head", "seq"}

None == "none"
Change == "change"
Checkpointer == "checkpointer"

VARIABLES
    revision,  \* the committed revision: changes made so far
    granted,   \* the committed grant: may the principal use the secret
    log,       \* the committed entries
    nextSeq,   \* "head": the head's next number; "seq": the sequence's next value
    floor,     \* "seq": the highest number a checkpoint has closed
    seen,      \* "seq": the sequence's last value when the last checkpoint closed
    signed,    \* the checkpoints signed: the floor, and the entries at or below it
    cp,        \* the checkpointer: whether it closed a floor whose entries it has not read yet, and that floor
    holder,    \* who holds the lock exclusively: the head row's, or "seq"'s advisory lock
    shared,    \* "seq": the uses holding the advisory lock shared
    u,         \* each use's state
    c,         \* the change's state
    answered,  \* the highest revision a change has answered at
    released   \* the uses whose value has left, with the revision they decided at

vars == <<revision, granted, log, nextSeq, floor, seen, signed, cp, holder, shared, u, c, answered, released>>

\* An entry: its number, its revision, a use's or a change's, allowed or not; for a use, the revision
\* committed and the highest answered when it committed.
Entry(seq, rev, kind, id, allow, atCommit, answeredAt) ==
    [seq |-> seq, rev |-> rev, kind |-> kind, id |-> id, allow |-> allow, atCommit |-> atCommit, answeredAt |-> answeredAt]

Init ==
    /\ revision = 0
    /\ granted = TRUE
    /\ log = {}
    /\ nextSeq = 1
    /\ floor = 0
    /\ seen = 0
    /\ signed = {}
    /\ cp = [open |-> FALSE, upto |-> 0]
    /\ holder = None
    /\ shared = {}
    /\ u = [x \in Uses |-> [pc |-> "idle", tries |-> 0, rev |-> 0, allow |-> FALSE, seq |-> 0, snapRev |-> 0, snapFloor |-> 0, ok |-> FALSE]]
    /\ c = [pc |-> "idle", n |-> 0, from |-> 0, seq |-> 0, aborts |-> 0]
    /\ answered = 0
    /\ released = {}

LockFree(x) ==
    IF Mode = "head" THEN holder = None ELSE holder = None /\ shared = {}

-----------------------------------------------------------------------------
(* A use. *)

\* The read: standing and revision in one snapshot; "seq" takes the entry's number.
UseRead(x) ==
    /\ u[x].pc = "idle"
    /\ u[x].tries < 2
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "read", !.tries = @ + 1, !.rev = revision, !.allow = granted,
                              !.seq = IF Mode = "seq" THEN nextSeq ELSE 0]]
    /\ nextSeq' = IF Mode = "seq" THEN nextSeq + 1 ELSE nextSeq
    /\ released' = IF ~ReleaseAfterCommit /\ granted THEN released \cup {[id |-> x, rev |-> revision]} ELSE released
    /\ UNCHANGED <<revision, granted, log, floor, seen, signed, cp, holder, shared, c, answered>>

\* The append's statement starts: its snapshot.
UseStart(x) ==
    /\ u[x].pc = "read"
    /\ u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "waiting", !.snapRev = revision, !.snapFloor = floor]]
    /\ UNCHANGED <<revision, granted, log, nextSeq, floor, seen, signed, cp, holder, shared, c, answered, released>>

\* It gets its lock: the head row alone, or the advisory lock shared.
UseLock(x) ==
    /\ u[x].pc = "waiting"
    /\ holder = None
    /\ IF Mode = "head" THEN holder' = x /\ UNCHANGED shared ELSE shared' = shared \cup {x} /\ UNCHANGED holder
    /\ u' = [u EXCEPT ![x].pc = "locked"]
    /\ UNCHANGED <<revision, granted, log, nextSeq, floor, seen, signed, cp, c, answered, released>>

\* The fence, under the lock.
UseCheck(x) ==
    /\ u[x].pc = "locked"
    /\ LET rev == IF FenceUnderLock THEN revision ELSE u[x].snapRev
           fl == IF FenceUnderLock THEN floor ELSE u[x].snapFloor
       IN u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "checked",
                                  !.ok = /\ (FenceChecked => rev = u[x].rev)
                                         /\ (Mode = "seq" /\ FloorChecked => fl < u[x].seq)]]
    /\ UNCHANGED <<revision, granted, log, nextSeq, floor, seen, signed, cp, holder, shared, c, answered, released>>

\* The commit, which lets the lock go; "head" numbers the entry here. A failed fence wrote nothing:
\* the use reads again, once.
UseCommit(x) ==
    /\ u[x].pc = "checked"
    /\ IF u[x].ok
       THEN LET seq == IF Mode = "head" THEN nextSeq ELSE u[x].seq
            IN /\ log' = log \cup {Entry(seq, u[x].rev, "use", x, u[x].allow, revision, answered)}
               /\ nextSeq' = IF Mode = "head" THEN nextSeq + 1 ELSE nextSeq
               /\ u' = [u EXCEPT ![x].pc = "committed"]
       ELSE /\ u' = [u EXCEPT ![x].pc = "idle"]
            /\ UNCHANGED <<log, nextSeq>>
    /\ IF Mode = "head" THEN holder' = None /\ UNCHANGED shared ELSE shared' = shared \ {x} /\ UNCHANGED holder
    /\ UNCHANGED <<revision, granted, floor, seen, signed, cp, c, answered, released>>

\* The value leaves, if allowed.
UseRelease(x) ==
    /\ u[x].pc = "committed"
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ released' = IF u[x].allow /\ ReleaseAfterCommit THEN released \cup {[id |-> x, rev |-> u[x].rev]} ELSE released
    /\ UNCHANGED <<revision, granted, log, nextSeq, floor, seen, signed, cp, holder, shared, c, answered>>

-----------------------------------------------------------------------------
(* A change: revoke, grant, revoke... *)

\* It reads the revision; "seq" takes its entry's number.
ChangeRead ==
    /\ c.pc = "idle"
    /\ c.n < MaxChanges
    /\ c' = [c EXCEPT !.pc = "read", !.from = revision, !.seq = IF Mode = "seq" THEN nextSeq ELSE 0]
    /\ nextSeq' = IF Mode = "seq" THEN nextSeq + 1 ELSE nextSeq
    /\ UNCHANGED <<revision, granted, log, floor, seen, signed, cp, holder, shared, u, answered, released>>

\* Its one statement takes the lock exclusively (or, without ChangeLocks, none).
ChangeLock ==
    /\ c.pc = "read"
    /\ ChangeLocks => LockFree(Change)
    /\ holder' = IF ChangeLocks THEN Change ELSE holder
    /\ c' = [c EXCEPT !.pc = "locked"]
    \* Without CommitBeforeAnswer, the change answers once it holds the lock.
    /\ answered' = IF CommitBeforeAnswer THEN answered ELSE c.from + 1
    /\ UNCHANGED <<revision, granted, log, nextSeq, floor, seen, signed, cp, shared, u, released>>

\* Under it, the revision has not moved (and, "seq", its number is above the floor): the grant flips,
\* the revision rises, its entry goes in, all committed together. Otherwise nothing, and it reads again.
ChangeCommit ==
    /\ c.pc = "locked"
    /\ holder' = IF ChangeLocks THEN None ELSE holder
    /\ IF revision = c.from /\ (Mode = "seq" => floor < c.seq)
       THEN /\ revision' = revision + 1
            /\ granted' = ~granted
            /\ log' = log \cup {Entry(IF Mode = "head" THEN nextSeq ELSE c.seq, revision + 1, "change", Change, TRUE, revision + 1, answered)}
            /\ nextSeq' = IF Mode = "head" THEN nextSeq + 1 ELSE nextSeq
            /\ c' = [c EXCEPT !.pc = "committed"]
       ELSE /\ c' = [c EXCEPT !.pc = "idle"]
            /\ UNCHANGED <<revision, granted, log, nextSeq>>
    /\ UNCHANGED <<floor, seen, signed, cp, shared, u, answered, released>>

\* Its statement fails instead (a deadline, a lost connection): rolled back, the lock let go; it
\* starts over.
ChangeAbort ==
    /\ c.pc = "locked"
    /\ c.aborts < MaxAborts
    /\ holder' = IF ChangeLocks THEN None ELSE holder
    /\ c' = [c EXCEPT !.pc = "idle", !.aborts = @ + 1]
    /\ UNCHANGED <<revision, granted, log, nextSeq, floor, seen, signed, cp, shared, u, answered, released>>

ChangeAnswer ==
    /\ c.pc = "committed"
    /\ answered' = IF answered > revision THEN answered ELSE revision
    /\ c' = [c EXCEPT !.pc = "idle", !.n = @ + 1]
    /\ UNCHANGED <<revision, granted, log, nextSeq, floor, seen, signed, cp, holder, shared, u, released>>

-----------------------------------------------------------------------------
(* "seq": the checkpointer. *)

\* Under the exclusive lock, in one statement: the floor rises to what the last tick saw of the
\* sequence, and this tick notes the sequence's value now.
CheckpointClose ==
    /\ Mode = "seq"
    /\ ~cp.open
    /\ Cardinality(signed) < MaxCheckpoints
    /\ CheckpointLocks => LockFree(Checkpointer)
    /\ floor' = IF seen > floor THEN seen ELSE floor
    /\ seen' = nextSeq - 1
    /\ cp' = [open |-> TRUE, upto |-> IF seen > floor THEN seen ELSE floor]
    /\ UNCHANGED <<revision, granted, log, nextSeq, signed, holder, shared, u, c, answered, released>>

\* Later, outside any lock: it reads the entries at or below the floor, and signs them.
CheckpointSign ==
    /\ cp.open
    /\ signed' = signed \cup {[upto |-> cp.upto, entries |-> {e \in log : e.seq <= cp.upto}]}
    /\ cp' = [cp EXCEPT !.open = FALSE]
    /\ UNCHANGED <<revision, granted, log, nextSeq, floor, seen, holder, shared, u, c, answered, released>>

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Uses : UseRead(x) \/ UseStart(x) \/ UseLock(x) \/ UseCheck(x) \/ UseCommit(x) \/ UseRelease(x)
    \/ ChangeRead \/ ChangeLock \/ ChangeCommit \/ ChangeAbort \/ ChangeAnswer
    \/ CheckpointClose \/ CheckpointSign

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold. *)

\* Every use's entry was committed at the revision its decision read: no change committed between
\* the read and the append. So the log never says a use was decided on standing it no longer had.
FenceHolds ==
    \A e \in log : e.kind = "use" => e.atCommit = e.rev

\* "Revoke returned => the next use is refused", in its strongest form: no use allowed by a decision
\* from before a change commits after that change has answered.
NothingAllowedAfterAnswer ==
    \A e \in log : (e.kind = "use" /\ e.allow) => e.answeredAt <= e.rev

\* A value leaves only with its entry in the log.
EveryReleaseAudited ==
    \A r \in released : \E e \in log : e.kind = "use" /\ e.id = r.id /\ e.allow /\ e.rev = r.rev

\* "head": the log in number order is a valid history: each use names the revision of the last
\* change before it. ("seq" orders by (revision, number), which holds this by construction.)
LogConsistent ==
    Mode = "head" =>
        \A e \in log : e.kind = "use" =>
            e.rev = Cardinality({d \in log : d.kind = "change" /\ d.seq < e.seq})

\* "seq": what a checkpoint signed stays exactly the entries at or below its floor: none commits
\* there later.
CheckpointsHold ==
    \A k \in signed : {e \in log : e.seq <= k.upto} = k.entries

\* Numbers are unique.
NumbersUnique ==
    \A d, e \in log : d.seq = e.seq => d = e

=============================================================================
