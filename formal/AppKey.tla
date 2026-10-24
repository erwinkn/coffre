-------------------------------- MODULE AppKey --------------------------------
(***************************************************************************)
(* The app key's rotation (server key-rotation.ts): starts under the new   *)
(* key B step it, each step a transaction under the log's head that signs  *)
(* the next row again under B if A signed it, and appends a `key.reseal`   *)
(* saying where the next goes on, the last one `key.rotate` too; while     *)
(* instances still under the old key A write rows and entries, and someone *)
(* who holds A and can write the database writes rows and entries under A  *)
(* past every check. docs/formal.md says what this covers, what it         *)
(* abstracts and what it does not prove.                                   *)
(*                                                                         *)
(* A row is its MAC's key and who last wrote what it says: a MAC binds the *)
(* row, so a row signed again is what it said, under the other key. One   *)
(* row a step, in their order, the cursor the next row's place. The log    *)
(* is the app's entries, in order. An instance under A writes a row and    *)
(* its entry in one transaction under the head.                            *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    N,              \* rows, 1..N, in the order a rotation signs them
    Procs,          \* concurrent processes
    Ops,            \* Ops[p]: what p may do
    Budget,         \* Budget[p]: how many times
    MaxLen          \* no entry past this many

CONSTANTS
    \* A step reads where the rotation stands under the head, in its own
    \* transaction (key-rotation.ts, rotateStep, keyState(tx) after
    \* lockLogHead), not before it takes it.
    StateUnderHead,
    \* An append under a key an entry of its author's names as moved from
    \* refuses, read under the head (db log.ts, appendEntries, KeyRetired).
    RetiredCheck,
    \* A verification takes an entry under A only before the first entry
    \* that names A as moved from (server db/audit.ts, appVerifier).
    WalkCutoff

None == "none"

VARIABLES
    rows,           \* rows[r]: [key, by, after]: the MAC's key, who wrote it, and whether after `key.rotate`
    log,            \* the app's entries: [key, kind, by, next]
    head,           \* the process holding the log's head, or None
    pc, op, l, left

procs == <<pc, op, l, left>>
vars == <<rows, log, head, procs>>

-----------------------------------------------------------------------------

Moves == {i \in 1..Len(log) : log[i].kind \in {"reseal", "rotate"}}
Rotated == \E i \in 1..Len(log) : log[i].kind = "rotate"

\* The first entry that names A as moved from: A writes nothing from there.
FirstMove == IF Moves = {} THEN Len(log) + 1 ELSE CHOOSE i \in Moves : \A j \in Moves : i <= j

\* Where the rotation stands, as a step reads it: done, or the next row.
Standing == IF Rotated THEN N + 1
            ELSE IF Moves = {} THEN 1
            ELSE log[CHOOSE i \in Moves : \A j \in Moves : j <= i].next

\* Whether a verification takes entry i, A's by the cutoff.
Accepted(i) == log[i].key = "B" \/ (log[i].key = "A" /\ (~WalkCutoff \/ i < FirstMove))

Entry(e) == log' = Append(log, e)

NoOp == [kind |-> "none", row |-> 0]
L0 == [next |-> 0]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Release(p) == head' = IF head = p THEN None ELSE head

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ Goto(p, CASE o.kind = "write" -> "write.head"
                      [] o.kind = "step" -> IF StateUnderHead THEN "step.head" ELSE "step.read"
                      [] OTHER -> "forge")
    /\ l' = [l EXCEPT ![p] = L0]
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<rows, log, head>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* An instance still under A, as during a deploy (app's `audited`): it     *)
(* takes the head, writes a row signed under A and appends its entry.      *)
(***************************************************************************)

WriteHead(p) ==
    /\ pc[p] = "write.head"
    /\ head = None
    /\ head' = p
    /\ Goto(p, "write.commit")
    /\ UNCHANGED <<rows, log, op, l, left>>

WriteCommit(p) ==
    /\ pc[p] = "write.commit"
    /\ IF (RetiredCheck /\ Moves # {}) \/ Len(log) >= MaxLen
         THEN UNCHANGED <<rows, log>>
         ELSE /\ rows' = [rows EXCEPT ![op[p].row] = [key |-> "A", by |-> "old", after |-> Rotated]]
              /\ Entry([key |-> "A", kind |-> "write", by |-> "old", next |-> 0])
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A step of the rotation, under B (rotateStep): the head, where it        *)
(* stands, then the next row signed again if A signed it, and the step's   *)
(* entries. A step finds it done, and writes nothing.                      *)
(***************************************************************************)

StepRead(p) ==
    /\ pc[p] = "step.read"
    /\ l' = [l EXCEPT ![p].next = Standing]
    /\ Goto(p, IF StateUnderHead THEN "step.work" ELSE "step.head")
    /\ UNCHANGED <<rows, log, head, op, left>>

StepHead(p) ==
    /\ pc[p] = "step.head"
    /\ head = None
    /\ head' = p
    /\ Goto(p, IF StateUnderHead THEN "step.read" ELSE "step.work")
    /\ UNCHANGED <<rows, log, op, l, left>>

StepWork(p) ==
    /\ pc[p] = "step.work"
    /\ LET r == l[p].next IN
       IF r > N \/ Len(log) + 2 > MaxLen
         THEN UNCHANGED <<rows, log>>
         ELSE /\ rows' = IF rows[r].key = "A" THEN [rows EXCEPT ![r].key = "B"] ELSE rows
              /\ LET step == [key |-> "B", kind |-> "reseal", by |-> "new", next |-> r + 1]
                     rotate == [key |-> "B", kind |-> "rotate", by |-> "new", next |-> r + 1]
                 IN log' = log \o (IF r = N THEN <<step, rotate>> ELSE <<step>>)
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Someone who holds A and can write the database: a row signed under A,   *)
(* or an entry under A chained on the log's end, past every check, at any  *)
(* moment.                                                                 *)
(***************************************************************************)

Forge(p) ==
    /\ pc[p] = "forge"
    /\ IF op[p].kind = "row"
         THEN /\ rows' = [rows EXCEPT ![op[p].row] = [key |-> "A", by |-> "attacker", after |-> Rotated]]
              /\ UNCHANGED log
         ELSE /\ Len(log) < MaxLen
              /\ Entry([key |-> "A", kind |-> "write", by |-> "attacker", next |-> 0])
              /\ UNCHANGED rows
    /\ Goto(p, "idle")
    /\ UNCHANGED <<head, op, l, left>>

-----------------------------------------------------------------------------

Init ==
    /\ rows = [r \in 1..N |-> [key |-> "A", by |-> "init", after |-> FALSE]]
    /\ log = <<[key |-> "A", kind |-> "write", by |-> "old", next |-> 0]>>
    /\ head = None
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget

Step(p) ==
    \/ Begin(p) \/ WriteHead(p) \/ WriteCommit(p)
    \/ StepRead(p) \/ StepHead(p) \/ StepWork(p) \/ Forge(p)

Finished == \A p \in Procs : pc[p] = "idle" /\ left[p] = 0

Next == (\E p \in Procs : Step(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK ==
    /\ head \in Procs \cup {None}
    /\ \A r \in 1..N : rows[r].key \in {"A", "B"}

\* One rotation: however many starts step it at once, one `key.rotate`.
OneRotate == Cardinality({i \in 1..Len(log) : log[i].kind = "rotate"}) <= 1

\* A rotation never signs under B what someone wrote under A after it: B
\* vouches only for what A signed before `key.rotate`.
NoLaunderingAfterRotate == \A r \in 1..N : rows[r].key = "B" => ~rows[r].after

\* An instance under A writes no entry from the rotation's first step on.
OldKeyWritesNothingAfter == \A i \in 1..Len(log) : (log[i].by = "old" /\ log[i].key = "A") => i < FirstMove

\* Once rotated, every row A alone signs is one written under A past the
\* checks, which fails under B as it should: no row of the instance's own
\* is left behind under A.
RotationComplete == Rotated => \A r \in 1..N : rows[r].key = "A" => rows[r].by = "attacker"

\* No entry forged under A from the first step on verifies.
NothingForgedAccepted == \A i \in 1..Len(log) : (log[i].by = "attacker" /\ i >= FirstMove) => ~Accepted(i)

=============================================================================
