------------------------------- MODULE Findings -------------------------------
(***************************************************************************)
(* When the vault's finding that a member's row was changed around it      *)
(* stands (T179 PR 4a; `findingStands`, `tamperedMembers`, `reportStands`  *)
(* in packages/db/src/grants.ts). A check of the row that finds it bad     *)
(* logs a finding; the vault changes the member only once its own check    *)
(* passes the row, so a change made after a finding's check means the row  *)
(* checked out again since. 0.14's rule: a finding stands while it is      *)
(* newer than the member's newest access entry, which every change wrote.  *)
(* 0.16 writes none (Writes014 = FALSE): the watermark would freeze, and   *)
(* every later finding read as standing for good. 0.15's: a finding names  *)
(* the number of the member's newest change its check weighed (`w`), and   *)
(* stands while no change is numbered above it.                            *)
(*                                                                         *)
(*   Check      a check of the bad row that read the member's newest       *)
(*              change (`#onLog`, `#integrity`): its finding names that    *)
(*              number;                                                    *)
(*   CheckLate  one that read none (`#seal`, `#notLogged`): its finding    *)
(*              names the newest as it appends (`#weigh`);                 *)
(*   Commit     a check's finding appended, in any order: two checks       *)
(*              commit in an order of their own, not the one they read in; *)
(*   Change     the vault's change of the member, which passes only a row  *)
(*              that checks out;                                           *)
(*   Tamper     a database writer leaves the row as no change of the       *)
(*              vault's left it; Restore puts it back.                     *)
(*                                                                         *)
(* The protections (scripts/formal.sh turns each off):                     *)
(*   WeighsChanges  a finding of 0.15's is weighed against the changes;    *)
(*                  without, by 0.14's rule, under 0.16 a change above it  *)
(*                  settles nothing (the frozen watermark);                *)
(*   MostWeighed    the most any finding weighed counts, not the newest    *)
(*                  finding's: without, a check that read before a change  *)
(*                  commits after a check that read past it, and hides     *)
(*                  that one's finding.                                    *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxChanges,      \* changes of the member the vault makes
    MaxChecks,       \* checks that find the row bad
    MaxTampers,      \* times the writer changes the row
    Writes014,       \* each change also writes 0.14's access entry (0.15); FALSE: 0.16's, none
    WeighsChanges,   \* protection
    MostWeighed      \* protection

VARIABLES
    row,       \* "good" | "bad": the member's row, as the log bears it out
    changes,   \* the number of the member's newest change, 0 for none
    checks,    \* checks in flight: [id, w], w the number read, or -1 for one that read none
    log,       \* the audit log, oldest first: findings [kind |-> "finding", w] and access entries
    made,      \* checks made
    tampers    \* times tampered

vars == <<row, changes, checks, log, made, tampers>>

LATE == -1

TypeOK ==
    /\ row \in {"good", "bad"}
    /\ changes \in 0..MaxChanges
    /\ \A c \in checks : c.id \in 1..MaxChecks /\ c.w \in {LATE} \cup 0..MaxChanges
    /\ \A i \in 1..Len(log) : log[i].kind \in {"finding", "access"} /\ log[i].w \in 0..MaxChanges

Init ==
    /\ row = "good"
    /\ changes = 0
    /\ checks = {}
    /\ log = <<>>
    /\ made = 0
    /\ tampers = 0

Tamper ==
    /\ tampers < MaxTampers
    /\ row = "good"
    /\ row' = "bad"
    /\ tampers' = tampers + 1
    /\ UNCHANGED <<changes, checks, log, made>>

Restore ==
    /\ row = "bad"
    /\ row' = "good"
    /\ UNCHANGED <<changes, checks, log, made, tampers>>

Check(late) ==
    /\ row = "bad"
    /\ made < MaxChecks
    /\ made' = made + 1
    /\ checks' = checks \cup {[id |-> made + 1, w |-> IF late THEN LATE ELSE changes]}
    /\ UNCHANGED <<row, changes, log, tampers>>

Commit(c) ==
    /\ checks' = checks \ {c}
    /\ log' = Append(log, [kind |-> "finding", w |-> IF c.w = LATE THEN changes ELSE c.w])
    /\ UNCHANGED <<row, changes, made, tampers>>

Change ==
    /\ row = "good"
    /\ changes < MaxChanges
    /\ changes' = changes + 1
    /\ log' = IF Writes014 THEN Append(log, [kind |-> "access", w |-> changes + 1]) ELSE log
    /\ UNCHANGED <<row, checks, made, tampers>>

Next ==
    \/ Tamper
    \/ Restore
    \/ Check(FALSE)
    \/ Check(TRUE)
    \/ \E c \in checks : Commit(c)
    \/ Change

Spec == Init /\ [][Next]_vars

Found == {i \in 1..Len(log) : log[i].kind = "finding"}
Newest(kind) == LET at == {i \in 1..Len(log) : log[i].kind = kind} IN IF at = {} THEN 0 ELSE CHOOSE i \in at : \A j \in at : j <= i

\* What the readers say (`findingStands`).
Stands ==
    IF ~WeighsChanges
    THEN Newest("finding") > Newest("access")
    ELSE IF MostWeighed
    THEN \E i \in Found : log[i].w >= changes
    ELSE Found # {} /\ log[Newest("finding")].w >= changes

\* A finding whose weighed change is still the member's newest stands: no change since says the row checked out.
StandsUnchanged == \A i \in Found : log[i].w = changes => Stands

\* A change above every one the findings weighed settles them: the watermark does not freeze.
Settles == (Found # {} /\ \A i \in Found : log[i].w < changes) => ~Stands
===============================================================================
