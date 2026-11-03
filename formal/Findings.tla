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
(* the member's newest change its check weighed, by the change's MAC (its  *)
(* identity, `id` here), and stands while that change is still their       *)
(* newest. A change's MAC covers every column but its number, which a      *)
(* database writer can change (Renumber): a rule that compares numbers     *)
(* lets them settle a finding, or stand one for good (review r1 of #476).  *)
(*                                                                         *)
(*   Check      a check of the bad row that read the member's newest       *)
(*              change (`#onLog`, `#integrity`): its finding names that    *)
(*              change;                                                    *)
(*   CheckLate  one that read none (`#seal`, `#notLogged`): its finding    *)
(*              names the newest as it appends (`#weigh`);                 *)
(*   CheckOld   0.14's check, which appends its finding at once, under     *)
(*              0.14's head, and names no change (Legacy: a finding of     *)
(*              before the cutover, read beside 0.15's);                   *)
(*   Commit     a check's finding appended, in any order: two checks       *)
(*              commit in an order of their own, not the one they read in; *)
(*   Change     the vault's change of the member, which passes only a row  *)
(*              that checks out against their newest change;               *)
(*   Tamper     a database writer leaves the row as no change of the       *)
(*              vault's left it; Restore puts it back;                     *)
(*   Renumber   the writer gives a change a number no other change holds.  *)
(*                                                                         *)
(* The readers take the change numbered highest as the newest. When that   *)
(* is not the newest the vault made (Honest is false), an older change put *)
(* above it, the vault's check finds the row stale and refuses, and what   *)
(* a finding says then is outside what this checks: an entry replayed or   *)
(* deleted whole, its MAC intact, is the checkpoints' to catch             *)
(* (docs/design/merkle-checkpoints.md).                                    *)
(*                                                                         *)
(* The protections (scripts/formal.sh turns each off):                     *)
(*   WeighsChanges  a finding of 0.15's is weighed against the changes;    *)
(*                  without, by 0.14's rule, under 0.16 a change after it  *)
(*                  settles nothing (the frozen watermark);                *)
(*   EveryFinding   any finding naming the newest change counts, not the   *)
(*                  newest finding alone: without, a check that read       *)
(*                  before a change commits after a check that read past   *)
(*                  it, and hides that one's finding;                      *)
(*   NamesChange    a finding names the change it weighed by its MAC;      *)
(*                  without, by its number, and it stands while no change  *)
(*                  is numbered above it: the writer renumbers the newest  *)
(*                  change up and settles it, or renumbers before a check  *)
(*                  and back after, and no later change ever settles it.   *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxChanges,      \* changes of the member the vault makes
    MaxChecks,       \* checks that find the row bad
    MaxTampers,      \* times the writer changes the row
    MaxRenumbers,    \* times the writer renumbers a change
    MaxNumber,       \* the numbers a change may hold
    Writes014,       \* each change also writes 0.14's access entry (0.15); FALSE: 0.16's, none
    Legacy,          \* findings of 0.14's, which name no change, beside 0.15's
    WeighsChanges,   \* protection
    EveryFinding,    \* protection
    NamesChange      \* protection

ASSUME Legacy => Writes014

VARIABLES
    row,       \* "good" | "bad": the member's row, as the log bears it out
    changes,   \* the vault's changes of the member, made in order: change i is the i-th, its id
    number,    \* number[i]: the number change i holds in log_changes
    seq,       \* the log's sequence: the number the next change takes
    checks,    \* checks in flight: [id, n] the change read and its number then, or id = LATE; at, the vault's changes then
    log,       \* the audit log, oldest first: findings, 0.14's findings and access entries
    made,      \* checks made
    tampers,   \* times tampered
    renumbers  \* times renumbered

vars == <<row, changes, number, seq, checks, log, made, tampers, renumbers>>

LATE == -1

Numbers == {number[i] : i \in 1..changes}

\* The change the readers take as the member's newest: the one numbered highest; 0 for none.
NewestId == IF changes = 0 THEN 0 ELSE CHOOSE i \in 1..changes : \A j \in 1..changes : number[j] <= number[i]
NumberOf(i) == IF i = 0 THEN 0 ELSE number[i]

\* The readers' newest is the vault's newest: the state whose findings this holds to its rule.
Honest == NewestId = changes

TypeOK ==
    /\ row \in {"good", "bad"}
    /\ changes \in 0..MaxChanges
    /\ number \in [1..changes -> 1..MaxNumber]
    /\ Cardinality(Numbers) = changes
    /\ \A c \in checks : c.id \in {LATE} \cup 0..MaxChanges
    /\ \A i \in 1..Len(log) : log[i].kind \in {"finding", "legacy", "access"} /\ log[i].id \in 0..MaxChanges /\ log[i].at \in 0..MaxChanges

Init ==
    /\ row = "good"
    /\ changes = 0
    /\ number = <<>>
    /\ seq = 1
    /\ checks = {}
    /\ log = <<>>
    /\ made = 0
    /\ tampers = 0
    /\ renumbers = 0

Tamper ==
    /\ tampers < MaxTampers
    /\ row = "good"
    /\ row' = "bad"
    /\ tampers' = tampers + 1
    /\ UNCHANGED <<changes, number, seq, checks, log, made, renumbers>>

Restore ==
    /\ row = "bad"
    /\ row' = "good"
    /\ UNCHANGED <<changes, number, seq, checks, log, made, tampers, renumbers>>

Renumber ==
    /\ renumbers < MaxRenumbers
    /\ \E i \in 1..changes, n \in 1..MaxNumber :
        /\ n \notin Numbers
        /\ number' = [number EXCEPT ![i] = n]
    /\ renumbers' = renumbers + 1
    /\ UNCHANGED <<row, changes, seq, checks, log, made, tampers>>

\* A check finds the row bad, or not the newest change's: one the writer changed, or an older change put above it.
Finds == row = "bad" \/ ~Honest

Check(late) ==
    /\ Finds
    /\ made < MaxChecks
    /\ made' = made + 1
    /\ checks' = checks \cup {IF late THEN [id |-> LATE, n |-> 0, at |-> changes, k |-> made + 1]
                                    ELSE [id |-> NewestId, n |-> NumberOf(NewestId), at |-> changes, k |-> made + 1]}
    /\ UNCHANGED <<row, changes, number, seq, log, tampers, renumbers>>

CheckOld ==
    /\ Legacy
    /\ Finds
    /\ made < MaxChecks
    /\ made' = made + 1
    /\ log' = Append(log, [kind |-> "legacy", id |-> NewestId, n |-> 0, at |-> changes])
    /\ UNCHANGED <<row, changes, number, seq, checks, tampers, renumbers>>

Commit(c) ==
    /\ checks' = checks \ {c}
    /\ log' = Append(log, [kind |-> "finding",
                           id |-> IF c.id = LATE THEN NewestId ELSE c.id,
                           n |-> IF c.id = LATE THEN NumberOf(NewestId) ELSE c.n,
                           \* A late one weighs what it names as it appends: what it says is as of then.
                           at |-> IF c.id = LATE THEN changes ELSE c.at])
    /\ UNCHANGED <<row, changes, number, seq, made, tampers, renumbers>>

\* The vault's change, which only a row that checks out against its newest change passes; it takes the
\* sequence's next number, and fails on one a writer already gave another change (log_changes' key).
Change ==
    /\ row = "good"
    /\ Honest
    /\ changes < MaxChanges
    /\ seq <= MaxNumber
    /\ seq \notin Numbers
    /\ changes' = changes + 1
    /\ number' = [i \in 1..changes + 1 |-> IF i <= changes THEN number[i] ELSE seq]
    /\ seq' = seq + 1
    /\ log' = IF Writes014 THEN Append(log, [kind |-> "access", id |-> changes + 1, n |-> 0, at |-> changes + 1]) ELSE log
    /\ UNCHANGED <<row, checks, made, tampers, renumbers>>

Next ==
    \/ Tamper
    \/ Restore
    \/ Renumber
    \/ Check(FALSE)
    \/ Check(TRUE)
    \/ CheckOld
    \/ \E c \in checks : Commit(c)
    \/ Change

Spec == Init /\ [][Next]_vars

Of(kinds) == {i \in 1..Len(log) : log[i].kind \in kinds}
Found == Of({"finding"})
Newest(kinds) == IF Of(kinds) = {} THEN 0 ELSE CHOOSE i \in Of(kinds) : \A j \in Of(kinds) : j <= i

\* Whether a finding of 0.15's names the readers' newest change (`findingStands`).
Names(f) == IF NamesChange THEN f.id = NewestId ELSE f.n >= NumberOf(NewestId)

\* What the readers say (`findingStands`): 0.15's findings by the change they name, 0.14's by the access entries.
Stands ==
    IF ~WeighsChanges
    THEN Newest({"finding", "legacy"}) > Newest({"access"})
    ELSE \/ Newest({"legacy"}) > Newest({"access"})
         \/ IF EveryFinding
            THEN \E i \in Found : Names(log[i])
            ELSE Found # {} /\ Names(log[Newest({"finding"})])

AllFound == Of({"finding", "legacy"})

\* A finding whose check read the vault's newest change, no change made since, stands: nothing since says the row checked out.
StandsUnchanged == Honest => (\A i \in AllFound : log[i].at = changes /\ log[i].id = changes => Stands)

\* A change after every finding's check settles them: the watermark neither freezes nor names a change for good.
Settles == (Honest /\ AllFound # {} /\ \A i \in AllFound : log[i].at < changes) => ~Stands
===============================================================================
