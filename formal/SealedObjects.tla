---------------------------- MODULE SealedObjects ----------------------------
(***************************************************************************)
(* What a 0.15 object's seal must cover (docs/design/sealed-inputs.md; the *)
(* plan's "use_credential correctness", T125, T126, T129). HotPathOne.tla  *)
(* checks the fence, the numbers and the seals of abstract inputs; this    *)
(* checks which rows and columns make an object, so that what a use reads *)
(* is what 0.14 decides on and what the log says.                          *)
(*                                                                         *)
(* One use reads a key through a fork F of its project P: the key is a     *)
(* reference H to a source whose value is a plain value V (the worst case: *)
(* every part below is read). The database holds, besides each object's    *)
(* seal:                                                                    *)
(*   - H's reference row, and whether it ended (`secret_references`);      *)
(*   - whether F is archived, and whether P is (`environments`,             *)
(*     `projects`);                                                         *)
(*   - V's text (`secret_versions.plaintext`).                              *)
(* 0.14 decides on all of them: a read through an ended reference is       *)
(* refused (`ended`, its `reference.end` entry), one through a fork of an  *)
(* archived project too (its snapshot's `archived`: the environment's or   *)
(* its project's), and a plain value is its text.                          *)
(*                                                                         *)
(* Honest code changes them: it ends the reference (0.14's vault writes    *)
(* `reference.end`, an entry and no row), archives and restores F and P,   *)
(* and writes V. Each change of an object is logged and sealed, the seal   *)
(* the object as its rows then make it. A database writer with no key     *)
(* (MaxTampers) sets any of those columns to any value; it forges no seal. *)
(* A use reads the rows in one snapshot, makes each object from them, and  *)
(* refuses (`tampered`, `stale`: one outcome here) unless every object is  *)
(* its seal's, which is its newest change's (HotPathOne's fence orders the *)
(* change and the use; here each is one step). Otherwise it decides on the *)
(* objects and, allowed, serves V's text as read.                          *)
(*                                                                         *)
(* The protections (scripts/formal.sh turns each off):                     *)
(*   EndInRow         a reference's end is in a row (`ended_at`), which    *)
(*                    the holder's object reads: its source is none once   *)
(*                    its newest reference row has ended, a change of its  *)
(*                    own (`secret.write`, source null). Without, the end  *)
(*                    is 0.14's entry alone, which no use reads;           *)
(*   EndWithEntry     ... written in the vault's decision that appends the *)
(*                    `reference.end` entry, one transaction. Without, the *)
(*                    app writes it after the vault answers: between the   *)
(*                    two (or forever, on a crash), 0.14 holds the         *)
(*                    reference ended and 0.15's row live;                 *)
(*   ProjectInObject  an environment's object holds its project's          *)
(*                    archival, which the decision reads as 0.14's         *)
(*                    snapshot does (archived: the environment or its      *)
(*                    project), and a project's archive or restore changes *)
(*                    each of its environments' objects. Without, the      *)
(*                    object reads its own row only: a fork of an archived *)
(*                    project reads live;                                  *)
(*   ArchivedApart    ... apart from the environment's own: two parts, not *)
(*                    one `archived` made of both. Without, while the      *)
(*                    project is archived the object is archived whatever  *)
(*                    the environment's own column says: a writer clears   *)
(*                    it under a valid seal, and the project's restore     *)
(*                    seals the edit in (TLC's finding);                   *)
(*   DigestInSeal     a plain value's object holds its text's digest.      *)
(*                    Without, nothing covers the text: a writer who edits *)
(*                    it changes what is read under a valid seal;          *)
(*   ReferenceInObject the holder's object holds the id of the reference   *)
(*                    row it reads through, beside its source, and an end  *)
(*                    decides on that object, checked against its seal,    *)
(*                    whether the holder stands on the reference ended.    *)
(*                    Without, it asks the rows: a writer who renames the  *)
(*                    genuine row's id makes the end skip the holder, then *)
(*                    renames it back, the holder still sealed live;       *)
(*   LivenessFromLog  ... and whether the holder has an object at all from *)
(*                    its log (its newest change's seal), not from its     *)
(*                    row's `archived_at`. Without, a writer who sets that *)
(*                    column on a live holder makes the end take the       *)
(*                    no-object path (the rows' end alone), then clears it *)
(*                    and the row's end: the holder's seal still reads the *)
(*                    source.                                              *)
(*                                                                         *)
(* So every input an end decides on is a MAC'd 0.14 entry (the end itself) *)
(* or an object checked against its seal (R53): no row alone.             *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Values,          \* the texts V may hold
    MaxTampers,      \* columns the writer sets
    EndInRow, EndWithEntry, ProjectInObject, ArchivedApart, DigestInSeal, ReferenceInObject, LivenessFromLog

VARIABLES
    rows,      \* the columns: H's newest reference row's id (ref: r1 the genuine one) and its end (ended), H's archived_at
               \* (harch), F's archived_at (env), P's (project), V's text
    truth,     \* the same as honest code left them, and 0.14's `reference.end` (ended): what 0.14 decides on
    seals,     \* each object's seal, which its newest change wrote: the object, as the vault made it then
    pending,   \* an end the vault answered whose row the app has yet to write (without EndWithEntry)
    tampers,
    last       \* the newest use's outcome, beside what 0.14 and the replay decide then (NoUse before the first)

vars == <<rows, truth, seals, pending, tampers, last>>

None == "none"
Objects == {"holder", "fork", "value"}

\* Each object as its columns make it (objects.ts): the holder's source and the reference row it reads through (none
\* once ended, none at all when archived: no object), the fork's `archived`, V's digest.
Holder(r) ==
    LET reads == ~r.harch /\ ~(EndInRow /\ r.ended)
    IN [gone |-> r.harch, src |-> IF reads THEN "source" ELSE None, ref |-> IF reads /\ ReferenceInObject THEN r.ref ELSE None]
Fork(r) ==
    LET project == ProjectInObject /\ r.project
    IN IF ArchivedApart THEN [own |-> r.env, project |-> project] ELSE [own |-> r.env \/ project, project |-> FALSE]
Value(r) == IF DigestInSeal THEN r.text ELSE None
ObjectsOf(r) == [holder |-> Holder(r), fork |-> Fork(r), value |-> Value(r)]

\* A change: honest code writes columns, then seals every object they moved (`prepare`, `change_input`).
Sealed(r) == ObjectsOf(r)

\* The decision on objects: through a live reference, read through a fork that is not archived.
Allows(o) == o.holder.src /= None /\ ~o.fork.own /\ ~o.fork.project
\* 0.14's, on what honest code left: no `reference.end`, the holder live, neither the fork nor its project archived.
Allows014(t) == ~t.ended /\ ~t.harch /\ ~t.env /\ ~t.project

TypeOK ==
    /\ rows \in [ref : {"r1", "r2"}, ended : BOOLEAN, harch : BOOLEAN, env : BOOLEAN, project : BOOLEAN, text : Values]
    /\ truth \in [ref : {"r1", "r2"}, ended : BOOLEAN, harch : BOOLEAN, env : BOOLEAN, project : BOOLEAN, text : Values]
    /\ pending \in BOOLEAN
    /\ tampers \in 0..MaxTampers
    /\ last \in [allowed : BOOLEAN, refused : BOOLEAN, honestText : BOOLEAN, allowed014 : BOOLEAN]

\* Before the first use: one refused, which every invariant passes by.
NoUse == [allowed |-> FALSE, refused |-> TRUE, honestText |-> TRUE, allowed014 |-> FALSE]

Start == [ref |-> "r1", ended |-> FALSE, harch |-> FALSE, env |-> FALSE, project |-> FALSE, text |-> CHOOSE v \in Values : TRUE]

Init ==
    /\ rows = Start
    /\ truth = Start
    /\ seals = Sealed(Start)
    /\ pending = FALSE
    /\ tampers = 0
    /\ last = NoUse

\* Honest code writes `r` to change `object`, sealed again as `r` makes it, only if its row is its seal's (the
\* vault checks the seal of what it changes, `prepare` and ChangeChecksSeal): never sealing a writer's edit in.
Write(object, r) ==
    /\ ObjectsOf(rows)[object] = seals[object]
    /\ rows' = r
    /\ seals' = [seals EXCEPT ![object] = ObjectsOf(r)[object]]

\* The vault ends the genuine reference, r1: 0.14's entry; with EndInRow its row too, in the same transaction
\* (EndWithEntry) or, after the vault answered, in the app's (EndRow). In the vault's decision: a holder with an
\* object (LivenessFromLog: its log says so; else its row) that stands on r1 (ReferenceInObject: its object, checked
\* against its seal, says so, or the end is refused, the action disabled; else its row's id) changes, its newest row
\* ended; any other has the named row, r1, ended by its id alone (here `ended` is the newest row's: r1's when it is).
End ==
    /\ ~truth.ended
    /\ truth' = [truth EXCEPT !.ended = TRUE]
    /\ IF EndInRow /\ EndWithEntry
         THEN LET live == IF LivenessFromLog THEN ~seals.holder.gone ELSE ~rows.harch
                  checked == ObjectsOf(rows).holder = seals.holder
                  stands == IF ReferenceInObject THEN seals.holder.ref = "r1" ELSE rows.ref = "r1"
              IN /\ (live /\ ReferenceInObject) => checked
                 /\ IF live /\ stands THEN Write("holder", [rows EXCEPT !.ended = TRUE])
                    ELSE /\ rows' = [rows EXCEPT !.ended = IF rows.ref = "r1" THEN TRUE ELSE @]
                         /\ UNCHANGED seals
              /\ UNCHANGED pending
         ELSE /\ pending' = EndInRow
              /\ UNCHANGED <<rows, seals>>
    /\ UNCHANGED <<tampers, last>>

EndRow ==
    /\ pending
    /\ pending' = FALSE
    /\ Write("holder", [rows EXCEPT !.ended = TRUE])
    /\ UNCHANGED <<truth, tampers, last>>

\* The holder archived: its object gone (`secret.delete`). Never restored here: an unarchive seals what the rows hold,
\* a gap of its own (its row is no object while archived), not an end's.
ArchiveHolder ==
    /\ ~truth.harch
    /\ truth' = [truth EXCEPT !.harch = TRUE]
    /\ Write("holder", [rows EXCEPT !.harch = TRUE])
    /\ UNCHANGED <<pending, tampers, last>>

\* Archive or restore the fork or its project (each the fork's object: a project's every environment); write V.
Flip(part) ==
    /\ truth' = [truth EXCEPT ![part] = ~@]
    /\ Write("fork", [rows EXCEPT ![part] = ~truth[part]])
    /\ UNCHANGED <<pending, tampers, last>>

WriteValue(v) ==
    /\ v /= truth.text
    /\ truth' = [truth EXCEPT !.text = v]
    /\ Write("value", [rows EXCEPT !.text = v])
    /\ UNCHANGED <<pending, tampers, last>>

\* The database writer: any column to any value, no seal.
Tamper ==
    /\ tampers < MaxTampers
    /\ tampers' = tampers + 1
    /\ \/ \E b \in BOOLEAN : rows' = [rows EXCEPT !.ended = b]
       \/ \E b \in BOOLEAN : rows' = [rows EXCEPT !.harch = b]
       \/ \E x \in {"r1", "r2"} : rows' = [rows EXCEPT !.ref = x]
       \/ \E b \in BOOLEAN : rows' = [rows EXCEPT !.env = b]
       \/ \E b \in BOOLEAN : rows' = [rows EXCEPT !.project = b]
       \/ \E v \in Values : rows' = [rows EXCEPT !.text = v]
    /\ UNCHANGED <<truth, seals, pending, last>>

\* A use: one snapshot of the rows; refused unless every object is its seal's; else decided, and V's text
\* as read served. Its outcome kept beside what 0.14 does then, on what honest code left. (That the replay of
\* the log decides as live is HotPathOne's ReplaySound and the suites' `replayAgrees`: here a use not refused
\* reads its seals' objects, so live and replay agree by construction.)
Use ==
    /\ LET o == ObjectsOf(rows)
           sealedOk == \A x \in Objects : o[x] = seals[x]
       IN last' = [allowed |-> sealedOk /\ Allows(o), refused |-> ~sealedOk, honestText |-> rows.text = truth.text,
                   allowed014 |-> Allows014(truth)]
    /\ UNCHANGED <<rows, truth, seals, pending, tampers>>

Next ==
    \/ End
    \/ EndRow
    \/ ArchiveHolder
    \/ \E part \in {"env", "project"} : Flip(part)
    \/ \E v \in Values : WriteValue(v)
    \/ Tamper
    \/ Use

Spec == Init /\ [][Next]_vars

(* The invariants, each on the newest use: every use is the newest once. *)

\* An allowed use is one 0.14 allows on what honest code left, and serves the text honest code wrote.
AllowedAsOld == last.allowed => last.allowed014 /\ last.honestText

\* A use not refused read V's text as honest code left it: a writer's edit is refused, whatever is decided after
\* (a plain value, which the vault hands back to no one, is still read under its seal).
UnrefusedReadsHonest == ~last.refused => last.honestText


=============================================================================
