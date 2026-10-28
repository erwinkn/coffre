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
(*                    source;                                              *)
(*   RestoreFromLog   an unarchive restores the object the holder's log    *)
(*                    last sealed (its newest change with a seal, `kept`), *)
(*                    and is refused when its rows make another (T134). An *)
(*                    archived key is no object, so nothing else checks    *)
(*                    them. Without, it seals what they hold: a writer     *)
(*                    who plants a reference row while the holder is       *)
(*                    archived has it sealed in, live through a reference  *)
(*                    0.14 holds ended;                                    *)
(*   RestorePinned    ... still the log's newest sealed object when the    *)
(*                    unarchive commits (`app_change`, `p_restores`), not  *)
(*                    only when it was prepared. Without, an end between   *)
(*                    the two, its row's end cleared by a writer, leaves   *)
(*                    the rows as read: the reference sealed live again;  *)
(*   EndWhileArchived the end of a reference an archived holder's kept     *)
(*                    object stands on changes that object: the vault      *)
(*                    logs it ended (`secret.write`, no source, then       *)
(*                    `secret.delete`: still no object). Without, the end  *)
(*                    is the row's alone: a writer clears it, and the      *)
(*                    unarchive restores the kept object, live; with       *)
(*                    RestoreFromLog and no tampering, an honest unarchive *)
(*                    after an end would be refused (HonestUnarchive).     *)
(*                                                                         *)
(* So every input an end decides on is a MAC'd 0.14 entry (the end itself) *)
(* or an object checked against its seal (R53): no row alone.             *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Values,          \* the texts V may hold
    MaxTampers,      \* columns the writer sets
    EndInRow, EndWithEntry, ProjectInObject, ArchivedApart, DigestInSeal, ReferenceInObject, LivenessFromLog,
    RestoreFromLog, RestorePinned, EndWhileArchived

VARIABLES
    rows,      \* the columns: H's newest reference row's id (ref: r1 the genuine one) and its end (ended), H's archived_at
               \* (harch), F's archived_at (env), P's (project), V's text
    truth,     \* the same as honest code left them, and 0.14's `reference.end` (ended): what 0.14 decides on
    seals,     \* each object's seal, which its newest change wrote: the object, as the vault made it then
    kept,      \* the holder's object as its log's newest change with a seal left it: what an unarchive restores
    prepared,  \* an unarchive in flight (on): the object its rows made, and the kept one it was checked against
    pending,   \* an end the vault answered whose row the app has yet to write (without EndWithEntry)
    tampers,
    last       \* the newest use's outcome, beside what 0.14 and the replay decide then (NoUse before the first)

vars == <<rows, truth, seals, kept, prepared, pending, tampers, last>>

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
HolderObjects == [gone : BOOLEAN, src : {"source", None}, ref : {"r1", "r2", None}]
\* A holder's object once its reference has ended: no source, no reference row.
Ended(o) == [o EXCEPT !.src = None, !.ref = None]

\* A change: honest code writes columns, then seals every object they moved (`prepare`, `change_input`).
Sealed(r) == ObjectsOf(r)

\* The decision on objects: through a live reference, read through a fork that is not archived.
Allows(o) == o.holder.src /= None /\ ~o.fork.own /\ ~o.fork.project
\* 0.14's, on what honest code left: no `reference.end`, the holder live, neither the fork nor its project archived.
Allows014(t) == ~t.ended /\ ~t.harch /\ ~t.env /\ ~t.project

TypeOK ==
    /\ rows \in [ref : {"r1", "r2"}, ended : BOOLEAN, harch : BOOLEAN, env : BOOLEAN, project : BOOLEAN, text : Values]
    /\ truth \in [ref : {"r1", "r2"}, ended : BOOLEAN, harch : BOOLEAN, env : BOOLEAN, project : BOOLEAN, text : Values]
    /\ kept \in HolderObjects
    /\ prepared \in [on : BOOLEAN, object : HolderObjects, against : HolderObjects]
    /\ pending \in BOOLEAN
    /\ tampers \in 0..MaxTampers
    /\ last \in [allowed : BOOLEAN, refused : BOOLEAN, honestText : BOOLEAN, allowed014 : BOOLEAN]

\* Before the first use: one refused, which every invariant passes by.
NoUse == [allowed |-> FALSE, refused |-> TRUE, honestText |-> TRUE, allowed014 |-> FALSE]

\* No unarchive in flight.
Idle == [on |-> FALSE, object |-> [gone |-> TRUE, src |-> None, ref |-> None], against |-> [gone |-> TRUE, src |-> None, ref |-> None]]

Start == [ref |-> "r1", ended |-> FALSE, harch |-> FALSE, env |-> FALSE, project |-> FALSE, text |-> CHOOSE v \in Values : TRUE]

Init ==
    /\ rows = Start
    /\ truth = Start
    /\ seals = Sealed(Start)
    /\ kept = Holder(Start)
    /\ prepared = Idle
    /\ pending = FALSE
    /\ tampers = 0
    /\ last = NoUse

\* Honest code writes `r` to change `object`, sealed again as `r` makes it, only if its row is its seal's (the
\* vault checks the seal of what it changes, `prepare` and ChangeChecksSeal): never sealing a writer's edit in. A
\* holder's object it seals is the one its log keeps for an unarchive; an archive keeps none (no seal).
Write(object, r) ==
    /\ ObjectsOf(rows)[object] = seals[object]
    /\ rows' = r
    /\ seals' = [seals EXCEPT ![object] = ObjectsOf(r)[object]]
    /\ kept' = IF object = "holder" /\ ~ObjectsOf(r).holder.gone THEN ObjectsOf(r).holder ELSE kept

\* The vault ends the genuine reference, r1: 0.14's entry; with EndInRow its row too, in the same transaction
\* (EndWithEntry) or, after the vault answered, in the app's (EndRow). In the vault's decision: a holder with an
\* object (LivenessFromLog: its log says so; else its row) that stands on r1 (ReferenceInObject: its object, checked
\* against its seal, says so, or the end is refused, the action disabled; else its row's id) changes, its newest row
\* ended; any other has the named row, r1, ended by its id alone (here `ended` is the newest row's: r1's when it is).
\* With EndWhileArchived, a holder with no object whose kept one (its log's, checked against its seal) stands on r1
\* has that kept object ended too: the vault logs it ended, then deleted again, so that it still has none.
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
                         /\ kept' = IF EndWhileArchived /\ seals.holder.gone /\ kept.src /= None
                                       /\ (ReferenceInObject => kept.ref = "r1")
                                    THEN Ended(kept) ELSE kept
                         /\ UNCHANGED seals
              /\ UNCHANGED pending
         ELSE /\ pending' = EndInRow
              /\ UNCHANGED <<rows, seals, kept>>
    /\ UNCHANGED <<prepared, tampers, last>>

EndRow ==
    /\ pending
    /\ pending' = FALSE
    /\ Write("holder", [rows EXCEPT !.ended = TRUE])
    /\ UNCHANGED <<truth, prepared, tampers, last>>

\* The holder archived: its object gone (`secret.delete`), its row's seal none.
ArchiveHolder ==
    /\ ~truth.harch
    /\ truth' = [truth EXCEPT !.harch = TRUE]
    /\ Write("holder", [rows EXCEPT !.harch = TRUE])
    /\ UNCHANGED <<prepared, pending, tampers, last>>

\* Its unarchive, in two steps: the vault prepares it from the rows as read (no lock: `prepare`), then the app's
\* transaction commits it under the fence (`app_change`), its rows as read (`stillAsRead`) and, ChangeChecksSeal, its
\* row still no object. With RestoreFromLog the prepare holds what the rows make to the object the log keeps; with
\* RestorePinned the commit holds that kept object to the log's then.
PrepareUnarchive ==
    /\ truth.harch
    /\ ~prepared.on
    /\ rows.harch
    /\ LET object == Holder([rows EXCEPT !.harch = FALSE])
       IN /\ RestoreFromLog => object = kept
          /\ prepared' = [on |-> TRUE, object |-> object, against |-> kept]
    /\ UNCHANGED <<rows, truth, seals, kept, pending, tampers, last>>

CommitUnarchive ==
    /\ prepared.on
    /\ prepared' = Idle
    /\ rows.harch
    /\ Holder([rows EXCEPT !.harch = FALSE]) = prepared.object
    /\ RestorePinned => kept = prepared.against
    /\ truth' = [truth EXCEPT !.harch = FALSE]
    /\ Write("holder", [rows EXCEPT !.harch = FALSE])
    /\ UNCHANGED <<pending, tampers, last>>

\* A prepared unarchive that does not commit (its transaction refused, or the request gone): prepared again, or not.
Abandon ==
    /\ prepared.on
    /\ prepared' = Idle
    /\ UNCHANGED <<rows, truth, seals, kept, pending, tampers, last>>

\* Archive or restore the fork or its project (each the fork's object: a project's every environment); write V.
Flip(part) ==
    /\ truth' = [truth EXCEPT ![part] = ~@]
    /\ Write("fork", [rows EXCEPT ![part] = ~truth[part]])
    /\ UNCHANGED <<prepared, pending, tampers, last>>

WriteValue(v) ==
    /\ v /= truth.text
    /\ truth' = [truth EXCEPT !.text = v]
    /\ Write("value", [rows EXCEPT !.text = v])
    /\ UNCHANGED <<prepared, pending, tampers, last>>

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
    /\ UNCHANGED <<truth, seals, kept, prepared, pending, last>>

\* A use: one snapshot of the rows; refused unless every object is its seal's; else decided, and V's text
\* as read served. Its outcome kept beside what 0.14 does then, on what honest code left. (That the replay of
\* the log decides as live is HotPathOne's ReplaySound and the suites' `replayAgrees`: here a use not refused
\* reads its seals' objects, so live and replay agree by construction.)
Use ==
    /\ LET o == ObjectsOf(rows)
           sealedOk == \A x \in Objects : o[x] = seals[x]
       IN last' = [allowed |-> sealedOk /\ Allows(o), refused |-> ~sealedOk, honestText |-> rows.text = truth.text,
                   allowed014 |-> Allows014(truth)]
    /\ UNCHANGED <<rows, truth, seals, kept, prepared, pending, tampers>>

Next ==
    \/ End
    \/ EndRow
    \/ ArchiveHolder
    \/ PrepareUnarchive
    \/ CommitUnarchive
    \/ Abandon
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

\* With no writer, an archived holder can always be unarchived: the protections refuse only rows the log does not
\* bear out, never an honest end's.
HonestUnarchive == (tampers = 0 /\ truth.harch /\ ~prepared.on) => ENABLED PrepareUnarchive


=============================================================================
