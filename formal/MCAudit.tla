------------------------------- MODULE MCAudit -------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Audit.tla, as MC.tla's of Coffre.tla.       *)
(***************************************************************************)
EXTENDS Audit

Op(kind) == [kind |-> kind, at |-> 0]
Edit(at) == [kind |-> "edit", at |-> at]

-----------------------------------------------------------------------------
(* Tampering: an entry of the app's and one of the vault's, a heartbeat that
   verified them, and the checkpoint that signed it. A request appends, two
   heartbeats run at once, each with its checkpoint, and someone edits an
   entry in place or rewrites the chain from one. *)

Start(kind) == [E(kind) EXCEPT !.verified = IF kind = "beat" THEN 2 ELSE 0, !.at = IF kind = "ckpt" THEN 3 ELSE 0]
StartLog == <<Start("app"), Start("vault"), Start("beat"), Start("ckpt")>>
TamperingProcs == {"request", "attacker", "beat1", "beat2"}
TamperingOps == [p \in TamperingProcs |->
    CASE p = "request" -> {Op("app"), Op("vault")}
      [] p = "attacker" -> {Op("rewrite"), Op("edit")}
      [] p \in {"beat1", "beat2"} -> {Op("beat")}]
TamperingBudget == [p \in TamperingProcs |-> 1]

-----------------------------------------------------------------------------
(* Readiness: requests append while two heartbeats, whose walks cover less
   than the log, run at once, each with its checkpoint, and a monitor asks
   for readiness. *)

ReadinessProcs == {"request", "beat1", "beat2", "monitor"}
ReadinessOps == [p \in ReadinessProcs |->
    CASE p = "request" -> {Op("app"), Op("vault")}
      [] p \in {"beat1", "beat2"} -> {Op("beat")}
      [] p = "monitor" -> {Op("probe")}]
ReadinessBudget == [p \in ReadinessProcs |-> IF p = "request" THEN 2 ELSE 1]

-----------------------------------------------------------------------------
(* Overtaking: four heartbeats at once, one of them with its checkpoint,
   while someone edits the entry the newest checkpoint signed, behind the
   app's cursor and the vault's: one beat finds it, one that walked from
   further on says so after it, and one after that walks from what that
   one says, before the checkpoint signs. *)

OvertakingProcs == {"attacker", "a", "b", "c", "z"}
OvertakingOps == [p \in OvertakingProcs |->
    CASE p = "attacker" -> {Edit(3)}
      [] p \in {"a", "b", "z"} -> {Op("beatonly")}
      [] p = "c" -> {Op("beat")}]
OvertakingBudget == [p \in OvertakingProcs |-> 1]

Revert(at) == [kind |-> "revert", at |-> at]
Hide(at) == [kind |-> "hide", at |-> at]

-----------------------------------------------------------------------------
(* Hiding: someone who writes again. They edit the entry the newest
   checkpoint signed; a beat finds it, and they hide the finder's row while
   a beat that walked before commits, then put it back. *)

HidingProcs == {"x", "y", "a", "z"}
HidingOps == [p \in HidingProcs |->
    CASE p = "x" -> {Edit(3)}
      [] p = "y" -> {Hide(5), Revert(5)}
      [] p = "a" -> {Op("beatonly")}
      [] p = "z" -> {Op("beat")}]
HidingBudget == [p \in HidingProcs |-> IF p = "y" THEN 2 ELSE 1]

-----------------------------------------------------------------------------
(* Reverting: from a beat that verified past the newest checkpoint, someone
   edits an entry behind its cursor and one ahead of it; a beat walking from
   that cursor finds the one ahead, another from the start the one behind,
   and they revert the one ahead while a third beat walks. *)

AheadLog == Append(StartLog, [E("beat") EXCEPT !.verified = 4])
RevertingProcs == {"x", "y", "b", "c", "z"}
RevertingOps == [p \in RevertingProcs |->
    CASE p = "x" -> {Edit(3)}
      [] p = "y" -> {Edit(5), Revert(5)}
      [] p \in {"b", "c"} -> {Op("beatonly")}
      [] p = "z" -> {Op("beat")}]
RevertingBudget == [p \in RevertingProcs |-> IF p = "y" THEN 2 ELSE 1]

-----------------------------------------------------------------------------
(* Masking: a beat walks past an entry before it is edited, and commits;
   another, which began before it, finds the edit and commits after it.
   Someone hides the finder's row while a third beat reads where to resume,
   and puts it back before that beat walks. *)

MaskingProcs == {"x", "y", "a", "b", "c"}
MaskingOps == [p \in MaskingProcs |->
    CASE p = "x" -> {Edit(3)}
      [] p = "y" -> {Hide(6), Revert(6)}
      [] p \in {"a", "b"} -> {Op("beatonly")}
      [] p = "c" -> {Op("beat")}]
MaskingBudget == [p \in MaskingProcs |-> IF p = "y" THEN 2 ELSE 1]

-----------------------------------------------------------------------------
(* Reediting: someone edits an entry, reverts it once a beat found it, and
   edits it again, behind every cursor, while beats walk one after another:
   only the scrub finds the second edit, and readiness is red only while the
   edit a beat found is in place. *)

ReeditProcs == {"x", "z1", "z2"}
ReeditOps == [p \in ReeditProcs |->
    CASE p = "x" -> {Edit(3), Revert(3)}
      [] p \in {"z1", "z2"} -> {Op("beat")}]
ReeditBudget == [p \in ReeditProcs |-> IF p = "x" THEN 3 ELSE 1]

-----------------------------------------------------------------------------
(* Rows: someone edits the entry the newest checkpoint signed, and hides,
   forges and puts back any heartbeat row, at any step, while three beats
   walk and commit at once, the last with its checkpoint. *)

RowsProcs == {"x", "y", "a", "b", "c"}
RowsOps == [p \in RowsProcs |->
    CASE p = "x" -> {Edit(3)}
      [] p = "y" -> {Op("hide"), Op("forge"), Op("revert")}
      [] p \in {"a", "b"} -> {Op("beatonly")}
      [] p = "c" -> {Op("beat")}]
RowsBudget == [p \in RowsProcs |-> IF p = "y" THEN 2 ELSE 1]

-----------------------------------------------------------------------------
(* Repairing: entry 5 edited, a beat that found it, from where it began at
   entry 2, its row more than a walk past there; someone puts the entry back
   when they like, and six beats, one after another, each with its
   checkpoint, catch up with the head. *)

Finder == [E("beat") EXCEPT !.verified = 2, !.broken = TRUE, !.fault = 5, !.fEdit = 1, !.bfrom = 2, !.head = 3]
RepairLog == StartLog \o <<[E("app") EXCEPT !.edited = 1], E("app"), E("app"), E("app"), Finder>>
RepairProcs == {"x", "z"}
RepairOps == [p \in RepairProcs |->
    CASE p = "x" -> {Revert(5)}
      [] p = "z" -> {Op("beat")}]
RepairBudget == [p \in RepairProcs |-> IF p = "x" THEN 1 ELSE 6]

\* Once the edit is put back, four beats that walked with no edit in place,
\* after the last that walked with one, catch up: readiness green.
RepairGoesGreen ==
    LET beats == {i \in 1..Len(log) : log[i].kind = "beat"}
        edgy == {i \in beats : ~log[i].calm}
        after == {i \in beats : \A j \in edgy : j < i}
    IN (Finished /\ Calm /\ Cardinality(after) >= 4) => ReadyNow

-----------------------------------------------------------------------------
(* Overtaken: entry 5 edited, behind the newest checkpoint's prefix; a
   beat that found it, from entry 2, its row more than a walk past where
   the next began; and, committed after it, a beat that walked past entry 5
   before the edit. Someone hides and puts back beat rows, while one beat
   walks from the second's cursor and another after it. A walk that began
   after the finder committed, but never went over the entry it found,
   clears nothing (`ClearsOverFault`); #296's review proposed it would. *)

Overtaker == [E("beat") EXCEPT !.verified = 5, !.bfrom = 2, !.head = 5]
OvertakenLog == StartLog \o <<[E("app") EXCEPT !.edited = 1], E("app"), E("app"), E("app"), [E("ckpt") EXCEPT !.at = 8], Finder, Overtaker>>
OvertakenProcs == {"y", "b", "c"}
OvertakenOps == [p \in OvertakenProcs |->
    CASE p = "y" -> {Op("hide"), Op("revert")}
      [] p = "b" -> {Op("beatonly")}
      [] p = "c" -> {Op("beat")}]
OvertakenBudget == [p \in OvertakenProcs |-> IF p = "y" THEN 2 ELSE 1]

=============================================================================
