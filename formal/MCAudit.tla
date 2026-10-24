------------------------------- MODULE MCAudit -------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Audit.tla, as MC.tla's of Coffre.tla.       *)
(***************************************************************************)
EXTENDS Audit

Op(kind) == [kind |-> kind, at |-> 0]
Edit(at) == [kind |-> "edit", at |-> at]
Revert(at) == [kind |-> "revert", at |-> at]

\* An entry of the app's and one of the vault's, a heartbeat, and the
\* checkpoint that signed it; the anchor, which a beat wrote after it,
\* caught up to that checkpoint.
StartLog == <<E("app"), E("vault"), E("beat"), [E("ckpt") EXCEPT !.at = 3]>>
StartAnchor == [NoAnchor EXCEPT !.exists = TRUE, !.rev = 1, !.at = 3, !.verified = 3, !.beat = 3]

-----------------------------------------------------------------------------
(* Tampering: a request appends, two heartbeats run at once, each with its
   checkpoint, someone edits an entry in place or rewrites the chain from
   one, and a monitor asks for readiness. *)

TamperingProcs == {"request", "attacker", "beat1", "beat2", "monitor"}
TamperingOps == [p \in TamperingProcs |->
    CASE p = "request" -> {Op("app"), Op("vault")}
      [] p = "attacker" -> {Op("rewrite"), Op("edit")}
      [] p \in {"beat1", "beat2"} -> {Op("beat")}
      [] p = "monitor" -> {Op("probe")}]
TamperingBudget == [p \in TamperingProcs |-> 1]

-----------------------------------------------------------------------------
(* Overtaking: three heartbeats at once while someone edits an entry past
   the anchor, the first beat's own row or its checkpoint's: one beat walks
   before the edit and anchors after another has found it. *)

OvertakingProcs == {"attacker", "a", "b", "c"}
OvertakingOps == [p \in OvertakingProcs |->
    CASE p = "attacker" -> {Edit(5), Edit(6)}
      [] p \in {"a", "b", "c"} -> {Op("beat")}]
OvertakingBudget == [p \in OvertakingProcs |-> 1]

-----------------------------------------------------------------------------
(* Rows: someone edits and puts back any entry, heartbeat rows among them,
   twice, at any step, while two beats run at once and a monitor asks. *)

RowsProcs == {"y", "a", "b", "monitor"}
RowsOps == [p \in RowsProcs |->
    CASE p = "y" -> {Op("edit"), Op("revert")}
      [] p \in {"a", "b"} -> {Op("beat")}
      [] p = "monitor" -> {Op("probe")}]
RowsBudget == [p \in RowsProcs |-> IF p = "y" THEN 2 ELSE 1]

-----------------------------------------------------------------------------
(* Readiness: requests append while two heartbeats, whose walks cover less
   than the log, run at once, and a monitor asks for readiness. *)

ReadinessProcs == {"request", "beat1", "beat2", "monitor"}
ReadinessOps == [p \in ReadinessProcs |->
    CASE p = "request" -> {Op("app"), Op("vault")}
      [] p \in {"beat1", "beat2"} -> {Op("beat")}
      [] p = "monitor" -> {Op("probe")}]
ReadinessBudget == [p \in ReadinessProcs |-> IF p = "request" THEN 2 ELSE 1]

-----------------------------------------------------------------------------
(* Repairing: entry 5 edited, and the anchor's finding of it, its walk
   having begun at entry 3; requests since, more than a walk; someone puts
   the entry back when they like, while beats, one after another, check it
   alone, then catch up with the head. *)

RepairLog == StartLog \o <<[E("app") EXCEPT !.edited = 1], E("app"), E("app"), E("app")>>
RepairAnchor == [StartAnchor EXCEPT !.found = 5]
RepairProcs == {"x", "z"}
RepairOps == [p \in RepairProcs |->
    CASE p = "x" -> {Revert(5)}
      [] p = "z" -> {Op("beat")}]
RepairBudget == [p \in RepairProcs |-> IF p = "x" THEN 1 ELSE 7]

=============================================================================
