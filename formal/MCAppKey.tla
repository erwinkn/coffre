------------------------------- MODULE MCAppKey -------------------------------
(***************************************************************************)
(* The scenarios TLC checks of AppKey.tla, as MC.tla's of Coffre.tla.      *)
(***************************************************************************)
EXTENDS AppKey

Write(r) == [kind |-> "write", row |-> r]
StepOp == [kind |-> "step", row |-> 0]
ForgeRow(r) == [kind |-> "row", row |-> r]
ForgeEntry == [kind |-> "entry", row |-> 0]

-----------------------------------------------------------------------------
(* Rotating: two starts under B step the rotation at once, an instance
   still under A writes a row, and someone who holds A writes rows and an
   entry under it, at any moment. *)

RotatingProcs == {"old", "new1", "new2", "attacker"}
RotatingOps == [p \in RotatingProcs |->
    CASE p = "old" -> {Write(1), Write(2)}
      [] p \in {"new1", "new2"} -> {StepOp}
      [] p = "attacker" -> {ForgeRow(1), ForgeRow(2), ForgeEntry}]
RotatingBudget == [p \in RotatingProcs |->
    CASE p = "old" -> 1
      [] p \in {"new1", "new2"} -> 2
      [] p = "attacker" -> 2]

=============================================================================
