------------------------------ MODULE MCRotation ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Rotation.tla, as MC.tla's of Coffre.tla: an *)
(* isolate under the old key A, serving on after the deploy, and one under *)
(* the new key B, serving from it.                                         *)
(***************************************************************************)
EXTENDS Rotation

TwoWriters == {"old", "new"}
TwoKeys == [x \in TwoWriters |-> IF x = "old" THEN "A" ELSE "B"]

=============================================================================
