-------------------------------- MODULE MCBulk --------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Bulk.tla, as MC.tla's of Coffre.tla.        *)
(***************************************************************************)
EXTENDS Bulk

Read(keys, cred) == [kind |-> "read", keys |-> keys, cred |-> cred]

-----------------------------------------------------------------------------
(* Bulk reads: one principal, at most two keys of three in a window of two
   ticks, reads on two credentials at once, while the clock runs. A read
   with a key in memory and one with a key service count alike: before the
   head, then under it (Bulk.tla). *)

BulkKeys == {"k1", "k2", "k3"}
BulkProcs == {"run1", "run2"}
BulkOps == [p \in BulkProcs |->
    IF p = "run1"
      THEN {Read({"k1", "k2"}, "c1"), Read({"k1", "k2", "k3"}, "c1")}
      ELSE {Read({"k3"}, "c2"), Read({"k2", "k3"}, "c2")}]
BulkBudget == [p \in BulkProcs |-> 2]

=============================================================================
