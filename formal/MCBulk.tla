-------------------------------- MODULE MCBulk --------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Bulk.tla, as MC.tla's of Coffre.tla.        *)
(***************************************************************************)
EXTENDS Bulk

Read(keys, cred, remote) == [kind |-> "read", keys |-> keys, cred |-> cred, remote |-> remote]

-----------------------------------------------------------------------------
(* Bulk reads: one principal, at most two keys of three in a window of two
   ticks, reads on two credentials at once, each with a local key or a key
   service, while the clock runs. *)

BulkKeys == {"k1", "k2", "k3"}
BulkProcs == {"run1", "run2"}
BulkOps == [p \in BulkProcs |->
    IF p = "run1"
      THEN {Read({"k1", "k2"}, "c1", FALSE), Read({"k1", "k2"}, "c1", TRUE), Read({"k1", "k2", "k3"}, "c1", FALSE)}
      ELSE {Read({"k3"}, "c2", TRUE), Read({"k2", "k3"}, "c2", FALSE)}]
BulkBudget == [p \in BulkProcs |-> 2]

=============================================================================
