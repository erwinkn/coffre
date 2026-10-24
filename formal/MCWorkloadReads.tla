---------------------------- MODULE MCWorkloadReads ----------------------------
(***************************************************************************)
(* The scenarios TLC checks of WorkloadReads.tla, as MC.tla's of           *)
(* Coffre.tla.                                                             *)
(***************************************************************************)
EXTENDS WorkloadReads

Op(kind, env, name, to) == [kind |-> kind, env |-> env, name |-> name, to |-> to]

-----------------------------------------------------------------------------
(* Reads: the workload reads any key of either place, copies one of prod's
   into dev or references it there, while Omar renames prod's keys onto
   each other's names, deletes and makes one again, or copies one into dev
   themselves. *)

ReadsProcs == {"wl", "omar"}
ReadsOps == [p \in ReadsProcs |->
    IF p = "wl"
      THEN {Op("read", e, n, None) : e \in Envs, n \in Names}
             \cup {Op("copy", "prod", n, "X") : n \in {"S", "W"}}
             \cup {Op("reference", "prod", n, "W") : n \in {"S", "W"}}
      ELSE {Op("rename", "prod", "W", "X"), Op("rename", "prod", "S", "W"),
            Op("recreate", "prod", "W", None), Op("copy", "prod", "S", "X")}]
ReadsBudget == [p \in ReadsProcs |-> IF p = "wl" THEN 3 ELSE 2]

=============================================================================
