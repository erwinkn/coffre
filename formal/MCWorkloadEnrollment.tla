------------------------- MODULE MCWorkloadEnrollment -------------------------
(***************************************************************************)
(* The scenarios TLC checks of WorkloadEnrollment.tla, as MC.tla's of      *)
(* Coffre.tla.                                                             *)
(***************************************************************************)
EXTENDS WorkloadEnrollment

Op(kind, code, caller) == [NoOp EXCEPT !.kind = kind, !.code = code, !.caller = caller]

-----------------------------------------------------------------------------
(* Capacity: two instances enroll on one code of one replica, and renew,
   restart and log out, and a third enrolls, while the clock runs and CI
   promotes the next code, with or without --now. *)

CapacityProcs == {"e1", "e2", "e3", "ci"}
CapacityOps == [p \in CapacityProcs |->
    CASE p = "ci" -> {[Op("promote", "c2", "deploy") EXCEPT !.now = n] : n \in BOOLEAN}
      [] p = "e3" -> {Op("enroll", "c1", None)}
      [] OTHER    -> {Op("enroll", "c1", None), Op("renew", None, None), Op("logout", None, None)}]
CapacityBudget == [p \in CapacityProcs |-> CASE p = "e3" -> 1 [] p = "ci" -> 1 [] OTHER -> 2]

-----------------------------------------------------------------------------
(* Minting: Omar, an Owner, Vic, a Viewer who manages the service, or CI
   mints a code, while Olga demotes Omar, a thief inside the app, or in a
   child of CI's session, mints or promotes one, and an instance enrolls on
   what was minted. *)

MintingProcs == {"m", "olga", "thief", "e1"}
MintingOps == [p \in MintingProcs |->
    CASE p = "m"     -> {Op("mint", "c2", c) : c \in {"omar", "vic", "deploy"}}
      [] p = "olga"  -> {Op("demote", None, "omar")}
      [] p = "thief" -> {Op("mint", "c3", c) : c \in {"api", "api.child", "deploy.child"}}
                          \cup {Op("promote", "c2", c) : c \in {"api", "api.child", "deploy.child"}}
      [] p = "e1"    -> {Op("enroll", "c2", None)}]
MintingBudget == [p \in MintingProcs |-> IF p = "e1" THEN 2 ELSE 1]

=============================================================================
