-------------------------- MODULE MCWorkloadTripwire --------------------------
(***************************************************************************)
(* The scenarios TLC checks of WorkloadTripwire.tla, as MC.tla's of        *)
(* Coffre.tla.                                                             *)
(***************************************************************************)
EXTENDS WorkloadTripwire

Ev(kind) == [kind |-> kind]
Kinds == {"crash", "down", "restart", "redeploy", "narrow", "enroll", "leave"}
At(most) == [k \in Kinds |-> IF k \in DOMAIN most THEN most[k] ELSE 0]

-----------------------------------------------------------------------------
(* Deploys: one replica crashes and restarts once, redeploys twice on the
   same code and narrows twice, and nobody else holds the code. *)

DeploysProcs == {"dep"}
DeploysOps == [p \in DeploysProcs |-> {Ev(k) : k \in {"crash", "restart", "redeploy", "narrow"}}]
DeploysBudget == [p \in DeploysProcs |-> 6]
DeploysMost == At([crash |-> 1, restart |-> 1, redeploy |-> 2, narrow |-> 2])

-----------------------------------------------------------------------------
(* Thief: beside one replica, which may crash, a thief enrolls up to five
   times, leaving in between whenever it likes. *)

ThiefProcs == {"dep", "thief"}
ThiefOps == [p \in ThiefProcs |->
    IF p = "dep" THEN {Ev("crash")} ELSE {Ev("enroll"), Ev("leave")}]
ThiefBudget == [p \in ThiefProcs |-> IF p = "dep" THEN 1 ELSE 9]
ThiefMost == At([crash |-> 1, enroll |-> 5, leave |-> 4])

-----------------------------------------------------------------------------
(* Copy: beside one replica, which may go down and come back, a thief
   enrolls, and may leave. *)

CopyProcs == {"dep", "thief"}
CopyOps == [p \in CopyProcs |->
    IF p = "dep" THEN {Ev("down"), Ev("restart")} ELSE {Ev("enroll"), Ev("leave")}]
CopyBudget == [p \in CopyProcs |-> IF p = "dep" THEN 2 ELSE 3]
CopyMost == At([down |-> 1, restart |-> 1, enroll |-> 2, leave |-> 1])

=============================================================================
