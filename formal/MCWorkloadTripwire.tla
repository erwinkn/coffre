-------------------------- MODULE MCWorkloadTripwire --------------------------
(***************************************************************************)
(* The scenarios TLC checks of WorkloadTripwire.tla, as MC.tla's of        *)
(* Coffre.tla.                                                             *)
(***************************************************************************)
EXTENDS WorkloadTripwire

Ev(kind) == [kind |-> kind]
Kinds == {"crash", "down", "restart", "redeploy", "narrow", "enroll", "leave", "lift"}
At(most) == [k \in Kinds |-> IF k \in DOMAIN most THEN most[k] ELSE 0]

-----------------------------------------------------------------------------
(* Deploys: one replica crashes once and restarts, trying twice, redeploys
   twice on the same code and narrows once, and nobody else holds the code. *)

DeploysProcs == {"dep"}
DeploysOps == [p \in DeploysProcs |-> {Ev(k) : k \in {"crash", "restart", "redeploy", "narrow"}}]
DeploysBudget == [p \in DeploysProcs |-> 6]
DeploysMost == At([crash |-> 1, restart |-> 2, redeploy |-> 2, narrow |-> 1])

-----------------------------------------------------------------------------
(* Thief: beside one replica, which may crash, a thief enrolls up to five
   times, leaving in between whenever it likes. *)

ThiefProcs == {"dep", "thief"}
ThiefOps == [p \in ThiefProcs |->
    IF p = "dep" THEN {Ev("crash")} ELSE {Ev("enroll"), Ev("leave")}]
ThiefBudget == [p \in ThiefProcs |-> IF p = "dep" THEN 1 ELSE 9]
ThiefMost == At([crash |-> 1, enroll |-> 5, leave |-> 4])

-----------------------------------------------------------------------------
(* Reenroll: beside one replica, which keeps running, a thief enrolls up to
   three times, leaving in between whenever it likes. *)

ReenrollProcs == {"thief"}
ReenrollOps == [p \in ReenrollProcs |-> {Ev("enroll"), Ev("leave")}]
ReenrollBudget == [p \in ReenrollProcs |-> 5]
ReenrollMost == At([enroll |-> 3, leave |-> 2])

-----------------------------------------------------------------------------
(* Lifting: a thief enrolls beside one replica and stays, the rule's runs
   commit their freezes after they count, and Omar lifts the freeze. *)

LiftingProcs == {"thief", "omar"}
LiftingOps == [p \in LiftingProcs |-> IF p = "thief" THEN {Ev("enroll")} ELSE {Ev("lift")}]
LiftingBudget == [p \in LiftingProcs |-> 1]
LiftingMost == At([enroll |-> 1, lift |-> 1])

-----------------------------------------------------------------------------
(* Copy: beside one replica, which may go down and come back, a thief
   enrolls, and may leave. *)

CopyProcs == {"dep", "thief"}
CopyOps == [p \in CopyProcs |->
    IF p = "dep" THEN {Ev("down"), Ev("restart")} ELSE {Ev("enroll"), Ev("leave")}]
CopyBudget == [p \in CopyProcs |-> IF p = "dep" THEN 2 ELSE 3]
CopyMost == At([down |-> 1, restart |-> 1, enroll |-> 2, leave |-> 1])

=============================================================================
