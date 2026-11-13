------------------------------ MODULE MCIssuing ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Issuing.tla, as MC.tla's of Coffre.tla.     *)
(***************************************************************************)
EXTENDS Issuing

Op(kind, actor, who) == [kind |-> kind, actor |-> actor, who |-> who]

-----------------------------------------------------------------------------
(* Issuing: Olga issues the service a token, twice, while Omar demotes her,
   removes and admits her again, or removes the service, and two first uses
   of the token an older release issued, by Olga, seal it at once. *)

IssuingProcs == {"olga", "omar", "use1", "use2"}
IssuingOps == [p \in IssuingProcs |->
    CASE p = "olga" -> {Op("issue", "olga", "svc")}
      [] p = "omar" -> {Op("demote", "omar", "olga"), Op("readmit", "omar", "olga"), Op("remove", "omar", "svc")}
      [] p \in {"use1", "use2"} -> {Op("seal", None, "olga")}]
IssuingBudget == [p \in IssuingProcs |-> IF p = "olga" THEN 2 ELSE 1]

-----------------------------------------------------------------------------
(* IssuingFlip: Olga issues the service a token, and a first use seals the
   older one, while Omar demotes and promotes her, three times: her seal
   comes back to a value it had, as a demotion undone leaves it. *)

IssuingFlipProcs == {"olga", "omar", "use1"}
IssuingFlipOps == [p \in IssuingFlipProcs |->
    CASE p = "olga" -> {Op("issue", "olga", "svc")}
      [] p = "omar" -> {Op("demote", "omar", "olga"), Op("promote", "omar", "olga")}
      [] p = "use1" -> {Op("seal", None, "olga")}]
IssuingFlipBudget == [p \in IssuingFlipProcs |-> IF p = "omar" THEN 3 ELSE 1]

=============================================================================
