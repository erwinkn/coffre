------------------------------ MODULE MCFactor ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Factor.tla, as MC.tla's of Coffre.tla.      *)
(***************************************************************************)
EXTENDS Factor

-----------------------------------------------------------------------------
(* Factor: the vault issues Ada a handle on her session, and the previous
   release's vault another, while a change to her passkeys runs: her first
   one, a removal or an Owner's reset. *)

FactorProcs == {"iss", "old", "chg"}
Op(kind) == [kind |-> kind]
FactorOps == [p \in FactorProcs |-> IF p = "chg" THEN {Op("first"), Op("remove"), Op("reset")} ELSE {Op("issue")}]

=============================================================================
