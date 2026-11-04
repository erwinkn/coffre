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
Op(kind) == [kind |-> kind, cred |-> None]
Changing == {Op("first"), Op("remove"), Op("reset")}
FactorOps == [p \in FactorProcs |-> IF p = "chg" THEN Changing ELSE {Op("issue")}]

-----------------------------------------------------------------------------
(* FactorApp: the app issues on Ada's session (an MCP connection, a token
   the vault leaves to it), and the previous release's app signs her in
   during the rollout, while a change to her passkeys runs; a request asks
   with what either issued (T176 PR 4). *)

FactorAppProcs == {"app", "prev", "chg", "req"}
FactorAppOps == [p \in FactorAppProcs |->
    CASE p = "chg" -> Changing
      [] p = "req" -> {[kind |-> "use", cred |-> "s"], [kind |-> "use", cred |-> "o"]}
      [] OTHER -> {Op("issue")}]

-----------------------------------------------------------------------------
(* FactorSignin: Ada, a Developer with no passkey, signs in under `optional`
   while an Owner promotes her to one (T176 PR 4b, review r1 of #500). *)

FactorSigninProcs == {"sgn", "pro"}
FactorSigninOps == [p \in FactorSigninProcs |-> IF p = "sgn" THEN {Op("signin")} ELSE {Op("promote")}]

=============================================================================
