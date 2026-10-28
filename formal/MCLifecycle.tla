----------------------------- MODULE MCLifecycle -----------------------------
(***************************************************************************)
(* The scenarios TLC checks of Lifecycle.tla, each under both placements:  *)
(* Placement is the configuration's constant.                              *)
(***************************************************************************)
EXTENDS Lifecycle

\* Ada gives svc a token while an admin demotes her and her session, or
\* the token, is revoked; svc uses its token meanwhile.
IssueProcs == {"ada", "admin", "rev", "u1"}
IssueOps == [p \in IssueProcs |-> CASE p = "admin" -> {"demote"} [] p = "rev" -> {"cA", "t"} [] OTHER -> {}]

\* Two CI runs sign in through one binding, at most one a window, while
\* svc is removed (and admitted again) or a credential revoked; a use
\* names whichever credential went out.
SignInProcs == {"s1", "s2", "admin", "rev", "u1"}
SignInOps == [p \in SignInProcs |-> CASE p = "admin" -> {"remove", "removeRestore"} [] p = "rev" -> {"x1", "cS"} [] OTHER -> {}]

\* A database writer puts back, forges or edits a row of svc's while it is
\* removed or its token revoked; two uses.
ForgeProcs == {"writer", "admin", "rev", "u1", "u2"}
ForgeOps == [p \in ForgeProcs |-> CASE p = "writer" -> {"putBack", "forge", "edit"} [] p = "admin" -> {"remove"} [] p = "rev" -> {"cS"} [] OTHER -> {}]

\* The app's own code, an attacker's, gives svc a token in Ada's name
\* while she is demoted or her session revoked.
CompromisedProcs == {"evil", "admin", "rev", "u1"}
CompromisedOps == [p \in CompromisedProcs |-> CASE p = "admin" -> {"demote"} [] p = "rev" -> {"cA"} [] OTHER -> {}]

=============================================================================
