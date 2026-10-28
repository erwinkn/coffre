----------------------------- MODULE MCLifecycle -----------------------------
(***************************************************************************)
(* The scenarios TLC checks of Lifecycle.tla.                              *)
(***************************************************************************)
EXTENDS Lifecycle

\* Ada gives svc a token while an admin demotes her and her session, or
\* the token, is revoked; svc uses its token meanwhile.
IssueProcs == {"ada", "admin", "rev", "u1"}
IssueOps == [p \in IssueProcs |-> CASE p = "admin" -> {"demote"} [] p = "rev" -> {"cA", "t"} [] OTHER -> {}]

\* Two CI runs sign in through one binding, at most one a window, with one
\* ID token (replayed) or two, while svc is removed (and admitted again) or
\* a credential revoked; a use presents whichever token went out.
SignInProcs == {"s1", "s2", "admin", "rev", "u1"}
SignInOps == [p \in SignInProcs |->
    CASE p = "s1" -> {[tok |-> "j1", b |-> "b", evil |-> FALSE]}
      [] p = "s2" -> {[tok |-> "j1", b |-> "b", evil |-> FALSE], [tok |-> "j2", b |-> "b", evil |-> FALSE]}
      [] p = "admin" -> {"remove", "removeRestore"}
      [] p = "rev" -> {"x1", "cS"}
      [] OTHER -> {}]

\* One ID token presented twice, by two runs, the binding's rate room for both.
ReplayProcs == {"s1", "s2", "u1"}
ReplayOps == [p \in ReplayProcs |-> CASE p \in {"s1", "s2"} -> {[tok |-> "j1", b |-> "b", evil |-> FALSE]} [] OTHER -> {}]

\* A run signs in while a manager unbinds its binding; a use of what it got.
UnbindProcs == {"s1", "ub", "u1"}
UnbindOps == [p \in UnbindProcs |-> CASE p = "s1" -> {[tok |-> "j1", b |-> "b", evil |-> FALSE]} [] OTHER -> {}]

\* A manager revokes svc's token while an admin takes the right away; a use of it.
RevokeProcs == {"rev", "admin", "u1"}
RevokeOps == [p \in RevokeProcs |-> CASE p = "rev" -> {"cS"} [] p = "admin" -> {"unmanage"} [] OTHER -> {}]

\* A database writer puts back, forges, edits or moves a row while svc is
\* removed or its token revoked; two uses.
ForgeProcs == {"writer", "admin", "rev", "u1", "u2"}
ForgeOps == [p \in ForgeProcs |-> CASE p = "writer" -> {"putBack", "forge", "edit", "move"} [] p = "admin" -> {"remove"} [] p = "rev" -> {"cS"} [] OTHER -> {}]

\* The app's own code, an attacker's: gives svc a token in Ada's name while
\* she is demoted or her session revoked; writes a binding of its own; and
\* signs in with a token nobody signed, or through its binding.
CompromisedProcs == {"evil", "eb", "s2", "admin", "rev", "u1"}
CompromisedOps == [p \in CompromisedProcs |->
    CASE p = "admin" -> {"demote"}
      [] p = "rev" -> {"cA"}
      [] p = "eb" -> {"bind"}
      [] p = "s2" -> {[tok |-> "bad", b |-> "b", evil |-> TRUE], [tok |-> "e2", b |-> "b2", evil |-> TRUE]}
      [] OTHER -> {}]

=============================================================================
