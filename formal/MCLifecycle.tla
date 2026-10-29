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
    CASE p = "s1" -> {[tok |-> "j1", b |-> "b", evil |-> FALSE, aud |-> "us"]}
      [] p = "s2" -> {[tok |-> "j1", b |-> "b", evil |-> FALSE, aud |-> "us"], [tok |-> "j2", b |-> "b", evil |-> FALSE, aud |-> "us"]}
      [] p = "admin" -> {"remove", "removeRestore"}
      [] p = "rev" -> {"x1", "cS"}
      [] OTHER -> {}]

\* One ID token presented twice, by two runs, the binding's rate room for both.
ReplayProcs == {"s1", "s2", "u1"}
ReplayOps == [p \in ReplayProcs |-> CASE p \in {"s1", "s2"} -> {[tok |-> "j1", b |-> "b", evil |-> FALSE, aud |-> "us"]} [] OTHER -> {}]

\* A run signs in while a manager unbinds its binding; a use of what it got.
UnbindProcs == {"s1", "ub", "u1"}
UnbindOps == [p \in UnbindProcs |-> CASE p = "s1" -> {[tok |-> "j1", b |-> "b", evil |-> FALSE, aud |-> "us"]} [] OTHER -> {}]

\* A manager revokes svc's token while an admin takes the right away; a use of it.
RevokeProcs == {"rev", "admin", "u1"}
RevokeOps == [p \in RevokeProcs |-> CASE p = "rev" -> {"cS"} [] p = "admin" -> {"unmanage"} [] OTHER -> {}]

\* Ada binds svc's CI (b3, through the vault, as a token is issued) while an
\* admin demotes her; a run signs in through b3 once it is there, and uses
\* what it got (PR 3a).
BindProcs == {"ada", "admin", "s1", "u1"}
BindOps == [p \in BindProcs |-> CASE p = "ada" -> {"bind"} [] p = "admin" -> {"demote"}
                                  [] p = "s1" -> {[tok |-> "j1", b |-> "b3", evil |-> FALSE, aud |-> "us"]} [] OTHER -> {}]

\* Ada gives svc a token while an Owner's policy change takes that right
\* from her role, her member row untouched; a use meanwhile (review r3).
PolicyProcs == {"ada", "pol", "u1"}
PolicyOps == [p \in PolicyProcs |-> {}]

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
      [] p = "s2" -> {[tok |-> "bad", b |-> "b", evil |-> TRUE, aud |-> "us"], [tok |-> "e2", b |-> "b2", evil |-> TRUE, aud |-> "us"],
                      \* A token b's issuer signed for another instance, which evil names as the audience to hold it to.
                      [tok |-> "x", b |-> "b", evil |-> TRUE, aud |-> "other"]}
      [] OTHER -> {}]

=============================================================================
