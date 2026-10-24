---------------------------- MODULE MCCredentials ----------------------------
(***************************************************************************)
(* The scenarios TLC checks of Credentials.tla, as MC.tla's of Coffre.tla. *)
(***************************************************************************)
EXTENDS Credentials

Op(kind, cred, token, at, proxy) == [kind |-> kind, cred |-> cred, token |-> token, at |-> at, proxy |-> proxy]
Exchange(t) == Op("exchange", None, t, None, FALSE)

-----------------------------------------------------------------------------
(* Exchanging: two CI runs present the same ID token at once, and each
   another of its own, while an owner untrusts the binding, replaces the
   issuer's keys, or removes the account and admits it again. *)

ExchangingProcs == {"run1", "run2", "owner"}
ExchangingOps == [p \in ExchangingProcs |->
    CASE p = "run1" -> {Exchange("t1"), Exchange("t2")}
      [] p = "run2" -> {Exchange("t1"), Exchange("t3")}
      [] p = "owner" -> {Op("unbind", None, None, "b1", FALSE), Op("replace", None, None, "b1", FALSE),
                         Op("remove", None, None, None, FALSE), Op("restore", None, None, None, FALSE)}]
ExchangingBudget == [p \in ExchangingProcs |-> IF p = "run2" THEN 1 ELSE 2]

-----------------------------------------------------------------------------
(* Revoking: a run reads through its token, through the proxy or by an
   export, and through a credential an exchange issued it, while an owner
   revokes the token, untrusts the binding, or removes the account, and
   another admits it again. *)

RevokingProcs == {"reader", "run", "owner", "admin"}
RevokingOps == [p \in RevokingProcs |->
    CASE p = "reader" -> {Op("use", "tok", None, None, TRUE), Op("use", "tok", None, None, FALSE),
                          Op("use", "exchanged", None, None, FALSE)}
      [] p = "run" -> {Exchange("t1")}
      [] p = "owner" -> {Op("revoke", "tok", None, None, FALSE), Op("revoke", "exchanged", None, None, FALSE),
                         Op("unbind", None, None, "b1", FALSE), Op("replace", None, None, "b1", FALSE),
                         Op("remove", None, None, None, FALSE)}
      [] p = "admin" -> {Op("restore", None, None, None, FALSE)}]
RevokingBudget == [p \in RevokingProcs |-> IF p = "reader" THEN 2 ELSE 1]

=============================================================================
