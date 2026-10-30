------------------------------ MODULE MCWaysIn ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of WaysIn.tla.                                 *)
(***************************************************************************)
EXTENDS WaysIn

\* Two uses through the MCP connection while its person disconnects it.
RevokeProcs == {"u1", "u2", "rk"}
RevokeOps == [p \in RevokeProcs |-> IF p \in {"u1", "u2"} THEN {"k"} ELSE {}]

\* Two uses through the Cloudflare binding while a manager unbinds it.
UnbindProcs == {"u1", "u2", "ub"}
UnbindOps == [p \in UnbindProcs |-> IF p \in {"u1", "u2"} THEN {"w"} ELSE {}]

\* Two uses, through any way in, while an admin removes the account, or
\* removes it and admits it again, the connection swept after.
RemoveProcs == {"u1", "u2", "admin"}
RemoveOps == [p \in RemoveProcs |-> IF p = "admin" THEN {"remove", "removeRestore"} ELSE Ways]

\* A database writer puts a row back while the connection is revoked and
\* the binding unbound; a use through either.
ForgeProcs == {"u1", "rk", "ub", "writer"}
ForgeOps == [p \in ForgeProcs |-> IF p = "u1" THEN Rowed ELSE {}]

=============================================================================
