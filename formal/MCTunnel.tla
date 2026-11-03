------------------------------- MODULE MCTunnel -------------------------------
(***************************************************************************)
(* The scenario TLC checks of Tunnel.tla: a check every four ticks, each    *)
(* given two to answer, as with `recheckSeconds` over the ten seconds a     *)
(* check may take; the handle revoked, its item saved anew and another     *)
(* item of the environment saved, each at any tick, a check answering in   *)
(* any time or never. The bound is R + D.                                  *)
(***************************************************************************)
EXTENDS Tunnel
=============================================================================
