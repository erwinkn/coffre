------------------------------ MODULE MCBatching ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Batching.tla, as MC.tla's of Coffre.tla.    *)
(***************************************************************************)
EXTENDS Batching

-----------------------------------------------------------------------------
(* Two requests of one principal's, each the same two keys of three, with at
   most two keys in the cap's set, the caller's standing changed once and time
   ageing a row once: every row's start, and every order of their statements. *)

BatchKeys == {"k1", "k2", "k3"}
BatchBatches == {"b1", "b2"}
BatchOrder == [b \in BatchBatches |-> <<"k1", "k2">>]

(* The same, the second request naming a key the rules refuse (a reference
   ended): it must cost nothing of the cap, nor wait on the lock, nor hand back
   its other value. *)

RefusedOrder == [b \in BatchBatches |-> IF b = "b1" THEN <<"k1", "k2">> ELSE <<"k2", "k3">>]

=============================================================================
