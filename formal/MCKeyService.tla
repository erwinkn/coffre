----------------------------- MODULE MCKeyService ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of KeyService.tla, as MC.tla's of Coffre.tla.  *)
(***************************************************************************)
EXTENDS KeyService

-----------------------------------------------------------------------------
(* One isolate: two uses, a read of three keys and a rewrap of two, with two
   slots, while KMS answers in any order, late or never. *)

KeyProcs == {"use1", "use2", "read", "rewrap"}
KeyUses == {"use1", "use2"}
KeyKeys == [p \in KeyProcs |-> CASE p = "read" -> 3 [] p = "rewrap" -> 2 [] OTHER -> 1]

=============================================================================
