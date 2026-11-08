----------------------------- MODULE MCKeyService ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of KeyService.tla, as MC.tla's of Coffre.tla.  *)
(***************************************************************************)
EXTENDS KeyService

-----------------------------------------------------------------------------
(* One isolate: two uses, a read of three keys and a rewrap of two, with two
   slots, while KMS answers in any order, late or never. The read's keys are
   under the vault's kek, a previous one and the kek again, as a batch read
   across a rotation; the rewrap's under a previous kek, then the kek. *)

KeyProcs == {"use1", "use2", "read", "rewrap"}
KeyUses == {"use1", "use2"}
KeyKeys == [p \in KeyProcs |-> CASE p = "read" -> 3 [] p = "rewrap" -> 2 [] OTHER -> 1]
KeyKek == [p \in KeyProcs |->
    CASE p = "read" -> <<"current", "previous", "current">>
      [] p = "rewrap" -> <<"previous", "current">>
      [] OTHER -> <<"current">>]

=============================================================================
