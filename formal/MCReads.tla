---------------------------- MODULE MCReads ----------------------------
(***************************************************************************)
(* The scenarios TLC checks of Reads.tla, as MC.tla's of Coffre.tla.      *)
(***************************************************************************)
EXTENDS Reads

Obj(acct, pl, v, src) == [acct |-> acct, pl |-> pl, v |-> v, src |-> src]
Ch(obj, val) == [k |-> "c", obj |-> obj, val |-> val, cred |-> "-", key |-> "-"]
Use(cred, key) == [k |-> "u", obj |-> "-", val |-> Obj("-", "-", 0, "-"), cred |-> cred, key |-> key]

-----------------------------------------------------------------------------
(* c1 and c2 act as A and B; k1 is at p, version 1, k2 at q, version 2; r, at p, refers to k1. c1 reads through r; r is
   repointed to k2 and c1 moved to B; c1 reads through r again, c2 reads k1. Every use's projection differs from every
   other's, and the first's from what the live rows say once the two changes commit. *)

ReadsStart ==
    [o \in {"c1", "c2", "k1", "k2", "r"} |->
        CASE o = "c1" -> Obj("A", "-", 0, "-")
          [] o = "c2" -> Obj("B", "-", 0, "-")
          [] o = "k1" -> Obj("-", "p", 1, "-")
          [] o = "k2" -> Obj("-", "q", 2, "-")
          [] o = "r"  -> Obj("-", "p", 0, "k1")]

ReadsScript ==
    << Use("c1", "r"),
       Ch("r", Obj("-", "p", 0, "k2")),
       Ch("c1", Obj("B", "-", 0, "-")),
       Use("c1", "r"),
       Use("c2", "k1") >>

=============================================================================
