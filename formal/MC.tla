--------------------------------- MODULE MC ---------------------------------
(***************************************************************************)
(* The scenarios TLC checks: who runs what, from which state. Each one is  *)
(* a configuration, formal/<Name>.cfg, which names its definitions here.   *)
(* Every process runs its operations one after another, choosing each from *)
(* its set; TLC tries every choice and every interleaving.                 *)
(***************************************************************************)
EXTENDS Coffre

Op(kind, actor, who, at) == [kind |-> kind, actor |-> actor, who |-> who, at |-> at]

\* Lock order is the principals' sort order, as `ORDER BY principal` gives it.
AllRanks == [m \in {"ada", "olga", "omar", "root", "sam"} |->
               CASE m = "ada" -> 1 [] m = "olga" -> 2 [] m = "omar" -> 3 [] m = "root" -> 4 [] m = "sam" -> 5]

-----------------------------------------------------------------------------
(* Deletion: an owner deletes an archived place while another grants on it,
   restores it or renames it. Both #134 races are here. *)

DeletionMembers == {"ada", "olga", "omar"}
DeletionRank == [m \in DeletionMembers |-> AllRanks[m]]
DeletionOwners == {"olga", "omar"}
DeletionProcs == {"deleter", "admin"}
DeletionOps == [p \in DeletionProcs |->
    IF p = "deleter"
      THEN {Op("delete", "olga", None, "proj"), Op("delete", "olga", None, "env")}
      ELSE {Op("grant", "omar", "ada", "proj"), Op("grant", "omar", "ada", "env"),
            Op("revoke", "omar", "ada", "env"),
            Op("unarchive", "omar", None, "proj"), Op("unarchive", "omar", None, "env"),
            Op("rename", "omar", None, "proj"), Op("rename", "omar", None, "env")}]
DeletionBudget == [p \in DeletionProcs |-> 2]
DeletionArchived == {"proj", "env"}
DeletionGrants == {[who |-> "ada", at |-> "env"]}

-----------------------------------------------------------------------------
(* Reads during a deletion: a place is archived, then deleted, while members
   holding each kind of grant, and a root admin, read and write there, and an
   owner adds an environment or renames a key. *)

ReadingMembers == {"ada", "olga", "root", "sam"}
ReadingRank == [m \in ReadingMembers |-> AllRanks[m]]
ReadingOwners == {"olga"}
ReadingRoots == {"root"}
ReadingProcs == {"reader", "archiver", "deleter"}
ReadingOps == [p \in ReadingProcs |->
    CASE p = "reader" -> {Op("read", "root", "root", "env"), Op("read", "sam", "sam", "env"),
                          Op("read", "ada", "ada", "env"), Op("write", "sam", "sam", "env"),
                          Op("addenv", "olga", None, "proj"), Op("renamekey", "olga", None, "env")}
      [] p = "archiver" -> {Op("archive", "olga", None, "proj"), Op("archive", "olga", None, "env")}
      [] p = "deleter" -> {Op("delete", "olga", None, "proj"), Op("delete", "olga", None, "env")}]
ReadingBudget == [p \in ReadingProcs |-> IF p = "reader" THEN 2 ELSE 1]
ReadingGrants == {[who |-> "ada", at |-> "proj"], [who |-> "sam", at |-> "*"]}

-----------------------------------------------------------------------------
(* Members: a member signs in, reads and writes while an owner removes them
   or changes their grants, and the vault moves to a new key. *)

MembersMembers == {"ada", "olga"}
MembersRank == [m \in MembersMembers |-> AllRanks[m]]
MembersOwners == {"olga"}
MembersProcs == {"signer", "admin", "reader", "rotator"}
MembersOps == [p \in MembersProcs |->
    CASE p = "signer" -> {Op("signin", "ada", "ada", None)}
      [] p = "admin" -> {Op("remove", "olga", "ada", None), Op("grant", "olga", "ada", "proj"),
                         Op("revoke", "olga", "ada", "env")}
      [] p = "reader" -> {Op("read", "ada", "ada", "env"), Op("write", "ada", "ada", "env")}
      [] p = "rotator" -> {Op("rotate", None, None, None)}]
MembersBudget == [p \in MembersProcs |-> IF p = "rotator" THEN 1 ELSE 2]
MembersGrants == {[who |-> "ada", at |-> "env"]}

-----------------------------------------------------------------------------
(* Lock order: two owners change each other's grants while the vault rotates
   its key, which locks every member, and a member reads. *)

LocksMembers == {"ada", "olga", "omar"}
LocksRank == [m \in LocksMembers |-> AllRanks[m]]
LocksOwners == {"olga", "omar"}
LocksProcs == {"olga", "omar", "rotator"}
LocksOps == [p \in LocksProcs |->
    CASE p = "olga" -> {Op("grant", "olga", "omar", "env"), Op("remove", "olga", "ada", None)}
      [] p = "omar" -> {Op("grant", "omar", "olga", "env"), Op("read", "omar", "omar", "env")}
      [] p = "rotator" -> {Op("rotate", None, None, None)}]
LocksBudget == [p \in LocksProcs |-> IF p = "rotator" THEN 1 ELSE 2]
LocksGrants == {[who |-> "omar", at |-> "proj"]}

-----------------------------------------------------------------------------
(* Everything at once: two owners each run two of nearly every operation on
   places and grants, while members read, write and sign in. *)

MixedMembers == {"ada", "olga", "root", "sam"}
MixedRank == [m \in MixedMembers |-> AllRanks[m]]
MixedOwners == {"olga"}
MixedRoots == {"root"}
MixedProcs == {"owner1", "owner2", "member"}
OwnerOps == {Op("archive", "olga", None, "proj"), Op("archive", "olga", None, "env"),
             Op("unarchive", "olga", None, "env"), Op("rename", "olga", None, "env"),
             Op("delete", "olga", None, "proj"), Op("delete", "olga", None, "env"),
             Op("grant", "olga", "ada", "env"), Op("revoke", "olga", "ada", "proj"),
             Op("grant", "olga", "sam", "proj"), Op("remove", "olga", "sam", None)}
MixedOps == [p \in MixedProcs |->
    IF p = "member"
      THEN {Op("read", "ada", "ada", "env"), Op("read", "sam", "sam", "env"), Op("read", "root", "root", "env"),
            Op("write", "ada", "ada", "env"), Op("signin", "sam", "sam", None), Op("rotate", None, None, None)}
      ELSE OwnerOps]
MixedBudget == [p \in MixedProcs |-> IF p = "owner1" THEN 2 ELSE 1]
MixedGrants == {[who |-> "ada", at |-> "proj"], [who |-> "sam", at |-> "*"]}

=============================================================================
