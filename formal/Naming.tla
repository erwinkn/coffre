------------------------------- MODULE Naming --------------------------------
(***************************************************************************)
(* A use as the request names it (T145, PR B; review r2 of #412): the      *)
(* vault maps a key's name to its id once (`use_resolve`), keeps the map,  *)
(* and uses by the id. Between the two, the key may be renamed away and    *)
(* another made, or renamed, under its name. Every use the log records     *)
(* must be of the key the request named, as the use read it                *)
(* (`UsedAsNamed`): the id kept is only ever a shortcut to the name.       *)
(*                                                                         *)
(* One request names `K` at a place of two keys, k1 (named `K`) and k2.    *)
(* The map is the isolate's, read again after any `moved`.                 *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Budget,         \* how many steps the request's reads and uses take
    \* The protection: `use_credential` holds the rows it reads to the names
    \* the request gave (`moved`): a key no longer named `K` is not used, and
    \* nothing is written; the vault reads the map again. Off, it uses the id.
    HeldToNames

Ids == {"k1", "k2"}

VARIABLES
    name,           \* each key's name now
    mapped,         \* the isolate's id for `K`, or "none"
    moved,          \* whether `K`'s key was renamed away and another named `K`
    logged,         \* the uses the log holds: <<id, its name as the use read it>>
    left

vars == <<name, mapped, moved, logged, left>>

Init ==
    /\ name = [i \in Ids |-> IF i = "k1" THEN "K" ELSE "other"]
    /\ mapped = "none"
    /\ moved = FALSE
    /\ logged = {}
    /\ left = Budget

\* `use_resolve`: the key named `K` now, if any.
Resolve ==
    /\ left > 0
    /\ mapped' = IF \E i \in Ids : name[i] = "K" THEN CHOOSE i \in Ids : name[i] = "K" ELSE "none"
    /\ left' = left - 1
    /\ UNCHANGED <<name, moved, logged>>

\* `K`'s key renamed away (or deleted, its row renamed), and the other made, or renamed, `K`.
Rename ==
    /\ ~moved
    /\ moved' = TRUE
    /\ name' = [name EXCEPT !["k1"] = "gone", !["k2"] = "K"]
    /\ UNCHANGED <<mapped, logged, left>>

\* A use by the id the map holds.
Use ==
    /\ left > 0
    /\ mapped # "none"
    /\ IF HeldToNames /\ name[mapped] # "K"
         THEN /\ mapped' = "none"
              /\ UNCHANGED logged
         ELSE /\ logged' = logged \cup {<<mapped, name[mapped]>>}
              /\ UNCHANGED mapped
    /\ left' = left - 1
    /\ UNCHANGED <<name, moved>>

Done == left = 0 /\ UNCHANGED vars

Next == Resolve \/ Rename \/ Use \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ name \in [Ids -> {"K", "other", "gone"}]
    /\ mapped \in Ids \cup {"none"}
    /\ moved \in BOOLEAN

\* Every use the log records is of the key named `K` when the use read it.
UsedAsNamed == \A e \in logged : e[2] = "K"

=============================================================================
