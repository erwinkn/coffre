------------------------------ MODULE MCWriting ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Writing.tla.                                *)
(***************************************************************************)
EXTENDS Writing

\* Ada writes key k twice at once while her grant is taken away and her
\* session revoked.
RevokeProcs == {"w1", "w2", "rev", "end", "ck"}

\* Ada writes key k while an Owner protects env and a maintainer archives it.
PlaceProcs == {"w1", "pol", "arc", "ck"}

\* Bob and Cy each add svc while an Owner demotes Bob.
AddProcs == {"bob", "cy", "dem", "ck"}
=============================================================================
