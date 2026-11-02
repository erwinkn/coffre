------------------------------ MODULE MCWriting ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Writing.tla.                                *)
(***************************************************************************)
EXTENDS Writing

\* Ada writes key k twice at once while her grant is taken away and her
\* session revoked.
RevokeProcs == {"w1", "w2", "rev", "end", "ck"}

\* Ada writes key k while an Owner redefines her role and changes the
\* policy, and a maintainer archives env.
PlaceProcs == {"w1", "rol", "pol", "arc", "ck"}

\* Ada regenerates key k in a fork while its parent is archived, the
\* parent's key she replaces is written, and the parent's key whose level
\* she inherits is marked sensitive.
ForkProcs == {"w1", "par", "rep", "mrk", "ck"}

\* Ada writes key k while her session is revoked and a database writer puts
\* its row back, live.
TamperProcs == {"w1", "end", "dbw", "ck"}

\* Bob and Cy each add svc while an Owner demotes Bob and changes the
\* policy so that only Owners add.
AddProcs == {"bob", "cy", "dem", "pol", "ck"}

\* Bob, no admin, sets up svc with a first grant at a place, as the services
\* setting lets him, while an Owner redefines the roles and closes the
\* setting, and a maintainer archives the place.
SetUpProcs == {"bob", "rol", "cls", "plc", "ck"}
=============================================================================
