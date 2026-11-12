------------------------------ MODULE MCWriting ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Writing.tla. Each review round's P1 is an   *)
(* adversary of one of them, so each stays pinned: rounds 1 and 2 in       *)
(* Revoke, Place and Fork, round 3 in Names, round 5 in Protect, round 6   *)
(* in Tamper and Add, T190's forged seal in Forge, PR 3's fallback to      *)
(* today's path in FallBack and Forge, its caller in Caller (r2 of #469);  *)
(* PR 5's add, its session and its fallback, in Add and Forge, its         *)
(* session's generation in Rejoin (r1 of #474); PR 6's refusal records in  *)
(* Refuse, Caller and Add, and what still goes down today's path in        *)
(* FallBack and CallerShape.                                               *)
(***************************************************************************)
EXTENDS Writing

\* Ada writes key k twice at once while her grant is taken away and her
\* session revoked.
RevokeProcs == {"w1", "w2", "rev", "end", "ck"}

\* Ada writes key k while her grant is taken away and given back.
ABAProcs == {"w1", "rev", "bk", "ck"}

\* Ada writes key k while an Owner redefines her role and changes the
\* policy, and a maintainer archives env.
PlaceProcs == {"w1", "rol", "pol", "arc", "ck"}

\* Ada regenerates key k in a fork while its parent is archived, the
\* parent's key she replaces is written, and the parent's key whose level
\* she inherits is marked sensitive.
ForkProcs == {"w1", "par", "rep", "mrk", "ck"}

\* Ada writes key k at `env@me` while k is renamed, the fork's parent gains
\* k, sensitive, and her personal config is deleted.
NamesProcs == {"w1", "ren", "phn", "del", "ck"}

\* Ada writes key k while her session is revoked and a database writer puts
\* its row back, live, and another copies a token hash onto her credential.
TamperProcs == {"w1", "end", "dbw", "sub", "ck"}

\* Ada writes key k while her session is revoked, or her grant taken away,
\* and a database writer puts the row back and writes its seal into the
\* revoke's change (T190); Bob adds svc while he is demoted and his row put
\* back the same way. A forged grant goes down today's path, which must
\* refuse it too.
ForgeProcs == {"w1", "bob", "end", "rev", "dem", "fsg", "ck"}

\* Ada writes key k while it is made a reference, the roles redefined and
\* her session revoked: a try the vault served whose hold fails, then one
\* it no longer serves (the key a reference), goes down today's path (PR 3's
\* fallback; a refusal no longer does, PR 6). A roles change between its
\* decision and its commit stops it (`policyStill`, review r3 of #469); her
\* session revoked there does not (TodayStandsAtCommit, EXPECTED broken).
FallBackProcs == {"w1", "shp", "rol", "end", "ck"}

\* Ada writes key k while it is made a reference, the roles redefined, the
\* policy changed and env protected: the policy today's commit holds to is
\* the seals of all it read of it (T272), so each of the three changes after
\* the front door stops the write (TodayUnheld leaves one seal out of the
\* digest); and the two-trip path's hold reads the protection as it reads
\* the rest.
DigestProcs == {"w1", "shp", "rol", "pol", "prv", "ck"}

\* Ada writes key k while her grant is taken away and given back and her
\* session revoked: a try the vault served whose hold fails, then a refusal
\* (review r2 of #469). Before PR 6 the refusal went down today's path, which
\* wrote once the grant was back, for the caller the first try checked, her
\* session revoked since; now it is recorded, and the request ends there
\* (TodayCallerStandsAtDecision holds; without RefusalLogged it breaks).
CallerProcs == {"w1", "rev", "bk", "end", "ck"}

\* Ada writes key k while it is made a reference and her session revoked: a
\* try the vault served whose hold fails, then today's path, which goes on
\* with the caller the first try checked and writes, her session revoked
\* since (TodayCallerStandsAtDecision, EXPECTED broken: what the two-trip
\* path does not serve keeps today's window, PR 3b and PR 7).
CallerShapeProcs == {"w1", "shp", "end", "ck"}

\* Ada writes key k twice while her grant is taken away: one is refused and
\* recorded (PR 6), and a database writer copies that record, MAC and all,
\* as the newest change of her member object, her row put back to match.
RefuseProcs == {"w1", "w2", "rev", "rfl", "ck"}

\* Bob and Cy each add svc while an Owner demotes Bob and changes the
\* policy so that only Owners add, a database writer copies a token hash
\* onto Bob's credential (round 6), and the adders' session is revoked
\* (PR 5: the add's read holds it). A refused add goes down today's path.
AddProcs == {"bob", "cy", "dem", "pol", "sub", "end", "ck"}

\* Bob adds svc while an Owner removes him and restores him as an admin, his
\* session's row not yet revoked: his removal ended it all the same (its
\* generation is no longer his membership's), so neither a first try nor a
\* retry after the hold fails adds with it (review r1 of #474).
RejoinProcs == {"bob", "rmb", "ck"}

\* Bob, no admin, sets up svc with a first grant at a place, as the services
\* setting lets him, while an Owner redefines the roles and closes the
\* setting, and a maintainer archives the place.
SetUpProcs == {"bob", "rol", "cls", "plc", "ck"}

\* Bob, no admin, sets up svc with a first grant on a whole project while an
\* Owner protects one of its environments, a protected fork is made in it,
\* the project is renamed and another made under its slug, and the role's
\* scope project is renamed likewise.
ProtectProcs == {"bob", "prt", "nev", "slg", "scp", "ck"}
=============================================================================
