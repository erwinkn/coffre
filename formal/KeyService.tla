------------------------------ MODULE KeyService -------------------------------
(***************************************************************************)
(* The key service's calls in one isolate (R75): who a call that opens or  *)
(* wraps a data key at AWS KMS may wait for. docs/formal.md says what this *)
(* covers.                                                                 *)
(*                                                                         *)
(* Each request opens some keys, one KMS request each, with a bound on how *)
(* many of its requests are in flight at once (core kek/aws-kms.ts,        *)
(* `CONCURRENCY`). A request in flight may answer at once, late or never:  *)
(* KMS can hang, and nothing here makes it answer (no fairness), which is  *)
(* the case that matters, a brownout. A use opens one key; a read, a wrap  *)
(* or a rewrap may open many. No lock is held across any of it (R75), and  *)
(* Coffre.tla holds the reads and wraps to that (StandingRecheckUnderHead).*)
(*                                                                         *)
(* Before R75 the bound was one pool per provider object, which a Worker   *)
(* keeps for the isolate: a request's call waited for a slot that another  *)
(* request's call held, behind a pending promise handed from one request   *)
(* to the other, and a use waited behind a read's hung calls past its own  *)
(* deadline (W331, measured: 5 s behind 8 hung calls).                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Procs,          \* concurrent requests in one isolate, each one a process
    Uses,           \* those that are uses
    Keys,           \* Keys[p]: how many keys p opens
    Slots           \* how many KMS requests may be in flight at once

CONSTANTS
    \* Each call's own requests take turns among themselves, and no other's
    \* (aws-kms.ts: the bound kept per operation, `CONCURRENCY` per call,
    \* whichever KEK each request goes to: a rotation's batch, under its kek
    \* and its previousKeks, takes turns in the same six). Off, one pool for
    \* every call of the isolate, as `Slots(8)` was.
    SlotsPerCall

VARIABLES
    pc,             \* pc[p]: "idle", "open" or "done"
    todo,           \* todo[p]: p's keys not yet sent
    inflight        \* inflight[p]: p's requests sent and not answered

vars == <<pc, todo, inflight>>

RECURSIVE SumOver(_, _)
SumOver(f, S) == IF S = {} THEN 0 ELSE LET x == CHOOSE y \in S : TRUE IN f[x] + SumOver(f, S \ {x})

\* The slots free to p's next request.
Free(p) == IF SlotsPerCall THEN Slots - inflight[p] ELSE Slots - SumOver(inflight, Procs)

Init ==
    /\ pc = [p \in Procs |-> "idle"]
    /\ todo = [p \in Procs |-> Keys[p]]
    /\ inflight = [p \in Procs |-> 0]

Start(p) ==
    /\ pc[p] = "idle"
    /\ pc' = [pc EXCEPT ![p] = "open"]
    /\ UNCHANGED <<todo, inflight>>

\* Send one more key's request, if a slot is free.
Send(p) ==
    /\ pc[p] = "open"
    /\ todo[p] > 0
    /\ Free(p) > 0
    /\ todo' = [todo EXCEPT ![p] = @ - 1]
    /\ inflight' = [inflight EXCEPT ![p] = @ + 1]
    /\ UNCHANGED pc

\* KMS answers one of p's requests, or the operation's deadline cancels it
\* (core kek/cancellation.ts): either way its slot is free again.
Answer(p) ==
    /\ inflight[p] > 0
    /\ inflight' = [inflight EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<pc, todo>>

Finish(p) ==
    /\ pc[p] = "open"
    /\ todo[p] = 0
    /\ inflight[p] = 0
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<todo, inflight>>

Finished == \A p \in Procs : pc[p] = "done"

Next == (\E p \in Procs : Start(p) \/ Send(p) \/ Answer(p) \/ Finish(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK ==
    /\ pc \in [Procs -> {"idle", "open", "done"}]
    /\ \A p \in Procs : todo[p] \in 0..Keys[p] /\ inflight[p] \in 0..Keys[p]

\* p has a key to send and no slot for it.
Waiting(p) == pc[p] = "open" /\ todo[p] > 0 /\ Free(p) = 0

\* A request waits for a slot only behind requests of its own call: never
\* behind another request's, hung or not, and so never for a promise that
\* another request settles (AGENTS.md, "What an isolate keeps").
WaitsOnlyBehindItsOwn == \A p \in Procs : Waiting(p) => inflight[p] > 0

\* A use, one key, never waits for a slot at all.
UsesNeverWait == \A u \in Uses : ~Waiting(u)

=============================================================================
