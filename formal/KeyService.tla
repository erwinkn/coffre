------------------------------ MODULE KeyService -------------------------------
(***************************************************************************)
(* The key service's calls in one isolate (R75): who a call that opens or  *)
(* wraps a data key at AWS KMS may wait for, and how many of one call's    *)
(* requests are in flight at once. docs/formal.md says what this covers.   *)
(*                                                                         *)
(* Each request opens some keys, one KMS request each, each key under one  *)
(* of two KEKs (a rotation's batch holds keys under the vault's kek and    *)
(* its previousKeks, each a provider object of its own), with a bound on   *)
(* how many of its requests are in flight at once (core kek/aws-kms.ts,    *)
(* `CONCURRENCY`, six: Workers' simultaneous open connections of one       *)
(* invocation, past which the runtime queues them with their attempts'     *)
(* clocks running). A request in flight may answer at once, late or never: *)
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
    Kek,            \* Kek[p][i]: the KEK of p's ith key, "current" or "previous"
    Slots           \* how many of one call's KMS requests may be in flight at once

CONSTANTS
    \* Each call's own requests take turns among themselves, and no other's
    \* (aws-kms.ts: the bound kept per operation, `CONCURRENCY` per call).
    \* Off, one pool for every call of the isolate, as `Slots(8)` was.
    SlotsPerCall,
    \* A call's bound spans every KEK it asks (aws-kms.ts, `slotsOf`, by
    \* operation, whichever provider object): a rotation's batch takes turns
    \* in the same six. Off, each KEK's provider keeps its own slots for the
    \* call (review r2 of #549).
    SlotsAcrossKeks

VARIABLES
    pc,             \* pc[p]: "idle", "open" or "done"
    sent,           \* sent[p]: how many of p's keys have been sent, in order
    inflight        \* inflight[p]: the indices of p's keys sent and not answered

vars == <<pc, sent, inflight>>

RECURSIVE SumOver(_, _)
SumOver(f, S) == IF S = {} THEN 0 ELSE LET x == CHOOSE y \in S : TRUE IN Cardinality(f[x]) + SumOver(f, S \ {x})

\* p's next key's KEK.
NextKek(p) == Kek[p][sent[p] + 1]

\* The slots free to p's next request.
Free(p) ==
    IF ~SlotsPerCall THEN Slots - SumOver(inflight, Procs)
    ELSE IF SlotsAcrossKeks THEN Slots - Cardinality(inflight[p])
    ELSE Slots - Cardinality({i \in inflight[p] : Kek[p][i] = NextKek(p)})

Init ==
    /\ pc = [p \in Procs |-> "idle"]
    /\ sent = [p \in Procs |-> 0]
    /\ inflight = [p \in Procs |-> {}]

Start(p) ==
    /\ pc[p] = "idle"
    /\ pc' = [pc EXCEPT ![p] = "open"]
    /\ UNCHANGED <<sent, inflight>>

\* Send one more key's request, if a slot is free.
Send(p) ==
    /\ pc[p] = "open"
    /\ sent[p] < Keys[p]
    /\ Free(p) > 0
    /\ sent' = [sent EXCEPT ![p] = @ + 1]
    /\ inflight' = [inflight EXCEPT ![p] = @ \cup {sent[p] + 1}]
    /\ UNCHANGED pc

\* KMS answers one of p's requests, or the operation's deadline cancels it
\* (core kek/cancellation.ts): either way its slot is free again.
Answer(p) ==
    /\ \E i \in inflight[p] : inflight' = [inflight EXCEPT ![p] = @ \ {i}]
    /\ UNCHANGED <<pc, sent>>

Finish(p) ==
    /\ pc[p] = "open"
    /\ sent[p] = Keys[p]
    /\ inflight[p] = {}
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<sent, inflight>>

Finished == \A p \in Procs : pc[p] = "done"

Next == (\E p \in Procs : Start(p) \/ Send(p) \/ Answer(p) \/ Finish(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK ==
    /\ pc \in [Procs -> {"idle", "open", "done"}]
    /\ \A p \in Procs : sent[p] \in 0..Keys[p] /\ inflight[p] \subseteq 1..sent[p]

\* p has a key to send and no slot for it.
Waiting(p) == pc[p] = "open" /\ sent[p] < Keys[p] /\ Free(p) <= 0

\* A request waits for a slot only behind requests of its own call: never
\* behind another request's, hung or not, and so never for a promise that
\* another request settles (AGENTS.md, "What an isolate keeps").
WaitsOnlyBehindItsOwn == \A p \in Procs : Waiting(p) => inflight[p] # {}

\* A use, one key, never waits for a slot at all.
UsesNeverWait == \A u \in Uses : ~Waiting(u)

\* No call has more than its slots' requests in flight at once, whichever KEKs
\* its keys are under: what Workers lets one invocation have waiting for its
\* answers before it queues the rest with their attempts' clocks running.
InFlightBounded == \A p \in Procs : Cardinality(inflight[p]) <= Slots

=============================================================================
