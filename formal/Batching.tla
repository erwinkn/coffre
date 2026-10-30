------------------------------ MODULE Batching -------------------------------
(***************************************************************************)
(* B2 (T167): a request's several keys, one vault call (`useMany`) and one *)
(* statement (`use_batch`, migration 0048), where each key had a call of   *)
(* its own. The statement makes each key's use as `use_credential` makes   *)
(* one, in the request's order, in one transaction: HotPathOne.tla holds   *)
(* each of those uses; this module holds what a batch adds, as several of  *)
(* them share one transaction, one principal's lock and one cap.           *)
(*                                                                         *)
(* A batch is two rounds, as a single use by ids is (T158, D153):          *)
(*   round 1, one statement under the fence (shared): each key whose row   *)
(*   of the cap's is fresh is used at once, its entry written; any other   *)
(*   key, which would take the principal's lock (to enter the cap's set,  *)
(*   or move its row on), answers `decide`, locking and writing nothing;   *)
(*   the vault decides every key on the rows round 1 read;                 *)
(*   round 2, only for the keys that answered `decide`, and only once the  *)
(*   vault allowed every key of the batch: one statement under the fence, *)
(*   the principal's lock, then each key's use, decided again on what it   *)
(*   reads then, entering the set or moving its row on.                    *)
(* Values leave once the vault has every key's outcome, and only if every  *)
(* one is allowed: all or nothing, as 0.14's unwrap and 0.15's uses one a  *)
(* key both answer a request of several keys.                              *)
(*                                                                         *)
(* One principal, whose standing a change revokes or restores (under the   *)
(* fence, exclusive), and whose cap holds at most BulkCount keys. `Refused` *)
(* are keys the rules refuse whatever the standing (a reference ended, a   *)
(* fork's parent unread). A key's row of the cap's is none, old (in the   *)
(* set, from an earlier period: a use moves it on, under the lock shared)  *)
(* or fresh (in the set this period: no lock); time ages rows. Row writes *)
(* are visible at once: only a holder of the lock exclusive enters a key,  *)
(* and a move keeps a key in the set.                                      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Batches,        \* concurrent requests of the principal's, each a batch
    Order,          \* Order[b]: the keys batch b names, in the request's order
    Keys,
    Refused,        \* keys the rules refuse whatever the caller's standing
    BulkCount,      \* the cap: at most this many of the principal's keys in its set
    MaxChanges,     \* revocations and restorations of the caller's standing
    MaxTicks,       \* steps of time: a row ages fresh -> old -> none
    \* The protections, each TRUE in the code:
    \* Round 1 takes no principal's lock: a key that would take it answers `decide` (`use_credential`, `p_decided`).
    DecideBeforeLock,
    \* Round 2 runs only once the vault allowed every key of the batch on round 1's rows (`useMany`).
    AllDecidedFirst,
    \* Round 2 takes the principal's lock exclusive before its first key (`use_batch`, `p_lock`), never shared then exclusive.
    StrongestFirst,
    \* Each key's use counts the set as its own statement reads it, the batch's earlier keys included (one statement a
    \* key, each its own snapshot, inside the transaction), not as the batch's first statement read it.
    CountsOwnBatch,
    \* Values leave only when every key of the batch was allowed (`useMany`; the app's `useValues`).
    AnswerWhole

None == "none"
Phases == {"r1", "decide", "r2", "r2x", "r2k", "answer", "done"}
KeysOf(b) == {Order[b][n] : n \in 1..Len(Order[b])}

VARIABLES
    standing,       \* whether the caller stands, as the sealed rows say
    row,            \* row[k]: the principal's row of the cap's for k
    changes, ticks,
    fenceS, fenceX, \* the fence: its shared holders (uses), its exclusive one (a change)
    lockS, lockX,   \* the principal's lock
    pc, i,          \* each batch's phase, and its next key
    seen,           \* seen[b][k]: what round 1 did of k: "used", "decide", or "none" yet
    stood,          \* stood[b]: the caller's standing as round 1 read it
    start,          \* start[b]: the set as round 2's first statement read it
    outcome,        \* outcome[b][k]: "allowed", "refused", "bulk" or "none" yet
    entered,        \* entered[b]: the keys b's uses entered in the set
    released,       \* released[b]: the keys whose values left
    waiting         \* waiting[b]: the principal's lock mode b waits for, or None

vars == <<standing, row, changes, ticks, fenceS, fenceX, lockS, lockX, pc, i, seen, stood, start, outcome, entered, released, waiting>>

InSet == {k \in Keys : row[k] # "none"}

Init ==
    /\ standing \in BOOLEAN
    /\ row \in [Keys -> {"none", "old", "fresh"}]
    /\ Cardinality(InSet) <= BulkCount
    /\ changes = 0
    /\ ticks = 0
    /\ fenceS = {}
    /\ fenceX = None
    /\ lockS = {}
    /\ lockX = None
    /\ pc = [b \in Batches |-> "r1"]
    /\ i = [b \in Batches |-> 1]
    /\ seen = [b \in Batches |-> [k \in Keys |-> "none"]]
    /\ stood = [b \in Batches |-> TRUE]
    /\ start = [b \in Batches |-> {}]
    /\ outcome = [b \in Batches |-> [k \in Keys |-> "none"]]
    /\ entered = [b \in Batches |-> {}]
    /\ released = [b \in Batches |-> {}]
    /\ waiting = [b \in Batches |-> None]

\* The rules' answer for k, on the standing read now.
Rule(k) == IF standing /\ k \notin Refused THEN "allowed" ELSE "refused"

CanX(b) == lockX \in {None, b} /\ lockS \ {b} = {}
CanS(b) == lockX \in {None, b}

\* One key's use under the principal's lock (round 2's, or round 1's without DecideBeforeLock): the lock its row needs,
\* waited for if another holds it; then the row read, the key entered if the cap has room, or moved on; its entry
\* written whatever the decision (the log records requests), decided on what it read.
LockedUse(b, k) ==
    LET mode == CASE row[k] = "none" -> "X" [] row[k] = "old" -> "S" [] OTHER -> "-"
        counted == (IF CountsOwnBatch THEN InSet ELSE start[b]) \ {k}
    IN  IF (mode = "X" /\ lockX # b /\ ~CanX(b)) \/ (mode = "S" /\ ~CanS(b))
          THEN /\ waiting[b] = None
               /\ waiting' = [waiting EXCEPT ![b] = mode]
               /\ UNCHANGED <<row, lockS, lockX, outcome, entered, i>>
          ELSE /\ waiting' = [waiting EXCEPT ![b] = None]
               /\ lockX' = IF mode = "X" THEN b ELSE lockX
               /\ lockS' = IF mode = "S" /\ lockX # b THEN lockS \cup {b} ELSE lockS
               /\ IF mode = "X" /\ Cardinality(counted) >= BulkCount
                    THEN /\ outcome' = [outcome EXCEPT ![b][k] = "bulk"]
                         /\ UNCHANGED <<row, entered>>
                    ELSE /\ row' = [row EXCEPT ![k] = "fresh"]
                         /\ entered' = IF mode = "X" THEN [entered EXCEPT ![b] = @ \cup {k}] ELSE entered
                         /\ outcome' = [outcome EXCEPT ![b][k] = Rule(k)]
               /\ i' = [i EXCEPT ![b] = @ + 1]

\* A statement's start: the fence shared, unless a change holds it.
Fenced(b) == b \in fenceS \/ fenceX = None

\* Round 1, one key: a fresh row is used at once; any other answers `decide` (or, without DecideBeforeLock, is used
\* under the lock there and then).
Round1(b) ==
    /\ pc[b] = "r1"
    /\ i[b] <= Len(Order[b])
    /\ Fenced(b)
    /\ LET k == Order[b][i[b]] IN
         /\ stood' = [stood EXCEPT ![b] = standing]
         /\ fenceS' = fenceS \cup {b}
         /\ IF row[k] = "fresh"
              THEN /\ seen' = [seen EXCEPT ![b][k] = "used"]
                   /\ outcome' = [outcome EXCEPT ![b][k] = Rule(k)]
                   /\ i' = [i EXCEPT ![b] = @ + 1]
                   /\ UNCHANGED <<row, lockS, lockX, entered, waiting>>
              ELSE IF DecideBeforeLock
                THEN /\ seen' = [seen EXCEPT ![b][k] = "decide"]
                     /\ i' = [i EXCEPT ![b] = @ + 1]
                     /\ UNCHANGED <<row, lockS, lockX, outcome, entered, waiting>>
                ELSE /\ seen' = [seen EXCEPT ![b][k] = "used"]
                     /\ LockedUse(b, k)
    /\ UNCHANGED <<standing, changes, ticks, fenceX, pc, start, released>>

\* A statement's commit: its locks go.
Commit(b, next) ==
    /\ fenceS' = fenceS \ {b}
    /\ lockS' = lockS \ {b}
    /\ lockX' = IF lockX = b THEN None ELSE lockX
    /\ pc' = [pc EXCEPT ![b] = next]
    /\ i' = [i EXCEPT ![b] = 1]

Round1Commit(b) ==
    /\ pc[b] = "r1"
    /\ i[b] > Len(Order[b])
    /\ Commit(b, "decide")
    /\ UNCHANGED <<standing, row, changes, ticks, fenceX, seen, stood, start, outcome, entered, released, waiting>>

\* Whether round 1's rows allowed every key of b: those it used, and those it left to decide.
AllowedAtFirst(b) == \A k \in KeysOf(b) : IF seen[b][k] = "decide" THEN stood[b] /\ k \notin Refused ELSE outcome[b][k] = "allowed"

\* The vault, on round 1's rows: a batch any key of which it refuses ends there, its keys left to decide refused too.
Decide(b) ==
    /\ pc[b] = "decide"
    /\ LET pending == {k \in KeysOf(b) : seen[b][k] = "decide"} IN
         IF AllDecidedFirst /\ ~AllowedAtFirst(b)
           THEN /\ outcome' = [outcome EXCEPT ![b] = [k \in Keys |-> IF k \in pending THEN "refused" ELSE @[k]]]
                /\ pc' = [pc EXCEPT ![b] = "answer"]
           ELSE /\ pc' = [pc EXCEPT ![b] = IF pending = {} THEN "answer" ELSE "r2"]
                /\ UNCHANGED outcome
    /\ UNCHANGED <<standing, row, changes, ticks, fenceS, fenceX, lockS, lockX, i, seen, stood, start, entered, released, waiting>>

\* Round 2's statement starts: the fence shared, and the set as it reads it then.
Round2(b) ==
    /\ pc[b] = "r2"
    /\ fenceX = None
    /\ fenceS' = fenceS \cup {b}
    /\ start' = [start EXCEPT ![b] = InSet]
    /\ pc' = [pc EXCEPT ![b] = IF StrongestFirst THEN "r2x" ELSE "r2k"]
    /\ UNCHANGED <<standing, row, changes, ticks, fenceX, lockS, lockX, i, seen, stood, outcome, entered, released, waiting>>

\* StrongestFirst: the principal's lock exclusive, waited for, before any key.
Round2Lock(b) ==
    /\ pc[b] = "r2x"
    /\ IF CanX(b)
         THEN /\ lockX' = b
              /\ waiting' = [waiting EXCEPT ![b] = None]
              /\ pc' = [pc EXCEPT ![b] = "r2k"]
         ELSE /\ waiting[b] = None
              /\ waiting' = [waiting EXCEPT ![b] = "X"]
              /\ UNCHANGED <<lockX, pc>>
    /\ UNCHANGED <<standing, row, changes, ticks, fenceS, fenceX, lockS, i, seen, stood, start, outcome, entered, released>>

\* Round 2, one key: one the vault left to decide is used under the lock, decided on what it reads now.
Round2Key(b) ==
    /\ pc[b] = "r2k"
    /\ i[b] <= Len(Order[b])
    /\ LET k == Order[b][i[b]] IN
         IF seen[b][k] # "decide"
           THEN /\ i' = [i EXCEPT ![b] = @ + 1]
                /\ UNCHANGED <<row, lockS, lockX, outcome, entered, waiting>>
           ELSE LockedUse(b, k)
    /\ UNCHANGED <<standing, changes, ticks, fenceS, fenceX, pc, seen, stood, start, released>>

Round2Commit(b) ==
    /\ pc[b] = "r2k"
    /\ i[b] > Len(Order[b])
    /\ Commit(b, "answer")
    /\ UNCHANGED <<standing, row, changes, ticks, fenceX, seen, stood, start, outcome, entered, released, waiting>>

\* The answer: every value, when every key was allowed; or, without AnswerWhole, each allowed one.
Answer(b) ==
    /\ pc[b] = "answer"
    /\ LET allowed == {k \in KeysOf(b) : outcome[b][k] = "allowed"} IN
         released' = [released EXCEPT ![b] = IF ~AnswerWhole \/ allowed = KeysOf(b) THEN allowed ELSE {}]
    /\ pc' = [pc EXCEPT ![b] = "done"]
    /\ UNCHANGED <<standing, row, changes, ticks, fenceS, fenceX, lockS, lockX, i, seen, stood, start, outcome, entered, waiting>>

\* A change of the caller's standing: the fence exclusive, its write and commit, between statements.
Change ==
    /\ changes < MaxChanges
    /\ fenceS = {}
    /\ fenceX = None
    /\ standing' = ~standing
    /\ changes' = changes + 1
    /\ UNCHANGED <<row, ticks, fenceS, fenceX, lockS, lockX, pc, i, seen, stood, start, outcome, entered, released, waiting>>

\* Time: a row ages, fresh to old (a use now moves it on), old to none (out of the set).
Tick ==
    /\ ticks < MaxTicks
    /\ \E k \in InSet : row' = [row EXCEPT ![k] = IF @ = "fresh" THEN "old" ELSE "none"]
    /\ ticks' = ticks + 1
    /\ UNCHANGED <<standing, changes, fenceS, fenceX, lockS, lockX, pc, i, seen, stood, start, outcome, entered, released, waiting>>

Done == (\A b \in Batches : pc[b] = "done") /\ UNCHANGED vars

Next ==
    \/ \E b \in Batches : Round1(b) \/ Round1Commit(b) \/ Decide(b) \/ Round2(b) \/ Round2Lock(b) \/ Round2Key(b) \/ Round2Commit(b) \/ Answer(b)
    \/ Change
    \/ Tick
    \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ standing \in BOOLEAN
    /\ row \in [Keys -> {"none", "old", "fresh"}]
    /\ pc \in [Batches -> Phases]
    /\ lockS \subseteq Batches
    /\ lockX \in Batches \cup {None}
    /\ fenceS \subseteq Batches
    /\ waiting \in [Batches -> {None, "X", "S"}]
    /\ \A b \in Batches : released[b] \subseteq KeysOf(b)

\* Holding or waiting for the principal's lock.
Locks(b) == lockX = b \/ b \in lockS \/ waiting[b] # None

\* The cap holds: never more keys in the principal's set than BulkCount.
CapHolds == Cardinality(InSet) <= BulkCount

\* No two batches each wait for the principal's lock the other holds (Postgres would end one, 40P01, after a second).
NoWaitCycle ==
    ~\E b1, b2 \in Batches :
        /\ b1 # b2
        /\ waiting[b1] # None /\ waiting[b2] # None
        /\ (lockX = b2 \/ b2 \in lockS) /\ (lockX = b1 \/ b1 \in lockS)

\* A batch takes, or waits for, the principal's lock only once the vault allowed every one of its keys on round 1's
\* rows: a caller refused, or a key the rules refuse, never waits on it (HotPathOne's NoLockWithoutStanding, per batch).
NoLockForRefused == \A b \in Batches : Locks(b) => pc[b] \in {"r2", "r2x", "r2k"} /\ AllowedAtFirst(b)

\* A batch the vault refused on round 1's rows enters no key in the set: a refused request costs the cap nothing.
RefusedEntersNothing == \A b \in Batches : pc[b] \in {"answer", "done"} /\ ~AllowedAtFirst(b) => entered[b] = {}

\* All or nothing: a batch hands back every one of its values, each allowed, or none.
AllOrNothing == \A b \in Batches : released[b] = {} \/ (released[b] = KeysOf(b) /\ \A k \in KeysOf(b) : outcome[b][k] = "allowed")

\* Only values allowed leave, each on the rules as its own use read them.
ReleasedAllowed == \A b \in Batches : \A k \in released[b] : outcome[b][k] = "allowed"

=============================================================================
