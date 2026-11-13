----------------------------- MODULE NamedLocks -----------------------------
(***************************************************************************)
(* A named use's read before its locks (L1, T282; review r2 of #585).      *)
(*                                                                         *)
(* A named use names a place and a key by name, and a caller with no       *)
(* standing at the place must learn nothing of the key, not from her       *)
(* answer and not from a lock she waited for (Probing.tla's `NoIsFixed`,   *)
(* `NoKeyBeforeStanding`). Probing.tla takes a request as one step. With   *)
(* object locks a named use is three: it reads, with no lock, what its     *)
(* names name; it takes the locks of what that read named, once, sorted;   *)
(* it runs its statement, which reads afresh and decides. A revoke, a      *)
(* grant, a write of the key or its deletion may come between any two.     *)
(* This model is those three steps and nothing else of a use.              *)
(*                                                                         *)
(* Two runs go side by side, as in Probing.tla, alike in everything but    *)
(* the key: in run "made" someone makes API_KEY, writes it, deletes it and *)
(* makes it again; in run "never" nobody does. Ada's standing at the place *)
(* is the same in both. A write of the key holds the key's lock exclusive  *)
(* for its last statement, so a call that locks the key waits for it.      *)
(*                                                                         *)
(* The instant that counts is the read's. A call takes a lock of the key's *)
(* side only if its read saw Ada stand (`NoKeyLockBeforeStanding`), so it  *)
(* waits for one only then (`NoWaitBeforeStanding`), and a call whose read *)
(* did not see her stand, and whose statement does not either, answers and *)
(* waits the same in both runs (`NoIsFixed`). What it does not give: a     *)
(* caller who stood at the read and was revoked before the locks has       *)
(* locked the key's side, may wait for it, and is refused (`NoWaitForNo`   *)
(* breaks, as scripts/formal.sh expects). She learns that a write of the   *)
(* key was under way at an instant when the key was hers to know of, as a  *)
(* use that waits for its principal's lock does since T158                 *)
(* (`DecideBeforeLock`: decided on one call's rows, the lock in the next). *)
(*                                                                         *)
(* A key made, or made again under another id, after the read is a key the *)
(* call did not lock: its statement answers `moved` and the vault calls    *)
(* again (HotPathOne.tla's `LockedAsRead`, which this model takes as       *)
(* given). The order of the locks is WriteLocks.tla's.                     *)
(*                                                                         *)
(* The protection:                                                         *)
(*   StandingBeforeKey  the read names the key's ids only to a caller who  *)
(*               stands at the place: it reads the caller's side, the      *)
(*               standing it gives there, and the key only then. Without,  *)
(*               it reads the key by its name whoever asks, and a caller   *)
(*               with no standing waits for a write of a key in one run    *)
(*               and for nothing in the other.                             *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Budget,             \* how many calls Ada makes
    MaxKeys,            \* how many times someone makes the key, each time under a new id
    StandingBeforeKey

Runs == {"made", "never"}
None == 0

VARIABLES
    stands,     \* whether Ada stands at the place now: the same in both runs
    key,        \* run "made": the id of the key now, None while there is none
    made,       \* how many ids the key has had
    writing,    \* run "made": a change of the key holds its lock, exclusive, for its last statement
    calls,      \* the calls begun
    phase,      \* each run's call: "idle", "read" (it has read, and locked nothing), "wait" (queued for the key's lock), "done"
    stood,      \* the standing the call's read saw: one read, the same instant in both runs
    named,      \* each run's: the key's id as the read named it, None if it named none; what the call locks
    waited,     \* each run's: whether the call waited for the key's lock
    decided,    \* each run's: the standing its statement saw, under the locks
    answer      \* each run's: "none" yet, "no", "yes", or "moved"

world == <<stands, key, made, writing>>
vars == <<stands, key, made, writing, calls, phase, stood, named, waited, decided, answer>>

Init ==
    /\ stands \in BOOLEAN
    /\ key = None /\ made = 0 /\ writing = FALSE
    /\ calls = 0
    /\ phase = [r \in Runs |-> "idle"]
    /\ stood = FALSE
    /\ named = [r \in Runs |-> None]
    /\ waited = [r \in Runs |-> FALSE]
    /\ decided = [r \in Runs |-> FALSE]
    /\ answer = [r \in Runs |-> "none"]

\* Others, at any time.
Revoke == stands /\ stands' = FALSE /\ UNCHANGED <<key, made, writing, calls, phase, stood, named, waited, decided, answer>>
Grant == ~stands /\ stands' = TRUE /\ UNCHANGED <<key, made, writing, calls, phase, stood, named, waited, decided, answer>>
\* Nobody names a key before the change that makes it commits: it holds no lock a call could wait for.
Make ==
    /\ key = None /\ made < MaxKeys
    /\ key' = made + 1 /\ made' = made + 1
    /\ UNCHANGED <<stands, writing, calls, phase, stood, named, waited, decided, answer>>
\* A change of the key's last statement: the key's lock, exclusive, to its commit, which writes the key or deletes it.
StartWrite ==
    /\ key # None /\ ~writing
    /\ writing' = TRUE
    /\ UNCHANGED <<stands, key, made, calls, phase, stood, named, waited, decided, answer>>
EndWrite ==
    /\ writing
    /\ writing' = FALSE
    /\ \E gone \in BOOLEAN : key' = IF gone THEN None ELSE key
    /\ UNCHANGED <<stands, made, calls, phase, stood, named, waited, decided, answer>>

\* The call's read, with no lock: the caller's side, her standing at the place, and the key's ids.
Read ==
    /\ calls < Budget
    /\ \A r \in Runs : phase[r] \in {"idle", "done"}
    /\ calls' = calls + 1
    /\ stood' = stands
    /\ named' = [r \in Runs |-> IF r = "made" /\ (stands \/ ~StandingBeforeKey) THEN key ELSE None]
    /\ phase' = [r \in Runs |-> "read"]
    /\ waited' = [r \in Runs |-> FALSE]
    /\ decided' = [r \in Runs |-> FALSE]
    /\ answer' = [r \in Runs |-> "none"]
    /\ UNCHANGED world

\* The key's lock is held against this run's call: it named the key that a change is writing.
Blocked(r) == r = "made" /\ named[r] # None /\ named[r] = key /\ writing
\* The statement, under the locks: it reads afresh. A key the call did not lock is `moved`.
Outcome(r) ==
    IF ~stands \/ r # "made" \/ key = None THEN "no"
    ELSE IF named[r] = key THEN "yes" ELSE "moved"

\* The locks, one take, then the statement: both runs at the same instant, but a run that waits.
Go ==
    /\ \A r \in Runs : phase[r] = "read"
    /\ phase' = [r \in Runs |-> IF Blocked(r) THEN "wait" ELSE "done"]
    /\ waited' = [r \in Runs |-> Blocked(r)]
    /\ decided' = [r \in Runs |-> IF Blocked(r) THEN FALSE ELSE stands]
    /\ answer' = [r \in Runs |-> IF Blocked(r) THEN "none" ELSE Outcome(r)]
    /\ UNCHANGED <<world, calls, stood, named>>
\* The run that waited, once the change has committed.
Late(r) ==
    /\ phase[r] = "wait" /\ ~Blocked(r)
    /\ phase' = [phase EXCEPT ![r] = "done"]
    /\ decided' = [decided EXCEPT ![r] = stands]
    /\ answer' = [answer EXCEPT ![r] = Outcome(r)]
    /\ UNCHANGED <<world, calls, stood, named, waited>>

Next == Revoke \/ Grant \/ Make \/ StartWrite \/ EndWrite \/ Read \/ Go \/ \E r \in Runs : Late(r)
Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ stands \in BOOLEAN /\ writing \in BOOLEAN /\ stood \in BOOLEAN
    /\ key \in 0..MaxKeys /\ made \in 0..MaxKeys /\ calls \in 0..Budget
    /\ phase \in [Runs -> {"idle", "read", "wait", "done"}]
    /\ named \in [Runs -> 0..MaxKeys]
    /\ waited \in [Runs -> BOOLEAN] /\ decided \in [Runs -> BOOLEAN]
    /\ answer \in [Runs -> {"none", "no", "yes", "moved"}]

\* A call locks nothing of the key unless its read saw her stand.
NoKeyLockBeforeStanding == \A r \in Runs : named[r] # None => stood
\* So it waits for nothing of the key unless its read saw her stand.
NoWaitBeforeStanding == \A r \in Runs : waited[r] => stood
\* A call whose read did not see her stand, and whose statement refuses her, costs and answers the same whatever
\* the key is or was.
NoIsFixed ==
    (~stood /\ \A r \in Runs : phase[r] = "done" /\ ~decided[r])
        => answer["made"] = answer["never"] /\ waited["made"] = waited["never"]
\* Expected to break: a caller who stood at the read and fell before the locks waits, and is refused.
NoWaitForNo == \A r \in Runs : (waited[r] /\ phase[r] = "done") => decided[r]
=============================================================================
