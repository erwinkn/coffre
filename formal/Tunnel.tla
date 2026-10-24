------------------------------- MODULE Tunnel --------------------------------
(***************************************************************************)
(* How long a revoked handle's tunnel session lives: one group's timer,    *)
(* which every `recheckSeconds` asks again for the database's URL as the   *)
(* vault decides it, one check at a time, a check that has not answered by *)
(* its deadline counting as no (server plugins/credential-proxy.ts,        *)
(* watch); and a watchdog that ends the sessions once the newest check     *)
(* that answered yes started Bound ago. Time is a clock in ticks; timers   *)
(* that come due at the same tick fire in any order, as the event loop may *)
(* run them.                                                               *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    R,              \* recheckMs, in ticks
    D,              \* min(recheckMs, RECHECK_DEADLINE_MS), in ticks
    MaxTime,        \* how far the clock runs
    Bound           \* R + D: how long after its revocation a session may still be open

CONSTANTS
    \* A check that has not answered by its deadline is a no (watch, `late`).
    DeadlineCountsAsNo,
    \* The sessions end once the newest check that answered yes, or the
    \* admission, started Bound ago (watch, `arm`, the watchdog).
    Watchdog

VARIABLES
    now,            \* the clock
    revokedAt,      \* when the handle's revocation committed, or 0 for not yet
    open,           \* the session is open
    nextTick,       \* when the group's timer fires next
    checking,       \* a check is under way
    start,          \* when it started
    read,           \* what it found: "none" yet, "yes" or "no"
    armed,          \* when the newest check that answered yes started, or the admission
    timedOut        \* a check ran to its deadline: the vault too slow, not the handle revoked

vars == <<now, revokedAt, open, nextTick, checking, start, read, armed, timedOut>>

Revoked == revokedAt > 0

Init ==
    /\ now = 1 /\ revokedAt = 0 /\ open = TRUE /\ nextTick = 1 + R
    /\ checking = FALSE /\ start = 0 /\ read = "none" /\ armed = 1 /\ timedOut = FALSE

\* The handle is revoked, at any tick.
Revoke == ~Revoked /\ revokedAt' = now /\ UNCHANGED <<now, open, nextTick, checking, start, read, armed, timedOut>>

\* The timer fires: a check starts, unless one is under way.
Interval ==
    /\ now = nextTick
    /\ nextTick' = nextTick + R
    /\ IF checking
         THEN UNCHANGED <<checking, start, read>>
         ELSE /\ checking' = TRUE /\ start' = now /\ read' = "none"
    /\ UNCHANGED <<now, revokedAt, open, armed, timedOut>>

\* The check reads the handle, at some point while it runs: the verify
\* that starts it, the vault's decision, and the fence after it
\* (credentialStill). When does not change the bound: a check that read
\* before a revocation passes, and the next one fails.
Read ==
    /\ checking /\ read = "none"
    /\ read' = IF Revoked THEN "no" ELSE "yes"
    /\ UNCHANGED <<now, revokedAt, open, nextTick, checking, start, armed, timedOut>>

\* It answers what it read, before its deadline, a yes arming the watchdog
\* from when it started. One that runs to its deadline is a no (`late`).
Answer ==
    /\ checking /\ read # "none"
    /\ (DeadlineCountsAsNo => now < start + D)
    /\ open' = (open /\ read = "yes")
    /\ armed' = IF read = "yes" THEN start ELSE armed
    /\ checking' = FALSE
    /\ UNCHANGED <<now, revokedAt, nextTick, start, read, timedOut>>

\* Its deadline passes unanswered: a no, and the sessions end.
Deadline ==
    /\ DeadlineCountsAsNo /\ checking /\ now = start + D
    /\ checking' = FALSE /\ open' = FALSE /\ timedOut' = TRUE
    /\ UNCHANGED <<now, revokedAt, nextTick, start, read, armed>>

\* The watchdog: the newest yes started Bound ago, and the sessions end.
Expire ==
    /\ Watchdog /\ open /\ now = armed + Bound
    /\ open' = FALSE
    /\ UNCHANGED <<now, revokedAt, nextTick, checking, start, read, armed, timedOut>>

\* The clock moves on once nothing is due now: the timer, a deadline, the
\* watchdog. A check may take any time, or never answer.
Tick ==
    /\ now < MaxTime
    /\ now < nextTick
    /\ ~(DeadlineCountsAsNo /\ checking /\ now = start + D)
    /\ ~(Watchdog /\ open /\ now = armed + Bound)
    /\ now' = now + 1
    /\ UNCHANGED <<revokedAt, open, nextTick, checking, start, read, armed, timedOut>>

Next == Revoke \/ Interval \/ Read \/ Answer \/ Deadline \/ Expire \/ Tick \/ (now = MaxTime /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

\* A revoked handle's session ends within Bound of its revocation.
EndsWithinBound == (open /\ Revoked) => now - revokedAt <= Bound

\* And a handle that stands keeps its session while every check answers
\* before its deadline: the watchdog ends none that the checks keep.
StandingStaysOpen == (~Revoked /\ ~timedOut /\ ~(checking /\ now >= start + D)) => open

=============================================================================
