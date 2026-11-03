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
(*                                                                         *)
(* A tunnel saved in the Proxy tab (T186 PR C2b3) is an item an Owner may  *)
(* edit mid-session, narrowing its hosts: its check is a named use of the  *)
(* item, which passes only if the item the vault decides on is the one the *)
(* session dialled, by its digest. Another item of the environment edited  *)
(* changes the object's seal, not this digest, and ends nothing.           *)
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
    Watchdog,
    \* A UI tunnel's check passes only if the decided item's digest is the
    \* session's (credential-proxy.ts, `uiTunnel`'s check): without it, the
    \* check is "the key is still there", which an edit leaves passing.
    DigestRecheck,
    \* What it compares is the item's own digest, never the object seal that
    \* every item of the environment changes (`DecidedItem.digest`).
    ItemDigest

VARIABLES
    now,            \* the clock
    revokedAt,      \* when the handle's revocation committed, or 0 for not yet
    open,           \* the session is open
    nextTick,       \* when the group's timer fires next
    checking,       \* a check is under way
    start,          \* when it started
    read,           \* what it found: "none" yet, "yes" or "no"
    armed,          \* when the newest check that answered yes started, or the admission
    timedOut,       \* a check ran to its deadline: the vault too slow, not the handle revoked
    editedAt,       \* when an edit of the session's item committed (its hosts narrowed), or 0
    otherAt         \* when an edit of another item of the environment committed, or 0

vars == <<now, revokedAt, open, nextTick, checking, start, read, armed, timedOut, editedAt, otherAt>>

Revoked == revokedAt > 0
Edited == editedAt > 0
Other == otherAt > 0

\* What a check that reads now finds wrong: the handle revoked, or the item
\* decided on not the one dialled, as the check compares them.
Stale ==
    \/ Revoked
    \/ (DigestRecheck /\ Edited)
    \/ (DigestRecheck /\ ~ItemDigest /\ Other)

Init ==
    /\ now = 1 /\ revokedAt = 0 /\ open = TRUE /\ nextTick = 1 + R
    /\ checking = FALSE /\ start = 0 /\ read = "none" /\ armed = 1 /\ timedOut = FALSE
    /\ editedAt = 0 /\ otherAt = 0

\* The handle is revoked, at any tick.
Revoke == ~Revoked /\ revokedAt' = now /\ UNCHANGED <<now, open, nextTick, checking, start, read, armed, timedOut, editedAt, otherAt>>

\* An Owner saves the tunnel's item anew (its hosts narrowed), at any tick.
Edit == ~Edited /\ editedAt' = now /\ UNCHANGED <<now, revokedAt, open, nextTick, checking, start, read, armed, timedOut, otherAt>>

\* Or another item of the same environment, at any tick.
EditOther == ~Other /\ otherAt' = now /\ UNCHANGED <<now, revokedAt, open, nextTick, checking, start, read, armed, timedOut, editedAt>>

\* The timer fires: a check starts, unless one is under way.
Interval ==
    /\ now = nextTick
    /\ nextTick' = nextTick + R
    /\ IF checking
         THEN UNCHANGED <<checking, start, read>>
         ELSE /\ checking' = TRUE /\ start' = now /\ read' = "none"
    /\ UNCHANGED <<now, revokedAt, open, armed, timedOut, editedAt, otherAt>>

\* The check reads the handle, at some point while it runs: the verify
\* that starts it, the vault's decision, and the fence after it
\* (credentialStill). When does not change the bound: a check that read
\* before a revocation passes, and the next one fails. A UI tunnel's
\* check reads the item with the handle, in the same statement.
Read ==
    /\ checking /\ read = "none"
    /\ read' = IF Stale THEN "no" ELSE "yes"
    /\ UNCHANGED <<now, revokedAt, open, nextTick, checking, start, armed, timedOut, editedAt, otherAt>>

\* It answers what it read, before its deadline, a yes arming the watchdog
\* from when it started. One that runs to its deadline is a no (`late`).
Answer ==
    /\ checking /\ read # "none"
    /\ (DeadlineCountsAsNo => now < start + D)
    /\ open' = (open /\ read = "yes")
    /\ armed' = IF read = "yes" THEN start ELSE armed
    /\ checking' = FALSE
    /\ UNCHANGED <<now, revokedAt, nextTick, start, read, timedOut, editedAt, otherAt>>

\* Its deadline passes unanswered: a no, and the sessions end.
Deadline ==
    /\ DeadlineCountsAsNo /\ checking /\ now = start + D
    /\ checking' = FALSE /\ open' = FALSE /\ timedOut' = TRUE
    /\ UNCHANGED <<now, revokedAt, nextTick, start, read, armed, editedAt, otherAt>>

\* The watchdog: the newest yes started Bound ago, and the sessions end.
Expire ==
    /\ Watchdog /\ open /\ now = armed + Bound
    /\ open' = FALSE
    /\ UNCHANGED <<now, revokedAt, nextTick, checking, start, read, armed, timedOut, editedAt, otherAt>>

\* The clock moves on once nothing is due now: the timer, a deadline, the
\* watchdog. A check may take any time, or never answer.
Tick ==
    /\ now < MaxTime
    /\ now < nextTick
    /\ ~(DeadlineCountsAsNo /\ checking /\ now = start + D)
    /\ ~(Watchdog /\ open /\ now = armed + Bound)
    /\ now' = now + 1
    /\ UNCHANGED <<revokedAt, open, nextTick, checking, start, read, armed, timedOut, editedAt, otherAt>>

Next == Revoke \/ Edit \/ EditOther \/ Interval \/ Read \/ Answer \/ Deadline \/ Expire \/ Tick \/ (now = MaxTime /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

\* A revoked handle's session ends within Bound of its revocation.
EndsWithinBound == (open /\ Revoked) => now - revokedAt <= Bound

\* A session whose item an Owner edited ends within Bound of the edit,
\* and the client's reconnect dials by the new item.
EditEndsWithinBound == (open /\ Edited) => now - editedAt <= Bound

\* And a handle that stands keeps its session while its item is unedited
\* and every check answers before its deadline, whatever else of the
\* environment is edited: the watchdog ends none that the checks keep.
StandingStaysOpen == (~Revoked /\ ~Edited /\ ~timedOut /\ ~(checking /\ now >= start + D)) => open

=============================================================================
