--------------------------- MODULE HotPathOneClock ---------------------------
(***************************************************************************)
(* 0.15's one-call use (W208, W211, experiments/lanes/src/one.ts), with    *)
(* time: the deadline, the floor of `at`, and the bulk cap with covers.    *)
(* HotPathOne.tla checks the order of uses against changes and has no      *)
(* clock; this module has no changes and checks what the clocks touch.     *)
(*                                                                         *)
(* Clocks. Postgres's clock `pnow` moves on, and may step back. A use is   *)
(* stamped `at` by the Worker's clock (pnow, give or take MaxSkew) when it *)
(* arrives, and its deadline is at + D (D: the 3 s bound, scaled down).    *)
(*                                                                         *)
(* A use: the fence lock shared; with an `at` below the floor, it writes  *)
(* nothing and answers `late`. Then statement A reads the principal's bulk *)
(* row for its key and, if the key must enter the cap's set or its time    *)
(* must be moved on, takes the principal's lock exclusive (held to the     *)
(* commit). Then statement B, with a snapshot of its own after that lock:  *)
(* past its deadline, it writes nothing (`late`); else covered (a repeat   *)
(* on the isolate's cover, nothing written), or the cap's rule and the     *)
(* entry, numbered from the sequence. The commit lets both locks go. The   *)
(* Worker releases the value if the cap admitted it, unless its deadline   *)
(* has passed: it answered 503 then. Deadlines are checked by Postgres's   *)
(* clock against the Worker's `at`; MaxSkew is how far the two differ.     *)
(*                                                                         *)
(* The checkpointer's barrier: under the fence lock exclusive, it raises   *)
(* the floor to its clock less D and closes every number handed out. The  *)
(* next checkpoint reads the entries numbered since, through the `at`     *)
(* index from the floor the previous barrier set: a use written after a   *)
(* barrier with an `at` below that barrier's floor would be missed.        *)
(*                                                                         *)
(* The bulk cap (R52): at most BulkCount distinct keys per principal in    *)
(* any BulkWindow (W), both parameters. One row per key the principal      *)
(* asked for, `last`, the time the key last entered the set or was moved  *)
(* on; a key is in the set at time t while last > t - W - delta. A key     *)
(* that is not in the set enters it if fewer than BulkCount others count   *)
(* at t, else the request is refused `bulk`; another key counts while      *)
(* last > t - W - delta - D: a use is decided up to D after its `at`, so   *)
(* it can be decided after a use stamped up to D later, which must have    *)
(* counted its key. A key in the set is moved on (last := t) only once its *)
(* `last` is Refresh (delta) old, so that a hot key does not write its row *)
(* on every use. Every request counts but the ones the cap refuses: the   *)
(* log stores requests, and the replay recomputes the cap from them in     *)
(* number order.                                                           *)
(*                                                                         *)
(* Covers: one isolate. Each cover is checked in SQL against the bulk row  *)
(* and the log, never against another isolate's, so more isolates only     *)
(* add more covers of the same kind (and HotPathOne.tla checks a cover     *)
(* against the changes).                                                   *)
(*                                                                         *)
(* The protections, each a constant (scripts/formal-hotpath.sh):           *)
(*   DeadlineChecked       a call that decides past its deadline writes    *)
(*                         nothing: checked after its last lock wait, in   *)
(*                         the statement that decides;                     *)
(*   FloorChecked          a use whose `at` is below the floor writes      *)
(*                         nothing;                                        *)
(*   WorkerHonoursDeadline a value whose call returns past its deadline    *)
(*                         never leaves (the Worker answered 503);         *)
(*   PrincipalLocks        a key that enters the set, or is moved on,     *)
(*                         takes the principal's lock;                     *)
(*   RefreshOnUse          a use moves its key on once `last` is delta old;*)
(*   CoverFresh            a repeat rides a cover only while its key's     *)
(*                         `last` is younger than delta;                   *)
(*   Slack                 the set keeps a key delta longer than W (its    *)
(*                         last use may be up to delta after `last`);      *)
(*   DeadlineSlack         another key counts against a new one D longer   *)
(*                         than it stays in the set.                       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Uses,             \* the uses, each one request, one call
    Keys,             \* the keys one principal asks for
    MaxTime,          \* Postgres's clock runs 0..MaxTime
    MaxClockBacks,    \* times it steps back by one in a behaviour
    MaxSkew,          \* how far a Worker's clock is from Postgres's
    D,                \* a use's deadline after its `at`
    MaxCheckpoints,   \* checkpoints signed in a behaviour
    Covers,           \* uses pass the isolate's cover
    BulkCount, BulkWindow, Refresh,
    DeadlineChecked, FloorChecked, WorkerHonoursDeadline, PrincipalLocks, RefreshOnUse, CoverFresh, Slack, DeadlineSlack

None == "none"
NoTime == -1000   \* a key never asked for

VARIABLES
    pnow,      \* Postgres's clock
    backs,     \* steps back so far
    nextSeq,   \* the sequence's next value
    shared,    \* the uses holding the fence lock shared
    plock,     \* the use holding the principal's lock, or None
    u,         \* each use's state
    log,       \* the committed entries (requests): number, key, at, deadline, when decided, the cap's decision
    bulk,      \* the principal's bulk rows, committed: each key's `last`, or NoTime
    floor,     \* the floor of `at`
    cp,        \* the checkpointer: a window closed and not yet signed
    lastUpto,  \* where the last checkpoint ended
    lastFloor, \* the floor its barrier set: where the next one reads uses from
    signed,    \* the checkpoints signed: their range and the numbers they read
    released,  \* the values that left: the use, its key, its at and deadline, the time
    cover      \* the isolate's cover per key: the number of an allowed entry, or 0

vars == <<pnow, backs, nextSeq, shared, plock, u, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

Max(a, b) == IF a > b THEN a ELSE b
Margin == IF Slack THEN Refresh ELSE 0
CountMargin == Margin + (IF DeadlineSlack THEN D ELSE 0)

\* The cap's set at time t, on rows L; the other keys that count against a new one.
InSet(L, k, t) == L[k] > t - BulkWindow - Margin
Counts(L, k, t) == L[k] > t - BulkWindow - CountMargin
Fresh(L, k, t) == L[k] > t - Refresh

\* The cap's rule for a request for k at t, on rows L: admitted or not, and the `last` it writes
\* (NoTime: none). The live statement B and the replay apply the same rule.
Rule(L, k, t) ==
    IF InSet(L, k, t)
    THEN [admitted |-> TRUE, write |-> IF RefreshOnUse /\ ~Fresh(L, k, t) THEN t ELSE NoTime]
    ELSE IF Cardinality({k2 \in Keys \ {k} : Counts(L, k2, t)}) >= BulkCount
         THEN [admitted |-> FALSE, write |-> NoTime]
         ELSE [admitted |-> TRUE, write |-> t]

Init ==
    /\ pnow = 0
    /\ backs = 0
    /\ nextSeq = 1
    /\ shared = {}
    /\ plock = None
    /\ u = [x \in Uses |-> [pc |-> "idle", key |-> None, at |-> 0, deadline |-> 0, decidedAt |-> 0, seq |-> 0,
                            covered |-> FALSE, admitted |-> FALSE, write |-> NoTime]]
    /\ log = {}
    /\ bulk = [k \in Keys |-> NoTime]
    /\ floor = 0 - D   \* the schema's: below every use to come
    /\ cp = [open |-> FALSE, from |-> 0, upto |-> 0, readFloor |-> 0, floor |-> 0]
    /\ lastUpto = 0
    /\ lastFloor = 0 - D
    /\ signed = {}
    /\ released = {}
    /\ cover = [k \in Keys |-> 0]

-----------------------------------------------------------------------------
(* Clocks. *)

Tick ==
    /\ pnow < MaxTime
    /\ pnow' = pnow + 1
    /\ UNCHANGED <<backs, nextSeq, shared, plock, u, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

ClockBack ==
    /\ backs < MaxClockBacks
    /\ pnow > 0
    /\ pnow' = pnow - 1
    /\ backs' = backs + 1
    /\ UNCHANGED <<nextSeq, shared, plock, u, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

-----------------------------------------------------------------------------
(* A use. *)

\* It arrives, for a key: stamped by the Worker's clock, its deadline set.
UseStart(x) ==
    /\ u[x].pc = "idle"
    /\ \E k \in Keys, s \in -MaxSkew..MaxSkew :
          u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "started", !.key = k, !.at = pnow + s, !.deadline = pnow + s + D]]
    /\ UNCHANGED <<pnow, backs, nextSeq, shared, plock, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

\* It gets the fence lock shared (no barrier holds it), then checks the floor: below it, it lets
\* the lock go having written nothing.
UseLock(x) ==
    /\ u[x].pc = "started"
    /\ LET late == FloorChecked /\ u[x].at < floor
       IN /\ u' = [u EXCEPT ![x].pc = IF late THEN "done" ELSE "locked"]
          /\ shared' = IF late THEN shared ELSE shared \cup {x}
    /\ UNCHANGED <<pnow, backs, nextSeq, plock, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

\* Statement A: the key's row, as committed. A key that must enter the set or be moved on asks
\* for the principal's lock.
UseRead(x) ==
    /\ u[x].pc = "locked"
    /\ LET k == u[x].key
           t == u[x].at
       IN u' = [u EXCEPT ![x].pc = IF PrincipalLocks /\ (~InSet(bulk, k, t) \/ ~Fresh(bulk, k, t)) THEN "waiting" ELSE "read"]
    /\ UNCHANGED <<pnow, backs, nextSeq, shared, plock, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

UsePrincipalLock(x) ==
    /\ u[x].pc = "waiting"
    /\ plock = None
    /\ plock' = x
    /\ u' = [u EXCEPT ![x].pc = "read"]
    /\ UNCHANGED <<pnow, backs, nextSeq, shared, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

\* Statement B, its snapshot taken now: past its deadline, nothing (the call ends, its locks go);
\* a repeat on the isolate's cover writes nothing; else the cap's rule, and the entry's number.
UseLate(x) ==
    /\ u[x].pc = "read"
    /\ DeadlineChecked /\ pnow > u[x].deadline
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ shared' = shared \ {x}
    /\ plock' = IF plock = x THEN None ELSE plock
    /\ UNCHANGED <<pnow, backs, nextSeq, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

UseRun(x) ==
    /\ u[x].pc = "read"
    /\ DeadlineChecked => pnow <= u[x].deadline
    /\ LET k == u[x].key
           t == u[x].at
           covered == Covers /\ cover[k] /= 0 /\ InSet(bulk, k, t) /\ (CoverFresh => Fresh(bulk, k, t))
           r == Rule(bulk, k, t)
       IN u' = [u EXCEPT ![x] = [@ EXCEPT !.pc = "ran", !.covered = covered, !.decidedAt = pnow,
                                 !.admitted = covered \/ r.admitted, !.write = IF covered THEN NoTime ELSE r.write,
                                 !.seq = IF covered THEN 0 ELSE nextSeq]]
          /\ nextSeq' = IF covered THEN nextSeq ELSE nextSeq + 1
    /\ UNCHANGED <<pnow, backs, shared, plock, log, bulk, floor, cp, lastUpto, lastFloor, signed, released, cover>>

\* The commit: the entry and the row (greatest of the two times, as an upsert would), then the
\* locks go.
UseCommit(x) ==
    /\ u[x].pc = "ran"
    /\ LET k == u[x].key
       IN /\ log' = IF u[x].covered THEN log
                    ELSE log \cup {[seq |-> u[x].seq, key |-> k, at |-> u[x].at, deadline |-> u[x].deadline,
                                    decidedAt |-> u[x].decidedAt, admitted |-> u[x].admitted]}
          /\ bulk' = IF u[x].write = NoTime THEN bulk ELSE [bulk EXCEPT ![k] = Max(@, u[x].write)]
    /\ shared' = shared \ {x}
    /\ plock' = IF plock = x THEN None ELSE plock
    /\ u' = [u EXCEPT ![x].pc = "committed"]
    /\ UNCHANGED <<pnow, backs, nextSeq, floor, cp, lastUpto, lastFloor, signed, released, cover>>

\* The Worker: the value leaves if the cap admitted it, unless its deadline has passed (it answered
\* 503 then). An admitted entry of its own becomes the isolate's cover; a refusal ends it.
UseRelease(x) ==
    /\ u[x].pc = "committed"
    /\ LET k == u[x].key
           answers == u[x].admitted /\ (WorkerHonoursDeadline => pnow <= u[x].deadline)
       IN /\ released' = IF answers THEN released \cup {[id |-> x, key |-> k, at |-> u[x].at, deadline |-> u[x].deadline, t |-> pnow]}
                         ELSE released
          /\ cover' = IF ~u[x].admitted THEN [cover EXCEPT ![k] = 0]
                      ELSE IF answers /\ ~u[x].covered THEN [cover EXCEPT ![k] = u[x].seq] ELSE cover
    /\ u' = [u EXCEPT ![x].pc = "done"]
    /\ UNCHANGED <<pnow, backs, nextSeq, shared, plock, log, bulk, floor, cp, lastUpto, lastFloor, signed>>

-----------------------------------------------------------------------------
(* The checkpointer. *)

\* The barrier, under the fence lock exclusive: the floor raised to its clock less D, never
\* lowered; every number handed out closed.
CheckpointClose ==
    /\ ~cp.open
    /\ Cardinality(signed) < MaxCheckpoints
    /\ shared = {}
    /\ floor' = Max(floor, pnow - D)
    /\ cp' = [open |-> TRUE, from |-> lastUpto, upto |-> nextSeq - 1, readFloor |-> lastFloor, floor |-> Max(floor, pnow - D)]
    /\ UNCHANGED <<pnow, backs, nextSeq, shared, plock, u, log, bulk, lastUpto, lastFloor, signed, released, cover>>

\* It reads the window, the uses through the `at` index from the previous barrier's floor, and signs.
CheckpointSign ==
    /\ cp.open
    /\ signed' = signed \cup {[from |-> cp.from, upto |-> cp.upto,
                               seqs |-> {e.seq : e \in {d \in log : cp.from < d.seq /\ d.seq <= cp.upto /\ d.at >= cp.readFloor}}]}
    /\ lastUpto' = cp.upto
    /\ lastFloor' = cp.floor
    /\ cp' = [cp EXCEPT !.open = FALSE]
    /\ UNCHANGED <<pnow, backs, nextSeq, shared, plock, u, log, bulk, floor, released, cover>>

-----------------------------------------------------------------------------

Next ==
    \/ Tick \/ ClockBack
    \/ \E x \in Uses : UseStart(x) \/ UseLock(x) \/ UseRead(x) \/ UsePrincipalLock(x) \/ UseLate(x) \/ UseRun(x) \/ UseCommit(x)
                      \/ UseRelease(x)
    \/ CheckpointClose \/ CheckpointSign

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold. *)

\* Each checkpoint signed exactly the entries numbered in its range: none missed by its `at`.
CheckpointsHold ==
    \A k \in signed : {e.seq : e \in {d \in log : k.from < d.seq /\ d.seq <= k.upto}} = k.seqs

\* No entry was decided past its deadline.
NoLateWork ==
    \A e \in log : e.decidedAt <= e.deadline

\* No value left past its deadline.
ReleaseByDeadline ==
    \A r \in released : r.t <= r.deadline

\* In any window of BulkWindow, by the requests' `at`, the values released to the principal are
\* of BulkCount distinct keys at most.
Times == (0 - MaxSkew)..(MaxTime + MaxSkew)
BulkCapHolds ==
    \A t \in Times : Cardinality({r.key : r \in {q \in released : t - BulkWindow < q.at /\ q.at <= t}}) <= BulkCount

\* The replay: the entries in number order, the cap's rule applied to each on the rows the ones
\* before it left. It must decide each as live did, and leave the rows live left.
RECURSIVE Replay(_, _, _)
Replay(es, L, decided) ==
    IF es = {} THEN [rows |-> L, decided |-> decided]
    ELSE LET e == CHOOSE e \in es : \A d \in es : e.seq <= d.seq
             r == Rule(L, e.key, e.at)
         IN Replay(es \ {e}, IF r.write = NoTime THEN L ELSE [L EXCEPT ![e.key] = Max(@, r.write)],
                   decided \cup {<<e.seq, r.admitted>>})

BulkReplayAgrees ==
    LET R == Replay(log, [k \in Keys |-> NoTime], {})
    IN /\ \A e \in log : <<e.seq, e.admitted>> \in R.decided
       /\ R.rows = bulk

=============================================================================
