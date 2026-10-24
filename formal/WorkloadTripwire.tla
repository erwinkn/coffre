--------------------------- MODULE WorkloadTripwire ---------------------------
(***************************************************************************)
(* The enrollment tripwire (docs/design/workload-access.md, 4.4, item 3):  *)
(* which histories of one code's sessions freeze its binding. The rule is  *)
(* arithmetic over the code's roots, live or ended, so the model is a      *)
(* timeline rather than a race: the deployment's instances crash, restart, *)
(* redeploy with overlap and narrow, a thief who holds a copy of the code  *)
(* enrolls and leaves, and after each exchange and each tick the rule      *)
(* reads the rows. WorkloadEnrollment.tla holds the races (the count under *)
(* the head, renewal on the clock). docs/formal.md says what this covers,  *)
(* what it abstracts and what it does not prove.                          *)
(*                                                                         *)
(* A tick is a renewal period: each running instance renews within it, and *)
(* a session that stops renewing lives `Life` ticks more. The run is       *)
(* shorter than the rule's hour, and starts at the last lift, so the rule  *)
(* counts it whole.                                                        *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Procs,          \* "dep", the deployment, and "thief"
    Ops,            \* Ops[p]: the events p may cause
    Budget,         \* Budget[p]: how many, one after another
    Most,           \* Most[kind]: how many of each the run holds at most
    Replicas,       \* the binding's `replicas`
    Life,           \* a session's life past its last renewal, in ticks
    Overlap,        \* how long a redeploy runs old and new instances together
    Threshold,      \* `overlapMinutes × replicas`, in session-ticks
    MaxTime         \* how far the clock runs

(***************************************************************************)
(* The rule's parts, each a switch, and the two assumptions the copy is    *)
(* caught under, which the model must fail without.                        *)
(***************************************************************************)
CONSTANTS
    \* The excess, `∫ (live − replicas)⁺ dt` over every root, ended ones
    \* included, past the threshold. Off, review r3's rule: the age of the
    \* `(replicas + 1)`-th live root past it.
    ExcessIntegral,
    \* More than `4 × replicas` roots made. Off, no count of roots.
    ChurnCounted,
    \* Only roots count (`ancestors IS NULL`). Off, `narrow`'s children too.
    RootsOnly,
    \* Assumed: the deployment never leaves a slot free.
    ReplicasFull,
    \* Assumed: a thief, once in, stays.
    ThiefStays

None == "none"
NoId == <<None, 0>>
\* A running session's end: it renews.
Forever == MaxTime + Life + 1

Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b

VARIABLES
    now,
    roots,          \* the code's sessions: [id, who, created, ends, child]
    running,        \* the deployment's running instances, by session
    old,            \* during a redeploy, the instances it replaces
    started,        \* when the redeploy started
    thief,          \* the thief's session, or NoId
    counts,         \* counts[kind]: the events of each kind so far
    log,            \* `workload.freeze`, once the rule fires
    pc, op, l, left

procs == <<pc, op, l, left>>
vars == <<now, roots, running, old, started, thief, counts, log, procs>>

-----------------------------------------------------------------------------
(* The rule, over a set of rows, at a time *)

Row(id) == CHOOSE r \in roots : r.id = id

LiveIn(rows, t) == {r \in rows : r.created <= t /\ t < r.ends}
Counted(rows) == IF RootsOnly THEN {r \in rows : ~r.child} ELSE rows

\* The excess over the tick from u to u + 1.
Over(rows, u) == Max(0, Cardinality(LiveIn(Counted(rows), u)) - Replicas)

RECURSIVE ExcessTo(_, _)
ExcessTo(rows, t) == IF t = 0 THEN 0 ELSE ExcessTo(rows, t - 1) + Over(rows, t - 1)

\* Review r3's rule: a live root beyond the `replicas` oldest, older than
\* the threshold.
AgedExtra(rows, t) ==
    \E r \in LiveIn(Counted(rows), t) :
        /\ Cardinality({q \in LiveIn(Counted(rows), t) : q.created <= r.created} \ {r}) >= Replicas
        /\ t - r.created > Threshold

Contended(rows, t) ==
    \/ IF ExcessIntegral THEN ExcessTo(rows, t) > Threshold ELSE AgedExtra(rows, t)
    \/ ChurnCounted /\ Cardinality(Counted(rows)) > 4 * Replicas

Frozen == log # <<>>

\* The rule runs after an exchange or a renewal (the tick), from the rows.
Trip(rows, t) ==
    log' = IF ~Frozen /\ Contended(rows, t) THEN Append(log, [kind |-> "workload.freeze", time |-> t]) ELSE log

\* An exchange is refused `full` past `2 × replicas` live roots, and
\* `frozen` once frozen.
Admitted(n) == ~Frozen /\ Cardinality(LiveIn({r \in roots : ~r.child}, now)) + n <= 2 * Replicas

-----------------------------------------------------------------------------
(* Events *)

NoOp == [kind |-> "none"]
L0 == [id |-> NoId]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ counts[o.kind] < Most[o.kind]
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = [L0 EXCEPT !.id = <<p, left[p]>>]]
         /\ Goto(p, o.kind)
         /\ counts' = [counts EXCEPT ![o.kind] = @ + 1]
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<now, roots, running, old, started, thief, log>>

Done(p) == Goto(p, "idle") /\ UNCHANGED <<op, l, left, counts>>

Root(p, who, child) == [id |-> l[p].id, who |-> who, created |-> now, ends |-> IF child THEN now + Life ELSE Forever, child |-> child]

Ended(id, at) == {IF r.id = id THEN [r EXCEPT !.ends = Min(r.ends, at)] ELSE r : r \in roots}

\* An instance crashes: its session lives `Life` more, unrenewed.
Crash(p) ==
    /\ pc[p] = "crash"
    /\ IF running = {}
         THEN UNCHANGED <<roots, running, old>>
         ELSE \E i \in running :
                /\ roots' = Ended(i, now + Life)
                /\ running' = running \ {i}
                /\ old' = old \ {i}
    /\ Done(p)
    /\ UNCHANGED <<now, started, thief, log>>

\* An instance stops for long, a slot left free, but only without
\* ReplicasFull: it logs out.
Down(p) ==
    /\ pc[p] = "down"
    /\ IF running = {} \/ ReplicasFull
         THEN UNCHANGED <<roots, running>>
         ELSE \E i \in running :
                /\ roots' = Ended(i, now)
                /\ running' = running \ {i}
    /\ Done(p)
    /\ UNCHANGED <<now, old, started, thief, log>>

\* A stopped instance starts again and enrolls, if admitted.
Restart(p) ==
    /\ pc[p] = "restart"
    /\ IF Cardinality(running) < Replicas /\ old = {} /\ Admitted(1)
         THEN LET r == Root(p, "dep", FALSE) IN
              /\ roots' = roots \cup {r}
              /\ running' = running \cup {r.id}
              /\ Trip(roots \cup {r}, now)
         ELSE UNCHANGED <<roots, running, log>>
    /\ Done(p)
    /\ UNCHANGED <<now, old, started, thief>>

\* A redeploy on the same code starts all `replicas` new instances beside
\* the old ones, which stop, logging out, within `Overlap`.
NewRoots(p) == {[Root(p, "dep", FALSE) EXCEPT !.id = <<l[p].id[1], l[p].id[2], i>>] : i \in 1..Replicas}

Redeploy(p) ==
    /\ pc[p] = "redeploy"
    /\ IF Cardinality(running) = Replicas /\ old = {} /\ Admitted(Replicas)
         THEN /\ roots' = roots \cup NewRoots(p)
              /\ running' = {r.id : r \in NewRoots(p)}
              /\ old' = running
              /\ started' = now
              /\ Trip(roots \cup NewRoots(p), now)
         ELSE UNCHANGED <<roots, running, old, started, log>>
    /\ Done(p)
    /\ UNCHANGED <<now, thief>>

Finish ==
    /\ old # {}
    /\ roots' = {IF r.id \in old THEN [r EXCEPT !.ends = Min(r.ends, now)] ELSE r : r \in roots}
    /\ old' = {}
    /\ UNCHANGED <<now, running, started, thief, counts, log, procs>>

\* An instance narrows its session for a tool: a child, which lives `Life`.
Narrow(p) ==
    /\ pc[p] = "narrow"
    /\ roots' = IF running = {} THEN roots ELSE roots \cup {Root(p, "dep", TRUE)}
    /\ Done(p)
    /\ UNCHANGED <<now, running, old, started, thief, log>>

\* The thief enrolls with its copy, if admitted, and renews from then on.
Enroll(p) ==
    /\ pc[p] = "enroll"
    /\ IF (thief = NoId \/ Row(thief).ends <= now) /\ Admitted(1)
         THEN LET r == Root(p, "thief", FALSE) IN
              /\ roots' = roots \cup {r}
              /\ thief' = r.id
              /\ Trip(roots \cup {r}, now)
         ELSE UNCHANGED <<roots, thief, log>>
    /\ Done(p)
    /\ UNCHANGED <<now, running, old, started>>

\* It logs out, unless it stays.
Leave(p) ==
    /\ pc[p] = "leave"
    /\ roots' = IF thief = NoId \/ ThiefStays THEN roots ELSE Ended(thief, now)
    /\ Done(p)
    /\ UNCHANGED <<now, running, old, started, thief, log>>

\* The clock runs, renewing every running session; a redeploy finishes in
\* time. The rule runs after the renewals.
Tick ==
    /\ now < MaxTime
    /\ ~(old # {} /\ now >= started + Overlap)
    /\ now' = now + 1
    /\ Trip(roots, now + 1)
    /\ UNCHANGED <<roots, running, old, started, thief, counts, procs>>

Init ==
    /\ now = 0
    /\ roots = {[id |-> <<"init", i>>, who |-> "dep", created |-> 0, ends |-> Forever, child |-> FALSE] : i \in 1..Replicas}
    /\ running = {<<"init", i>> : i \in 1..Replicas}
    /\ old = {}
    /\ started = 0
    /\ thief = NoId
    /\ counts = [k \in DOMAIN Most |-> 0]
    /\ log = <<>>
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget

Step(p) ==
    \/ Begin(p)
    \/ Crash(p) \/ Down(p) \/ Restart(p) \/ Redeploy(p) \/ Narrow(p)
    \/ Enroll(p) \/ Leave(p)

Next == (\E p \in Procs : Step(p)) \/ Finish \/ Tick \/ (now = MaxTime /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* What must hold in every state (section 12.1).                           *)
(***************************************************************************)

TypeOK ==
    /\ now \in 0..MaxTime
    /\ running \subseteq {r.id : r \in roots}

\* What the thief alone added: in each tick, its live sessions, up to the
\* excess of the code's roots then.
RECURSIVE ForeignTo(_)
ForeignTo(t) ==
    IF t = 0 THEN 0
    ELSE ForeignTo(t - 1) + Min(Cardinality({r \in LiveIn(roots, t - 1) : r.who = "thief"}),
                                Max(0, Cardinality(LiveIn({r \in roots : ~r.child}, t - 1)) - Replicas))

\* What the deployment's own events add at most: each redeploy `replicas`
\* extra sessions for `Overlap`, each crash a session's tail of `Life` beside
\* its restart, and a root per restart and per new instance.
OwnExcess == Most["redeploy"] * Replicas * Overlap + Most["crash"] * Life
OwnRoots == Replicas + Most["redeploy"] * Replicas + Most["restart"]

\* With no foreign holder, the deployment's own crashes, restarts,
\* redeploys and children never freeze the code, while what they add stays
\* within the threshold and `4 × replicas` roots.
NoFalseContention == (OwnExcess <= Threshold /\ OwnRoots <= 4 * Replicas) => ~Frozen

\* A thief whose excess beside the deployment passes the threshold, in any
\* number of sessions with any gaps, or who makes more than `4 × replicas`
\* roots, has frozen the code.
TripwireFires ==
    (ForeignTo(now) > Threshold \/ Cardinality({r \in roots : r.who = "thief"}) > 4 * Replicas) => Frozen

\* Every copy that enrolls is frozen out once it has been in for longer than
\* the threshold. Not a guarantee: it holds only while the deployment
\* leaves no slot free and the thief stays (docs/formal.md).
CopyCaught == \A r \in roots : (r.who = "thief" /\ now > r.created + Threshold) => Frozen

=============================================================================
