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
(* what it abstracts and what it does not prove.                           *)
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
(* The rule's parts, each a switch, and the assumption the copy is caught  *)
(* under, which the model must fail without.                               *)
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
    \* A full code answers `full` (4.4, item 2). Off, review r1's rule: the
    \* exchange is admitted, and the oldest live roots fenced to make room.
    RefusesWhenFull,
    \* `full` answers are no signal. Off, review r2's rule: a run of two
    \* `full` in a row freezes the code.
    BusyIsNoSignal,
    \* A tripwire run reads the rows and appends its freeze in two steps,
    \* outside the exchange's and the renewal's transactions (scenario).
    TripLags,
    \* A run's freeze commits under the head only while the binding's
    \* newest freeze or lift is still the one the run read...
    TripFencedOnLift,
    \* ...which it reads before the rows it counts. Off, after them: a lift
    \* between the two reads passes the fence.
    EntryReadFirst,
    \* Assumed: the deployment never leaves a slot free.
    ReplicasFull

None == "none"
NoId == <<None, 0>>
\* A running session's end: it renews.
Forever == MaxTime + Life + 1

Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b

VARIABLES
    now,
    roots,          \* the code's sessions: [id, seq, who, created, ends, child], seq their order
    running,        \* the deployment's running instances, by session
    old,            \* during a redeploy, the instances it replaces
    started,        \* when the redeploy started
    thief,          \* the thief's session, or NoId
    counts,         \* counts[kind]: the events of each kind so far
    log,            \* the binding's `workload.freeze` and `workload.unfreeze` entries
    pending,        \* the tripwire runs under way: [at, entry, rows, since, from, hit]
    fenced,         \* the roots r1's rule fenced
    busy,           \* the `full` answers in a row
    pc, op, l, left

procs == <<pc, op, l, left>>
vars == <<now, roots, running, old, started, thief, counts, log, pending, fenced, busy, procs>>

-----------------------------------------------------------------------------
(* The rule, over a set of rows, at a time                                 *)

Row(id) == CHOOSE r \in roots : r.id = id

LiveIn(rows, t) == {r \in rows : r.created <= t /\ t < r.ends}
Counted(rows) == IF RootsOnly THEN {r \in rows : ~r.child} ELSE rows

\* The excess over the tick from u to u + 1.
Over(rows, u) == Max(0, Cardinality(LiveIn(Counted(rows), u)) - Replicas)

\* The binding is frozen while its newest entry is a freeze (8.2). The rule
\* counts only since the newest lift: its index (0: none), and its time.
Frozen == log # <<>> /\ log[Len(log)].kind = "workload.freeze"
LiftBefore(n) == LET is == {i \in 1..(n - 1) : log[i].kind = "workload.unfreeze"}
                 IN IF is = {} THEN 0 ELSE CHOOSE i \in is : \A j \in is : j <= i
Since == LiftBefore(Len(log) + 1)
From == IF Since = 0 THEN 0 ELSE log[Since].time

RECURSIVE ExcessTo(_, _)
ExcessTo(rows, t) == IF t <= From THEN 0 ELSE ExcessTo(rows, t - 1) + Over(rows, t - 1)

\* Review r3's rule: a live root beyond the `replicas` oldest, older than
\* the threshold.
AgedExtra(rows, t) ==
    \E r \in LiveIn(Counted(rows), t) :
        /\ Cardinality({q \in LiveIn(Counted(rows), t) : q.created <= r.created} \ {r}) >= Replicas
        /\ t - r.created > Threshold

Contended(rows, t) ==
    \/ IF ExcessIntegral THEN ExcessTo(rows, t) > Threshold ELSE AgedExtra(rows, t)
    \/ ChurnCounted /\ Cardinality({r \in Counted(rows) : r.created >= From}) > 4 * Replicas

\* A freeze, and the newest lift its count started from.
Freeze(from, t) == [kind |-> "workload.freeze", time |-> t, since |-> from]

\* The rule runs after an exchange or a renewal (the tick), from the rows:
\* at once, or, with TripLags, as a run of its own steps.
Trip(rows, t) ==
    IF TripLags
      THEN /\ pending' = pending \cup {[at |-> t, entry |-> FALSE, rows |-> FALSE, since |-> 0, from |-> 0, hit |-> FALSE]}
           /\ UNCHANGED log
      ELSE /\ log' = IF ~Frozen /\ Contended(rows, t) THEN Append(log, Freeze(Since, t)) ELSE log
           /\ UNCHANGED pending

\* A run's next step: it reads the binding's newest freeze or lift, the
\* fence; it counts the rows, from the newest lift then; and once it has
\* both, its freeze commits under the head only while the binding is not
\* frozen and the entry it read is still the newest. A run on a frozen
\* binding does nothing.
TripStep ==
    /\ \E run \in pending :
         LET rest == pending \ {run} IN
         IF ~run.entry /\ (EntryReadFirst \/ run.rows)
           THEN /\ pending' = rest \cup {[run EXCEPT !.entry = TRUE, !.since = Since]}
                /\ UNCHANGED log
         ELSE IF ~run.rows
           THEN /\ pending' = rest \cup {[run EXCEPT !.rows = TRUE, !.from = Since, !.hit = ~Frozen /\ Contended(roots, now)]}
                /\ UNCHANGED log
         ELSE /\ pending' = rest
              /\ log' = IF run.hit /\ ~Frozen /\ (TripFencedOnLift => run.since = Since)
                          THEN Append(log, Freeze(run.from, now)) ELSE log
    /\ UNCHANGED <<now, roots, running, old, started, thief, counts, fenced, busy, procs>>

\* How many slots an exchange of n roots lacks: past `2 × replicas` live
\* roots.
Short(n) == Cardinality(LiveIn({r \in roots : ~r.child}, now)) + n - 2 * Replicas

\* The k oldest live roots, which r1's rule fences, by when they were made.
Oldest(k) ==
    LET live == LiveIn({r \in roots : ~r.child}, now) IN
    CHOOSE set \in SUBSET live :
        Cardinality(set) = k /\ \A a \in set, b \in live \ set : a.seq < b.seq

\* An exchange of the rows `new`: refused `frozen` once frozen, and `full`
\* past the capacity, which counts towards a run of them; or, under r1's
\* rule, admitted with the oldest fenced. `admit` is what else it changes.
Exchange(new, admit) ==
    LET n == Cardinality(new)
        out == IF Short(n) > 0 THEN {r.id : r \in Oldest(Short(n))} ELSE {}
        rows == {IF r.id \in out THEN [r EXCEPT !.ends = Min(r.ends, now)] ELSE r : r \in roots} \cup new
    IN IF ~Frozen /\ (Short(n) <= 0 \/ ~RefusesWhenFull)
         THEN /\ roots' = rows
              /\ fenced' = fenced \cup out
              /\ busy' = 0
              /\ Trip(rows, now)
              /\ admit
         ELSE /\ busy' = IF Frozen THEN busy ELSE busy + 1
              /\ log' = IF ~Frozen /\ ~BusyIsNoSignal /\ busy + 1 >= 2
                          THEN Append(log, Freeze(Since, now)) ELSE log
              /\ UNCHANGED <<roots, fenced, running, old, started, thief, pending>>

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
    /\ UNCHANGED <<now, roots, running, old, started, thief, log, pending, fenced, busy>>

Done(p) == Goto(p, "idle") /\ UNCHANGED <<op, l, left, counts>>

Root(p, who, child) == [id |-> l[p].id, seq |-> Cardinality(roots) + 1, who |-> who, created |-> now,
                        ends |-> IF child THEN now + Life ELSE Forever, child |-> child]

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
    /\ UNCHANGED <<now, started, thief, log, pending, fenced, busy>>

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
    /\ UNCHANGED <<now, old, started, thief, log, pending, fenced, busy>>

\* A stopped instance starts again and enrolls.
Restart(p) ==
    /\ pc[p] = "restart"
    /\ LET r == Root(p, "dep", FALSE) IN
       IF Cardinality(running) < Replicas
         THEN Exchange({r}, running' = running \cup {r.id} /\ UNCHANGED <<old, started, thief>>)
         ELSE UNCHANGED <<roots, running, old, started, thief, log, pending, fenced, busy>>
    /\ Done(p)
    /\ UNCHANGED now

\* A redeploy on the same code starts all `replicas` new instances beside
\* the old ones, which stop, logging out, within `Overlap`.
NewRoots(p) == {[Root(p, "dep", FALSE) EXCEPT !.id = <<l[p].id[1], l[p].id[2], i>>, !.seq = Cardinality(roots) + i] : i \in 1..Replicas}

Redeploy(p) ==
    /\ pc[p] = "redeploy"
    /\ IF Cardinality(running) = Replicas /\ old = {}
         THEN Exchange(NewRoots(p), /\ running' = {r.id : r \in NewRoots(p)}
                                    /\ old' = running
                                    /\ started' = now
                                    /\ UNCHANGED thief)
         ELSE UNCHANGED <<roots, running, old, started, thief, log, pending, fenced, busy>>
    /\ Done(p)
    /\ UNCHANGED now

Finish ==
    /\ old # {}
    /\ roots' = {IF r.id \in old THEN [r EXCEPT !.ends = Min(r.ends, now)] ELSE r : r \in roots}
    /\ old' = {}
    /\ UNCHANGED <<now, running, started, thief, counts, log, pending, fenced, busy, procs>>

\* An instance narrows its session for a tool: a child, which lives `Life`.
Narrow(p) ==
    /\ pc[p] = "narrow"
    /\ roots' = IF running = {} THEN roots ELSE roots \cup {Root(p, "dep", TRUE)}
    /\ Done(p)
    /\ UNCHANGED <<now, running, old, started, thief, log, pending, fenced, busy>>

\* The thief enrolls with its copy, and renews from then on.
Enroll(p) ==
    /\ pc[p] = "enroll"
    /\ LET r == Root(p, "thief", FALSE) IN
       IF thief = NoId \/ Row(thief).ends <= now
         THEN Exchange({r}, thief' = r.id /\ UNCHANGED <<running, old, started>>)
         ELSE UNCHANGED <<roots, running, old, started, thief, log, pending, fenced, busy>>
    /\ Done(p)
    /\ UNCHANGED now

\* It logs out.
Leave(p) ==
    /\ pc[p] = "leave"
    /\ roots' = IF thief = NoId THEN roots ELSE Ended(thief, now)
    /\ Done(p)
    /\ UNCHANGED <<now, running, old, started, thief, log, pending, fenced, busy>>

\* A person lifts the freeze: `workload.unfreeze`.
Lift(p) ==
    /\ pc[p] = "lift"
    /\ log' = IF Frozen THEN Append(log, [kind |-> "workload.unfreeze", time |-> now, since |-> 0]) ELSE log
    /\ Done(p)
    /\ UNCHANGED <<now, roots, running, old, started, thief, pending, fenced, busy>>

\* The clock runs, renewing every running session; a redeploy finishes in
\* time. The rule runs after the renewals.
Tick ==
    /\ now < MaxTime
    /\ ~(old # {} /\ now >= started + Overlap)
    /\ now' = now + 1
    /\ Trip(roots, now + 1)
    /\ UNCHANGED <<roots, running, old, started, thief, counts, fenced, busy, procs>>

Init ==
    /\ now = 0
    /\ roots = {[id |-> <<"init", i>>, seq |-> i, who |-> "dep", created |-> 0, ends |-> Forever, child |-> FALSE] : i \in 1..Replicas}
    /\ running = {<<"init", i>> : i \in 1..Replicas}
    /\ old = {}
    /\ started = 0
    /\ thief = NoId
    /\ counts = [k \in DOMAIN Most |-> 0]
    /\ log = <<>>
    /\ pending = {}
    /\ fenced = {}
    /\ busy = 0
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget

Step(p) ==
    \/ Begin(p)
    \/ Crash(p) \/ Down(p) \/ Restart(p) \/ Redeploy(p) \/ Narrow(p)
    \/ Enroll(p) \/ Leave(p) \/ Lift(p)

Next == (\E p \in Procs : Step(p)) \/ Finish \/ TripStep \/ Tick \/ (now = MaxTime /\ UNCHANGED vars)

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
    IF t <= From THEN 0
    ELSE ForeignTo(t - 1) + Min(Cardinality({r \in LiveIn(roots, t - 1) : r.who = "thief"}),
                                Max(0, Cardinality(LiveIn({r \in roots : ~r.child}, t - 1)) - Replicas))

\* What the deployment's own events add at most: each redeploy `replicas`
\* extra sessions for `Overlap`, each crash a session's tail of `Life` beside
\* its restart, and a root per new instance and per crash's restart.
OwnExcess == Most["redeploy"] * Replicas * Overlap + Most["crash"] * Life
OwnRoots == Replicas + Most["redeploy"] * Replicas + Most["crash"]

\* What NoFalseContention assumes of the scenario: the deployment's own
\* events stay within the threshold and `4 × replicas` roots. Checked as an
\* invariant beside it, so that a scenario past it fails rather than
\* holding vacuously.
WithinOwnBudget == OwnExcess <= Threshold /\ OwnRoots <= 4 * Replicas

\* With no foreign holder, the deployment's own crashes, restarts,
\* redeploys and children never freeze the code, nor fence a session of an
\* instance still running.
NoFalseContention == ~Frozen /\ fenced \cap (running \cup old) = {}

\* A thief whose excess beside the deployment passes the threshold since
\* the newest lift, in any number of sessions with any gaps, or who makes
\* more than `4 × replicas` roots since, has frozen the code.
TripwireFires ==
    (ForeignTo(now) > Threshold \/ Cardinality({r \in roots : r.who = "thief" /\ r.created >= From}) > 4 * Replicas) => Frozen

\* A lift is not undone by the history before it: every freeze's count
\* started from the newest lift before the freeze.
LiftHolds == \A i \in 1..Len(log) : log[i].kind = "workload.freeze" => log[i].since = LiftBefore(i)

\* Every copy that has been in for longer than the threshold is frozen out.
\* Not a guarantee: it holds only while the deployment leaves no slot free
\* (docs/formal.md).
CopyCaught == \A r \in roots : (r.who = "thief" /\ Min(r.ends, now) - r.created > Threshold) => Frozen

=============================================================================
