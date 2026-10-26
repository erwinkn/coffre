-------------------------------- MODULE Bulk ---------------------------------
(***************************************************************************)
(* The vault's bulk limit (R28): at most so many distinct keys released to *)
(* one principal in any rolling window, however many requests and          *)
(* credentials they read with at once. docs/formal.md says what this       *)
(* covers, what it abstracts and what it does not prove.                   *)
(*                                                                         *)
(* One step is one SQL statement, or a run of statements nothing else can  *)
(* interleave with because the step holds the lock they need, as in        *)
(* Coffre.tla. Isolation is READ COMMITTED. One lock, held to the end of   *)
(* its transaction: the log's head. A read takes the reader's row too,     *)
(* vault_members, but shared with their other reads (vault store.ts,       *)
(* lockMembers, FOR SHARE), so it orders none of them, and is left out.    *)
(*                                                                         *)
(* There is no counter: each decision counts the distinct keys of the      *)
(* reader's `secret.read` entries stamped inside the window, with the keys *)
(* it would release (vault snapshot.postgres.ts, the bulk count). The code *)
(* reads them from vault_releases, each key's newest stamp, which a        *)
(* trigger keeps from those entries in their own transaction: the same     *)
(* count. Time is a clock that ticks: an entry stamped at t counts until   *)
(* t + Window.                                                             *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Keys,           \* the keys the principal reads
    Cap,            \* bulkLimit.count: how many distinct keys in a window
    Window,         \* bulkLimit.windowMs, in ticks
    MaxTime,        \* how far the clock runs
    Procs,          \* concurrent requests, each one a process
    Ops,            \* Ops[p]: the reads process p may run
    Budget          \* Budget[p]: how many it runs, one after another

CONSTANTS
    \* With a key service, the read counts again under the head, once the
    \* keys are open, in the statement that takes it (vault.ts, #keys, the
    \* check run again with `late`), not only before the key service.
    BulkRecountUnderHead,
    \* The count takes in the keys the read would release (the count adds
    \* the distinct keys asked for), not only those released before.
    CountsTheRequest,
    \* The count is the principal's, all their credentials' together (the
    \* entries' `actor`), not the credential's.
    PerPrincipal,
    \* The entries are stamped with the clock of the statement that counted
    \* last (log.ts, appendEntries, `occurred_at` from the held head), not
    \* with the clock before the key service.
    StampedWhenCounted

None == "none"

VARIABLES
    now,            \* the database's clock
    log,            \* the vault's allowed `secret.read` entries: [key, cred, stamp]
    head,           \* the process holding the log's head, or None
    pc, op, l, left,
    decided         \* history: each key the vault decided to release, and when

procs == <<pc, op, l, left>>
vars == <<now, log, head, procs, decided>>

-----------------------------------------------------------------------------

\* The distinct keys of the entries the window at t holds, the request's
\* own if it is counted too: `occurred_at > NOW - window`.
Counted(t, cred, request) ==
    {e.key : e \in {e \in log : e.stamp + Window > t /\ (PerPrincipal \/ e.cred = cred)}}
      \cup (IF CountsTheRequest THEN request ELSE {})

\* The read is over the limit: refused whole, each key `bulk_limit`.
Over(t, o) == Cardinality(Counted(t, o.cred, o.keys)) > Cap

NoOp == [kind |-> "none", keys |-> {}, cred |-> None, remote |-> FALSE]
L0 == [stamp |-> 0, over |-> FALSE]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Release(p) == head' = IF head = p THEN None ELSE head

Refuse(p) ==
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<now, log, op, l, left, decided>>

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = L0]
         /\ Goto(p, IF o.remote THEN "read.check" ELSE "read.head")
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<now, log, head, decided>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A read (vault vault.ts, unwrap, #keys, #decideOnce). With a local key,  *)
(* the vault takes the head in the statement that counts, right after the  *)
(* row, and decides once. With a key service, it counts without the head,  *)
(* opens the keys, then counts again in the statement that takes the head. *)
(* The intent a key service's read logs first, in a transaction of its     *)
(* own, counts the same way and releases nothing: left out.                *)
(***************************************************************************)

\* With a key service: the count, without the head; then the key service,
\* while the clock may run, and the reader's other reads with it.
ReadCheck(p) ==
    /\ pc[p] = "read.check"
    /\ IF Over(now, op[p])
         THEN Refuse(p)
         ELSE /\ l' = [l EXCEPT ![p] = [stamp |-> now, over |-> FALSE]]
              /\ Goto(p, "read.head")
              /\ UNCHANGED <<now, log, head, op, left, decided>>

\* The statement that takes the head waits for it (SKIP LOCKED, then a
\* statement of its own) and reads again once it holds it.
ReadHead(p) ==
    /\ pc[p] = "read.head"
    /\ head \in {None, p}
    /\ head' = p
    /\ Goto(p, "read.count")
    /\ UNCHANGED <<now, log, op, l, left, decided>>

\* Under the head, in the statement that takes it: the count (again, with
\* a key service), and the clock the entries are stamped with. This is the
\* decision, at that clock.
ReadCount(p) ==
    /\ pc[p] = "read.count"
    /\ IF (~op[p].remote \/ BulkRecountUnderHead) /\ Over(now, op[p])
         THEN Refuse(p)
         ELSE /\ l' = [l EXCEPT ![p].stamp = IF op[p].remote /\ ~StampedWhenCounted THEN @ ELSE now]
              /\ decided' = decided \cup {[key |-> k, at |-> now] : k \in op[p].keys}
              /\ Goto(p, "read.commit")
              /\ UNCHANGED <<now, log, head, op, left>>

\* The keys opened, the entries appended with that stamp, the commit, the
\* keys handed over; the clock may have moved since the count.
ReadCommit(p) ==
    /\ pc[p] = "read.commit"
    /\ log' = log \cup {[key |-> k, cred |-> op[p].cred, stamp |-> l[p].stamp] : k \in op[p].keys}
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<now, op, l, left, decided>>

-----------------------------------------------------------------------------

\* The clock runs, whatever the requests do.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<log, head, procs, decided>>

Init ==
    /\ now = 0
    /\ log = {}
    /\ head = None
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ decided = {}

Step(p) == Begin(p) \/ ReadCheck(p) \/ ReadHead(p) \/ ReadCount(p) \/ ReadCommit(p)

Finished == \A p \in Procs : pc[p] = "idle" /\ left[p] = 0

Next == (\E p \in Procs : Step(p)) \/ Tick \/ (Finished /\ now = MaxTime /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK ==
    /\ now \in 0..MaxTime
    /\ head \in Procs \cup {None}

\* However its reads interleave, and whichever credentials they come in on,
\* the vault decides to release at most Cap distinct keys to the principal
\* in any window: by when each decision was, the clock of the statement
\* that counted, not by what its entries say. A key reaches its caller at
\* the commit after, a transaction later: a window of releases, rather than
\* decisions, may hold one more read's keys at its edge (docs/formal.md).
CapHolds == Cardinality({d.key : d \in {d \in decided : d.at + Window > now}}) <= Cap

=============================================================================
