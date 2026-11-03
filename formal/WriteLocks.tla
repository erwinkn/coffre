----------------------------- MODULE WriteLocks -----------------------------
(***************************************************************************)
(* The locks of a key write in five round trips (T179 PR 3; Writing.tla's  *)
(* WCommit, which holds none), against the transactions that take the same *)
(* ones, with Postgres's lock queue: a request waits for every lock held   *)
(* that conflicts with it, and also for every request queued ahead of it   *)
(* that does (a shared request queues behind a waiting exclusive one).     *)
(* Postgres breaks such a cycle only after `deadlock_timeout` (1 s), by    *)
(* reordering the queue or failing one: meanwhile the fence is held and    *)
(* every use waits.                                                        *)
(*                                                                         *)
(*   write    the key write's transaction (`heldWrite`, `heldWrites`):     *)
(*            0.14's head; its credential's last use, when due (an UPDATE  *)
(*            of the credential's row); `hold_inputs`: the issue lock      *)
(*            shared, then the fence exclusive;                            *)
(*   issue    a token issued on that credential (`issue_token`, 0036): the *)
(*            credential's row FOR SHARE, then the issue lock shared;      *)
(*   barrier  the checkpointer's: the issue lock exclusive, then the       *)
(*            fence;                                                       *)
(*   revoke   the credential revoked (`revoke_credential`, 0034): 0.14's   *)
(*            head, the row, the fence;                                    *)
(*   use      a use: the fence shared.                                     *)
(*                                                                         *)
(* The protection (scripts/formal.sh turns it off):                        *)
(*   TouchFirst  the write updates its credential's row before the hold,   *)
(*               as the issuer and the revoke take it: row, issue lock,    *)
(*               fence. Without, it holds the issue lock and the fence and *)
(*               waits for the row, which the issuer holds shared, queued  *)
(*               for the issue lock behind the barrier, which waits for    *)
(*               the write's issue lock: a cycle (review r1 of #469).      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS TouchFirst

Procs == {"write", "issue", "barrier", "revoke", "use"}

\* Each one's locks, in the order it takes them: a lock and its mode, S(hared) or X (exclusive).
Plan(p) ==
    CASE p = "write" ->
            IF TouchFirst THEN << <<"head", "X">>, <<"cred", "X">>, <<"issue", "S">>, <<"fence", "X">> >>
                          ELSE << <<"head", "X">>, <<"issue", "S">>, <<"fence", "X">>, <<"cred", "X">> >>
      [] p = "issue" -> << <<"cred", "S">>, <<"issue", "S">> >>
      [] p = "barrier" -> << <<"issue", "X">>, <<"fence", "X">> >>
      [] p = "revoke" -> << <<"head", "X">>, <<"cred", "X">>, <<"fence", "X">> >>
      [] p = "use" -> << <<"fence", "S">> >>

Locks == {"head", "cred", "issue", "fence"}

VARIABLES
    pc,      \* each one's step: "run" (asks its next lock, or commits), "wait" (queued), "done"
    got,     \* how many of its locks it holds
    held,    \* each lock's holders: a set of [p, mode]
    queue    \* each lock's requests waiting, first come first

vars == <<pc, got, held, queue>>

Compatible(m1, m2) == m1 = "S" /\ m2 = "S"
Next(p) == Plan(p)[got[p] + 1]

Init ==
    /\ pc = [p \in Procs |-> "run"]
    /\ got = [p \in Procs |-> 0]
    /\ held = [l \in Locks |-> {}]
    /\ queue = [l \in Locks |-> <<>>]

\* It asks for its next lock, at the end of that lock's queue.
Ask(p) ==
    /\ pc[p] = "run"
    /\ got[p] < Len(Plan(p))
    /\ queue' = [queue EXCEPT ![Next(p)[1]] = Append(@, [p |-> p, mode |-> Next(p)[2]])]
    /\ pc' = [pc EXCEPT ![p] = "wait"]
    /\ UNCHANGED <<got, held>>

\* The request at `i` in its lock's queue is granted once it conflicts with no holder and no request ahead of it.
Grantable(l, i) ==
    LET r == queue[l][i] IN
    /\ \A h \in held[l] : h.p = r.p \/ Compatible(h.mode, r.mode)
    /\ \A j \in 1..(i - 1) : Compatible(queue[l][j].mode, r.mode)

Grant(l, i) ==
    LET r == queue[l][i] IN
    /\ Grantable(l, i)
    /\ held' = [held EXCEPT ![l] = @ \cup {r}]
    /\ queue' = [queue EXCEPT ![l] = SubSeq(@, 1, i - 1) \o SubSeq(@, i + 1, Len(@))]
    /\ got' = [got EXCEPT ![r.p] = @ + 1]
    /\ pc' = [pc EXCEPT ![r.p] = "run"]

\* With all its locks, it commits, and lets them go.
Commit(p) ==
    /\ pc[p] = "run"
    /\ got[p] = Len(Plan(p))
    /\ held' = [l \in Locks |-> {h \in held[l] : h.p /= p}]
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<got, queue>>

Done == \A p \in Procs : pc[p] = "done"

Step ==
    \/ \E p \in Procs : Ask(p) \/ Commit(p)
    \/ \E l \in Locks : \E i \in 1..Len(queue[l]) : Grant(l, i)
    \/ (Done /\ UNCHANGED vars)

Spec == Init /\ [][Step]_vars

-----------------------------------------------------------------------------

TypeOK ==
    /\ pc \in [Procs -> {"run", "wait", "done"}]
    /\ \A p \in Procs : got[p] \in 0..Len(Plan(p))

\* Whom p waits for: a holder of its lock in a conflicting mode, or a request ahead of it in the queue that conflicts.
WaitsFor(p, q) ==
    /\ p /= q
    /\ pc[p] = "wait"
    /\ LET l == Next(p)[1]
           m == Next(p)[2]
           at == CHOOSE i \in 1..Len(queue[l]) : queue[l][i].p = p
       IN \/ \E h \in held[l] : h.p = q /\ ~Compatible(h.mode, m)
          \/ \E j \in 1..(at - 1) : queue[l][j].p = q /\ ~Compatible(queue[l][j].mode, m)

\* Everyone p waits for, through any number of others.
Reach(p) ==
    LET R[n \in 0..Cardinality(Procs)] ==
            IF n = 0 THEN {q \in Procs : WaitsFor(p, q)}
            ELSE LET prev == R[n - 1] IN prev \cup {q \in Procs : \E r \in prev : WaitsFor(r, q)}
    IN R[Cardinality(Procs)]

\* No one waits, through others, for itself: Postgres never has a cycle to break.
NoWaitCycle == \A p \in Procs : p \notin Reach(p)

\* Every run ends: each one commits.
AllCommit == <>Done

=============================================================================
