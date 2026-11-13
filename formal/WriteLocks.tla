----------------------------- MODULE WriteLocks -----------------------------
(***************************************************************************)
(* The locks a change takes, and the order it takes them in, with          *)
(* Postgres's lock queue: a request waits for every lock held that         *)
(* conflicts with it, and also for every request queued ahead of it that   *)
(* does (a shared request queues behind a waiting exclusive one). Postgres *)
(* breaks such a cycle only after `deadlock_timeout` (1 s), by reordering  *)
(* the queue or failing one: meanwhile the fence is held and every use     *)
(* waits.                                                                  *)
(*                                                                         *)
(* That queue is the lock manager's, which an advisory lock goes through.  *)
(* A row's lock does not quite: FOR SHARE joins the shares already held on *)
(* a row even while a writer waits for them (`lockMembers` in the vault's  *)
(* store.ts, which pairs each member's row with an advisory lock for that  *)
(* reason). The model queues rows like the rest, and loses nothing by it   *)
(* here: in each flow one process at most asks for a given row shared (the *)
(* issue), so no share is ever there for another to join past a writer. A  *)
(* flow with two shared requests of one row must model that row's lock     *)
(* apart.                                                                  *)
(*                                                                         *)
(* Three locks are global. The change lock (0.16; before it, the row       *)
(* `audit_chain_head`, 0.14's head) is an advisory lock that only changes  *)
(* take, exclusive, where they took the head: in their first statement,    *)
(* after the members' rows. It orders a change against every other from    *)
(* there to its commit, so what it reads in between stands (Coffre.tla).   *)
(* The issue lock and the fence are taken by a change's last statement     *)
(* (`change_input`, `change_bindings`, `app_change`, `hold_inputs`,        *)
(* `admit_hold`), shared and exclusive. The order is: rows a flow shares   *)
(* with an issue, the change lock, the issue lock, the fence. A use takes  *)
(* the fence shared and no other; the checkpointer's barrier takes the     *)
(* issue lock, then the fence, and never the change lock.                  *)
(*                                                                         *)
(* Flow = "write": a key write in two round trips (Writing.tla's     *)
(* WCommit, which holds none).                                             *)
(*   write    the key write's transaction (`heldOnce`, `heldWrites`): the  *)
(*            change lock; its credential's last use, when due (an UPDATE  *)
(*            of the credential's row); `hold_inputs`: the issue lock      *)
(*            shared, then the fence exclusive; then the key's row (its    *)
(*            current version, an UPDATE);                                 *)
(*   patch    another change of that key down today's path (`setSecrets`,  *)
(*            `patchSecret`: a reference made of it, an archive, a         *)
(*            rename): the change lock (`audited`), the key's row (`lock`, *)
(*            FOR UPDATE), then `app_change`: the issue lock shared, the   *)
(*            fence;                                                       *)
(*   issue    a token issued on that credential (`issue_token`, 0036): the *)
(*            credential's row FOR SHARE, then the issue lock shared;      *)
(*   barrier  the checkpointer's: the issue lock exclusive, then the       *)
(*            fence;                                                       *)
(*   revoke   the credential revoked (`revoke_credential`, 0034): the      *)
(*            change lock, the row, the fence;                             *)
(*   use      a use: the fence shared.                                     *)
(* Its protections (scripts/formal.sh turns each off):                     *)
(*   TouchFirst  the write updates its credential's row before the hold,   *)
(*               as the issuer and the revoke take it: row, issue lock,    *)
(*               fence. Without, it holds the issue lock and the fence and *)
(*               waits for the row, which the issuer holds shared, queued  *)
(*               for the issue lock behind the barrier, which waits for    *)
(*               the write's issue lock: a cycle (review r1 of #469).      *)
(*   WriteTakesChangeLock  the write takes the change lock first, as it    *)
(*               took the head. Without, it holds the issue lock and the   *)
(*               fence and waits for the key's row, which a patch holds,   *)
(*               under the change lock, queued for the issue lock behind   *)
(*               the barrier, which waits for the write's (no barrier      *)
(*               about, the patch waits for the write's fence instead). So *)
(*               the two-trip write keeps the lock: its hold orders *)
(*               it against what a change commits, not against the rows a  *)
(*               change locks before its last statement.                   *)
(*                                                                         *)
(* Flow = "add": a member add's (Writing.tla's AWrite, which    *)
(* holds none): its first statement locks the members' rows (`lockMembers`:*)
(* the adder's and the new member's queue locks and rows) and the change   *)
(* lock; its second (`admit_hold`) takes the issue lock shared, then the   *)
(* fence, and holds the read. Nothing is read under the change lock.       *)
(* Against:                                                                *)
(*   demote   a change of the adder's member (`#decide`, `change_input`):  *)
(*            the row, the change lock, the issue lock shared, the fence;  *)
(*   issue    a token issued to the adder (`issue_token`, 0047): the       *)
(*            members' rows FOR SHARE, the credential's, the issue lock;   *)
(*   barrier, revoke, use as above.                                        *)
(*   MembersFirst  the add locks the rows before the change lock, as every *)
(*               flow that takes both does. Without, it holds the lock and *)
(*               waits for the row a demotion holds, which waits for the   *)
(*               lock.                                                     *)
(* The add takes the change lock as every change does (one rule, no  *)
(* exemption). No wait cycle needs it there: the rows it locks first are   *)
(* every lock it shares with a change before the fence.                    *)
(*                                                                         *)
(* Flow = "change": the order itself, for every change of more than one    *)
(* statement, whichever way it takes the issue lock.                       *)
(*   vault    the vault's change of a member (`#decideOnce`,               *)
(*            `change_input`): the member's row, the change lock, the      *)
(*            issue lock shared, the fence. On `main` the issue lock is    *)
(*            the one the trigger of its 0.14 entry takes, `change_input`  *)
(*            itself taking none: 0.16, which deletes that entry, takes it *)
(*            in `change_input`, before the fence (A1);                    *)
(*   app      the app's change (`audited`, `app_change`): the change lock, *)
(*            a credential's row it writes, the issue lock shared, the     *)
(*            fence;                                                       *)
(*   policy   the vault's change of the policy (`changePolicy`), which an  *)
(*            issue compares: the actor's row, the change lock, the issue  *)
(*            lock exclusive (`holdIssues`, so that an issue in flight is  *)
(*            ordered against it), the fence;                              *)
(*   slug     the app's change of a protected environment's slug, which an *)
(*            issue compares too (`changes.commit`): the change lock, the  *)
(*            issue lock exclusive, the fence;                             *)
(*   issue    a token issued to that member on that credential: the        *)
(*            member's row FOR SHARE, the credential's, the issue lock;    *)
(*   barrier, use as above.                                                *)
(*   ChangeLockFirst  the app's change takes the change lock before the    *)
(*               issue lock. Without (an entry numbered, `note` or an      *)
(*               issue, before the lock), it holds the issue lock shared   *)
(*               and waits for the change lock, which the vault's change   *)
(*               holds, queued for the issue lock behind the barrier,      *)
(*               which waits for the app's.                                *)
(*   IssueBeforeFence  it takes the issue lock before the fence. Without,  *)
(*               it holds the fence and waits for the issue lock, which    *)
(*               the barrier holds while it waits for the fence.           *)
(*   PolicyIssueFirst  the policy's change takes the issue lock before the *)
(*               fence. Without, it holds the fence and waits for the      *)
(*               issue lock, which the barrier holds while it waits for    *)
(*               the fence.                                                *)
(*   BarrierIssueFirst  the barrier takes the issue lock before the fence. *)
(*               Without, it holds the fence and waits for the issue lock, *)
(*               which a change holds shared while it waits for the fence. *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Flow, TouchFirst, WriteTakesChangeLock, MembersFirst,
          ChangeLockFirst, IssueBeforeFence, BarrierIssueFirst, PolicyIssueFirst

Procs == CASE Flow = "write" -> {"write", "patch", "issue", "barrier", "revoke", "use"}
           [] Flow = "add" -> {"add", "demote", "issue", "barrier", "revoke", "use"}
           [] Flow = "change" -> {"vault", "app", "policy", "slug", "issue", "barrier", "use"}

\* Each one's locks, in the order it takes them: a lock and its mode, S(hared) or X (exclusive).
Changing(takes) == IF takes THEN << <<"change", "X">> >> ELSE << >>
Plan(p) ==
    CASE p = "write" ->
            Changing(WriteTakesChangeLock) \o
            (IF TouchFirst THEN << <<"cred", "X">>, <<"issue", "S">>, <<"fence", "X">>, <<"key", "X">> >>
                           ELSE << <<"issue", "S">>, <<"fence", "X">>, <<"cred", "X">>, <<"key", "X">> >>)
      [] p = "patch" -> << <<"change", "X">>, <<"key", "X">>, <<"issue", "S">>, <<"fence", "X">> >>
      [] p = "add" ->
            IF MembersFirst THEN << <<"member", "X">>, <<"change", "X">>, <<"issue", "S">>, <<"fence", "X">> >>
                            ELSE << <<"change", "X">>, <<"member", "X">>, <<"issue", "S">>, <<"fence", "X">> >>
      [] p \in {"demote", "vault"} -> << <<"member", "X">>, <<"change", "X">>, <<"issue", "S">>, <<"fence", "X">> >>
      [] p = "policy" ->
            IF PolicyIssueFirst THEN << <<"member", "X">>, <<"change", "X">>, <<"issue", "X">>, <<"fence", "X">> >>
                                ELSE << <<"member", "X">>, <<"change", "X">>, <<"fence", "X">>, <<"issue", "X">> >>
      [] p = "slug" -> << <<"change", "X">>, <<"issue", "X">>, <<"fence", "X">> >>
      [] p = "app" ->
            IF ~ChangeLockFirst THEN << <<"issue", "S">>, <<"change", "X">>, <<"cred", "X">>, <<"fence", "X">> >>
            ELSE IF ~IssueBeforeFence THEN << <<"change", "X">>, <<"cred", "X">>, <<"fence", "X">>, <<"issue", "S">> >>
            ELSE << <<"change", "X">>, <<"cred", "X">>, <<"issue", "S">>, <<"fence", "X">> >>
      [] p = "issue" /\ Flow = "write" -> << <<"cred", "S">>, <<"issue", "S">> >>
      [] p = "issue" /\ Flow # "write" -> << <<"member", "S">>, <<"cred", "S">>, <<"issue", "S">> >>
      [] p = "barrier" -> IF BarrierIssueFirst THEN << <<"issue", "X">>, <<"fence", "X">> >>
                                               ELSE << <<"fence", "X">>, <<"issue", "X">> >>
      [] p = "revoke" -> << <<"change", "X">>, <<"cred", "X">>, <<"fence", "X">> >>
      [] p = "use" -> << <<"fence", "S">> >>

Locks == {"member", "change", "cred", "key", "issue", "fence"}

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
