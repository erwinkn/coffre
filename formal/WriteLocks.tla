----------------------------- MODULE WriteLocks -----------------------------
(***************************************************************************)
(* The locks a transaction takes, and the order it takes them in, with     *)
(* Postgres's lock queue: a request waits for every lock held that         *)
(* conflicts with it, and also for every request queued ahead of it that   *)
(* does (a shared request queues behind a waiting exclusive one). Postgres *)
(* breaks such a cycle only after `deadlock_timeout` (1 s), by reordering  *)
(* the queue or failing one: meanwhile the locks in it are held, and the   *)
(* uses behind them wait.                                                  *)
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
(* The issue lock is taken shared by a change's last statement and by an   *)
(* issue, exclusive by the checkpointer's barrier and by the two changes   *)
(* an issue compares. The fence is the barrier's: it alone takes it        *)
(* exclusive, after the issue lock; a use, and a change's last statement   *)
(* (`change_input`, `change_bindings`, `app_change`, `hold_inputs`,        *)
(* `admit_hold`, `revoke_credential`), take it shared, so that the barrier *)
(* waits for every number in flight.                                       *)
(*                                                                         *)
(* Object locks (L1, T282) order a use against a change, which the fence   *)
(* did until 0.16, held exclusive by every change: each object whose seal  *)
(* a decision checks has an advisory lock of its own, keyed as its changes *)
(* are in the log (`log_object`), named `@` here. Today those are a        *)
(* credential, a connection, a binding, a member, a key, its environment,  *)
(* a reference's source, a proxy's definition, the names reserved for      *)
(* proxies, a role, the roles and the policy: the rule is the statement's  *)
(* seal probes, not this list. A use takes the lock of each object it      *)
(* reads, shared; a change's last statement the lock of each object it     *)
(* writes, exclusive. So a change makes only the uses of what it writes    *)
(* wait, for that one statement.                                           *)
(*                                                                         *)
(* A two-trip change's hold reads again what the vault decided on and goes *)
(* ahead only if it answers the same (Writing.tla): it takes the lock of   *)
(* each object it read, shared, with those it writes, so that the read     *)
(* stands to its COMMIT against any change of them, whichever other locks  *)
(* that change takes. Until L1 the fence did that too, held exclusive.     *)
(*                                                                         *)
(* One order, for every transaction: the rows a flow shares with an issue, *)
(* the change lock, the issue lock, the fence, its objects' locks in key   *)
(* order (here, their names'), all of them before its first read or write  *)
(* under them, then, for a use, its principal's lock (the bulk cap's,      *)
(* HotPathOne.tla).                                                        *)
(*                                                                         *)
(* Flow = "write": a key write in two round trips (T179; Writing.tla's     *)
(* WCommit, which holds none).                                             *)
(*   write    the key write's transaction (`heldOnce`, `heldWrites`): the  *)
(*            change lock; its credential's last use, when due (an UPDATE  *)
(*            of the credential's row); `hold_inputs`: the issue lock      *)
(*            shared, the fence shared, the lock of the credential it      *)
(*            read, shared, and the key's; then the key's row (its current *)
(*            version, an UPDATE);                                         *)
(*   patch    another change of that key down today's path (`setSecrets`,  *)
(*            `patchSecret`: a reference made of it, an archive, a         *)
(*            rename): the change lock (`audited`), the key's row (`lock`, *)
(*            FOR UPDATE), then `app_change`: the issue lock shared, the   *)
(*            fence shared, the key's lock;                                *)
(*   issue    a token issued on that credential (`issue_token`, 0036): the *)
(*            credential's row FOR SHARE, then the issue lock shared;      *)
(*   barrier  the checkpointer's: the issue lock exclusive, then the fence *)
(*            exclusive;                                                   *)
(*   revoke   the credential revoked (`revoke_credential`, 0034): the      *)
(*            change lock, the row, the issue lock shared (L1: it orders   *)
(*            the revoke against the barrier, as its fence did while       *)
(*            exclusive), the fence shared, the credential's lock;         *)
(*   use      a use: the fence shared, then the credential's lock and the  *)
(*            key's, shared.                                               *)
(* Its protections (scripts/formal.sh turns each off):                     *)
(*   TouchFirst  the write updates its credential's row before the hold,   *)
(*               as the issuer and the revoke take it: row, issue lock,    *)
(*               fence. Without, it holds the issue lock and waits for the *)
(*               row, which the issuer holds shared, queued for the issue  *)
(*               lock behind the barrier, which waits for the write's      *)
(*               issue lock: a cycle (review r1 of #469).                  *)
(*   WriteTakesChangeLock                                                  *)
(*               the write takes the change lock first, as it took         *)
(*               the head. Without, it holds the issue lock, the fence and *)
(*               the key's lock and waits for the key's row, which a patch *)
(*               holds, under the change lock, queued for the issue lock   *)
(*               behind the barrier, which waits for the write's; no       *)
(*               barrier about, the patch waits for the key's lock         *)
(*               instead, which the write holds (before L1, for its        *)
(*               fence). So the two-trip write keeps the lock (T272), with *)
(*               object locks as without: its hold orders it against what  *)
(*               a change commits, not against the rows a change locks     *)
(*               before its last statement.                                *)
(*                                                                         *)
(* Flow = "add": a member add's (T179 PR 5; Writing.tla's AWrite, which    *)
(* holds none): its first statement locks the members' rows                *)
(* (`lockMembers`: the adder's and the new member's queue locks and rows)  *)
(* and the change lock; its second (`admit_hold`) takes the issue lock     *)
(* shared, the fence shared, then the lock of the credential it read,      *)
(* shared, and the member's, and holds the read. Nothing is read under the *)
(* change lock. Against:                                                   *)
(*   demote   a change of the adder's member (`#decide`, `change_input`):  *)
(*            the row, the change lock, the issue lock shared, the fence   *)
(*            shared, the member's lock;                                   *)
(*   issue    a token issued to the adder (`issue_token`, 0047): the       *)
(*            members' rows FOR SHARE, the credential's, the issue lock;   *)
(*   use      a use: the fence shared, the credential's lock, the          *)
(*            member's;                                                    *)
(*   barrier, revoke as above.                                             *)
(*   MembersFirst                                                          *)
(*               the add locks the rows before the change lock, as every   *)
(*               flow that takes both does. Without, it holds the lock and *)
(*               waits for the row a demotion holds, which waits for the   *)
(*               lock.                                                     *)
(* The add takes the change lock as every change does (T272: one rule, no  *)
(* exemption). No wait cycle needs it there: the rows it locks first are   *)
(* every lock it shares with a change before the fence.                    *)
(*                                                                         *)
(* Flow = "change": the order itself, for every change of more than one    *)
(* statement, whichever way it takes the issue lock.                       *)
(*   vault    the vault's change of a member (`#decideOnce`,               *)
(*            `change_input`): the member's row, the change lock, the      *)
(*            issue lock shared, the fence shared, the member's lock. On   *)
(*            `main` the issue lock is the one the trigger of its 0.14     *)
(*            entry takes, `change_input` itself taking none: 0.16, which  *)
(*            deletes that entry, takes it in `change_input`, before the   *)
(*            fence (A1);                                                  *)
(*   app      the app's change (`audited`, `app_change`): the change lock, *)
(*            a credential's row it writes, the issue lock shared, the     *)
(*            fence shared, the credential's lock;                         *)
(*   policy   the vault's change of the policy (`changePolicy`), which an  *)
(*            issue compares: the actor's row, the change lock, the issue  *)
(*            lock exclusive (`holdIssues`, so that an issue in flight is  *)
(*            ordered against it), the fence shared, the policy's lock;    *)
(*   slug     the app's change of a protected environment's slug, which an *)
(*            issue compares too (`changes.commit`): the change lock, the  *)
(*            issue lock exclusive, the fence shared, the environment's    *)
(*            lock;                                                        *)
(*   issue    a token issued to that member on that credential: the        *)
(*            member's row FOR SHARE, the credential's, the issue lock;    *)
(*   use      a use: the fence shared, then the credential's lock, the     *)
(*            environment's, the member's and the policy's;                *)
(*   barrier  as above.                                                    *)
(*   ChangeLockFirst                                                       *)
(*               the app's change takes the change lock before the         *)
(*               issue lock. Without (an entry numbered, `note` or an      *)
(*               issue, before the lock), it holds the issue lock shared   *)
(*               and waits for the change lock, which the vault's change   *)
(*               holds, queued for the issue lock behind the barrier,      *)
(*               which waits for the app's.                                *)
(*   IssueBeforeFence                                                      *)
(*               it takes the issue lock before the fence. Without, it     *)
(*               holds the fence shared and waits for the issue lock,      *)
(*               which the barrier holds while it waits for the fence      *)
(*               (Migration015.tla's, for 0.14's head).                    *)
(*   BarrierIssueFirst                                                     *)
(*               the barrier takes the issue lock before the fence.        *)
(*               Without, it holds the fence and waits for the issue lock, *)
(*               which a change holds shared while it waits for the fence. *)
(*                                                                         *)
(* Flow = "objects": the object locks themselves (L1), two objects, a      *)
(* before b in key order.                                                  *)
(*   use      a use that reads both and moves its key on in the cap's set  *)
(*            (`use_credential`): the fence shared, a's lock, b's, then    *)
(*            its principal's lock, shared;                                *)
(*   one      a use that reads b alone: the fence shared, b's lock;        *)
(*   batch    a request of several keys in one statement (`use_batch`,     *)
(*            Batching.tla), whose round 2 enters a key in the set: the    *)
(*            fence shared, a's lock, b's, shared, then the principal's    *)
(*            lock, exclusive. The request names b first;                  *)
(*   change   a change of both in one statement (a project's or an         *)
(*            environment's delete, `app_change` once per row; a member    *)
(*            removed with their credentials): the change lock, the issue  *)
(*            lock shared, the fence shared, a's lock, b's, exclusive. Its *)
(*            calls come b first;                                          *)
(*   revoke   a credential's revoke, of b (`revoke_credential`): the       *)
(*            change lock, which orders its compare of the policy against  *)
(*            a policy change's as it always did; the issue lock shared,   *)
(*            new with L1, which orders it against the barrier as it does  *)
(*            every change; the fence shared, b's lock;                    *)
(*   barrier  as above.                                                    *)
(* `change_bindings` has no proc of its own. An unbind and a sweep that    *)
(* revokes, a replacement's too, take the locks of `app` in Flow =         *)
(* "change": the change lock, then the rows they write (the bindings',     *)
(* then the credentials', each by id), the issue lock shared, the fence,   *)
(* their objects sorted. A replacement locks its members' rows before the  *)
(* change lock, as the add does (MembersFirst). A bind that makes a        *)
(* binding where it takes the fence today (it also ends one outright, or   *)
(* revokes a credential) takes with its objects, shared, the lock of each  *)
(* key it read by name, as a hold does: there the fence, exclusive, held a *)
(* rename off between its compare of those names and its commit. Where it  *)
(* takes no fence today, the compare stays unlocked, as today: a rename    *)
(* that commits after it is a rename after the bind. A sign-in through a   *)
(* binding locks the binding's row and takes no change lock: `issue`. A    *)
(* bind that only makes a binding and a sweep that revokes no credential,  *)
(* whether it only closes or makes a binding in their place, take no fence *)
(* today and no object's lock after. Each takes the issue lock, shared, so *)
(* the barrier waits for it: one that makes a binding numbers its change   *)
(* under it, and a sweep that only closes writes no change, numbers        *)
(* nothing, and compares the policy under it. Nobody names a binding       *)
(* before its commit, and no use reads `closed`.                           *)
(* A change takes the fence before its objects' locks, as a use does: one  *)
(* helper for both. No wait cycle of this flow needs it, but only while    *)
(* every change takes the issue lock first, which orders it against the    *)
(* barrier. `ObjectLocksFenceLast.cfg` is this flow with the two the other *)
(* way round (`FenceFirst = FALSE`, the code's shape and no protection):   *)
(* it must hold too, and stops holding the day a change takes the fence    *)
(* with no issue lock before it. `FenceFirst` turns a last statement       *)
(* (`Last`) and this flow's change and revoke; a hold (`Hold`) takes the   *)
(* fence first whatever it says, and the other order there is not checked. *)
(*   UsesInKeyOrder                                                        *)
(*               a use takes its objects' locks in key order, all before   *)
(*               its first read: a batch every key's, sorted, not each     *)
(*               key's as its turn comes in the request. Without, the      *)
(*               batch holds b's and waits for a's, which the change holds *)
(*               while it waits for b's.                                   *)
(*   ChangesInKeyOrder                                                     *)
(*               a change takes them in key order too, all before its      *)
(*               first write, not each call's as it comes. Without, it     *)
(*               holds b's and waits for a's, which a use holds while it   *)
(*               waits for b's.                                            *)
(*   PrincipalLast                                                         *)
(*               a batch takes its principal's lock after its objects'     *)
(*               locks, as a single use does, which learns that it needs   *)
(*               it from what it reads under them (`use_batch` and         *)
(*               `use_route` took it before their first key until L1).     *)
(*               Without, the batch holds                                  *)
(*               it and waits for a's lock behind the change, queued for   *)
(*               a's behind the use, which holds a's and waits for the     *)
(*               principal's lock.                                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Flow, TouchFirst, WriteTakesChangeLock, MembersFirst,
          ChangeLockFirst, IssueBeforeFence, BarrierIssueFirst,
          UsesInKeyOrder, ChangesInKeyOrder, PrincipalLast,
          FenceFirst    \* a change's last statement takes the fence before its objects' locks (`Last`, and the objects flow; not `Hold`): the code's shape, no protection

Procs == CASE Flow = "write" -> {"write", "patch", "issue", "barrier", "revoke", "use"}
           [] Flow = "add" -> {"add", "demote", "issue", "barrier", "revoke", "use"}
           [] Flow = "change" -> {"vault", "app", "policy", "slug", "issue", "barrier", "use"}
           [] Flow = "objects" -> {"use", "one", "batch", "change", "revoke", "barrier"}

\* Each one's locks, in the order it takes them: a lock and its mode, S(hared) or X (exclusive). An object's lock is
\* named `@`; key order is their names'.
Changing(takes) == IF takes THEN << <<"change", "X">> >> ELSE << >>
\* A change's last statement, after the issue lock: the fence shared, then the object it writes (the object first without `FenceFirst`).
Last(object) == IF FenceFirst THEN << <<"fence", "S">>, <<object, "X">> >> ELSE << <<object, "X">>, <<"fence", "S">> >>
\* A two-trip change's hold: the fence shared, first in every scenario (`FenceFirst` does not turn it), then the caller's credential, which it read, shared, and the object it writes.
\* The credential stands for every object the hold read (the member, the roles, the policy, the environment): each shared,
\* in key order with those it writes.
Hold(object) == << <<"fence", "S">>, <<"@cred", "S">>, <<object, "X">> >>
Plan(p) ==
    CASE p = "write" ->
            Changing(WriteTakesChangeLock) \o
            (IF TouchFirst THEN << <<"cred", "X">>, <<"issue", "S">> >> \o Hold("@key") \o << <<"key", "X">> >>
                           ELSE << <<"issue", "S">> >> \o Hold("@key") \o << <<"cred", "X">>, <<"key", "X">> >>)
      [] p = "patch" -> << <<"change", "X">>, <<"key", "X">>, <<"issue", "S">> >> \o Last("@key")
      [] p = "add" ->
            (IF MembersFirst THEN << <<"member", "X">>, <<"change", "X">> >> ELSE << <<"change", "X">>, <<"member", "X">> >>)
            \o << <<"issue", "S">> >> \o Hold("@member")
      [] p \in {"demote", "vault"} -> << <<"member", "X">>, <<"change", "X">>, <<"issue", "S">> >> \o Last("@member")
      [] p = "policy" -> << <<"member", "X">>, <<"change", "X">>, <<"issue", "X">> >> \o Last("@policy")
      [] p = "slug" -> << <<"change", "X">>, <<"issue", "X">> >> \o Last("@env")
      [] p = "app" ->
            IF ~ChangeLockFirst THEN << <<"issue", "S">>, <<"change", "X">>, <<"cred", "X">> >> \o Last("@cred")
            ELSE IF ~IssueBeforeFence THEN << <<"change", "X">>, <<"cred", "X">> >> \o Last("@cred") \o << <<"issue", "S">> >>
            ELSE << <<"change", "X">>, <<"cred", "X">>, <<"issue", "S">> >> \o Last("@cred")
      [] p = "issue" /\ Flow = "write" -> << <<"cred", "S">>, <<"issue", "S">> >>
      [] p = "issue" /\ Flow # "write" -> << <<"member", "S">>, <<"cred", "S">>, <<"issue", "S">> >>
      [] p = "barrier" -> IF BarrierIssueFirst THEN << <<"issue", "X">>, <<"fence", "X">> >>
                                               ELSE << <<"fence", "X">>, <<"issue", "X">> >>
      [] p = "revoke" /\ Flow # "objects" -> << <<"change", "X">>, <<"cred", "X">>, <<"issue", "S">> >> \o Last("@cred")
      [] p = "revoke" /\ Flow = "objects" ->
            << <<"change", "X">>, <<"issue", "S">> >> \o Last("@b")
      [] p = "use" /\ Flow = "write" -> << <<"fence", "S">>, <<"@cred", "S">>, <<"@key", "S">> >>
      [] p = "use" /\ Flow = "add" -> << <<"fence", "S">>, <<"@cred", "S">>, <<"@member", "S">> >>
      [] p = "use" /\ Flow = "change" -> << <<"fence", "S">>, <<"@cred", "S">>, <<"@env", "S">>, <<"@member", "S">>, <<"@policy", "S">> >>
      [] p = "use" /\ Flow = "objects" -> << <<"fence", "S">>, <<"@a", "S">>, <<"@b", "S">>, <<"principal", "S">> >>
      [] p = "one" -> << <<"fence", "S">>, <<"@b", "S">> >>
      [] p = "batch" ->
            LET objects == IF UsesInKeyOrder THEN << <<"@a", "S">>, <<"@b", "S">> >> ELSE << <<"@b", "S">>, <<"@a", "S">> >>
            IN IF PrincipalLast THEN << <<"fence", "S">> >> \o objects \o << <<"principal", "X">> >>
                                ELSE << <<"fence", "S">>, <<"principal", "X">> >> \o objects
      [] p = "change" ->
            LET objects == IF ChangesInKeyOrder THEN << <<"@a", "X">>, <<"@b", "X">> >> ELSE << <<"@b", "X">>, <<"@a", "X">> >>
            IN << <<"change", "X">>, <<"issue", "S">> >> \o
               (IF FenceFirst THEN << <<"fence", "S">> >> \o objects ELSE objects \o << <<"fence", "S">> >>)

Locks == {"member", "change", "cred", "key", "issue", "fence", "principal", "@cred", "@key", "@member", "@policy", "@env", "@a", "@b"}

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
