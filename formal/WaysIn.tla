------------------------------- MODULE WaysIn -------------------------------
(***************************************************************************)
(* 0.15's uses through a way in with no credentials row (T147, T136): an   *)
(* MCP connection, a Cloudflare service binding, and a browser behind      *)
(* Cloudflare Access. Each use is the vault's one statement, as through a  *)
(* credential (Lifecycle.tla): the fence shared, the way in and its        *)
(* account read and weighed as they are, the number, the commit; the app   *)
(* reads nothing after it.                                                 *)
(*                                                                         *)
(*   connection  "k", an MCP client the account connected: its row         *)
(*               (`mcp_connections`) is a sealed object of the log, which  *)
(*               the app's revokes change (`app_change`, the fence         *)
(*               exclusive), as they change a credential.                  *)
(*   binding     "w", the account's Cloudflare binding, a sealed object    *)
(*               the vault makes and unbinds (`change_bindings`, the fence *)
(*               exclusive).                                               *)
(*   access      "a", no row at all: Cloudflare Access signs a browser,    *)
(*               or a service token, in, and the account's object is all a *)
(*               use weighs.                                               *)
(*                                                                         *)
(* Each ends: a revoke of k (by its person, or the removal's sweep), an    *)
(* unbind of w, the account's removal. A removal moves the account's       *)
(* generation on and revokes its connections in a sweep of its own, after  *)
(* it (members.ts, removeMember), so an admission between the two finds k  *)
(* live but of an earlier generation. A binding is never swept: its        *)
(* generation alone ends it.                                               *)
(*                                                                         *)
(* One step is one statement, or the part of one between two lock waits;   *)
(* READ COMMITTED, each step reading what is committed.                    *)
(*                                                                         *)
(* Who is who:                                                             *)
(*   u1, u2   uses, each through one way in, which the app checked first   *)
(*            (its row's MAC, revoked, generation; the vault's answer      *)
(*            about the account), unlocked, as it authenticates;           *)
(*   rk       the person disconnecting k (Connected apps);                 *)
(*   ub       a manager unbinding w;                                       *)
(*   admin    removes the account, or removes it and admits it again, the  *)
(*            removal's sweep after;                                       *)
(*   writer   a database writer holding no key: puts a row back.           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs,          \* the processes of the scenario (MCWaysIn.tla)
    Ops             \* Ops[p]: what process p may do, one of them

CONSTANTS
    \* The use's statement reads the way in's object, a connection's or a
    \* binding's row and its seal, and decides on it. Without, it decides
    \* on the account alone, as 0.14's unwrap did: the app's check of the
    \* way in, before it, is all there is.
    WayReadInUse,
    \* The use's statement reads the account's object and decides on it,
    \* not on the app's answer about it, which the app asked for before.
    AccountReadInUse,
    \* A use refuses a way in made at an earlier generation of its account:
    \* a connection between the removal and its sweep, a binding for good.
    UseChecksGeneration,
    \* A connection's revoke, the app's change, takes the fence exclusive
    \* (`app_change`), which every use takes shared.
    RevokeTakesFence,
    \* An unbind, the vault's change, takes it too (`change_bindings`).
    UnbindTakesFence,
    \* And a removal (`change_input`).
    RemovalTakesFence,
    \* A use decides only on a row that is its object's newest sealed
    \* change (sealed-inputs.md): a row put back is none.
    SealChecked

None == "none"
Rowed == {"k", "w"}
Ways == Rowed \cup {"a"}
Ends == {"rk", "ub", "admin"}
Uses == {"u1", "u2"} \cap Procs

\* A way in's row: the account's generation it was made at, and whether it was revoked.
Row(g) == [gen |-> g, revoked |-> FALSE]
Revoked(row) == [row EXCEPT !.revoked = TRUE]

VARIABLES
    rows,       \* rows[x]: the way in's row as committed
    sealed,     \* sealed[x]: what its newest change in the log left
    history,    \* every row x ever had honestly: a writer may put any back
    status,     \* the account: "active" or "removed"
    gen,        \* its generation: a removal moves it on, an admission keeps it
    next,       \* the log's next number
    fx, fs,     \* the fence: its exclusive holder, its shared holders
    pc, op, l,  \* each process: where it is, what it does, what it read
    answered,   \* the ways in whose end was answered: sealed, past its seal wait
    ends,       \* each end committed: the way in, its number
    removals,   \* each removal committed: its number
    restores,   \* each admission again committed: its number
    used        \* each use decided

vars == <<rows, sealed, history, status, gen, next, fx, fs, pc, op, l, answered, ends, removals, restores, used>>

-----------------------------------------------------------------------------

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]
FenceFree == fx = None /\ fs = {}
\* Every lock p holds, let go: at its commit.
Release(p) == /\ fx' = IF fx = p THEN None ELSE fx
              /\ fs' = fs \ {p}
Done(p) == Goto(p, "done") /\ Release(p)

\* What the app checks as it authenticates, unlocked: the row its MAC
\* covers, one it wrote once (a row put back passes), not revoked, of the
\* account's generation; and the vault's answer, an active account.
AppAccepts(x) == /\ status = "active"
                 /\ x \in Rowed => /\ rows[x] \in history[x]
                                   /\ ~rows[x].revoked
                                   /\ rows[x].gen = gen

Init ==
    /\ rows = [x \in Rowed |-> Row(0)]
    /\ sealed = rows
    /\ history = [x \in Rowed |-> {Row(0)}]
    /\ status = "active"
    /\ gen = 0
    /\ next = 1
    /\ fx = None /\ fs = {}
    /\ pc = [p \in Procs |-> "start"]
    /\ op = [p \in Procs |-> [kind |-> "none"]]
    /\ l = [p \in Procs |-> [way |-> None, ok |-> FALSE, n |-> 0, w |-> Row(0), seal |-> Row(0), gen |-> 0, st |-> "active",
                             before |-> {}, from |-> Row(0)]]
    /\ answered = {}
    /\ ends = {} /\ removals = {} /\ restores = {}
    /\ used = {}

-----------------------------------------------------------------------------
(* Uses: the app's check, then the vault's one statement: the fence shared,
   the read and the decision, the number, the commit. The read and the
   number are two steps: within one statement, a commit can come between its
   snapshot and its `nextval`. *)

UseStart(u) ==
    /\ pc[u] = "start"
    /\ \E x \in Ops[u] :
        /\ l' = [l EXCEPT ![u].way = x]
        /\ Goto(u, IF AppAccepts(x) THEN "fence" ELSE "done")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, fs, op, answered, ends, removals, restores, used>>

\* Which ends had answered when the use began: none of theirs may serve it.
UseFence(u) ==
    /\ pc[u] = "fence"
    /\ fx = None
    /\ fs' = fs \cup {u}
    /\ l' = [l EXCEPT ![u].before = answered]
    /\ Goto(u, "read")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, op, answered, ends, removals, restores, used>>

UseRead(u) ==
    /\ pc[u] = "read"
    /\ LET x == l[u].way
           row == IF x \in Rowed THEN rows[x] ELSE Row(gen)
           seal == IF x \in Rowed THEN sealed[x] ELSE Row(gen)
           way == x \in Rowed /\ WayReadInUse =>
                     /\ SealChecked => row = seal
                     /\ ~row.revoked
                     /\ UseChecksGeneration => row.gen = gen
           account == AccountReadInUse => status = "active"
       IN l' = [l EXCEPT ![u] = [@ EXCEPT !.ok = way /\ account, !.w = row, !.seal = seal, !.gen = gen, !.st = status]]
    /\ Goto(u, "number")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, fs, op, answered, ends, removals, restores, used>>

UseNumber(u) ==
    /\ pc[u] = "number"
    /\ l' = [l EXCEPT ![u].n = next]
    /\ next' = next + 1
    /\ Goto(u, "commit")
    /\ UNCHANGED <<rows, sealed, history, status, gen, fx, fs, op, answered, ends, removals, restores, used>>

UseCommit(u) ==
    /\ pc[u] = "commit"
    /\ used' = used \cup {[way |-> l[u].way, allow |-> l[u].ok, n |-> l[u].n, row |-> l[u].w, seal |-> l[u].seal,
                           gen |-> l[u].gen, st |-> l[u].st, before |-> l[u].before]}
    /\ Done(u)
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, op, l, answered, ends, removals, restores>>

-----------------------------------------------------------------------------
(* A connection's revoke, the app's change (api/changes.ts, AppChanges):
   the vault seals it from the row as read, outside any transaction; then
   the app's transaction writes the row and calls `app_change`, which takes
   the fence, moves the seal only from the one read (ChangeCAS), numbers it,
   and commits; then the seal wait, and the answer. Another revoke between
   the two: prepared again, and nothing left to revoke. A row that is not
   its object's newest change (a writer's) refuses the write, as `prepare`
   and `app_change` refuse it (`tampered`, `stale`). The removal's sweep is
   the same change, in the admin's request, of a connection still live. *)

RevPrepare(p) ==
    /\ pc[p] = "prepare"
    /\ l' = [l EXCEPT ![p].from = sealed["k"]]
    /\ Goto(p, IF sealed["k"].revoked THEN "done" ELSE "fence")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, fs, op, answered, ends, removals, restores, used>>

RevFence(p) ==
    /\ pc[p] = "fence"
    /\ RevokeTakesFence => FenceFree
    /\ fx' = IF RevokeTakesFence THEN p ELSE fx
    /\ Goto(p, "commit")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fs, op, l, answered, ends, removals, restores, used>>

RevCommit(p) ==
    /\ pc[p] = "commit"
    /\ IF rows["k"] = l[p].from /\ sealed["k"] = l[p].from
       THEN /\ rows' = [rows EXCEPT !["k"] = Revoked(@)]
            /\ sealed' = [sealed EXCEPT !["k"] = Revoked(rows["k"])]
            /\ history' = [history EXCEPT !["k"] = @ \cup {Revoked(rows["k"])}]
            /\ ends' = ends \cup {[way |-> "k", n |-> next]}
            /\ next' = next + 1
            /\ Goto(p, "answer")
       ELSE \* A row not the log's refuses; another revoke's commit: prepared again.
            /\ Goto(p, IF rows["k"] /= sealed["k"] THEN "done" ELSE "prepare")
            /\ UNCHANGED <<rows, sealed, history, ends, next>>
    /\ Release(p)
    /\ UNCHANGED <<status, gen, op, l, answered, removals, restores, used>>

\* Sealed in a checkpoint (R51), then answered: whoever asked may tell the world.
RevAnswer(p) ==
    /\ pc[p] = "answer"
    /\ answered' = answered \cup {"k"}
    /\ Goto(p, "done")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, fs, op, l, ends, removals, restores, used>>

RkStart(p) ==
    /\ pc[p] = "start"
    /\ Goto(p, "prepare")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, fs, op, l, answered, ends, removals, restores, used>>

-----------------------------------------------------------------------------
(* An unbind of w, the vault's one statement (PR 3a): the binding's row, the
   fence, the change numbered, the commit; then the answer. *)

UbStart(p) ==
    /\ pc[p] = "start"
    /\ Goto(p, "fence")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, fs, op, l, answered, ends, removals, restores, used>>

UbFence(p) ==
    /\ pc[p] = "fence"
    /\ UnbindTakesFence => FenceFree
    /\ fx' = IF UnbindTakesFence THEN p ELSE fx
    /\ Goto(p, "commit")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fs, op, l, answered, ends, removals, restores, used>>

UbCommit(p) ==
    /\ pc[p] = "commit"
    /\ rows' = [rows EXCEPT !["w"] = Revoked(@)]
    /\ sealed' = [sealed EXCEPT !["w"] = Revoked(rows["w"])]
    /\ history' = [history EXCEPT !["w"] = @ \cup {Revoked(rows["w"])}]
    /\ ends' = ends \cup {[way |-> "w", n |-> next]}
    /\ next' = next + 1
    /\ Goto(p, "answer")
    /\ Release(p)
    /\ UNCHANGED <<status, gen, op, l, answered, removals, restores, used>>

UbAnswer(p) ==
    /\ pc[p] = "answer"
    /\ answered' = answered \cup {"w"}
    /\ Goto(p, "done")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, fs, op, l, ends, removals, restores, used>>

-----------------------------------------------------------------------------
(* The account's removal, the vault's change (`change_input`): the fence,
   the account removed and its generation moved on, numbered, committed.
   Then, as "removeRestore", an admission again, which keeps the
   generation; then the removal's sweep of k, a revoke as rk's. *)

AdminStart(a) ==
    /\ pc[a] = "start"
    /\ \E o \in Ops[a] : op' = [op EXCEPT ![a] = [kind |-> o]]
    /\ Goto(a, "afence")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fx, fs, l, answered, ends, removals, restores, used>>

AdminFence(a) ==
    /\ pc[a] = "afence"
    /\ RemovalTakesFence => FenceFree
    /\ fx' = IF RemovalTakesFence THEN a ELSE fx
    /\ Goto(a, "abody")
    /\ UNCHANGED <<rows, sealed, history, status, gen, next, fs, op, l, answered, ends, removals, restores, used>>

AdminBody(a) ==
    /\ pc[a] = "abody"
    /\ IF op[a].kind \in {"remove", "removeRestore"}
       THEN /\ status' = "removed"
            /\ gen' = gen + 1
            /\ removals' = removals \cup {next}
            /\ op' = [op EXCEPT ![a].kind = IF @ = "removeRestore" THEN "restore" ELSE "sweep"]
            /\ UNCHANGED restores
       ELSE /\ status' = "active"
            /\ restores' = restores \cup {next}
            /\ op' = [op EXCEPT ![a].kind = "sweep"]
            /\ UNCHANGED <<gen, removals>>
    /\ next' = next + 1
    /\ Goto(a, IF op'[a].kind = "restore" THEN "afence" ELSE "prepare")
    /\ Release(a)
    /\ UNCHANGED <<rows, sealed, history, l, answered, ends, used>>

-----------------------------------------------------------------------------
(* A database writer, holding no key: puts back a row of k or w that the
   log sealed once (live again after its end), or none. *)

WriterStep(p) ==
    /\ pc[p] = "start"
    /\ \/ UNCHANGED rows
       \/ \E x \in Rowed : \E h \in history[x] : h /= rows[x] /\ rows' = [rows EXCEPT ![x] = h]
    /\ Goto(p, "done")
    /\ UNCHANGED <<sealed, history, status, gen, next, fx, fs, op, l, answered, ends, removals, restores, used>>

-----------------------------------------------------------------------------

Step(p) ==
    \/ p \in Uses /\ (UseStart(p) \/ UseFence(p) \/ UseRead(p) \/ UseNumber(p) \/ UseCommit(p))
    \/ p = "rk" /\ (RkStart(p) \/ RevPrepare(p) \/ RevFence(p) \/ RevCommit(p) \/ RevAnswer(p))
    \/ p = "ub" /\ (UbStart(p) \/ UbFence(p) \/ UbCommit(p) \/ UbAnswer(p))
    \/ p = "admin" /\ (AdminStart(p) \/ AdminFence(p) \/ AdminBody(p) \/ RevPrepare(p) \/ RevFence(p) \/ RevCommit(p) \/ RevAnswer(p))
    \/ p = "writer" /\ WriterStep(p)

Terminating == /\ \A p \in Procs : pc[p] = "done"
               /\ UNCHANGED vars

Next == (\E p \in Procs : Step(p)) \/ Terminating

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold *)

TypeOK ==
    /\ fx \in Procs \cup {None}
    /\ fs \subseteq Uses
    /\ status \in {"active", "removed"}
    /\ answered \subseteq Rowed

\* An end orders its way in's uses: none allowed is numbered after it.
EndOrdersUses ==
    \A u \in used, e \in ends : (u.allow /\ u.way = e.way) => u.n < e.n

\* No use that began once an end was sealed and answered serves its way in.
NothingAfterEndAnswered ==
    \A u \in used : u.allow => u.way \notin u.before

\* A removal orders the account's uses, through any way in: none allowed
\* is numbered after it, but after an admission again since.
RemovalOrdersUses ==
    \A u \in used, r \in removals : u.allow => (u.n < r \/ \E s \in restores : r < s /\ s < u.n)

\* Only rows the log sealed decide: nothing a database writer put back
\* serves a use.
AllowedOnSealed ==
    \A u \in used : (u.allow /\ u.way \in Rowed) => u.row = u.seal

\* A way in serves only at its account's generation: removed, its
\* connections and bindings end, whatever admits it again.
AllowedAtCurrentGeneration ==
    \A u \in used : (u.allow /\ u.way \in Rowed) => u.row.gen = u.gen

=============================================================================
