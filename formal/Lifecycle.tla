------------------------------ MODULE Lifecycle ------------------------------
(***************************************************************************)
(* The vault owns a credential's life in 0.15 (T149, D146-D148;            *)
(* docs/design/credential-lifecycle.md): a CI run's sign-in, a token's     *)
(* issue and a revoke are each one vault call, beside the uses.            *)
(*                                                                         *)
(*   sign-in  one statement: the account's row shared, the binding's row   *)
(*            exclusive, the binding, the account, the rate and the ID     *)
(*            token weighed on them, the token spent, the credential       *)
(*            written and numbered under the issue lock, the commit.       *)
(*   issue    a token a person gives a service account: the vault reads    *)
(*            the issuer's objects and the policy and decides (statement   *)
(*            1, no lock), then writes only while they are still what it   *)
(*            decided on, under their rows and the issue lock (statement   *)
(*            2). Nothing is held between.                                 *)
(*   revoke   one statement: the credential's row, the fence exclusive,    *)
(*            the row weighed, numbered, committed; then the seal wait.    *)
(*                                                                         *)
(* Uses: one statement under the fence shared, deciding on the credential  *)
(* the presented token's hash names, only if its row is its object's       *)
(* newest sealed change, at its account's generation (W242).               *)
(*                                                                         *)
(* An unbind is still the app's transaction (0.14's head, the binding's    *)
(* row, then the sweep of what it issued, the fence), as built.            *)
(*                                                                         *)
(* One step is one statement, or the part of one between two lock waits;   *)
(* READ COMMITTED, each step reading what is committed.                    *)
(*                                                                         *)
(* Who is who:                                                             *)
(*   ada     an Owner of the project, giving the service account "svc" a   *)
(*           token that reads sensitive values (R32), on her session cA;   *)
(*           or binding b3 for it, which signs its runs in to the same:    *)
(*           the vault weighs and writes it as it does a token (PR 3a);    *)
(*   s1, s2  two CI runs signing in as svc through binding "b", which      *)
(*           makes at most Rate credentials a window, each with an ID      *)
(*           token (the same one, replayed, or two);                       *)
(*   ub      a manager unbinding "b";                                      *)
(*   admin   demotes Ada, or removes svc, or removes and admits it again;  *)
(*   pol     an Owner's policy change that takes from Ada, by her role,    *)
(*           the right to give sensitive reads: no member's row moves;     *)
(*   rev     revokes one credential, by a right the policy gives it (a     *)
(*           service's manager's), which an admin may take away;           *)
(*   u1, u2  uses of a sensitive value, each presenting a token handed out;*)
(*   writer  a database writer holding no key;                             *)
(*   evil    the app's own code, an attacker's: issues in Ada's name; as   *)
(*           "eb", writes a binding that trusts its own key; as a sign-in, *)
(*           presents a token nobody signed, or one through that binding.  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs,          \* the processes of the scenario (MCLifecycle.tla)
    Ops,            \* Ops[p]: what process p may do, one of them
    Rate            \* how many credentials the binding makes a window

CONSTANTS
    \* A revoke takes the fence exclusive, which every use takes shared:
    \* no use decided on the live row is numbered after the revoke.
    RevokeTakesFence,
    \* A revoke goes ahead only while the policy its right was weighed on
    \* is still the newest, read under the fence, which every policy change
    \* takes too (as `policyStill` under 0.14's head).
    RevokePolicyHeld,
    \* An issue or a sign-in never takes the fence: the issue lock, shared
    \* (0026, IssueOwnLock; T123, R58).
    IssueOffFence,
    \* An issue's write holds the issuer's member row and the credential
    \* she asks on, shared, to its commit: a demotion or a revoke waits.
    IssuerLocked,
    \* An issue's write goes ahead only while the issuer's objects are the
    \* ones the vault decided on in its read (their seals, compared under
    \* the locks); otherwise it answers "moved" and the vault reads again.
    IssuerCAS,
    \* An issue checks the policy it was weighed on only once it holds the
    \* issue lock shared, and is numbered under it; a policy change takes
    \* it exclusive, so the two are ordered (as `policyStill` under 0.14's
    \* head; review r3). Without it, the check comes before the lock.
    IssuePolicyHeld,
    \* A policy change takes the issue lock before the fence, as the
    \* checkpointer's barrier does (HotPathOne's BarrierIssueFirst): it
    \* never holds the fence while it waits for an issue, so a use never
    \* waits behind one (R58).
    PolicyIssueFirst,
    \* A sign-in holds the account's row shared, which its removal takes
    \* exclusive.
    MemberLocked,
    \* A use refuses a credential issued at an earlier generation of its
    \* account (W242, T145).
    UseChecksGeneration,
    \* A sign-in holds the binding's row exclusive while it weighs the
    \* binding and its rate: another sign-in through it, or its unbind,
    \* waits.
    BindingLocked,
    \* An unbind sweeps what the binding issued only once it holds the
    \* binding's row (its update comes first).
    SweepAfterLock,
    \* The ID token spent once: the sign-in's insert into
    \* `consumed_tokens`, unique.
    SpentChecked,
    \* A use decides only on a row that is its object's newest sealed
    \* change (sealed-inputs.md).
    SealChecked,
    \* The credential's object seals its token's hash (D-T149 (a)): a row
    \* whose hash moved is not the sealed object.
    HashSealed,
    \* The app checks the row's APP_KEY MAC, which covers the token's hash,
    \* before anything leaves (W242 B1, option (b)): a row the app once
    \* wrote passes, one put back included; an edited, forged or moved one
    \* does not. A compromised app checks nothing.
    AppChecksMac,
    \* The vault verifies the CI run's ID token itself (D148), against the
    \* binding's keys.
    VaultVerifiesToken,
    \* The vault takes only a binding it sealed (a change of the log, made
    \* by a manager of the account): the app's row alone is no binding.
    BindingSealed

None == "none"
Members == {"ada", "svc"}
Creds == {"cA", "cS", "t", "e", "x1", "x2", "f"}
Sens == {"read", "sens"}
Bindings == {"b", "b2", "b3"}
\* The ID tokens: j1 and j2, signed by b's issuer; "bad", signed by nobody;
\* "e2", signed by the key evil's binding b2 trusts.
IdTokens == {"j1", "j2", "bad", "e2"}
SignedBy == [b \in Bindings |-> IF b = "b2" THEN {"e2"} ELSE {"j1", "j2"}]
Valid == SignedBy["b"]

\* The credential each issuing process makes.
IssuedBy == [p \in {"ada", "evil", "s1", "s2"} |->
                CASE p = "ada" -> "t" [] p = "evil" -> "e" [] p = "s1" -> "x1" [] p = "s2" -> "x2"]
Issuers == {"ada", "evil"} \cap Procs
SignIns == {"s1", "s2"} \cap Procs
Uses == {"u1", "u2"} \cap Procs

\* A credential's row: who it acts as, its scope, its account's generation,
\* revoked, the binding that issued it, and its token's hash (named after
\* the credential it was made for).
Row(who, scope, g, by, hash) == [who |-> who, scope |-> scope, gen |-> g, revoked |-> FALSE, by |-> by, hash |-> hash]
NoRow == [who |-> None, scope |-> {}, gen |-> 0, revoked |-> TRUE, by |-> None, hash |-> None]

\* What the vault's seal covers of a row: all of it, or all but its hash.
Sealed(row) == IF HashSealed THEN row ELSE [row EXCEPT !.hash = None]

VARIABLES
    rows,       \* rows[c]: the credentials table as committed; NoRow for none
    sealed,     \* sealed[c]: what c's newest change in the log left; NoRow for none
    history,    \* every row c ever had honestly: a writer may put any back
    owner,      \* whether Ada is an Owner of the project
    status,     \* svc's membership: "active" or "removed"
    gen,        \* and its generation: a removal moves it on, an admission keeps it
    next,       \* the log's next number
    fx, fs,     \* the fence: its exclusive holder, its shared holders
    hd,         \* 0.14's head (an admin's change, an unbind)
    mx, ms,     \* members' rows: exclusive holder, shared holders
    cx, cs,     \* credentials' rows: exclusive holder, shared holders
    bx,         \* binding b's row
    ix, is,     \* the issue lock (0026): its exclusive holder, its shared holders
    bindings,   \* the binding rows: b, b2 once evil writes it, b3 once Ada's bind commits
    bsealed,    \* the bindings the vault sealed: b, and b3 once Ada's bind commits
    unbound,    \* whether b was unbound, and its number (0: not)
    spent,      \* the ID tokens spent (`consumed_tokens`)
    pc, op, l,  \* each process: where it is, what it does, what it read
    handed,     \* the tokens that went out: a use may present them
    answered,   \* the revokes answered: sealed, past their seal wait
    given,      \* each issue committed
    revs,       \* each revoke committed: the credential, its number
    dems,       \* each policy change committed: Ada's demotion, her right narrowed by the policy, or the revoker's taken away; its number
    used        \* each use decided

locks == <<fx, fs, hd, mx, ms, cx, cs, bx, ix, is>>
vars == <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, pc, op, l, handed, answered, given, revs, dems, used>>

-----------------------------------------------------------------------------
(* Locks *)

Holds(p) ==
    \/ fx = p \/ p \in fs \/ hd = p \/ bx = p \/ ix = p \/ p \in is
    \/ \E m \in Members : mx[m] = p \/ p \in ms[m]
    \/ \E c \in Creds : cx[c] = p \/ p \in cs[c]

\* Every lock p holds, let go: at its commit, its refusal's rollback, or a
\* statement's end.
Release(p) ==
    /\ fx' = IF fx = p THEN None ELSE fx
    /\ fs' = fs \ {p}
    /\ hd' = IF hd = p THEN None ELSE hd
    /\ mx' = [m \in Members |-> IF mx[m] = p THEN None ELSE mx[m]]
    /\ ms' = [m \in Members |-> ms[m] \ {p}]
    /\ cx' = [c \in Creds |-> IF cx[c] = p THEN None ELSE cx[c]]
    /\ cs' = [c \in Creds |-> cs[c] \ {p}]
    /\ bx' = IF bx = p THEN None ELSE bx
    /\ ix' = IF ix = p THEN None ELSE ix
    /\ is' = is \ {p}

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]
Done(p) == /\ Goto(p, "done") /\ Release(p)

StatusOf(m) == IF m = "svc" THEN status ELSE "active"
GenOf(m) == IF m = "svc" THEN gen ELSE 0
\* A credential as the vault weighs it now: its row the log's, live, of its account's generation.
Live(c) == rows[c] /= NoRow /\ Sealed(rows[c]) = Sealed(sealed[c]) /\ ~rows[c].revoked
           /\ StatusOf(rows[c].who) = "active" /\ rows[c].gen = GenOf(rows[c].who)

FenceFree == fx = None /\ fs = {}
IssueLockFree == ix = None /\ is = {}

\* Whether the policy took from Ada the right to give sensitive reads.
Narrowed == \E d \in dems : d.kind = "narrow"

\* Whether the revoker still holds the right the policy gave it.
Manages == ~\E d \in dems : d.kind = "unmanage"

\* The row a presented token's hash finds, if any.
Resolve(tok) == IF \E c \in Creds : rows[c] /= NoRow /\ rows[c].hash = tok
                THEN CHOOSE c \in Creds : rows[c] /= NoRow /\ rows[c].hash = tok
                ELSE None

-----------------------------------------------------------------------------
(* Initial state: Ada's session and svc's token cS, which an Owner gave
   sensitive reads, are in the log. *)

Init ==
    /\ rows = [c \in Creds |-> CASE c = "cA" -> Row("ada", Sens, 0, None, "cA")
                                 [] c = "cS" -> Row("svc", Sens, 0, None, "cS")
                                 [] OTHER -> NoRow]
    /\ sealed = rows
    /\ history = [c \in Creds |-> {rows[c]} \ {NoRow}]
    /\ owner = TRUE
    /\ status = "active"
    /\ gen = 0
    /\ next = 1
    /\ fx = None /\ fs = {} /\ hd = None /\ bx = None /\ ix = None /\ is = {}
    /\ mx = [m \in Members |-> None] /\ ms = [m \in Members |-> {}]
    /\ cx = [c \in Creds |-> None] /\ cs = [c \in Creds |-> {}]
    /\ bindings = {"b"}
    /\ bsealed = {"b"}
    /\ unbound = 0
    /\ spent = {}
    /\ pc = [p \in Procs |-> "start"]
    /\ op = [p \in Procs |-> [kind |-> "none"]]
    /\ l = [p \in Procs |-> [c |-> None, tok |-> None, n |-> 0, gen |-> 0, ok |-> FALSE, w |-> NoRow,
                             owner |-> FALSE, cA |-> NoRow, set |-> {}, b |-> None, before |-> {}]]
    /\ handed = {"cS"}
    /\ answered = {}
    /\ given = {} /\ revs = {} /\ dems = {} /\ used = {}

\* A credential's row and the log's object for it, written as one commit.
Write(c, row) ==
    /\ rows' = [rows EXCEPT ![c] = row]
    /\ sealed' = [sealed EXCEPT ![c] = row]
    /\ history' = [history EXCEPT ![c] = @ \cup {row}]

-----------------------------------------------------------------------------
(* Uses: one statement, the fence shared, the decision, the number, the
   commit. The read and the number are two steps: within one statement, a
   commit can come between its snapshot and its `nextval`. *)

UseStart(u) ==
    /\ pc[u] = "start"
    /\ \E tok \in handed : l' = [l EXCEPT ![u].tok = tok]
    /\ Goto(u, "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, op, handed, answered, given, revs, dems, used>>

\* Which revokes had answered when the use began: none of theirs may serve it.
UseFence(u) ==
    /\ pc[u] = "fence"
    /\ fx = None
    /\ fs' = fs \cup {u}
    /\ l' = [l EXCEPT ![u].before = answered]
    /\ Goto(u, "read")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, hd, mx, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, handed, answered, given, revs, dems, used>>

UseRead(u) ==
    /\ pc[u] = "read"
    /\ LET tok == l[u].tok
           c == Resolve(tok)
           row == IF c = None THEN NoRow ELSE rows[c]
           allow == /\ c /= None
                    /\ SealChecked => Sealed(row) = Sealed(sealed[c])
                    \* The app's MAC check: a row it once signed for c, as written then (a row put back passes).
                    /\ AppChecksMac => row \in history[c]
                    /\ ~row.revoked
                    /\ StatusOf(row.who) = "active"
                    /\ UseChecksGeneration => row.gen = GenOf(row.who)
                    /\ "sens" \in row.scope
       IN l' = [l EXCEPT ![u] = [@ EXCEPT !.c = c, !.ok = allow, !.w = row, !.gen = GenOf(row.who)]]
    /\ Goto(u, "number")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, op, handed, answered, given, revs, dems, used>>

UseNumber(u) ==
    /\ pc[u] = "number"
    /\ l' = [l EXCEPT ![u].n = next]
    /\ next' = next + 1
    /\ Goto(u, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, locks, bindings, bsealed, unbound, spent, op, handed, answered, given, revs, dems, used>>

UseCommit(u) ==
    /\ pc[u] = "commit"
    /\ used' = used \cup {[c |-> l[u].c, tok |-> l[u].tok, row |-> l[u].w, seal |-> IF l[u].c = None THEN NoRow ELSE sealed[l[u].c],
                           gen |-> l[u].gen, n |-> l[u].n, allow |-> l[u].ok, before |-> l[u].before]}
    /\ Done(u)
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems>>

-----------------------------------------------------------------------------
(* A token: Ada, on her session cA, gives svc sensitive reads; or the app's
   attacker, naming her session. The vault weighs both the same way: on
   what it reads, never on what the app says of her. *)

\* Statement 1: the vault reads Ada's objects, and decides on them, at the vault.
IssueRead(p) ==
    /\ pc[p] \in {"start", "read"}
    /\ op' = [op EXCEPT ![p] = [kind |-> IF "bind" \in Ops[p] THEN "bind" ELSE "issue"]]
    /\ IF owner /\ ~Narrowed /\ Live("cA") /\ status = "active"
       THEN /\ l' = [l EXCEPT ![p] = [@ EXCEPT !.owner = owner, !.cA = rows["cA"], !.gen = gen]]
            /\ Goto(p, "rows")
       ELSE /\ Goto(p, "done") /\ UNCHANGED l
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, handed, answered, given, revs, dems, used>>

\* Statement 2: Ada's row and her credential's, svc's, shared; then, with IssuePolicyHeld, the issue lock.
IssueRows(p) ==
    /\ pc[p] = "rows"
    /\ IssuerLocked => mx["ada"] = None /\ cx["cA"] = None
    /\ MemberLocked => mx["svc"] = None
    /\ ms' = [m \in Members |-> IF (m = "ada" /\ IssuerLocked) \/ (m = "svc" /\ MemberLocked) THEN ms[m] \cup {p} ELSE ms[m]]
    /\ cs' = [cs EXCEPT !["cA"] = IF IssuerLocked THEN @ \cup {p} ELSE @]
    /\ Goto(p, IF IssuePolicyHeld THEN "ilock" ELSE "check")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, cx, bx, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

\* The issue lock, shared, which a policy change takes exclusive (an issue's, or a sign-in's, just before its number).
IssueLock(p) ==
    /\ pc[p] = "ilock"
    /\ ix = None
    /\ is' = is \cup {p}
    /\ Goto(p, IF p \in Issuers /\ IssuePolicyHeld THEN "check" ELSE "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, ms, cx, cs, bx, ix, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

\* Still the objects it decided on? Else "moved": the statement ends, and the vault reads again. The policy is still
\* the one it was weighed on, which the statement always compares (`issue_token`): with IssuePolicyHeld, under the
\* issue lock; else before it, and a change may commit in between.
IssueCheck(p) ==
    /\ pc[p] = "check"
    /\ LET same == /\ owner = l[p].owner
                   /\ rows["cA"] = l[p].cA /\ Sealed(sealed["cA"]) = Sealed(l[p].cA)
                   /\ status = "active" /\ gen = l[p].gen
       IN IF (IssuerCAS => same) /\ ~Narrowed
          THEN Goto(p, IF IssuePolicyHeld THEN "fence" ELSE "ilock") /\ UNCHANGED <<fx, fs, hd, mx, ms, cx, cs, bx, ix, is>>
          ELSE Goto(p, "read") /\ Release(p)
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

\* The fence, only if an issue takes it.
IssueFence(p) ==
    /\ pc[p] = "fence"
    /\ IssueOffFence \/ FenceFree
    /\ fx' = IF IssueOffFence THEN fx ELSE p
    /\ Goto(p, "number")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fs, hd, mx, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

IssueNumber(p) ==
    /\ pc[p] = "number"
    /\ l' = [l EXCEPT ![p].n = next]
    /\ next' = next + 1
    /\ Goto(p, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, locks, bindings, bsealed, unbound, spent, op, handed, answered, given, revs, dems, used>>

IssueCommit(p) ==
    /\ pc[p] = "commit"
    /\ IF op[p].kind = "bind"
       THEN \* A binding of svc's that signs its runs in to sensitive reads: written, and sealed, by the vault.
            /\ bindings' = bindings \cup {"b3"}
            /\ bsealed' = bsealed \cup {"b3"}
            /\ given' = given \cup {[kind |-> "binding", via |-> "cA", n |-> l[p].n, sens |-> TRUE, tok |-> None]}
            /\ UNCHANGED <<rows, sealed, history, handed>>
       ELSE /\ Write(IssuedBy[p], Row("svc", Sens, l[p].gen, None, IssuedBy[p]))
            /\ given' = given \cup {[kind |-> "token", via |-> "cA", n |-> l[p].n, sens |-> TRUE, tok |-> None]}
            /\ handed' = handed \cup {IssuedBy[p]}
            /\ UNCHANGED <<bindings, bsealed>>
    /\ Done(p)
    /\ UNCHANGED <<owner, status, gen, next, unbound, spent, op, l, answered, revs, dems, used>>

-----------------------------------------------------------------------------
(* A CI run's sign-in. At the app: the run's ID token, and the binding it
   names (b; or b2, which evil wrote). The honest app verifies the token's
   signature against the binding's keys; evil checks nothing. Then the
   vault's one statement. *)

SignInStart(s) ==
    /\ pc[s] = "start"
    /\ \/ \E o \in Ops[s] :
            /\ o.b \in bindings
            /\ l' = [l EXCEPT ![s].tok = o.tok, ![s].b = o.b]
            /\ op' = [op EXCEPT ![s] = [kind |-> "signin"]]
            \* The honest app refuses a token its binding's keys did not sign.
            /\ IF o.evil \/ o.tok \in SignedBy[o.b] THEN Goto(s, "rows") ELSE Goto(s, "done")
       \/ \* Never asks.
          /\ Goto(s, "done") /\ UNCHANGED <<l, op>>
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, handed, answered, given, revs, dems, used>>

\* svc's row shared, the binding's exclusive, in the vault's statement.
SignInRows(s) ==
    /\ pc[s] = "rows"
    /\ MemberLocked => mx["svc"] = None
    /\ BindingLocked /\ l[s].b = "b" => bx = None
    /\ ms' = [ms EXCEPT !["svc"] = IF MemberLocked THEN @ \cup {s} ELSE @]
    /\ bx' = IF BindingLocked /\ l[s].b = "b" THEN s ELSE bx
    /\ Goto(s, "body")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, cx, cs, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

\* The binding, the account, the rate and the token weighed as they are now; the token spent.
SignInBody(s) ==
    /\ pc[s] = "body"
    /\ LET b == l[s].b
           tok == l[s].tok
           ok == /\ b = "b" => unbound = 0
                 /\ BindingSealed => b \in bsealed
                 /\ VaultVerifiesToken => tok \in SignedBy[b]
                 /\ status = "active" /\ gen = 0
                 /\ Cardinality({g \in given : g.kind = "signin"}) < Rate
                 /\ SpentChecked => tok \notin spent
       IN IF ok
          THEN /\ l' = [l EXCEPT ![s].gen = gen]
               /\ spent' = spent \cup {tok}
               /\ Goto(s, "ilock")
               /\ UNCHANGED <<fx, fs, hd, mx, ms, cx, cs, bx, ix, is>>
          ELSE /\ Done(s) /\ UNCHANGED <<l, spent>>
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, bindings, bsealed, unbound, op, handed, answered, given, revs, dems, used>>

SignInCommit(s) ==
    /\ pc[s] = "commit"
    /\ Write(IssuedBy[s], Row("svc", Sens, l[s].gen, l[s].b, IssuedBy[s]))
    /\ given' = given \cup {[kind |-> "signin", via |-> None, n |-> l[s].n, sens |-> FALSE, tok |-> l[s].tok]}
    /\ handed' = handed \cup {IssuedBy[s]}
    /\ Done(s)
    /\ UNCHANGED <<owner, status, gen, next, bindings, bsealed, unbound, spent, op, l, answered, revs, dems, used>>

-----------------------------------------------------------------------------
(* evil writes a binding row of its own, b2, trusting its own key: the app's
   login may write the table, and the app holds APP_KEY. *)

EvilBinding(e) ==
    /\ pc[e] = "start"
    /\ "bind" \in Ops[e]
    /\ bindings' = bindings \cup {"b2"}
    /\ Goto(e, "done")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

-----------------------------------------------------------------------------
(* An unbind of b, the vault's one statement (PR 3a; before it, the app's
   transaction under 0.14's head, which no other step here waits on): the
   binding's row (its update) and the sweep of the live credentials it
   issued, in the order SweepAfterLock says, then the fence, the changes
   numbered, the commit. The vault reads the set before its statement and
   the statement holds it to the one under the row's lock: the same as
   reading it there. *)

UbStart(b) ==
    /\ pc[b] = "start"
    /\ op' = [op EXCEPT ![b] = [kind |-> "unbind"]]
    /\ Goto(b, IF SweepAfterLock THEN "lock" ELSE "sweep")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, l, handed, answered, given, revs, dems, used>>

UbLock(b) ==
    /\ pc[b] = "lock"
    /\ bx = None
    /\ bx' = b
    /\ Goto(b, IF SweepAfterLock THEN "sweep" ELSE "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, ms, cx, cs, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

UbSweep(b) ==
    /\ pc[b] = "sweep"
    /\ l' = [l EXCEPT ![b].set = {c \in Creds : rows[c] /= NoRow /\ rows[c].by = "b" /\ ~rows[c].revoked}]
    /\ Goto(b, IF SweepAfterLock THEN "fence" ELSE "lock")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, op, handed, answered, given, revs, dems, used>>

UbFence(b) ==
    /\ pc[b] = "fence"
    /\ FenceFree
    /\ fx' = b
    /\ Goto(b, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fs, hd, mx, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

UbCommit(b) ==
    /\ pc[b] = "commit"
    /\ LET set == l[b].set
           n == next
       IN /\ rows' = [c \in Creds |-> IF c \in set THEN [rows[c] EXCEPT !.revoked = TRUE] ELSE rows[c]]
          /\ sealed' = [c \in Creds |-> IF c \in set THEN [rows[c] EXCEPT !.revoked = TRUE] ELSE sealed[c]]
          /\ history' = [c \in Creds |-> IF c \in set THEN history[c] \cup {[rows[c] EXCEPT !.revoked = TRUE]} ELSE history[c]]
          /\ revs' = revs \cup {[c |-> c, n |-> n, mgr |-> FALSE] : c \in set}
          /\ unbound' = n
    /\ next' = next + 1
    /\ Done(b)
    /\ UNCHANGED <<owner, status, gen, bindings, bsealed, spent, op, l, handed, answered, given, dems, used>>

-----------------------------------------------------------------------------
(* A revoke of one credential: one statement, its row, then the fence, the
   row weighed, numbered, committed; then the seal wait, and the answer. *)

\* At the app: who may, weighed on the policy as the request was loaded.
RevStart(r) ==
    /\ pc[r] = "start"
    /\ \E c \in Ops[r] :
        /\ op' = [op EXCEPT ![r] = [kind |-> "revoke", c |-> c]]
        /\ l' = [l EXCEPT ![r].c = c]
    /\ Goto(r, IF Manages THEN "rows" ELSE "done")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, handed, answered, given, revs, dems, used>>

RevRow(r) ==
    /\ pc[r] = "rows"
    /\ cx[l[r].c] = None /\ cs[l[r].c] = {}
    /\ cx' = [cx EXCEPT ![l[r].c] = r]
    /\ Goto(r, "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, ms, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

RevFence(r) ==
    /\ pc[r] = "fence"
    /\ RevokeTakesFence => FenceFree
    /\ fx' = IF RevokeTakesFence THEN r ELSE fx
    /\ LET c == l[r].c IN
       IF rows[c] /= NoRow /\ Sealed(rows[c]) = Sealed(sealed[c]) /\ ~rows[c].revoked /\ (RevokePolicyHeld => Manages)
       THEN /\ l' = [l EXCEPT ![r].n = next, ![r].ok = TRUE]
            /\ next' = next + 1
       ELSE UNCHANGED <<l, next>>
    /\ Goto(r, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, fs, hd, mx, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, handed, answered, given, revs, dems, used>>

RevCommit(r) ==
    /\ pc[r] = "commit"
    /\ LET c == l[r].c IN
       IF l[r].ok
       THEN /\ Write(c, [rows[c] EXCEPT !.revoked = TRUE])
            /\ revs' = revs \cup {[c |-> c, n |-> l[r].n, mgr |-> TRUE]}
       ELSE UNCHANGED <<rows, sealed, history, revs>>
    /\ Goto(r, "answer")
    /\ Release(r)
    /\ UNCHANGED <<owner, status, gen, next, bindings, bsealed, unbound, spent, op, l, handed, answered, given, dems, used>>

\* Sealed in a checkpoint (R51), then answered: whoever asked may tell the world.
RevAnswer(r) ==
    /\ pc[r] = "answer"
    /\ answered' = answered \cup (IF l[r].ok THEN {l[r].c} ELSE {})
    /\ Goto(r, "done")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, op, l, handed, given, revs, dems, used>>

-----------------------------------------------------------------------------
(* The vault's own changes to a member (`change_input`): the member's row,
   0.14's head, the fence, then the change; a removal revokes the account's
   live credentials in it. A removal and admission again is two such
   transactions. *)

Who(o) == IF o \in {"demote", "unmanage"} THEN "ada" ELSE "svc"

AdminStart(a) ==
    /\ pc[a] = "start"
    /\ \E o \in Ops[a] : op' = [op EXCEPT ![a] = [kind |-> o]]
    /\ Goto(a, "row")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, l, handed, answered, given, revs, dems, used>>

AdminRow(a) ==
    /\ pc[a] = "row"
    /\ mx[Who(op[a].kind)] = None /\ ms[Who(op[a].kind)] = {}
    /\ mx' = [mx EXCEPT ![Who(op[a].kind)] = a]
    /\ Goto(a, "head")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

AdminHead(a) ==
    /\ pc[a] = "head"
    /\ hd = None
    /\ hd' = a
    /\ Goto(a, "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, mx, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

AdminFence(a) ==
    /\ pc[a] = "fence"
    /\ FenceFree
    /\ fx' = a
    /\ Goto(a, "body")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fs, hd, mx, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

AdminBody(a) ==
    /\ pc[a] = "body"
    /\ LET n == next
           swept == {c \in Creds : rows[c] /= NoRow /\ rows[c].who = "svc" /\ ~rows[c].revoked /\ Sealed(rows[c]) = Sealed(sealed[c])}
       IN CASE op[a].kind = "demote" ->
               /\ owner' = FALSE
               /\ dems' = dems \cup {[n |-> n, kind |-> "demote"]}
               /\ UNCHANGED <<rows, sealed, history, status, gen, revs, op>>
            [] op[a].kind = "unmanage" ->
               /\ dems' = dems \cup {[n |-> n, kind |-> "unmanage"]}
               /\ UNCHANGED <<rows, sealed, history, owner, status, gen, revs, op>>
            [] op[a].kind \in {"remove", "removeRestore"} ->
               /\ status' = "removed"
               /\ gen' = gen + 1
               /\ rows' = [c \in Creds |-> IF c \in swept THEN [rows[c] EXCEPT !.revoked = TRUE] ELSE rows[c]]
               /\ sealed' = [c \in Creds |-> IF c \in swept THEN [rows[c] EXCEPT !.revoked = TRUE] ELSE sealed[c]]
               /\ history' = [c \in Creds |-> IF c \in swept THEN history[c] \cup {[rows[c] EXCEPT !.revoked = TRUE]} ELSE history[c]]
               /\ revs' = revs \cup {[c |-> c, n |-> n, mgr |-> FALSE] : c \in swept}
               /\ op' = [op EXCEPT ![a].kind = IF @ = "removeRestore" THEN "restore" ELSE @]
               /\ UNCHANGED <<owner, dems>>
            [] op[a].kind = "restore" ->
               /\ status' = "active"
               /\ op' = [op EXCEPT ![a].kind = "restored"]
               /\ UNCHANGED <<rows, sealed, history, owner, gen, revs, dems>>
    /\ next' = next + 1
    /\ pc' = [pc EXCEPT ![a] = IF op'[a].kind = "restore" THEN "row" ELSE "done"]
    /\ Release(a)
    /\ UNCHANGED <<bindings, bsealed, unbound, spent, l, handed, answered, given, used>>

-----------------------------------------------------------------------------
(* An Owner's policy change (`changePolicy`): a vault entry under 0.14's
   head, whose trigger takes the fence. It narrows Ada's role: she may no
   longer give sensitive reads, though her member row is as it was. With
   IssuePolicyHeld it takes the issue lock exclusive, after the head and,
   with PolicyIssueFirst, before the fence. *)

PolStart(a) ==
    /\ pc[a] = "start"
    /\ hd = None
    /\ hd' = a
    /\ op' = [op EXCEPT ![a] = [kind |-> "narrow"]]
    /\ Goto(a, IF IssuePolicyHeld /\ PolicyIssueFirst THEN "ilock" ELSE "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, mx, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, l, handed, answered, given, revs, dems, used>>

PolIssueLock(a) ==
    /\ pc[a] = "ilock"
    /\ IssueLockFree
    /\ ix' = a
    /\ Goto(a, IF PolicyIssueFirst THEN "fence" ELSE "body")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, ms, cx, cs, bx, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

PolFence(a) ==
    /\ pc[a] = "fence"
    /\ FenceFree
    /\ fx' = a
    /\ Goto(a, IF IssuePolicyHeld /\ ~PolicyIssueFirst THEN "ilock" ELSE "body")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fs, hd, mx, ms, cx, cs, bx, ix, is, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

PolBody(a) ==
    /\ pc[a] = "body"
    /\ dems' = dems \cup {[n |-> next, kind |-> "narrow"]}
    /\ next' = next + 1
    /\ Done(a)
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, used>>

-----------------------------------------------------------------------------
(* A database writer, holding no key: one write, or none. *)

WriterStep(w) ==
    /\ pc[w] = "start"
    /\ \/ \* Gives up.
          UNCHANGED rows
       \/ \* Puts back a row the log sealed once: cS live again after its revoke.
          /\ "putBack" \in Ops[w]
          /\ \E c \in {"cS", "x1"} : \E h \in history[c] : h /= rows[c] /\ rows' = [rows EXCEPT ![c] = h]
       \/ \* Writes a row of its own, for svc's sensitive reads, under the hash of a token handed out (cS's).
          /\ "forge" \in Ops[w]
          /\ rows' = [rows EXCEPT !["f"] = Row("svc", Sens, gen, None, "cS"), !["cS"] = [@ EXCEPT !.hash = None]]
       \/ \* Edits a credential of svc's: live, and of the account's generation now.
          /\ "edit" \in Ops[w]
          /\ \E c \in {"cS", "x1"} : rows[c] /= NoRow /\ rows' = [rows EXCEPT ![c] = [@ EXCEPT !.revoked = FALSE, !.gen = gen]]
       \/ \* Moves the hash of svc's token cS onto cA, Ada's session: cS's holder would act as Ada.
          /\ "move" \in Ops[w]
          /\ rows' = [rows EXCEPT !["cA"] = [@ EXCEPT !.hash = "cS"], !["cS"] = [@ EXCEPT !.hash = None]]
    /\ Goto(w, "done")
    /\ UNCHANGED <<sealed, history, owner, status, gen, next, locks, bindings, bsealed, unbound, spent, op, l, handed, answered, given, revs, dems, used>>

-----------------------------------------------------------------------------

Step(p) ==
    \/ p \in Uses /\ (UseStart(p) \/ UseFence(p) \/ UseRead(p) \/ UseNumber(p) \/ UseCommit(p))
    \/ p \in Issuers /\ (IssueRead(p) \/ IssueRows(p) \/ IssueLock(p) \/ IssueCheck(p) \/ IssueFence(p) \/ IssueNumber(p) \/ IssueCommit(p))
    \/ p = "eb" /\ EvilBinding(p)
    \/ p \in SignIns /\ (SignInStart(p) \/ SignInRows(p) \/ SignInBody(p) \/ IssueLock(p) \/ IssueFence(p) \/ IssueNumber(p) \/ SignInCommit(p))
    \/ p = "ub" /\ (UbStart(p) \/ UbLock(p) \/ UbSweep(p) \/ UbFence(p) \/ UbCommit(p))
    \/ p = "rev" /\ (RevStart(p) \/ RevRow(p) \/ RevFence(p) \/ RevCommit(p) \/ RevAnswer(p))
    \/ p = "admin" /\ (AdminStart(p) \/ AdminRow(p) \/ AdminHead(p) \/ AdminFence(p) \/ AdminBody(p))
    \/ p = "pol" /\ (PolStart(p) \/ PolIssueLock(p) \/ PolFence(p) \/ PolBody(p))
    \/ p = "writer" /\ WriterStep(p)

Terminating == /\ \A p \in Procs : pc[p] = "done"
               /\ UNCHANGED vars

Next == (\E p \in Procs : Step(p)) \/ Terminating

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold *)

TypeOK ==
    /\ fx \in Procs \cup {None}
    /\ hd \in Procs \cup {None}
    /\ bx \in Procs \cup {None}
    /\ status \in {"active", "removed"}
    /\ handed \subseteq Creds
    /\ spent \subseteq IdTokens

\* A revoke orders its credential's uses: none allowed is numbered after it.
RevokeOrdersUses ==
    \A u \in used, r \in revs : (u.allow /\ u.c = r.c) => u.n < r.n

\* No use that began once a revoke was sealed and answered serves its credential.
NothingAfterRevokeAnswered ==
    \A u \in used : u.allow => u.c \notin u.before

\* Only rows the log sealed decide: nothing a database writer put back,
\* forged or edited serves a use.
AllowedOnSealed ==
    \A u \in used : u.allow => Sealed(u.row) = Sealed(u.seal)

\* A use serves the credential whose token was presented, never another
\* whose row a writer gave that token's hash.
AllowedAsPresented ==
    \A u \in used : u.allow => u.c = u.tok

\* A credential serves only at its account's generation: removed, its
\* credentials end, whatever admits it again.
AllowedAtCurrentGeneration ==
    \A u \in used : u.allow => u.row.gen = u.gen

\* Rights never widen (R15, R32): a token giving sensitive reads is numbered
\* before any demotion of its issuer or policy change that takes the right
\* from her role, and before any revoke of the credential its issue came in
\* on.
SensitiveOnlyFromOwners ==
    \A g \in given, d \in dems : (g.sens /\ d.kind \in {"demote", "narrow"}) => g.n < d.n
IssuedByLiveCredential ==
    \A g \in given, r \in revs : g.via = r.c => g.n < r.n

\* A revoke by a right the policy gave is numbered before that right was
\* taken away: none ends a credential its revoker no longer may.
RevokesOnStandingRight ==
    \A r \in revs, d \in dems : (r.mgr /\ d.kind = "unmanage") => r.n < d.n

\* The binding makes at most Rate credentials, and an ID token buys one.
RateHeld ==
    Cardinality({g \in given : g.kind = "signin"}) <= Rate
SpentOnce ==
    \A g, h \in given : (g.kind = "signin" /\ h.kind = "signin" /\ g.tok = h.tok) => g = h

\* A run's credential comes only of an ID token its binding's issuer signed:
\* never of one nobody signed, nor through a binding the app made up (D148).
SignInsOnValidTokens ==
    \A g \in given : g.kind = "signin" => g.tok \in Valid

\* Unbound, a binding's credentials end: none serves a use numbered after.
EndedBindingEndsCredentials ==
    \A u \in used : (u.allow /\ u.row.by = "b" /\ unbound > 0) => u.n < unbound

\* R58: a use never waits on an issue or a sign-in, nor on any lock but
\* the fence (it takes no row's): whoever holds the fence it waits for is
\* neither, nor waits for one on the issue lock.
UsesNeverWaitOnIssues ==
    \A u \in Uses : (pc[u] = "fence" /\ fx /= None) => /\ fx \notin Issuers \cup SignIns
                                                       /\ ~(pc[fx] = "ilock" /\ is /= {})

\* And a use never takes the issue lock (R58): only issues, sign-ins and
\* what must be ordered against them do.
UsesTakeNoIssueLock ==
    \A u \in Uses : u \notin is /\ ix /= u

\* An issue holds no lock between its two statements: what waits for it
\* waits for Postgres, never for the vault's round trip.
IssuesHoldNoLockBetween ==
    \A p \in Issuers : pc[p] = "read" => ~Holds(p)

\* R44: a sign-in never takes 0.14's head.
SignInsTakeNoHead ==
    \A s \in SignIns : hd /= s

=============================================================================
