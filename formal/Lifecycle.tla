------------------------------ MODULE Lifecycle ------------------------------
(***************************************************************************)
(* Who owns a credential's life in 0.15 (T149): its issue (a person's      *)
(* token for a service account, a CI run's sign-in), its revoke, and the   *)
(* uses beside them. Two placements, one constant:                         *)
(*                                                                         *)
(*   A  the vault. An issue, a sign-in and a revoke are each one vault     *)
(*      call, one statement in Postgres (one transaction, autocommit): it  *)
(*      takes its locks, decides on the rows as they are under them,       *)
(*      writes the row, its seal and its number, and commits, all without  *)
(*      a round trip to anyone. The app verifies the request (the CI       *)
(*      run's ID token, the issuer's own credential) and names it.         *)
(*                                                                         *)
(*   B  the app, as 0.15 is built (W220, W224, with W242's sealed          *)
(*      generation). The app asks the vault about the issuer and the       *)
(*      account (`access`), has the vault seal the row it will write       *)
(*      (`prepare`, which reads nothing and weighs no right), then, in its *)
(*      own transaction, takes 0.14's head, checks again under it          *)
(*      (`issuerStill`, `credentialStill`, `exchangeStill`), writes the    *)
(*      row with `app_change` numbering it, and commits: a round trip a    *)
(*      statement.                                                         *)
(*                                                                         *)
(* Uses are the vault's in both: one statement under the fence shared,     *)
(* deciding on the credential's row only if it is its object's newest      *)
(* sealed change, and its account's (W242) generation.                     *)
(*                                                                         *)
(* One step is one statement, or the part of one that runs between two    *)
(* lock waits; READ COMMITTED, each step reading what is committed. A      *)
(* step's label says where the process is: in Postgres (a statement        *)
(* running or waiting for a lock), or at the app, a round trip away,       *)
(* between two statements of its transaction (`AtApp`). What a lock holder *)
(* does at the app is what everyone waiting for that lock waits for.       *)
(*                                                                         *)
(* Who is who:                                                             *)
(*   ada     an Owner of the project, issuing the service account "svc" a  *)
(*           token that reads sensitive values (R32), on her session cA;   *)
(*   s1, s2  two CI runs signing in as svc through one binding, which      *)
(*           makes at most Rate credentials a window;                      *)
(*   admin   demotes Ada, or removes svc, or removes and admits it again;  *)
(*   rev     revokes one credential: Ada's session, svc's token cS, or the *)
(*           token Ada issued;                                             *)
(*   u1, u2  svc's uses of a sensitive value, each naming a credential     *)
(*           whose token was handed out;                                   *)
(*   writer  a database writer holding no key: puts back a row the log     *)
(*           sealed once, forges one, or edits one;                        *)
(*   evil    the app's own code, an attacker's: it calls the vault as it   *)
(*           likes, claiming Ada as the issuer.                            *)
(*                                                                         *)
(* docs/design/credential-lifecycle.md weighs the two with these results;  *)
(* docs/formal.md says what the model abstracts.                           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Placement,      \* "A": the vault issues and revokes; "B": the app does, the vault seals
    Procs,          \* the processes of the scenario (MCLifecycle.tla)
    Ops,            \* Ops[p]: what process p may do, one of them
    Rate            \* how many credentials the binding makes a window

CONSTANTS
    \* A revoke takes the fence exclusive, which every use takes shared
    \* (app_change; 0.15-plan.md, PR 4b): no use decided on the live row
    \* is numbered after the revoke.
    RevokeTakesFence,
    \* An issue, a token's or a sign-in's, never takes the fence: the issue
    \* lock, shared (0026, IssueOwnLock; T123, R58).
    IssueOffFence,
    \* The issuer's standing (an Owner) and the credential the request came
    \* in on, read again where nothing can change them before the commit.
    \* A: in the vault's statement, under Ada's member row and her
    \* credential's row, shared. B: under 0.14's head (`issuerStill`,
    \* `credentialStill`), which the demotion and the revoke take too.
    IssuerLocked,
    \* The account's standing and generation, likewise. A: under svc's
    \* member row, shared, which its removal takes exclusive. B:
    \* `stillMember`, `exchangeStill`, under the head.
    MemberLocked,
    \* The binding's rate, counted where no other sign-in of it can commit
    \* meanwhile. A: under the binding's row, exclusive, in the statement.
    \* B: `exchangeStill`'s count, under the head.
    RateLocked,
    \* A use refuses a credential issued at an earlier generation of its
    \* account (W242, T145: the generation sealed into both objects).
    UseChecksGeneration,
    \* A use decides only on a row that is its object's newest sealed
    \* change (sealed-inputs.md: `stale`, `tampered`).
    SealChecked,
    \* B as built: the app's transaction takes 0.14's head first (`audited`,
    \* and `app_change` takes it again). B's checks above are under it, or
    \* under nothing. A takes no head: no 0.14 entry of its own.
    HeadInB

None == "none"
Members == {"ada", "svc"}
Creds == {"cA", "cS", "t", "e", "x1", "x2", "f"}
Sens == {"read", "sens"}

\* The credential each issuing process makes.
IssuedBy == [p \in {"ada", "evil", "s1", "s2"} |->
                CASE p = "ada" -> "t" [] p = "evil" -> "e" [] p = "s1" -> "x1" [] p = "s2" -> "x2"]
Issuers == {"ada", "evil"} \cap Procs
SignIns == {"s1", "s2"} \cap Procs
Uses == {"u1", "u2"} \cap Procs

Row(who, scope, gen) == [who |-> who, scope |-> scope, gen |-> gen, revoked |-> FALSE]
NoRow == [who |-> None, scope |-> {}, gen |-> 0, revoked |-> TRUE]

VARIABLES
    rows,       \* rows[c]: the credentials table as committed; NoRow for none
    sealed,     \* sealed[c]: what c's newest change in the log left; NoRow for none
    history,    \* every object of c's changes ever left: a writer may put any back
    owner,      \* whether Ada is an Owner of the project
    status,     \* svc's membership: "active" or "removed"
    gen,        \* and its generation: a removal moves it on, an admission keeps it (W242)
    next,       \* the log's next number
    fx, fs,     \* the fence: its exclusive holder, its shared holders
    hd,         \* 0.14's head
    mx, ms,     \* members' rows: exclusive holder, shared holders
    cx, cs,     \* credentials' rows: exclusive holder, shared holders
    bx,         \* the binding's row
    pc, op, l,  \* each process: where it is, what it does, what it read
    handed,     \* the credentials whose token went out: a use may name them
    given,      \* each issue committed: its kind, the credential it came in on, its number, whether it reads sensitive values
    revs,       \* each revoke committed: the credential, its number
    dems,       \* each demotion committed: its number
    used        \* each use decided: its credential, the row and seal it read, the account's generation then, its number, the outcome

locks == <<fx, fs, hd, mx, ms, cx, cs, bx>>
vars == <<rows, sealed, history, owner, status, gen, next, locks, pc, op, l, handed, given, revs, dems, used>>

-----------------------------------------------------------------------------
(* Where a process is *)

\* The labels at which a process is at the app, between two statements of
\* its transaction: whatever it holds, it holds across a round trip.
AppLabels == {"still", "change", "commit"}
AtApp(p) == Placement = "B" /\ p \in Issuers \cup SignIns \cup {"rev"} /\ pc[p] \in AppLabels

Holds(p) ==
    \/ fx = p \/ p \in fs \/ hd = p \/ bx = p
    \/ \E m \in Members : mx[m] = p \/ p \in ms[m]
    \/ \E c \in Creds : cx[c] = p \/ p \in cs[c]

\* Every lock p holds, let go: at its commit, or its refusal's rollback.
Release(p) ==
    /\ fx' = IF fx = p THEN None ELSE fx
    /\ fs' = fs \ {p}
    /\ hd' = IF hd = p THEN None ELSE hd
    /\ mx' = [m \in Members |-> IF mx[m] = p THEN None ELSE mx[m]]
    /\ ms' = [m \in Members |-> ms[m] \ {p}]
    /\ cx' = [c \in Creds |-> IF cx[c] = p THEN None ELSE cx[c]]
    /\ cs' = [c \in Creds |-> cs[c] \ {p}]
    /\ bx' = IF bx = p THEN None ELSE bx

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]
Done(p) == /\ Goto(p, "done") /\ Release(p)

StatusOf(m) == IF m = "svc" THEN status ELSE "active"
GenOf(m) == IF m = "svc" THEN gen ELSE 0
\* A credential as the vault would weigh it now: its row the log's, live, of its account's generation.
Live(c) == rows[c] /= NoRow /\ rows[c] = sealed[c] /\ ~rows[c].revoked
           /\ StatusOf(rows[c].who) = "active" /\ rows[c].gen = GenOf(rows[c].who)

\* The fence exclusive, once nobody holds it: a use waits for whoever does.
FenceFree == fx = None /\ fs = {}

-----------------------------------------------------------------------------
(* Initial state: Ada's session and svc's token cS, which an Owner gave
   sensitive reads, are in the log. *)

Init ==
    /\ rows = [c \in Creds |-> CASE c = "cA" -> Row("ada", Sens, 0)
                                 [] c = "cS" -> Row("svc", Sens, 0)
                                 [] OTHER -> NoRow]
    /\ sealed = rows
    /\ history = [c \in Creds |-> {rows[c]} \ {NoRow}]
    /\ owner = TRUE
    /\ status = "active"
    /\ gen = 0
    /\ next = 1
    /\ fx = None /\ fs = {} /\ hd = None /\ bx = None
    /\ mx = [m \in Members |-> None] /\ ms = [m \in Members |-> {}]
    /\ cx = [c \in Creds |-> None] /\ cs = [c \in Creds |-> {}]
    /\ pc = [p \in Procs |-> "start"]
    /\ op = [p \in Procs |-> [kind |-> "none"]]
    /\ l = [p \in Procs |-> [c |-> None, n |-> 0, gen |-> 0, ok |-> FALSE, w |-> NoRow]]
    /\ handed = {"cS"}
    /\ given = {} /\ revs = {} /\ dems = {} /\ used = {}

\* Writing a credential's row and the log's object for it, as one commit.
Write(c, row) ==
    /\ rows' = [rows EXCEPT ![c] = row]
    /\ sealed' = [sealed EXCEPT ![c] = row]
    /\ history' = [history EXCEPT ![c] = @ \cup {row}]

-----------------------------------------------------------------------------
(* Uses: one statement, the fence shared, the decision on the rows read,
   the number, the commit. The read and the number are two steps: within
   one statement, a commit can come between its snapshot and its
   `nextval`. *)

UseStart(u) ==
    /\ pc[u] = "start"
    /\ \E c \in handed :
        /\ l' = [l EXCEPT ![u].c = c]
        /\ op' = [op EXCEPT ![u] = [kind |-> "use", c |-> c]]
        /\ Goto(u, "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, handed, given, revs, dems, used>>

UseFence(u) ==
    /\ pc[u] = "fence"
    /\ fx = None
    /\ fs' = fs \cup {u}
    /\ Goto(u, "read")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, hd, mx, ms, cx, cs, bx, op, l, handed, given, revs, dems, used>>

UseRead(u) ==
    /\ pc[u] = "read"
    /\ LET c == l[u].c
           row == rows[c]
           allow == /\ row /= NoRow
                    /\ SealChecked => row = sealed[c]
                    /\ ~row.revoked
                    /\ StatusOf(row.who) = "active"
                    /\ UseChecksGeneration => row.gen = GenOf(row.who)
                    /\ "sens" \in row.scope
       IN l' = [l EXCEPT ![u] = [@ EXCEPT !.ok = allow, !.w = row, !.gen = GenOf(row.who)]]
    /\ Goto(u, "number")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, op, handed, given, revs, dems, used>>

UseNumber(u) ==
    /\ pc[u] = "number"
    /\ l' = [l EXCEPT ![u].n = next]
    /\ next' = next + 1
    /\ Goto(u, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, locks, op, handed, given, revs, dems, used>>

UseCommit(u) ==
    /\ pc[u] = "commit"
    /\ used' = used \cup {[c |-> l[u].c, row |-> l[u].w, seal |-> sealed[l[u].c], gen |-> l[u].gen, n |-> l[u].n, allow |-> l[u].ok]}
    /\ Done(u)
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, op, l, handed, given, revs, dems>>

\* `seal` above is the newest sealed object when the use commits; under the
\* fence shared, no change of the credential commits between its read and
\* its commit, so it is the one its read was weighed against.

-----------------------------------------------------------------------------
(* A token: Ada, on her session cA, gives svc sensitive reads; or the app's
   attacker, claiming her. *)

\* At the app: what the vault answers about Ada and svc (`access`). The
\* attacker claims whatever passes.
IssueStart(p) ==
    /\ pc[p] = "start"
    /\ op' = [op EXCEPT ![p] = [kind |-> "issue"]]
    /\ l' = [l EXCEPT ![p] = [@ EXCEPT !.gen = gen, !.ok = (p = "evil" \/ (owner /\ Live("cA") /\ status = "active"))]]
    /\ Goto(p, IF Placement = "A" THEN "rows" ELSE "prepare")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, handed, given, revs, dems, used>>

\* A, in the vault's statement: Ada's row and her credential's, svc's, shared.
IssueRows(p) ==
    /\ pc[p] = "rows"
    /\ IssuerLocked => mx["ada"] = None /\ cx["cA"] = None
    /\ MemberLocked => mx["svc"] = None
    /\ ms' = [m \in Members |-> IF (m = "ada" /\ IssuerLocked) \/ (m = "svc" /\ MemberLocked) THEN ms[m] \cup {p} ELSE ms[m]]
    /\ cs' = [cs EXCEPT !["cA"] = IF IssuerLocked THEN @ \cup {p} ELSE @]
    /\ Goto(p, "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, cx, bx, op, l, handed, given, revs, dems, used>>

\* A: the fence, only if an issue takes it.
IssueFence(p) ==
    /\ pc[p] = "fence"
    /\ IssueOffFence \/ FenceFree
    /\ fx' = IF IssueOffFence THEN fx ELSE p
    /\ Goto(p, "body")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fs, hd, mx, ms, cx, cs, bx, op, l, handed, given, revs, dems, used>>

\* A: the vault weighs the issue on the rows as they are, whatever the app said.
IssueBody(p) ==
    /\ pc[p] = "body"
    /\ IF owner /\ Live("cA") /\ status = "active"
       THEN /\ l' = [l EXCEPT ![p].gen = gen]
            /\ Goto(p, "number")
            /\ UNCHANGED <<fx, fs, hd, mx, ms, cx, cs, bx>>
       ELSE /\ Done(p) /\ UNCHANGED l
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, op, handed, given, revs, dems, used>>

\* B, at the app: the vault seals the row the app proposes, weighing no right.
IssuePrepare(p) ==
    /\ pc[p] = "prepare"
    /\ IF l[p].ok THEN Goto(p, "head") ELSE Goto(p, "done")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, op, l, handed, given, revs, dems, used>>

\* B: BEGIN and 0.14's head, the attacker's own transaction excepted.
TakeHead(p) ==
    /\ pc[p] = "head"
    /\ IF HeadInB /\ p /= "evil" THEN hd = None /\ hd' = p ELSE UNCHANGED hd
    /\ Goto(p, "still")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, mx, ms, cx, cs, bx, op, l, handed, given, revs, dems, used>>

\* B, a round trip later: the checks again, as committed now; the attacker checks nothing.
IssueStill(p) ==
    /\ pc[p] = "still"
    /\ LET ok == /\ IssuerLocked => owner /\ Live("cA")
                 /\ MemberLocked => status = "active" /\ gen = l[p].gen
       IN IF p = "evil" \/ ok
          THEN (Goto(p, "change") /\ UNCHANGED <<fx, fs, hd, mx, ms, cx, cs, bx>>)
          ELSE Done(p)
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, op, l, handed, given, revs, dems, used>>

\* B, a round trip later: the row and `app_change`, its number under the issue lock, or the fence.
IssueChange(p) ==
    /\ pc[p] = "change"
    /\ IssueOffFence \/ FenceFree
    /\ fx' = IF IssueOffFence THEN fx ELSE p
    /\ l' = [l EXCEPT ![p].n = next]
    /\ next' = next + 1
    /\ Goto(p, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, fs, hd, mx, ms, cx, cs, bx, op, handed, given, revs, dems, used>>

\* A: the number, in the statement.
IssueNumber(p) ==
    /\ pc[p] = "number"
    /\ l' = [l EXCEPT ![p].n = next]
    /\ next' = next + 1
    /\ Goto(p, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, locks, op, handed, given, revs, dems, used>>

IssueCommit(p) ==
    /\ pc[p] = "commit"
    /\ Write(IssuedBy[p], Row("svc", Sens, l[p].gen))
    /\ given' = given \cup {[kind |-> "token", via |-> "cA", n |-> l[p].n, sens |-> TRUE]}
    /\ handed' = handed \cup {IssuedBy[p]}
    /\ Done(p)
    /\ UNCHANGED <<owner, status, gen, next, op, l, revs, dems, used>>

-----------------------------------------------------------------------------
(* A CI run's sign-in: its ID token verified at the app (signature,
   claims, binding: not modelled), then the credential. *)

SignInStart(s) ==
    /\ pc[s] = "start"
    /\ op' = [op EXCEPT ![s] = [kind |-> "signin"]]
    \* What the vault answers about svc (`access`), and, unlocked, the binding's rate.
    /\ l' = [l EXCEPT ![s] = [@ EXCEPT !.gen = gen,
                                       !.ok = status = "active" /\ Cardinality({g \in given : g.kind = "signin"}) < Rate]]
    /\ Goto(s, IF Placement = "A" THEN "rows" ELSE "prepare")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, handed, given, revs, dems, used>>

\* A: the binding's row exclusive, svc's shared, in the vault's statement.
SignInRows(s) ==
    /\ pc[s] = "rows"
    /\ RateLocked => bx = None
    /\ MemberLocked => mx["svc"] = None
    /\ bx' = IF RateLocked THEN s ELSE bx
    /\ ms' = [ms EXCEPT !["svc"] = IF MemberLocked THEN @ \cup {s} ELSE @]
    /\ Goto(s, "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, cx, cs, op, l, handed, given, revs, dems, used>>

SignInBody(s) ==
    /\ pc[s] = "body"
    /\ IF status = "active" /\ Cardinality({g \in given : g.kind = "signin"}) < Rate
       THEN /\ l' = [l EXCEPT ![s].gen = gen]
            /\ Goto(s, "number")
            /\ UNCHANGED <<fx, fs, hd, mx, ms, cx, cs, bx>>
       ELSE /\ Done(s) /\ UNCHANGED l
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, op, handed, given, revs, dems, used>>

\* B, a round trip after the head: `exchangeStill`, the account and the rate again.
SignInStill(s) ==
    /\ pc[s] = "still"
    /\ LET ok == /\ MemberLocked => status = "active" /\ gen = l[s].gen
                 /\ RateLocked => Cardinality({g \in given : g.kind = "signin"}) < Rate
       IN IF ok THEN (Goto(s, "change") /\ UNCHANGED <<fx, fs, hd, mx, ms, cx, cs, bx>>) ELSE Done(s)
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, op, l, handed, given, revs, dems, used>>

SignInCommit(s) ==
    /\ pc[s] = "commit"
    /\ Write(IssuedBy[s], Row("svc", Sens, l[s].gen))
    /\ given' = given \cup {[kind |-> "signin", via |-> None, n |-> l[s].n, sens |-> FALSE]}
    /\ handed' = handed \cup {IssuedBy[s]}
    /\ Done(s)
    /\ UNCHANGED <<owner, status, gen, next, op, l, revs, dems, used>>

-----------------------------------------------------------------------------
(* A revoke of one credential. A: one statement, its row then the fence.
   B: the vault seals the revoke from the row the app read, then the app's
   transaction: the head, the row again, the update with `app_change` under
   the fence, the commit. *)

RevStart(r) ==
    /\ pc[r] = "start"
    /\ \E c \in Ops[r] :
        /\ op' = [op EXCEPT ![r] = [kind |-> "revoke", c |-> c]]
        /\ l' = [l EXCEPT ![r].c = c]
    /\ Goto(r, IF Placement = "A" THEN "rows" ELSE "head")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, handed, given, revs, dems, used>>

RevRow(r) ==
    /\ pc[r] = "rows"
    /\ cx[l[r].c] = None /\ cs[l[r].c] = {}
    /\ cx' = [cx EXCEPT ![l[r].c] = r]
    /\ Goto(r, "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, mx, ms, cs, bx, op, l, handed, given, revs, dems, used>>

\* A, in the statement: the fence, the row weighed, the number.
RevFence(r) ==
    /\ pc[r] = "fence"
    /\ RevokeTakesFence => FenceFree
    /\ fx' = IF RevokeTakesFence THEN r ELSE fx
    /\ LET c == l[r].c IN
       IF rows[c] /= NoRow /\ rows[c] = sealed[c] /\ ~rows[c].revoked
       THEN /\ l' = [l EXCEPT ![r].n = next, ![r].ok = TRUE]
            /\ next' = next + 1
       ELSE UNCHANGED <<l, next>>
    /\ Goto(r, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, fs, hd, mx, ms, cx, cs, bx, op, handed, given, revs, dems, used>>

\* B, a round trip after the head: the row, as its prepare read it, still live.
RevStill(r) ==
    /\ pc[r] = "still"
    /\ LET c == l[r].c IN
       IF rows[c] /= NoRow /\ rows[c] = sealed[c] /\ ~rows[c].revoked
       THEN (Goto(r, "change") /\ UNCHANGED <<fx, fs, hd, mx, ms, cx, cs, bx>>)
       ELSE Done(r)
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, op, l, handed, given, revs, dems, used>>

\* B, a round trip later: the update, its row's lock, and `app_change` under the fence.
RevChange(r) ==
    /\ pc[r] = "change"
    /\ cx[l[r].c] = None /\ cs[l[r].c] = {}
    /\ RevokeTakesFence => FenceFree
    /\ cx' = [cx EXCEPT ![l[r].c] = r]
    /\ fx' = IF RevokeTakesFence THEN r ELSE fx
    /\ l' = [l EXCEPT ![r].n = next, ![r].ok = TRUE]
    /\ next' = next + 1
    /\ Goto(r, "commit")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, fs, hd, mx, ms, cs, bx, op, handed, given, revs, dems, used>>

RevCommit(r) ==
    /\ pc[r] = "commit"
    /\ LET c == l[r].c IN
       IF l[r].ok
       THEN /\ Write(c, [rows[c] EXCEPT !.revoked = TRUE])
            /\ revs' = revs \cup {[c |-> c, n |-> l[r].n]}
       ELSE UNCHANGED <<rows, sealed, history, revs>>
    /\ Done(r)
    /\ UNCHANGED <<owner, status, gen, next, op, l, handed, given, dems, used>>

-----------------------------------------------------------------------------
(* The vault's own changes to a member, in either placement (`change_input`):
   the member's row, 0.14's head, the fence, then the change, and a removal
   revokes the account's live credentials in it. A removal and admission
   again is two such transactions. Each is in Postgres throughout. *)

Who(o) == IF o = "demote" THEN "ada" ELSE "svc"

AdminStart(a) ==
    /\ pc[a] = "start"
    /\ \E o \in Ops[a] : op' = [op EXCEPT ![a] = [kind |-> o]]
    /\ Goto(a, "row")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, locks, l, handed, given, revs, dems, used>>

AdminRow(a) ==
    /\ pc[a] = "row"
    /\ mx[Who(op[a].kind)] = None /\ ms[Who(op[a].kind)] = {}
    /\ mx' = [mx EXCEPT ![Who(op[a].kind)] = a]
    /\ Goto(a, "head")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, hd, ms, cx, cs, bx, op, l, handed, given, revs, dems, used>>

AdminHead(a) ==
    /\ pc[a] = "head"
    /\ hd = None
    /\ hd' = a
    /\ Goto(a, "fence")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fx, fs, mx, ms, cx, cs, bx, op, l, handed, given, revs, dems, used>>

AdminFence(a) ==
    /\ pc[a] = "fence"
    /\ FenceFree
    /\ fx' = a
    /\ Goto(a, "body")
    /\ UNCHANGED <<rows, sealed, history, owner, status, gen, next, fs, hd, mx, ms, cx, cs, bx, op, l, handed, given, revs, dems, used>>

\* The change, written and committed. A removal sweeps svc's live rows as they are now (`expectRevoked`).
AdminBody(a) ==
    /\ pc[a] = "body"
    /\ LET n == next
           swept == {c \in Creds : rows[c] /= NoRow /\ rows[c].who = "svc" /\ ~rows[c].revoked /\ rows[c] = sealed[c]}
       IN CASE op[a].kind = "demote" ->
               /\ owner' = FALSE
               /\ dems' = dems \cup {[n |-> n]}
               /\ UNCHANGED <<rows, sealed, history, status, gen, revs, op>>
            [] op[a].kind \in {"remove", "removeRestore"} ->
               /\ status' = "removed"
               /\ gen' = gen + 1
               /\ rows' = [c \in Creds |-> IF c \in swept THEN [rows[c] EXCEPT !.revoked = TRUE] ELSE rows[c]]
               /\ sealed' = [c \in Creds |-> IF c \in swept THEN [rows[c] EXCEPT !.revoked = TRUE] ELSE sealed[c]]
               /\ history' = [c \in Creds |-> IF c \in swept THEN history[c] \cup {[rows[c] EXCEPT !.revoked = TRUE]} ELSE history[c]]
               /\ revs' = revs \cup {[c |-> c, n |-> n] : c \in swept}
               /\ op' = [op EXCEPT ![a].kind = IF @ = "removeRestore" THEN "restore" ELSE @]
               /\ UNCHANGED <<owner, dems>>
            [] op[a].kind = "restore" ->
               /\ status' = "active"
               /\ op' = [op EXCEPT ![a].kind = "restored"]
               /\ UNCHANGED <<rows, sealed, history, owner, gen, revs, dems>>
    /\ next' = next + 1
    /\ pc' = [pc EXCEPT ![a] = IF op'[a].kind = "restore" THEN "row" ELSE "done"]
    /\ Release(a)
    /\ UNCHANGED <<l, handed, given, used>>

-----------------------------------------------------------------------------
(* A database writer, holding no key: one write, or none. *)

WriterStep(w) ==
    /\ pc[w] = "start"
    /\ \/ \* Gives up.
          /\ UNCHANGED <<rows, handed>>
       \/ \* Puts back an object the log sealed once: cS live again after its revoke.
          /\ "putBack" \in Ops[w]
          /\ \E c \in {"cS", "x1"} : \E h \in history[c] : h /= rows[c] /\ rows' = [rows EXCEPT ![c] = h]
          /\ UNCHANGED handed
       \/ \* Writes a row of its own, a token it holds, for svc's sensitive reads.
          /\ "forge" \in Ops[w]
          /\ rows' = [rows EXCEPT !["f"] = Row("svc", Sens, gen)]
          /\ handed' = handed \cup {"f"}
       \/ \* Edits a credential of svc's: live, and of the account's generation now.
          /\ "edit" \in Ops[w]
          /\ \E c \in {"cS", "x1"} : rows[c] /= NoRow /\ rows' = [rows EXCEPT ![c] = [@ EXCEPT !.revoked = FALSE, !.gen = gen]]
          /\ UNCHANGED handed
    /\ Goto(w, "done")
    /\ UNCHANGED <<sealed, history, owner, status, gen, next, locks, op, l, given, revs, dems, used>>

-----------------------------------------------------------------------------

Step(p) ==
    \/ p \in Uses /\ (UseStart(p) \/ UseFence(p) \/ UseRead(p) \/ UseNumber(p) \/ UseCommit(p))
    \/ p \in Issuers /\ (IssueStart(p) \/ IssueRows(p) \/ IssueFence(p) \/ IssueBody(p) \/ IssueNumber(p)
                         \/ IssuePrepare(p) \/ TakeHead(p) \/ IssueStill(p) \/ IssueChange(p) \/ IssueCommit(p))
    \/ p \in SignIns /\ (SignInStart(p) \/ SignInRows(p) \/ IssueFence(p) \/ SignInBody(p) \/ IssueNumber(p)
                         \/ IssuePrepare(p) \/ TakeHead(p) \/ SignInStill(p) \/ IssueChange(p) \/ SignInCommit(p))
    \/ p = "rev" /\ (RevStart(p) \/ RevRow(p) \/ RevFence(p) \/ TakeHead(p) \/ RevStill(p) \/ RevChange(p) \/ RevCommit(p))
    \/ p = "admin" /\ (AdminStart(p) \/ AdminRow(p) \/ AdminHead(p) \/ AdminFence(p) \/ AdminBody(p))
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

\* A revoke orders its credential's uses: none allowed is numbered after it.
\* (A use that starts after the revoke commits reads it revoked; one in
\* flight is numbered before it, or refused.)
RevokeOrdersUses ==
    \A u \in used, r \in revs : (u.allow /\ u.c = r.c) => u.n < r.n

\* Only rows the log sealed decide: nothing a database writer put back,
\* forged or edited serves a use.
AllowedOnSealed ==
    \A u \in used : u.allow => u.row = u.seal

\* A credential serves only at the generation of its account it was
\* issued at: removed, its credentials end, whatever admits it again.
AllowedAtCurrentGeneration ==
    \A u \in used : u.allow => u.row.gen = u.gen

\* Rights never widen (R15, R32): a token giving sensitive reads is numbered
\* before any demotion of its issuer, and before any revoke of the
\* credential its issue came in on. Its issue was weighed on both as they
\* stood at its number.
SensitiveOnlyFromOwners ==
    \A g \in given, d \in dems : g.sens => g.n < d.n
IssuedByLiveCredential ==
    \A g \in given, r \in revs : g.via = r.c => g.n < r.n

\* The binding makes at most Rate credentials.
RateHeld ==
    Cardinality({g \in given : g.kind = "signin"}) <= Rate

\* R58: a use never waits on an issue or a sign-in.
UsesNeverWaitOnIssues ==
    \A u \in Uses : (pc[u] = "fence" /\ fx /= None) => fx \notin Issuers \cup SignIns

\* R44: a sign-in never queues behind 0.14's head.
SignInsNeverWaitOnHead ==
    \A s \in SignIns : ~(pc[s] = "head" /\ HeadInB /\ hd \notin {None, s})

\* An issue or a sign-in holds no lock across a round trip to the app: what
\* waits for it waits for Postgres, never for the network.
IssuesHoldNoLockAtApp ==
    \A p \in Issuers \cup SignIns : AtApp(p) => ~Holds(p)

\* A use waits on a revoke only while the revoke runs in Postgres, never
\* for its round trips (R58 lets a revoke hold uses briefly).
UsesWaitOnlyOnDbWork ==
    \A u \in Uses : (pc[u] = "fence" /\ fx /= None) => ~AtApp(fx)

=============================================================================
