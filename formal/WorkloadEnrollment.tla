-------------------------- MODULE WorkloadEnrollment --------------------------
(***************************************************************************)
(* Enrollment codes (docs/design/workload-access.md, section 4.4): minting *)
(* a code with its scope, exchanging it for sessions up to the capacity,   *)
(* renewing them on the database's clock, and promoting another code,      *)
(* which supersedes it. docs/formal.md says what this covers, what it      *)
(* abstracts and what it does not prove.                                   *)
(*                                                                         *)
(* One step is one SQL statement, or a run of statements nothing else can  *)
(* interleave with because the step holds the lock they need, as in        *)
(* Coffre.tla. Isolation is READ COMMITTED. One lock matters, the log's    *)
(* head, which the exchange's commit, a mint's and a promote's take, and   *)
(* renewal does not. Time is the database's statement clock, one tick at a *)
(* time: a session is live while `expires_at` is past it.                  *)
(*                                                                         *)
(* The service is `token:api`, with one enrollment binding. Its codes are  *)
(* "c1", "c2" and "c3"; CI minted some before the scenario starts.         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

RECURSIVE SeqOf(_)
SeqOf(set) == IF set = {} THEN <<>> ELSE LET x == CHOOSE x \in set : TRUE IN <<x>> \o SeqOf(set \ {x})

CONSTANTS
    Procs,          \* concurrent requests, each one a process
    Ops,            \* Ops[p]: the operations process p may run
    Budget,         \* Budget[p]: how many it runs, one after another
    Replicas,       \* the binding's `replicas`
    Life,           \* an enrollment session's life past its last renewal, in ticks
    MaxTime,        \* how far the clock runs
    Initial         \* the codes CI minted before the scenario starts

(***************************************************************************)
(* The protections the design has, each a switch, as in Coffre.tla.        *)
(***************************************************************************)
CONSTANTS
    \* The exchange counts the code's live roots inside its commit, under
    \* the head (4.4, item 2). Off, it counts before it takes the head.
    CountUnderHead,
    \* A renewal updates only a row still live at the update's own
    \* statement clock, and still at the expiry it read: `WHERE expires_at =
    \* $old AND $old > statement_timestamp() + 5s AND revoked_at IS NULL`
    \* (4.4, item 1). Off, only `expires_at = $old AND revoked_at IS NULL`.
    RenewOnlyLive,
    \* The exchange refuses a code an `enrollment.supersede` names (4.4,
    \* item 4), in its commit.
    SupersedeCheckedAtExchange,
    \* So does renewal (PROOFS' renew.check).
    SupersedeCheckedAtRenewal,
    \* And renewal checks it in the statement that updates the row, after
    \* it read the clock. Off, in a statement of its own before it.
    SupersedeCheckInUpdate,
    \* A session takes its code's scope, fixed at minting (`enrollments.scope`),
    \* not the binding's.
    ScopeFromCode,
    \* A code's scope reads sensitive values only where its minter is an
    \* Owner, as a person (R32).
    SensitiveNeedsOwnerMinter,
    \* A mint is weighed on the vault's answer read after the newest entry
    \* about the minter's access, and commits only while that entry is still
    \* the newest (Issuing.tla's issuerNow and issuerStill).
    MinterFence,
    \* The mint and promote routes refuse a session proven by enrollment...
    MintRefusesEnrollment,
    \* ...and checkPolicy refuses a `mintedBy` naming the binding's own
    \* service: each covers for the other.
    MintedByNotSelf,
    \* The mint and promote routes refuse every `narrow` child.
    MintRefusesChildren

None == "none"
\* Sessions are named as entries are, by the operation that made them.
NoSession == <<None, 0>>
Codes == {"c1", "c2", "c3"}
\* A scope's rights at the binding's one place: "r" reads (and uses) its
\* values, "s" its sensitive ones. The binding's own is both: an Owner made it.
BindingScope == {"r", "s"}

\* Who may ask to mint or promote: two people who manage the service, an
\* Owner and a Viewer, CI's session (an `oidc` exchange of token:deploy),
\* and the children and enrollment sessions a thief could hold.
Callers == {"omar", "vic", "deploy", "deploy.child", "api", "api.child"}
Caller(c) ==
    CASE c = "omar"         -> [principal |-> "omar", person |-> TRUE, enrolled |-> FALSE, child |-> FALSE]
      [] c = "vic"          -> [principal |-> "vic", person |-> TRUE, enrolled |-> FALSE, child |-> FALSE]
      [] c = "deploy"       -> [principal |-> "deploy", person |-> FALSE, enrolled |-> FALSE, child |-> FALSE]
      [] c = "deploy.child" -> [principal |-> "deploy", person |-> FALSE, enrolled |-> FALSE, child |-> TRUE]
      [] c = "api"          -> [principal |-> "api", person |-> FALSE, enrolled |-> TRUE, child |-> FALSE]
      [] c = "api.child"    -> [principal |-> "api", person |-> FALSE, enrolled |-> TRUE, child |-> TRUE]
Principals == {"omar", "vic", "deploy", "api"}

VARIABLES
    now,            \* the database's statement clock
    codes,          \* codes[c]: the enrollments row, [minted, scope]
    mintedBy,       \* the binding's policy's `mintedBy`
    sessions,       \* the code's sessions, roots: [id, code, expires, revoked, scope]
    held,           \* held[p]: the session process p holds, or NoSession
    holdings,       \* holdings[principal]: what the vault answers it holds
    owners,         \* the Owners of the project, as people
    log,            \* the audit log, in seq order
    head,           \* the process holding the log's head, or None
    pc, op, l, left,
    minted,         \* history: per code, what its minter held at the commit
    renewals        \* history: per renewal that updated, where in the log

rows == <<codes, mintedBy, sessions, held, holdings, owners>>
procs == <<pc, op, l, left>>
history == <<minted, renewals>>
vars == <<now, rows, log, head, procs, history>>

-----------------------------------------------------------------------------
(* Codes and sessions *)

Row(id) == CHOOSE r \in sessions : r.id = id
Live(r) == ~r.revoked /\ r.expires > now
\* The code's live roots, as the count reads them: `ancestors IS NULL`,
\* unrevoked, `expires_at > statement_timestamp()`. Children are no slot,
\* and not modelled here.
LiveRoots(c) == {r \in sessions : r.code = c /\ Live(r)}

\* An `enrollment.supersede` names the code (its tombstone index).
Tombstoned(c) == \E i \in 1..Len(log) : log[i].kind = "enrollment.supersede" /\ log[i].code = c
SupersededAt(c) == LET is == {i \in 1..Len(log) : log[i].kind = "enrollment.supersede" /\ log[i].code = c}
                   IN log[CHOOSE i \in is : \A j \in is : i <= j].time

\* The newest entry about a principal's access, by its index (0: none).
NewestAbout(m) == LET is == {i \in 1..Len(log) : log[i].kind = "member.role" /\ log[i].who = m}
                  IN IF is = {} THEN 0 ELSE CHOOSE i \in is : \A j \in is : j <= i

\* A code's scope from the minter's holdings, as the vault answered them.
CodeScope(have, owner) == (BindingScope \cap have) \ (IF owner \/ ~SensitiveNeedsOwnerMinter THEN {} ELSE {"s"})

\* Whether a caller may mint or promote the binding's codes (4.4).
MayMint(c) ==
    LET k == Caller(c) IN
    IF k.person THEN TRUE
    ELSE /\ ~(MintRefusesChildren /\ k.child)
         /\ ~(MintRefusesEnrollment /\ k.enrolled)
         /\ k.principal = mintedBy

-----------------------------------------------------------------------------
(* Processes *)

NoOp == [kind |-> "none", code |-> None, caller |-> None, now |-> FALSE]
L0 == [id |-> <<None, 0>>, count |-> 0, old |-> 0, new |-> 0, s |-> NoSession, entry |-> 0, have |-> {}, owner |-> FALSE]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Release(p) == head' = IF head = p THEN None ELSE head

TakeHead(p, then) ==
    /\ head \in {None, p}
    /\ head' = p
    /\ Goto(p, then)
    /\ UNCHANGED <<now, rows, log, op, l, left, history>>

Read(p, then, locals) ==
    /\ Goto(p, then)
    /\ l' = [l EXCEPT ![p] = locals]
    /\ UNCHANGED <<now, rows, log, head, op, left, history>>

\* Refused, or rolled back: the head goes.
Refuse(p) ==
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<now, rows, log, op, l, left, history>>

Entry(kind, p) == [kind |-> kind, id |-> l[p].id, code |-> None, who |-> None, by |-> None, time |-> now]

FirstLabel(kind) ==
    CASE kind = "enroll"  -> IF CountUnderHead THEN "ex.head" ELSE "ex.count"
      [] kind = "renew"   -> IF SupersedeCheckInUpdate THEN "renew.clock" ELSE "renew.check"
      [] kind = "logout"  -> "logout.head"
      [] kind = "mint"    -> "mint.entry"
      [] kind = "promote" -> "promote.access"
      [] kind = "demote"  -> "demote.head"

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = [L0 EXCEPT !.id = <<p, left[p]>>]]
         /\ Goto(p, FirstLabel(o.kind))
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<now, rows, log, head, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* The exchange of a code (4.1, step 7): under the head, the tombstone,    *)
(* the count of the code's live roots, then the session and               *)
(* `token.exchange`. The steps before (limiters, shape, binding, the       *)
(* code's hash, vault.access) decide nothing here: left out. A process     *)
(* that enrolls again has restarted: its old session renews no more.       *)
(***************************************************************************)

\* Off CountUnderHead: the count, before the head.
ExCount(p) ==
    /\ pc[p] = "ex.count"
    /\ Read(p, "ex.head", [l[p] EXCEPT !.count = Cardinality(LiveRoots(op[p].code))])

ExHead(p) == pc[p] = "ex.head" /\ TakeHead(p, "ex.commit")

ExCommit(p) ==
    /\ pc[p] = "ex.commit"
    /\ LET c == op[p].code
           count == IF CountUnderHead THEN Cardinality(LiveRoots(c)) ELSE l[p].count
       IN IF \/ ~codes[c].minted
             \/ SupersedeCheckedAtExchange /\ Tombstoned(c)
             \/ count >= 2 * Replicas
            THEN Refuse(p)
            ELSE /\ sessions' = sessions \cup
                      {[id |-> l[p].id, code |-> c, expires |-> now + Life, revoked |-> FALSE,
                        scope |-> IF ScopeFromCode THEN codes[c].scope ELSE BindingScope]}
                 /\ held' = [held EXCEPT ![p] = l[p].id]
                 /\ log' = Append(log, [Entry("token.exchange", p) EXCEPT !.code = c])
                 /\ Release(p)
                 /\ Goto(p, "idle")
                 /\ UNCHANGED <<now, codes, mintedBy, holdings, owners, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Renewal (4.4, item 1): two steps, because the app computes the row's    *)
(* MAC. It reads the clock and computes the new expiry, then updates the   *)
(* row only as it read it, and only if it is still live.                   *)
(***************************************************************************)

\* Off SupersedeCheckInUpdate: the tombstone, before the clock.
RenewCheck(p) ==
    /\ pc[p] = "renew.check"
    /\ IF held[p] # NoSession /\ SupersedeCheckedAtRenewal /\ Tombstoned(Row(held[p]).code)
         THEN Refuse(p)
         ELSE Read(p, "renew.clock", l[p])

RenewClock(p) ==
    /\ pc[p] = "renew.clock"
    /\ IF held[p] = NoSession
         THEN Refuse(p)
         ELSE LET r == Row(held[p]) IN
              Read(p, "renew.update", [l[p] EXCEPT !.s = r.id, !.old = r.expires, !.new = now + Life])

\* The update's statement: its own clock, and the tombstone with it.
RenewUpdate(p) ==
    /\ pc[p] = "renew.update"
    /\ LET r == Row(l[p].s) IN
       IF \/ r.expires # l[p].old \/ r.revoked
          \/ RenewOnlyLive /\ ~(l[p].old > now)
          \/ SupersedeCheckedAtRenewal /\ SupersedeCheckInUpdate /\ Tombstoned(r.code)
         THEN Refuse(p)
         ELSE /\ sessions' = (sessions \ {r}) \cup {[r EXCEPT !.expires = l[p].new]}
              /\ renewals' = renewals \cup {[s |-> r.id, code |-> r.code, at |-> Len(log)]}
              /\ Goto(p, "idle")
              /\ UNCHANGED <<now, codes, mintedBy, held, holdings, owners, log, head, op, l, left, minted>>

\* A graceful stop logs out at once: `token.revoke` under the head.
LogoutHead(p) == pc[p] = "logout.head" /\ TakeHead(p, "logout.commit")

LogoutCommit(p) ==
    /\ pc[p] = "logout.commit"
    /\ IF held[p] = NoSession
         THEN Refuse(p)
         ELSE LET r == Row(held[p]) IN
              /\ sessions' = (sessions \ {r}) \cup {[r EXCEPT !.revoked = TRUE]}
              /\ held' = [held EXCEPT ![p] = NoSession]
              /\ log' = Append(log, [Entry("token.revoke", p) EXCEPT !.code = r.code])
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<now, codes, mintedBy, holdings, owners, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Minting a code (4.4): the newest entry about the minter's access, the   *)
(* vault's answer, then under the head the fence and the row, its scope    *)
(* the binding's intersected with what the minter holds.                   *)
(***************************************************************************)

MintEntry(p) ==
    /\ pc[p] = "mint.entry"
    /\ Read(p, "mint.access", [l[p] EXCEPT !.entry = NewestAbout(Caller(op[p].caller).principal)])

MintAccess(p) ==
    /\ pc[p] = "mint.access"
    /\ LET k == Caller(op[p].caller) IN
       IF MayMint(op[p].caller)
         THEN Read(p, "mint.head", [l[p] EXCEPT !.have = holdings[k.principal],
                                               !.owner = k.person /\ k.principal \in owners])
         ELSE Refuse(p)

MintHead(p) == pc[p] = "mint.head" /\ TakeHead(p, "mint.commit")

MintCommit(p) ==
    /\ pc[p] = "mint.commit"
    /\ LET c == op[p].code
           k == Caller(op[p].caller)
       IN IF \/ codes[c].minted
             \/ MinterFence /\ NewestAbout(k.principal) # l[p].entry
            THEN Refuse(p)
            ELSE /\ codes' = [codes EXCEPT ![c] = [minted |-> TRUE, scope |-> CodeScope(l[p].have, l[p].owner)]]
                 /\ log' = Append(log, [Entry("enrollment.create", p) EXCEPT !.code = c, !.by = op[p].caller])
                 /\ minted' = [minted EXCEPT ![c] = [have |-> holdings[k.principal],
                                                     owner |-> k.person /\ k.principal \in owners]]
                 /\ Release(p)
                 /\ Goto(p, "idle")
                 /\ UNCHANGED <<now, mintedBy, sessions, held, holdings, owners, op, l, left, renewals>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Promoting a code (4.4, item 4): under the head, one                     *)
(* `enrollment.supersede` per other code, and with `--now` their sessions  *)
(* revoked.                                                                *)
(***************************************************************************)

PromoteAccess(p) ==
    /\ pc[p] = "promote.access"
    /\ IF MayMint(op[p].caller) THEN Read(p, "promote.head", l[p]) ELSE Refuse(p)

PromoteHead(p) == pc[p] = "promote.head" /\ TakeHead(p, "promote.commit")

PromoteCommit(p) ==
    /\ pc[p] = "promote.commit"
    /\ LET c == op[p].code
           older == {o \in Codes : o # c /\ codes[o].minted /\ ~Tombstoned(o)}
           each == SeqOf(older)
           entries == [i \in 1..Len(each) |-> [Entry("enrollment.supersede", p) EXCEPT !.code = each[i], !.by = op[p].caller]]
       IN IF ~codes[c].minted \/ Tombstoned(c)
            THEN Refuse(p)
            ELSE /\ log' = log \o entries
                 /\ sessions' = IF op[p].now
                                  THEN {IF r.code \in older THEN [r EXCEPT !.revoked = TRUE] ELSE r : r \in sessions}
                                  ELSE sessions
                 /\ Release(p)
                 /\ Goto(p, "idle")
                 /\ UNCHANGED <<now, codes, mintedBy, held, holdings, owners, op, l, left, history>>

\* Demoting an Owner, in the vault, under the head: `member.role`.
DemoteHead(p) == pc[p] = "demote.head" /\ TakeHead(p, "demote.commit")

DemoteCommit(p) ==
    /\ pc[p] = "demote.commit"
    /\ LET m == Caller(op[p].caller).principal IN
       /\ holdings' = [holdings EXCEPT ![m] = {"r"}]
       /\ owners' = owners \ {m}
       /\ log' = Append(log, [Entry("member.role", p) EXCEPT !.who = m])
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<now, codes, mintedBy, sessions, held, op, l, left, history>>

-----------------------------------------------------------------------------

\* The clock runs, whatever the requests do.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<rows, log, head, procs, history>>

Init ==
    /\ now = 0
    /\ codes = [c \in Codes |-> [minted |-> c \in Initial, scope |-> IF c \in Initial THEN {"r"} ELSE {}]]
    /\ mintedBy \in IF MintedByNotSelf THEN {"deploy"} ELSE {"deploy", "api"}
    /\ sessions = {}
    /\ held = [p \in Procs |-> NoSession]
    /\ holdings = [m \in Principals |-> IF m = "vic" THEN {"r"} ELSE {"r", "s"}]
    /\ owners = {"omar"}
    /\ log = <<>>
    /\ head = None
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ minted = [c \in Codes |-> [have |-> IF c \in Initial THEN holdings["deploy"] ELSE {}, owner |-> FALSE]]
    /\ renewals = {}

Step(p) ==
    \/ Begin(p)
    \/ ExCount(p) \/ ExHead(p) \/ ExCommit(p)
    \/ RenewCheck(p) \/ RenewClock(p) \/ RenewUpdate(p)
    \/ LogoutHead(p) \/ LogoutCommit(p)
    \/ MintEntry(p) \/ MintAccess(p) \/ MintHead(p) \/ MintCommit(p)
    \/ PromoteAccess(p) \/ PromoteHead(p) \/ PromoteCommit(p)
    \/ DemoteHead(p) \/ DemoteCommit(p)

Finished == \A p \in Procs : pc[p] = "idle" /\ left[p] = 0

Next == (\E p \in Procs : Step(p)) \/ Tick \/ (Finished /\ now = MaxTime /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* What must hold in every state (section 12.1).                           *)
(***************************************************************************)

TypeOK ==
    /\ now \in 0..MaxTime
    /\ head \in Procs \cup {None}
    /\ mintedBy \in Principals

\* A code has at most twice `replicas` live roots, under concurrent
\* exchanges and renewals.
Capacity == \A c \in Codes : Cardinality(LiveRoots(c)) <= 2 * Replicas

\* No session is made from a code once an `enrollment.supersede` names it,
\* none renews after, and so every one of its sessions ends within a
\* session's life of the supersede: the old deployment drains.
Superseded ==
    /\ \A i, j \in 1..Len(log) :
         (i < j /\ log[i].kind = "enrollment.supersede" /\ log[j].kind = "token.exchange") => log[i].code # log[j].code
    /\ \A u \in renewals : ~\E i \in 1..u.at : log[i].kind = "enrollment.supersede" /\ log[i].code = u.code
    /\ \A r \in sessions : (Tombstoned(r.code) /\ ~r.revoked) => r.expires <= SupersededAt(r.code) + Life

\* A code's sessions never hold more than its minter held when it was
\* minted, and read a sensitive value only if the minter was an Owner then,
\* as a person; no enrollment session and no child mints or promotes.
MinterBound ==
    /\ \A r \in sessions : r.scope \subseteq minted[r.code].have /\ ("s" \in r.scope => minted[r.code].owner)
    /\ \A i \in 1..Len(log) :
         log[i].kind \in {"enrollment.create", "enrollment.supersede"} =>
           ~Caller(log[i].by).enrolled /\ ~Caller(log[i].by).child

=============================================================================
