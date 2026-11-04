------------------------------ MODULE Factor ------------------------------
(***************************************************************************)
(* A person's factor lock (T176; docs/design/passkeys.md, sections 6.1     *)
(* and 6.3): every issue of a credential of a person's, and every change   *)
(* to their passkeys, takes it, so that a change that ends credentials     *)
(* ends every one issued before it, and none is issued after it from a     *)
(* source it ended.                                                        *)
(*                                                                         *)
(*   issue    the vault's statement, `issue_token`: the person's factor    *)
(*            lock first, then the members' rows shared, then the          *)
(*            credential it comes in on (`via`) shared, checked live and   *)
(*            naming the passkey the issue carries, then the insert,       *)
(*            naming that passkey; the commit. The new vault carries       *)
(*            `via`'s passkey, as the app read it.                         *)
(*   old      the same statement as the previous release's vault calls it  *)
(*            during a rollout (migration 0064): the new one carrying no   *)
(*            passkey, so it takes the lock too, and issues only from a    *)
(*            credential no passkey confirmed.                             *)
(*   change   a change to the person's passkeys, the app's transaction:    *)
(*            the factor lock, the log's head (`audited`), the read of the *)
(*            person's live credentials, then a revoke of each, which      *)
(*            takes the member's row exclusive and the credential's (as    *)
(*            `change_input` does), the new session it issues to the       *)
(*            browser that touched (rule 1), the commit.                   *)
(*   app      the app's own issue (T176 PR 4): a session at sign-in or at  *)
(*            a device login's poll, an MCP connection, a token the vault  *)
(*            leaves to it; here, one issued on cA, carrying its passkey.  *)
(*            Its transaction takes the log's head first, as every one of  *)
(*            `audited`'s does, and no factor lock: the head is what       *)
(*            orders it against a change. Under the head it checks its     *)
(*            source live and the passkey rule (section 6.1): what it      *)
(*            names, a live passkey of the person's, or none while they    *)
(*            hold none.                                                   *)
(*   prev     the previous release's app signing Ada in during a rollout,  *)
(*            or any app while the policy is `off`: the head, an insert    *)
(*            naming no passkey, no rule.                                  *)
(*   req      a request on one credential: its one statement reads the     *)
(*            row, the passkey it names and whether its person holds a     *)
(*            live one (section 6.2), and serves it or refuses.            *)
(*                                                                         *)
(* One step is one statement, or the part of one between two lock waits;   *)
(* READ COMMITTED, each step reading what is committed.                    *)
(*                                                                         *)
(* Who is who: Ada, a person, signed in on her browser session cA, which   *)
(* a passkey confirmed ("pa") or none did; "iss", the vault issuing Ada a  *)
(* handle h1 on cA; "old", the previous release's vault issuing h2 on cA;  *)
(* "chg", a change to Ada's passkeys, which issues the session n:          *)
(*   first   her first passkey, "pn": ends every credential that names     *)
(*           none (section 6.1);                                           *)
(*   remove  she removes "pa", keeping "pb": ends every credential of hers *)
(*           but n;                                                        *)
(*   reset   an Owner resets hers: ends every one, and issues none.        *)
(* "app" issues s on cA; "prev" signs Ada in with o; "req" asks with one.  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs,              \* the processes of the scenario (MCFactor.tla)
    Ops                 \* Ops[p]: what p may do, one of them

CONSTANTS
    \* `issue_token` takes the person's factor lock (`via`'s, the actor's).
    IssueTakesFactor,
    \* A change to a person's passkeys takes it before it reads what to end.
    ChangeTakesFactor,
    \* `issue_token` takes it first, before the members' rows: a change,
    \* which holds it and then takes the member's row to revoke, never
    \* waits on an issue that waits on it.
    FactorFirst,
    \* `issue_token` goes ahead only while `via` names the passkey the issue
    \* carries (`c.passkey_id IS NOT DISTINCT FROM p_passkey`).
    IssueChecksPasskey,
    \* A change's transaction takes the log's head before it reads what to
    \* end (`audited`): what orders it against the app's issues.
    ChangeTakesHead,
    \* The app's issue checks, under the head, that its source is live and
    \* that what it names is a live passkey of the person's, or none while
    \* they hold none (section 6.1).
    AppIssueChecks,
    \* Every request's statement reads its credential with the passkey it
    \* names and whether its person holds a live one, and refuses one no
    \* live passkey stands behind (section 6.2).
    RequestChecks

None == "none"
Creds == {"cA", "h1", "h2", "n", "s", "o"}
Issuers == {"iss", "old"} \cap Procs
Changes == {"chg"} \cap Procs
AppIssuers == {"app"} \cap Procs
Previous == {"prev"} \cap Procs
Requests == {"req"} \cap Procs
IssuedBy == [p \in {"iss", "old"} |-> IF p = "iss" THEN "h1" ELSE "h2"]

\* A credential's row: whether it exists, whether it is revoked, the passkey
\* it names, and the credential it was issued on.
Row(passkey, via) == [exists |-> TRUE, revoked |-> FALSE, passkey |-> passkey, via |-> via]
NoRow == [exists |-> FALSE, revoked |-> FALSE, passkey |-> None, via |-> None]
Live(row) == row.exists /\ ~row.revoked

\* What a change ends, of the rows it read, and what it leaves Ada.
Ends(kind, row) == IF kind = "first" THEN row.passkey = None ELSE TRUE
NewSession == [k \in {"first", "remove"} |-> IF k = "first" THEN "pn" ELSE "pb"]
Remaining(kind, keys) == CASE kind = "first" -> {"pn"} [] kind = "remove" -> keys \ {"pa"} [] kind = "reset" -> {}

VARIABLES
    rows,       \* rows[c]: the credentials table as committed
    passkeys,   \* Ada's live passkeys, as committed
    fx,         \* the factor lock's holder
    hx,         \* the log's head: its holder
    mx, ms,     \* Ada's member row: exclusive holder, shared holders
    cx, cs,     \* each credential's row: exclusive holder, shared holders
    pc, op,     \* each process: where it is, what it does
    l,          \* a change: the credentials it read to end, and those it holds
    leftover,   \* at a change's commit: what it should have ended and did not
    unbacked    \* the credentials a request was served on with no live passkey behind them

locks == <<fx, hx, mx, ms, cx, cs>>
vars == <<rows, passkeys, locks, pc, op, l, leftover, unbacked>>

\* The passkey an issue carries, which its row's MAC covers: the new vault
\* `via`'s, which never changes once written; the previous release's none.
Carried(p) == IF p = "iss" THEN rows["cA"].passkey ELSE None

\* What a credential needs behind it (section 6.2): the live passkey it
\* names, or, naming none, a person who holds none.
Backed(row) == IF row.passkey = None THEN passkeys = {} ELSE row.passkey \in passkeys

Holds(p) == fx = p \/ hx = p \/ mx = p \/ p \in ms \/ \E c \in Creds : cx[c] = p \/ p \in cs[c]

Release(p) ==
    /\ fx' = IF fx = p THEN None ELSE fx
    /\ hx' = IF hx = p THEN None ELSE hx
    /\ mx' = IF mx = p THEN None ELSE mx
    /\ ms' = ms \ {p}
    /\ cx' = [c \in Creds |-> IF cx[c] = p THEN None ELSE cx[c]]
    /\ cs' = [c \in Creds |-> cs[c] \ {p}]

-----------------------------------------------------------------------------
(* The vault's issue *)

IssueBegin(p) ==
    /\ pc[p] = "begin"
    /\ pc' = [pc EXCEPT ![p] = IF IssueTakesFactor /\ FactorFirst THEN "factor" ELSE "rows"]
    /\ UNCHANGED <<rows, passkeys, locks, op, l, leftover, unbacked>>

IssueFactor(p) ==
    /\ pc[p] = "factor"
    /\ fx = None
    /\ fx' = p
    /\ pc' = [pc EXCEPT ![p] = IF FactorFirst THEN "rows" ELSE "via"]
    /\ UNCHANGED <<rows, passkeys, hx, mx, ms, cx, cs, op, l, leftover, unbacked>>

\* IssuerLocked: the members' rows shared, Ada's among them.
IssueRows(p) ==
    /\ pc[p] = "rows"
    /\ mx = None
    /\ ms' = ms \cup {p}
    /\ pc' = [pc EXCEPT ![p] = IF IssueTakesFactor /\ ~FactorFirst THEN "factor" ELSE "via"]
    /\ UNCHANGED <<rows, passkeys, fx, hx, mx, cx, cs, op, l, leftover, unbacked>>

\* The credential it comes in on, shared, then compared: live and naming the
\* passkey the issue carries, or "ended".
IssueVia(p) ==
    /\ pc[p] = "via"
    /\ cx["cA"] = None
    /\ IF Live(rows["cA"]) /\ (IssueChecksPasskey => rows["cA"].passkey = Carried(p))
          THEN /\ cs' = [cs EXCEPT !["cA"] = @ \cup {p}]
               /\ pc' = [pc EXCEPT ![p] = "insert"]
               /\ UNCHANGED <<fx, hx, mx, ms, cx>>
          ELSE /\ Release(p)
               /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<rows, passkeys, op, l, leftover, unbacked>>

IssueCommit(p) ==
    /\ pc[p] = "insert"
    /\ rows' = [rows EXCEPT ![IssuedBy[p]] = Row(Carried(p), "cA")]
    /\ Release(p)
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<passkeys, op, l, leftover, unbacked>>

-----------------------------------------------------------------------------
(* A change to Ada's passkeys *)

ChangeBegin(p) ==
    /\ pc[p] = "begin"
    /\ pc' = [pc EXCEPT ![p] = IF ChangeTakesFactor THEN "factor" ELSE IF ChangeTakesHead THEN "head" ELSE "read"]
    /\ UNCHANGED <<rows, passkeys, locks, op, l, leftover, unbacked>>

ChangeFactor(p) ==
    /\ pc[p] = "factor"
    /\ fx = None
    /\ fx' = p
    /\ pc' = [pc EXCEPT ![p] = IF ChangeTakesHead THEN "head" ELSE "read"]
    /\ UNCHANGED <<rows, passkeys, hx, mx, ms, cx, cs, op, l, leftover, unbacked>>

\* `audited`: the log's head, before any row.
TakeHead(p, next) ==
    /\ pc[p] = "head"
    /\ hx = None
    /\ hx' = p
    /\ pc' = [pc EXCEPT ![p] = next]
    /\ UNCHANGED <<rows, passkeys, fx, mx, ms, cx, cs, op, l, leftover, unbacked>>

\* One statement: Ada's live credentials, those the change ends.
ChangeRead(p) ==
    /\ pc[p] = "read"
    /\ l' = [l EXCEPT ![p] = [ends |-> {c \in Creds : Live(rows[c]) /\ Ends(op[p].kind, rows[c])}, held |-> {}]]
    /\ pc' = [pc EXCEPT ![p] = "member"]
    /\ UNCHANGED <<rows, passkeys, locks, op, leftover, unbacked>>

\* Its revokes' first lock: the member's row, exclusive (`change_input`).
ChangeMember(p) ==
    /\ pc[p] = "member"
    /\ mx = None /\ ms \subseteq {p}
    /\ mx' = p
    /\ pc' = [pc EXCEPT ![p] = "revoke"]
    /\ UNCHANGED <<rows, passkeys, fx, hx, ms, cx, cs, op, l, leftover, unbacked>>

\* Each credential it ends: its row, exclusive.
ChangeRevoke(p) ==
    /\ pc[p] = "revoke"
    /\ \E c \in l[p].ends \ l[p].held :
        /\ cx[c] = None /\ cs[c] \subseteq {p}
        /\ cx' = [cx EXCEPT ![c] = p]
        /\ l' = [l EXCEPT ![p].held = @ \cup {c}]
    /\ UNCHANGED <<rows, passkeys, fx, hx, mx, ms, cs, pc, op, leftover, unbacked>>

ChangeCommit(p) ==
    /\ pc[p] = "revoke"
    /\ l[p].held = l[p].ends
    /\ LET ended == [c \in Creds |-> IF c \in l[p].ends THEN [rows[c] EXCEPT !.revoked = TRUE] ELSE rows[c]]
           after == IF op[p].kind = "reset" THEN ended ELSE [ended EXCEPT !["n"] = Row(NewSession[op[p].kind], None)]
       IN /\ rows' = after
          \* What it should have ended, as committed now: every credential of
          \* Ada's its rule names, but the session it issued.
          /\ leftover' = leftover \cup {c \in Creds \ {"n"} : Live(after[c]) /\ Ends(op[p].kind, after[c])}
    /\ passkeys' = Remaining(op[p].kind, passkeys)
    /\ Release(p)
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<op, l, unbacked>>

-----------------------------------------------------------------------------
(* The app's issue on cA: the head, then its check, then the insert *)

AppBegin(p) ==
    /\ pc[p] = "begin"
    /\ pc' = [pc EXCEPT ![p] = "head"]
    /\ UNCHANGED <<rows, passkeys, locks, op, l, leftover, unbacked>>

\* Under the head: cA still live, and what s would name backed now.
AppCheck(p) ==
    /\ pc[p] = "check"
    /\ IF ~AppIssueChecks \/ (Live(rows["cA"]) /\ Backed(rows["cA"]))
          THEN /\ pc' = [pc EXCEPT ![p] = "insert"]
               /\ UNCHANGED locks
          ELSE /\ Release(p)
               /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<rows, passkeys, op, l, leftover, unbacked>>

AppCommit(p) ==
    /\ pc[p] = "insert"
    /\ rows' = [rows EXCEPT !["s"] = Row(rows["cA"].passkey, "cA")]
    /\ Release(p)
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<passkeys, op, l, leftover, unbacked>>

(* The previous release's sign-in: the head, then its session, naming none *)

PrevCommit(p) ==
    /\ pc[p] = "insert"
    /\ rows' = [rows EXCEPT !["o"] = Row(None, None)]
    /\ Release(p)
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<passkeys, op, l, leftover, unbacked>>

(* A request on op[p].cred: one statement *)

Request(p) ==
    /\ pc[p] = "begin"
    /\ LET row == rows[op[p].cred]
           served == Live(row) /\ (RequestChecks => Backed(row))
       IN unbacked' = IF served /\ ~Backed(row) THEN unbacked \cup {op[p].cred} ELSE unbacked
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<rows, passkeys, locks, op, l, leftover>>

-----------------------------------------------------------------------------

Init ==
    /\ \E start \in {"pa", None} :
        /\ rows = [c \in Creds |-> IF c = "cA" THEN Row(start, None) ELSE NoRow]
        /\ passkeys = IF start = None THEN {} ELSE {"pa", "pb"}
        \* A first passkey is a change for someone who has none, the others for someone who has some.
        /\ op \in [Procs -> UNION {Ops[p] : p \in Procs}]
        /\ \A p \in Procs : op[p] \in Ops[p]
        /\ \A p \in Changes : (op[p].kind = "first") = (start = None)
    /\ fx = None /\ hx = None /\ mx = None /\ ms = {}
    /\ cx = [c \in Creds |-> None] /\ cs = [c \in Creds |-> {}]
    /\ pc = [p \in Procs |-> "begin"]
    /\ l = [p \in Procs |-> [ends |-> {}, held |-> {}]]
    /\ leftover = {}
    /\ unbacked = {}

Step(p) ==
    CASE p \in Issuers -> IssueBegin(p) \/ IssueFactor(p) \/ IssueRows(p) \/ IssueVia(p) \/ IssueCommit(p)
      [] p \in Changes -> ChangeBegin(p) \/ ChangeFactor(p) \/ TakeHead(p, "read") \/ ChangeRead(p) \/ ChangeMember(p) \/ ChangeRevoke(p) \/ ChangeCommit(p)
      [] p \in AppIssuers -> AppBegin(p) \/ TakeHead(p, "check") \/ AppCheck(p) \/ AppCommit(p)
      [] p \in Previous -> AppBegin(p) \/ TakeHead(p, "insert") \/ PrevCommit(p)
      [] p \in Requests -> Request(p)

Finished == \A p \in Procs : pc[p] = "done"

Next == (\E p \in Procs : Step(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold *)

TypeOK ==
    /\ pc \in [Procs -> {"begin", "factor", "head", "check", "rows", "via", "insert", "read", "member", "revoke", "done"}]
    /\ fx \in Procs \cup {None} /\ hx \in Procs \cup {None} /\ mx \in Procs \cup {None} /\ ms \subseteq Procs
    /\ leftover \subseteq Creds /\ unbacked \subseteq Creds

\* A change ends every credential of the person's its rule names, those
\* issued while it ran included (section 6.1, review r12's interleaving).
ChangeEndsAll == leftover = {}

\* No credential stays live once the one it was issued on is ended: nothing
\* is issued from a source a change ended, and nothing issued from one
\* escapes it (in this model, only changes revoke).
LiveFromLive == \A c \in Creds : Live(rows[c]) /\ rows[c].via # None => Live(rows[rows[c].via])

\* What either vault issues names the passkey of the credential it came in
\* on (section 6.3): the previous release's, which can carry none, issues
\* nothing from a session a passkey confirmed.
NamesItsSource == \A h \in {"h1", "h2"} : rows[h].exists => rows[h].passkey = rows["cA"].passkey

\* Every live credential the new release issued has a live passkey behind
\* it, or names none while its person holds none: what the app's check
\* under the head and the revocations keep. Only the previous release's
\* sign-in, o, issues past the rule.
IssuedBacked == \A c \in Creds \ {"o"} : Live(rows[c]) => Backed(rows[c])

\* No request is served on a credential no live passkey stands behind,
\* whoever issued it (section 6.2).
ServedBacked == unbacked = {}

\* Who waits on whom: p waits for a lock q holds.
Blocks(p, q) ==
    /\ p # q
    /\ \/ pc[p] = "factor" /\ fx = q
       \/ pc[p] = "rows" /\ mx = q
       \/ pc[p] = "via" /\ cx["cA"] = q
       \/ pc[p] = "member" /\ (mx = q \/ q \in ms)
       \/ pc[p] = "revoke" /\ \E c \in l[p].ends \ l[p].held : cx[c] = q \/ q \in cs[c]

\* No two (or three) processes wait on each other in a circle: Postgres
\* would end one with a deadlock.
NoWaitCycle ==
    ~\E p, q \in Procs :
        \/ Blocks(p, q) /\ Blocks(q, p)
        \/ \E w \in Procs : Blocks(p, q) /\ Blocks(q, w) /\ Blocks(w, p)

=============================================================================
