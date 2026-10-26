----------------------------- MODULE Credentials -----------------------------
(***************************************************************************)
(* A service account's credentials: a CI run's ID token exchanged for one, *)
(* a credential used to read a value, and every way one ends. docs/formal.md *)
(* says what this covers, what it abstracts and what it does not prove.    *)
(*                                                                         *)
(* One step is one SQL statement, or a run of statements nothing else can  *)
(* interleave with because the step holds the lock they need, as in        *)
(* Coffre.tla. Isolation is READ COMMITTED. Two locks matter, each held to *)
(* the end of its transaction:                                             *)
(*                                                                         *)
(*   - the account's row, vault_members, which every vault decision about  *)
(*     it takes first (vault store.ts, lockMembers): FOR NO KEY UPDATE, or *)
(*     FOR SHARE for a read, which its other reads share and a change to   *)
(*     the account waits for, queued behind a change that asked first;     *)
(*   - the log's head, audit_chain_head, which every app transaction takes *)
(*     first (server api/context.ts, audited) and every vault decision     *)
(*     after the rows (vault vault.ts, #decideOnce).                       *)
(*                                                                         *)
(* An exchange inserts the credential's row, whose foreign key takes a KEY *)
(* SHARE lock on the account's row: that never waits for NO KEY UPDATE, so *)
(* it is left out.                                                         *)
(*                                                                         *)
(* The account is a service account with one trust binding, "b1", on one   *)
(* issuer, and a token, "tok", someone issued it. Replacing the issuer's   *)
(* keys (`coffre trust --replace-keys`) makes "b2" in its place. Each CI   *)
(* run holds an ID token, "t1", "t2" or "t3", good for one credential.    *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Procs,          \* concurrent requests, each one a process
    Ops,            \* Ops[p]: the operations process p may run
    Budget,         \* Budget[p]: how many it runs, one after another
    RateCap         \* how many credentials a binding issues within the minute

(***************************************************************************)
(* The protections the code has, each a switch, as in Coffre.tla.          *)
(***************************************************************************)
CONSTANTS
    \* The exchange spends the ID token in the transaction that issues its
    \* credential, an insert into consumed_tokens whose primary key is the
    \* token's hash (server api/workloads.ts, #exchange, exchangeToken). Off,
    \* only the read before it (exchangeCandidates) stands in its way.
    SpentTokenInsertedWithCredential,
    \* The exchange reads its binding again under the head (#exchange,
    \* exchangeStill), not only before it (exchangeCandidates).
    BindingRecheckUnderHead,
    \* And the account's standing and generation (#exchange, exchangeStill).
    MemberRecheckInExchange,
    \* The binding's rate, credentials it issued in the last minute, is
    \* counted under the head (#exchange, exchangeStill), not before it.
    RateCountUnderHead,
    \* Untrusting or replacing a binding revokes the live credentials it
    \* issued (workloads.ts, #revoke, revokeLiveCredentials).
    RevokeIssuedCredentials,
    \* A credential a binding issued is checked at each use against its
    \* binding, which must still stand (server db/queries.ts, findCredential,
    \* standingBinding; api/signin.ts, #liveCredential, bindingStands).
    BindingCheckedAtUse,
    \* Once the vault has released a value, the app reads the credential and
    \* the account's generation again before it answers (server
    \* api/context.ts, recorded, credentialStill): under the head when it
    \* commits entries of its own, as through the proxy when the vault did
    \* not log its use, and with no lock when it has none, as an export and
    \* a use the vault logged.
    CredentialFenceUnderHead,
    CredentialFenceUnlocked,
    \* A use may decide on the vault's answer about the account kept from an
    \* earlier request (server accesses.ts, accessFor), which its unwrap
    \* names: the vault decides it only while that is still its answer, under
    \* the account's row (vault.ts, #keys, `accessRevision`), and the use
    \* starts over, asking, otherwise (fetch-api.ts, AccessChanged).
    KeptAnswerChecked

None == "none"
\* Credentials are named as entries are, by the operation that made them,
\* or "tok", the token the account starts with.
NoCred == <<None, 0>>
Tok == <<"tok", 0>>
Bindings == {"b1", "b2"}
IdTokens == {"t1", "t2", "t3"}

VARIABLES
    \* app rows
    binding,        \* binding[b]: [made, revoked, gen], service_bindings
    creds,          \* the credentials rows: [id, by, gen, revoked]
    consumed,       \* the ID tokens spent, consumed_tokens
    \* vault rows
    status,         \* the account's status: "active" or "removed"
    gen,            \* its generation
    \* both
    log,            \* the audit log, in seq order
    \* locks
    rowLock,        \* the process holding the account's row alone, or None
    rowShared,      \* the processes sharing it
    head,           \* the process holding the log's head, or None
    \* processes
    pc, op, l, left,
    \* history, for the invariants
    issued,         \* a record per credential an exchange issued: whether at the account's generation then
    revealed        \* a record per use whose value reached its caller

rows == <<binding, creds, consumed, status, gen>>
locks == <<rowLock, rowShared, head>>
procs == <<pc, op, l, left>>
history == <<issued, revealed>>
vars == <<rows, log, locks, procs, history>>

-----------------------------------------------------------------------------
(* Credentials and bindings *)

\* The binding stands: made, not revoked, at the account's generation as it
\* was made (exchangeCandidates and exchangeStill read all three).
Stands(b, g) == binding[b].made /\ ~binding[b].revoked /\ binding[b].gen = g

Cred(c) == CHOOSE r \in creds : r.id = c

\* Whether an operation naming "tok" or "exchanged" is about r: the token,
\* or any credential an exchange issued.
Named(name, r) == IF name = "exchanged" THEN r.by # "token" ELSE r.id = Tok

\* What verify finds of a credential, unlocked (signin.ts, #liveCredential):
\* not revoked, its binding standing if a binding issued it, and the
\* account active at the generation it was issued at.
Verifies(r) ==
    /\ ~r.revoked
    /\ (BindingCheckedAtUse /\ r.by # "token") => Stands(r.by, r.gen)
    /\ status = "active" /\ gen = r.gen

\* What the fence reads of it (context.ts, credentialStill): its row not
\* revoked, and the account active at its generation.
StillLive(r) == ~r.revoked /\ status = "active" /\ gen = r.gen

\* Revoke every live credential the binding issued.
RevokeBy(b) == {IF r.by = b THEN [r EXCEPT !.revoked = TRUE] ELSE r : r \in creds}

-----------------------------------------------------------------------------
(* Processes *)

NoOp == [kind |-> "none", cred |-> None, token |-> None, at |-> None, proxy |-> FALSE]

L0 == [id |-> <<None, 0>>,
       b |-> None,            \* the binding an exchange matched
       bgen |-> 0,            \* its generation, as read
       gen |-> 0,             \* the account's generation, as the vault answered
       rate |-> 0,            \* the binding's credentials, counted before the head
       cred |-> NoCred,       \* the credential a use came in on
       at |-> 0,              \* where its `secret.read` is in the log
       recalled |-> FALSE,    \* a use decided on a kept answer, not one it asked for
       kept |-> 0,            \* that answer's generation
       asks |-> FALSE,        \* a use started over: it asks, keeping nothing
       plan |-> {}]           \* the bindings a replace listed

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Release(p) ==
    /\ rowLock' = IF rowLock = p THEN None ELSE rowLock
    /\ rowShared' = rowShared \ {p}
    /\ head' = IF head = p THEN None ELSE head

TakeRow(p, then) ==
    /\ rowLock \in {None, p}
    /\ rowShared \subseteq {p}
    /\ rowLock' = p
    /\ Goto(p, then)
    /\ UNCHANGED <<rows, log, rowShared, head, op, l, left, history>>

\* Share the row, waiting while another holds it alone, or is about to.
ShareRow(p, then) ==
    /\ rowLock \in {None, p}
    /\ ~\E q \in Procs \ {p} : pc[q] \in {"remove.lock", "restore.lock"}
    /\ rowShared' = rowShared \cup {p}
    /\ Goto(p, then)
    /\ UNCHANGED <<rows, log, rowLock, head, op, l, left, history>>

TakeHead(p, then) ==
    /\ head \in {None, p}
    /\ head' = p
    /\ Goto(p, then)
    /\ UNCHANGED <<rows, log, rowLock, rowShared, op, l, left, history>>

Read(p, then, locals) ==
    /\ Goto(p, then)
    /\ l' = [l EXCEPT ![p] = locals]
    /\ UNCHANGED <<rows, log, locks, op, left, history>>

\* Refused, or rolled back: every lock goes. A refusal's own entry commits
\* in a transaction of its own, which decides nothing, and is left out.
Refuse(p) ==
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<rows, log, op, l, left, history>>

Entry(kind, p) == [kind |-> kind, id |-> l[p].id, cred |-> NoCred, b |-> None, token |-> None, gen |-> gen, stale |-> FALSE]

FirstLabel(kind) ==
    CASE kind = "exchange" -> "ex.candidates"
      [] kind = "use"      -> "use.verify"
      [] kind = "revoke"   -> "revoke.head"
      [] kind = "unbind"   -> "unbind.head"
      [] kind = "replace"  -> "replace.plan"
      [] kind = "remove"   -> "remove.lock"
      [] kind = "restore"  -> "restore.lock"

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = [L0 EXCEPT !.id = <<p, left[p]>>]]
         /\ Goto(p, FirstLabel(o.kind))
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<rows, log, locks, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Exchanging an ID token (server api/workloads.ts, #exchange). The token's *)
(* signature, audience, times and claims are checked against the binding   *)
(* it matched, which decides nothing about concurrency: left out.          *)
(***************************************************************************)

\* The account's live bindings on the token's issuer, oldest first, one
\* read and no lock (db/queries.ts, exchangeCandidates): the oldest that
\* matches is taken. With them, here, what the binding issued in the last
\* minute, as the rate would be counted without the head.
ExCandidates(p) ==
    /\ pc[p] = "ex.candidates"
    /\ LET live == {b \in Bindings : Stands(b, gen)}
           b == IF "b1" \in live THEN "b1" ELSE "b2"
       IN IF live = {}
            THEN Refuse(p)
            ELSE Read(p, "ex.spent", [l[p] EXCEPT !.b = b, !.bgen = binding[b].gen,
                                                  !.rate = Cardinality({r \in creds : r.by = b})])

\* Whether the token was spent already: in the code, read in the same statement as the bindings
\* (db/queries.ts, exchangeCandidates); here a step of its own, which allows more interleavings, not fewer.
ExSpent(p) ==
    /\ pc[p] = "ex.spent"
    /\ IF op[p].token \in consumed THEN Refuse(p) ELSE Read(p, "ex.access", l[p])

\* The vault's answer about the account, outside any transaction
\* (vault.access): active, at the binding's generation.
ExAccess(p) ==
    /\ pc[p] = "ex.access"
    /\ IF status = "active" /\ gen = l[p].bgen
         THEN Read(p, "ex.head", [l[p] EXCEPT !.gen = gen])
         ELSE Refuse(p)

ExHead(p) == pc[p] = "ex.head" /\ TakeHead(p, "ex.commit")

\* Under the head: the account and the binding again, the rate, the token
\* spent, the credential issued and `token.exchange` logged, or none of it.
ExCommit(p) ==
    /\ pc[p] = "ex.commit"
    /\ LET b == l[p].b
           rate == IF RateCountUnderHead THEN Cardinality({r \in creds : r.by = b}) ELSE l[p].rate
           new == [id |-> l[p].id, by |-> b, gen |-> l[p].bgen, revoked |-> FALSE]
       IN IF \/ MemberRecheckInExchange /\ ~(status = "active" /\ gen = l[p].gen)
             \/ BindingRecheckUnderHead /\ ~Stands(b, l[p].bgen)
             \/ rate >= RateCap
             \/ SpentTokenInsertedWithCredential /\ op[p].token \in consumed
            THEN Refuse(p)
            ELSE /\ consumed' = consumed \cup {op[p].token}
                 /\ creds' = creds \cup {new}
                 /\ log' = Append(log, [Entry("token.exchange", p) EXCEPT !.cred = l[p].id, !.b = b,
                                                                         !.token = op[p].token, !.gen = l[p].bgen])
                 /\ issued' = issued \cup {[id |-> l[p].id, current |-> status = "active" /\ gen = l[p].bgen]}
                 /\ Release(p)
                 /\ Goto(p, "idle")
                 /\ UNCHANGED <<binding, status, gen, op, l, left, revealed>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Using a credential to read a value (server auth.ts, authenticateRequest; *)
(* api/signin.ts, verify; api/secrets.ts, reveal; vault vault.ts, unwrap   *)
(* and #keys; api/context.ts, recorded). Through the credential proxy the  *)
(* vault appends the app's `credential.use` with its read, and the app     *)
(* commits nothing more, as an export; an older vault's use, or one of     *)
(* plain values only, the app commits itself under the head.               *)
(***************************************************************************)

\* The credential's row, unlocked (findCredential), and for one a binding
\* issued, the binding. A use of "exchanged" comes in on any credential an
\* exchange issued, as a CI run does on its own.
UseVerify(p) ==
    /\ pc[p] = "use.verify"
    /\ LET named == {r \in creds : Named(op[p].cred, r)} IN
       IF named = {}
         THEN Refuse(p)
         ELSE \E r \in named :
                IF ~r.revoked /\ ((BindingCheckedAtUse /\ r.by # "token") => Stands(r.by, r.gen))
                  THEN Read(p, "use.access", [l[p] EXCEPT !.cred = r.id])
                  ELSE Refuse(p)

\* The vault's answer about the account (vault.access), and the
\* generation the credential was issued at (#liveCredential, and again in
\* authenticateRequest). Or an answer kept from an earlier request, the
\* account active then, at any generation it has had: one that verifies
\* the credential.
UseAccess(p) ==
    /\ pc[p] = "use.access"
    /\ \/ IF status = "active" /\ gen = Cred(l[p].cred).gen
            THEN Read(p, "use.lock", [l[p] EXCEPT !.recalled = FALSE])
            ELSE Refuse(p)
       \/ /\ ~l[p].asks
          /\ Cred(l[p].cred).gen <= gen
          /\ Read(p, "use.lock", [l[p] EXCEPT !.recalled = TRUE, !.kept = Cred(l[p].cred).gen])

UseLock(p) == pc[p] = "use.lock" /\ ShareRow(p, "use.head")

UseHead(p) == pc[p] = "use.head" /\ TakeHead(p, "use.decide")

\* Under the row and the head, the vault decides on the account's standing
\* and grants, appends `secret.read` and commits. It is told which
\* credential the request came in on, and only copies it into the entry
\* (vault.ts, traced): its row is the app's, and nothing here reads it.
UseDecide(p) ==
    /\ pc[p] = "use.decide"
    /\ IF KeptAnswerChecked /\ l[p].recalled /\ (status # "active" \/ gen # l[p].kept)
         \* Not the vault's answer now: nothing logged, and the use starts over, asking.
         THEN /\ Release(p)
              /\ Goto(p, "use.verify")
              /\ l' = [l EXCEPT ![p].asks = TRUE]
              /\ UNCHANGED <<rows, log, op, left, history>>
         ELSE IF status # "active"
         THEN Refuse(p)
         \* A release on a kept answer is the model's to see when that answer is not the account's now.
         \* Through the proxy, the vault appends the app's `credential.use` beside its read, in the same step
         \* (vault.ts, unwrap's `use`), and the app checks the credential with no lock, as an export does; or,
         \* a vault older than 0.14.5, a use of plain values only or a record too long for the vault, the app appends
         \* it under the head itself.
         ELSE \E byVault \in (IF op[p].proxy THEN BOOLEAN ELSE {FALSE}) :
              LET read == Append(log, [Entry("secret.read", p) EXCEPT !.cred = l[p].cred, !.stale = l[p].recalled /\ gen # l[p].kept])
              IN /\ log' = IF byVault THEN Append(read, [Entry("credential.use", p) EXCEPT !.cred = l[p].cred]) ELSE read
                 /\ l' = [l EXCEPT ![p].at = Len(log) + 1]
                 /\ Release(p)
                 /\ Goto(p, IF op[p].proxy /\ ~byVault THEN "use.apphead" ELSE "use.fence")
                 /\ UNCHANGED <<rows, op, left, history>>

\* Through the proxy, its use not logged by the vault: the app's own
\* transaction, under the head, appends `credential.use`, after the fence.
UseAppHead(p) == pc[p] = "use.apphead" /\ TakeHead(p, "use.commit")

UseCommit(p) ==
    /\ pc[p] = "use.commit"
    /\ IF CredentialFenceUnderHead /\ ~StillLive(Cred(l[p].cred))
         THEN Refuse(p)
         ELSE /\ log' = Append(log, [Entry("credential.use", p) EXCEPT !.cred = l[p].cred])
              /\ Release(p)
              /\ Goto(p, "use.answer")
              /\ UNCHANGED <<rows, op, l, left, history>>

\* An export: nothing more to commit, the fence read alone, unlocked: a
\* revocation committed before it is seen, and one after came after the
\* release.
UseFence(p) ==
    /\ pc[p] = "use.fence"
    /\ IF CredentialFenceUnlocked /\ ~StillLive(Cred(l[p].cred))
         THEN Refuse(p)
         ELSE Read(p, "use.answer", l[p])

\* The value reaches the caller.
UseAnswer(p) ==
    /\ pc[p] = "use.answer"
    /\ revealed' = revealed \cup {[id |-> l[p].id, cred |-> l[p].cred, at |-> l[p].at]}
    /\ Goto(p, "idle")
    /\ UNCHANGED <<rows, log, locks, op, l, left, issued>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Ending credentials.                                                     *)
(***************************************************************************)

\* Revoking one credential (signin.ts, revokeCredential): under the head,
\* its row, then revoked_at and `token.revoke`. Of "exchanged": any one an
\* exchange issued, as found then.
RevokeHead(p) == pc[p] = "revoke.head" /\ TakeHead(p, "revoke.commit")

RevokeCommit(p) ==
    /\ pc[p] = "revoke.commit"
    /\ IF ~\E r \in creds : ~r.revoked /\ Named(op[p].cred, r)
         THEN Refuse(p)
         ELSE \E r \in creds :
                /\ ~r.revoked /\ Named(op[p].cred, r)
                /\ creds' = (creds \ {r}) \cup {[r EXCEPT !.revoked = TRUE]}
                /\ log' = Append(log, [Entry("token.revoke", p) EXCEPT !.cred = r.id])
                /\ Release(p)
                /\ Goto(p, "idle")
                /\ UNCHANGED <<binding, consumed, status, gen, op, l, left, history>>

\* Untrusting a binding (workloads.ts, unbind): under the head, it must
\* still be live; it is revoked with what it issued (#revoke), and
\* `token.unbind` logged.
UnbindHead(p) == pc[p] = "unbind.head" /\ TakeHead(p, "unbind.commit")

UnbindCommit(p) ==
    /\ pc[p] = "unbind.commit"
    /\ LET b == op[p].at IN
       IF ~(binding[b].made /\ ~binding[b].revoked)
         THEN Refuse(p)
         ELSE /\ binding' = [binding EXCEPT ![b].revoked = TRUE]
              /\ creds' = IF RevokeIssuedCredentials THEN RevokeBy(b) ELSE creds
              /\ log' = Append(log, [Entry("token.unbind", p) EXCEPT !.b = b])
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<consumed, status, gen, op, l, left, history>>

\* Replacing the issuer's keys (workloads.ts, replaceKeys): the live
\* bindings listed before the head, the same found under it or 409, then a
\* new binding for each, at its generation, and the old one revoked as an
\* untrust revokes it.
ReplacePlan(p) ==
    /\ pc[p] = "replace.plan"
    /\ Read(p, "replace.head", [l[p] EXCEPT !.plan = {b \in Bindings : binding[b].made /\ ~binding[b].revoked}])

ReplaceHead(p) == pc[p] = "replace.head" /\ TakeHead(p, "replace.commit")

ReplaceCommit(p) ==
    /\ pc[p] = "replace.commit"
    /\ IF {b \in Bindings : binding[b].made /\ ~binding[b].revoked} # l[p].plan \/ l[p].plan # {"b1"}
         THEN Refuse(p)
         ELSE /\ binding' = [binding EXCEPT !["b1"].revoked = TRUE,
                                            !["b2"] = [made |-> TRUE, revoked |-> FALSE, gen |-> binding["b1"].gen]]
              /\ creds' = IF RevokeIssuedCredentials THEN RevokeBy("b1") ELSE creds
              /\ log' = log \o <<[Entry("token.unbind", p) EXCEPT !.b = "b1"], [Entry("token.bind", p) EXCEPT !.b = "b2"]>>
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<consumed, status, gen, op, l, left, history>>

\* Removing the account (vault vault.ts, remove; server api/members.ts,
\* removeMember): the vault, under its row and the head, moves its
\* generation on and logs `member.remove`; then the app, in a transaction
\* of its own, revokes the credentials below that generation.
RemoveLock(p) == pc[p] = "remove.lock" /\ TakeRow(p, "remove.head")

RemoveHead(p) == pc[p] = "remove.head" /\ TakeHead(p, "remove.commit")

RemoveCommit(p) ==
    /\ pc[p] = "remove.commit"
    /\ IF status # "active"
         THEN Refuse(p)
         ELSE /\ status' = "removed"
              /\ gen' = gen + 1
              /\ log' = Append(log, [Entry("member.remove", p) EXCEPT !.gen = gen + 1])
              /\ Release(p)
              /\ Goto(p, "remove.sweephead")
              /\ UNCHANGED <<binding, creds, consumed, op, l, left, history>>

RemoveSweepHead(p) == pc[p] = "remove.sweephead" /\ TakeHead(p, "remove.sweep")

RemoveSweep(p) ==
    /\ pc[p] = "remove.sweep"
    /\ creds' = {IF r.gen < gen THEN [r EXCEPT !.revoked = TRUE] ELSE r : r \in creds}
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<binding, consumed, status, gen, log, op, l, left, history>>

\* Admitting it again (vault.ts, setAccess with admit): under its row and
\* the head, active, at the generation the removal moved on to.
RestoreLock(p) == pc[p] = "restore.lock" /\ TakeRow(p, "restore.head")

RestoreHead(p) == pc[p] = "restore.head" /\ TakeHead(p, "restore.commit")

RestoreCommit(p) ==
    /\ pc[p] = "restore.commit"
    /\ IF status # "removed"
         THEN Refuse(p)
         ELSE /\ status' = "active"
              /\ log' = Append(log, Entry("member.restore", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<binding, creds, consumed, gen, op, l, left, history>>

-----------------------------------------------------------------------------

Init ==
    /\ binding = [b \in Bindings |-> [made |-> b = "b1", revoked |-> FALSE, gen |-> 0]]
    /\ creds = {[id |-> Tok, by |-> "token", gen |-> 0, revoked |-> FALSE]}
    /\ consumed = {}
    /\ status = "active"
    /\ gen = 0
    /\ log = <<>>
    /\ rowLock = None
    /\ rowShared = {}
    /\ head = None
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ issued = {}
    /\ revealed = {}

Step(p) ==
    \/ Begin(p)
    \/ ExCandidates(p) \/ ExSpent(p) \/ ExAccess(p) \/ ExHead(p) \/ ExCommit(p)
    \/ UseVerify(p) \/ UseAccess(p) \/ UseLock(p) \/ UseHead(p) \/ UseDecide(p)
    \/ UseAppHead(p) \/ UseCommit(p) \/ UseFence(p) \/ UseAnswer(p)
    \/ RevokeHead(p) \/ RevokeCommit(p)
    \/ UnbindHead(p) \/ UnbindCommit(p)
    \/ ReplacePlan(p) \/ ReplaceHead(p) \/ ReplaceCommit(p)
    \/ RemoveLock(p) \/ RemoveHead(p) \/ RemoveCommit(p) \/ RemoveSweepHead(p) \/ RemoveSweep(p)
    \/ RestoreLock(p) \/ RestoreHead(p) \/ RestoreCommit(p)

Finished == \A p \in Procs : pc[p] = "idle" /\ left[p] = 0

Next == (\E p \in Procs : Step(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* What must hold in every state.                                          *)
(***************************************************************************)

TypeOK ==
    /\ status \in {"active", "removed"}
    /\ consumed \subseteq IdTokens
    /\ rowLock \in Procs \cup {None}
    /\ rowShared \subseteq Procs
    /\ rowLock # None => rowShared \subseteq {rowLock}
    /\ head \in Procs \cup {None}

\* An ID token buys one credential, however many runs present it at once.
SingleUse ==
    \A t \in IdTokens : Cardinality({i \in 1..Len(log) : log[i].kind = "token.exchange" /\ log[i].token = t}) <= 1

\* No exchange through a binding follows its `token.unbind` in the log.
NoExchangeAfterUnbind ==
    \A i, j \in 1..Len(log) :
        (i < j /\ log[i].kind = "token.unbind" /\ log[j].kind = "token.exchange") => log[i].b # log[j].b

\* An exchange issues to an active account, at its generation as it is
\* when the credential commits.
ExchangedAtCurrentGeneration == \A c \in issued : c.current

\* A binding issues no more than its rate.
RateHeld == \A b \in Bindings : Cardinality({r \in creds : r.by = b}) <= RateCap

\* Whether the entry at i ends credential r: its `token.revoke`, its
\* binding's `token.unbind`, or a removal moving the account past its
\* generation.
Ends(e, r) ==
    \/ e.kind = "token.revoke" /\ e.cred = r.id
    \/ e.kind = "token.unbind" /\ e.b = r.by
    \/ e.kind = "member.remove" /\ e.gen > r.gen

\* No value reaches a caller through a credential whose release, the
\* vault's `secret.read`, follows the entry that ended it in the log.
NoReleaseAfterEnd ==
    \A u \in revealed : \A i \in 1..(u.at - 1) : ~Ends(log[i], Cred(u.cred))

\* No `secret.read` is logged on an answer kept from an earlier request that
\* is no longer the vault's: such a use starts over, asking.
NoReadOnStaleAnswer == \A i \in 1..Len(log) : ~log[i].stale

\* A credential an untrusted or replaced binding issued never verifies again.
UnboundStayUnusable ==
    \A r \in creds : (r.by # "token" /\ binding[r.by].revoked) => ~Verifies(r)

=============================================================================
