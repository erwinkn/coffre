------------------------------- MODULE Issuing -------------------------------
(***************************************************************************)
(* Who may hand a service account sensitive values (R32): only an Owner of *)
(* the project, on a token or binding they issue, or one an older release  *)
(* made, sealed at its first use with whether whoever issued it is an      *)
(* Owner of it now. docs/formal.md says what this covers, what it          *)
(* abstracts and what it does not prove.                                   *)
(*                                                                         *)
(* One step is one SQL statement, or a run of statements nothing else can  *)
(* interleave with because the step holds the lock they need, as in        *)
(* Coffre.tla. Isolation is READ COMMITTED. The locks are members' rows,   *)
(* in principal order, which a vault decision takes first, and the change  *)
(* lock (Coffre.tla; before 0.16 the log's head), which every app          *)
(* transaction that changes something takes first.                         *)
(*                                                                         *)
(* Olga is an Owner of the project, and so is Omar, who may demote her    *)
(* and promote her back, or remove her and admit her again, an Owner       *)
(* again, at a new generation.                                             *)
(* The service account "svc" holds a grant there. A token an older release *)
(* issued it, by Olga, is not sealed yet: whether it reads the sensitive   *)
(* values there is decided at its first use.                               *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Procs,          \* concurrent requests, each one a process
    Ops,            \* Ops[p]: the operations process p may run
    Budget          \* Budget[p]: how many it runs, one after another

CONSTANTS
    \* What decides a credential's sensitive reads, the issuer's standing as
    \* an Owner of the project, is weighed from the vault's answer about
    \* them, and committed only while their row's seal is still the one that
    \* answer carries, under the change lock (server api/services.ts,
    \* issuerNow and issuerStill): issuing a token, and sealing one
    \* (sealCredentials).
    IssuerFence,
    SealIssuerFence,
    \* The seal held to is the one the vault checked against the object it
    \* answered from (vault vault.ts, #read, Access.seal), not one the app
    \* read before it asked: a seal is the member's state, which a demotion
    \* and a promotion put back as it was.
    IssuerSealFromAnswer,
    \* Issuing reads the service account's standing again under the change lock
    \* (server api/signin.ts, issueServiceToken, #stillMember).
    ServiceRecheckInIssue,
    \* A seal updates the row only as it read it, unsealed (server
    \* api/services.ts, sealCredentials, updateAuth's match on its scope).
    SealCompareAndSet,
    \* The vault's answer about the issuer counts only at the generation the
    \* request came in at (services.ts, issuerNow, `generation`).
    IssuerGenerationKept,
    \* And under the change lock, the request's credential and its member still
    \* stand, at that generation (server api/context.ts, credentialStill).
    IssuerStandsUnderChangeLock

None == "none"
People == {"olga", "omar"}
Members == People \cup {"svc"}
\* Lock order: `ORDER BY principal`.
Rank == [m \in Members |-> CASE m = "olga" -> 1 [] m = "omar" -> 2 [] m = "svc" -> 3]

VARIABLES
    \* vault rows
    owners,         \* the people who are Owners of the project
    olgaStatus,     \* Olga's membership: "active" or "removed"
    olgaGen,        \* and its generation
    svcStatus,      \* the service account's status
    svcGen,         \* and generation
    \* app rows
    legacy,         \* the older release's token: "unsealed", or sealed, reading sensitive values or not
    \* both
    log,            \* the audit log, in seq order
    \* locks
    rowLock,        \* rowLock[m]: the process holding m's row, or None
    changeLock,           \* the process holding the change lock, or None
    \* processes
    pc, op, l, left,
    \* history, for the invariants
    given           \* a record per scope committed: whether it reads sensitive values, and whether its issuer is an Owner then

rows == <<owners, olgaStatus, olgaGen, svcStatus, svcGen, legacy>>
locks == <<rowLock, changeLock>>
procs == <<pc, op, l, left>>
vars == <<rows, log, locks, procs, given>>

-----------------------------------------------------------------------------
(* Seals *)

\* m's seal (principals.seal): the vault's MAC over their object, so one
\* value per state of it, whether an Owner, their status and generation,
\* the same again once a change is undone.
Seal(m) == <<m \in owners, IF m = "olga" THEN olgaStatus ELSE "active", IF m = "olga" THEN olgaGen ELSE 0>>

\* Whether the vault answers that m is an Owner of the project
\* (core access.ts, ownsProject): only while a member.
Owns(m) == m \in owners /\ (m = "olga" => olgaStatus = "active")

\* Olga, as the request she issues on came in: active, at that generation.
AsAuthenticated(gen) == olgaStatus = "active" /\ olgaGen = gen

-----------------------------------------------------------------------------
(* Processes *)

NoOp == [kind |-> "none", actor |-> None, who |-> None]

L0 == [id |-> <<None, 0>>,
       seal |-> <<>>,         \* the issuer's seal, held to under the change lock
       owner |-> FALSE,       \* whether the vault answered that the issuer is an Owner
       gen |-> 0,             \* the service account's generation, as the vault answered
       auth |-> 0,            \* the issuer's generation, as the request authenticated
       sealed |-> FALSE,      \* whether the seal read the row sealed already
       toLock |-> <<>>]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Release(p) ==
    /\ rowLock' = [m \in Members |-> IF rowLock[m] = p THEN None ELSE rowLock[m]]
    /\ changeLock' = IF changeLock = p THEN None ELSE changeLock

Sorted(S) == [i \in 1..Cardinality(S) |-> CHOOSE m \in S : Cardinality({n \in S : Rank[n] < Rank[m]}) = i - 1]

LockNext(p, then) ==
    LET m == Head(l[p].toLock) IN
    /\ rowLock[m] \in {None, p}
    /\ rowLock' = [rowLock EXCEPT ![m] = p]
    /\ l' = [l EXCEPT ![p].toLock = Tail(@)]
    /\ Goto(p, IF Tail(l[p].toLock) = <<>> THEN then ELSE pc[p])
    /\ UNCHANGED <<rows, log, changeLock, op, left, given>>

TakeChangeLock(p, then) ==
    /\ changeLock \in {None, p}
    /\ changeLock' = p
    /\ Goto(p, then)
    /\ UNCHANGED <<rows, log, rowLock, op, l, left, given>>

Read(p, then, locals) ==
    /\ Goto(p, then)
    /\ l' = [l EXCEPT ![p] = locals]
    /\ UNCHANGED <<rows, log, locks, op, left, given>>

Refuse(p) ==
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<rows, log, op, l, left, given>>

Entry(kind, p) == [kind |-> kind, id |-> l[p].id, who |-> op[p].who, sensitive |-> FALSE]

FirstLabel(kind) ==
    CASE kind = "issue"  -> "issue.auth"
      [] kind = "seal"   -> "seal.read"
      [] kind = "demote" -> "demote.lock"
      [] kind = "promote" -> "promote.lock"
      [] kind = "remove" -> "remove.lock"
      [] kind = "readmit" -> "readmit.lock"

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = [L0 EXCEPT !.id = <<p, left[p]>>,
                                             !.toLock = CASE o.kind \in {"demote", "promote", "readmit"} -> Sorted({o.actor, o.who})
                                                           [] o.kind = "remove" -> <<o.who>>
                                                           [] OTHER -> <<>>]]
         /\ Goto(p, FirstLabel(o.kind))
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<rows, log, locks, given>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Issuing a service token (server api/signin.ts, issueServiceToken and    *)
(* #tokenScope; api/services.ts, managedAccount and issuedScope). A trust  *)
(* binding is issued the same way (api/workloads.ts, bind and replaceKeys), *)
(* so only the token is modelled.                                          *)
(***************************************************************************)

\* The request comes in: its credential checked, Olga at her generation
\* then (server auth.ts, authenticateRequest).
IssueAuth(p) ==
    /\ pc[p] = "issue.auth"
    /\ IF olgaStatus = "active"
         THEN Read(p, IF IssuerSealFromAnswer THEN "issue.access" ELSE "issue.load", [l[p] EXCEPT !.auth = olgaGen])
         ELSE Refuse(p)

\* Without IssuerSealFromAnswer: the issuer's seal, read before the vault is asked.
IssueLoad(p) ==
    /\ pc[p] = "issue.load"
    /\ Read(p, "issue.access", [l[p] EXCEPT !.seal = Seal(op[p].actor)])

\* The vault's answers, outside any transaction: whether the issuer is an
\* Owner of the project, which is whether the scope reads its sensitive
\* values, with the seal it checked; and the account's standing
\* (managedAccount).
IssueAccess(p) ==
    /\ pc[p] = "issue.access"
    /\ IF svcStatus = "active" /\ (IssuerGenerationKept => AsAuthenticated(l[p].auth))
         THEN Read(p, "issue.changelock", [l[p] EXCEPT !.owner = Owns(op[p].actor), !.gen = svcGen,
                                                       !.seal = IF IssuerSealFromAnswer THEN Seal(op[p].actor) ELSE @])
         ELSE Refuse(p)

IssueChangeLock(p) == pc[p] = "issue.changelock" /\ TakeChangeLock(p, "issue.commit")

\* Under the change lock: the account again, the issuer's seal again, then
\* the token and `token.create`.
IssueCommit(p) ==
    /\ pc[p] = "issue.commit"
    /\ IF \/ ServiceRecheckInIssue /\ ~(svcStatus = "active" /\ svcGen = l[p].gen)
          \/ IssuerFence /\ Seal(op[p].actor) # l[p].seal
          \/ IssuerStandsUnderChangeLock /\ ~AsAuthenticated(l[p].auth)
         THEN Refuse(p)
         ELSE /\ log' = Append(log, [Entry("token.create", p) EXCEPT !.who = op[p].actor, !.sensitive = l[p].owner])
              /\ given' = given \cup {[id |-> l[p].id, sensitive |-> l[p].owner, owner |-> Owns(op[p].actor),
                                       current |-> svcStatus = "active" /\ svcGen = l[p].gen,
                                       authenticated |-> AsAuthenticated(l[p].auth)]}
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<rows, op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Sealing the older release's token at its first use (server             *)
(* api/services.ts, sealScopes and sealCredentials; api/signin.ts, verify). *)
(***************************************************************************)

\* The row, unsealed; without IssuerSealFromAnswer, its issuer's seal too.
SealRead(p) ==
    /\ pc[p] = "seal.read"
    /\ IF legacy # "unsealed"
         THEN Refuse(p)
         ELSE Read(p, "seal.access", [l[p] EXCEPT !.seal = IF IssuerSealFromAnswer THEN @ ELSE Seal(op[p].who)])

\* The vault's answer about the issuer, with the seal it checked, outside
\* any transaction.
SealAccess(p) ==
    /\ pc[p] = "seal.access"
    /\ Read(p, "seal.changelock", [l[p] EXCEPT !.owner = Owns(op[p].who), !.seal = IF IssuerSealFromAnswer THEN Seal(op[p].who) ELSE @])

SealChangeLock(p) == pc[p] = "seal.changelock" /\ TakeChangeLock(p, "seal.commit")

\* Under the change lock: the issuer's seal again, then the row,
\* only if it is still as read, and `token.seal`. One sealed meanwhile is
\* left as it is, and logs nothing.
SealCommit(p) ==
    /\ pc[p] = "seal.commit"
    /\ IF SealIssuerFence /\ Seal(op[p].who) # l[p].seal
         THEN Refuse(p)
         ELSE IF SealCompareAndSet /\ legacy # "unsealed"
           THEN Refuse(p)
           ELSE /\ legacy' = IF l[p].owner THEN "sensitive" ELSE "secret"
                /\ log' = Append(log, [Entry("token.seal", p) EXCEPT !.sensitive = l[p].owner])
                /\ given' = given \cup {[id |-> l[p].id, sensitive |-> l[p].owner, owner |-> Owns(op[p].who), current |-> TRUE,
                                         authenticated |-> TRUE]}
                /\ Release(p)
                /\ Goto(p, "idle")
                /\ UNCHANGED <<owners, olgaStatus, olgaGen, svcStatus, svcGen, op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Changing access, in the vault (vault vault.ts, setAccess and remove).   *)
(***************************************************************************)

\* Demoting an Owner of the project: the actor's row and theirs, in
\* principal order, then the change lock, then `member.role` about them.
DemoteLock(p) == pc[p] = "demote.lock" /\ LockNext(p, "demote.changelock")

DemoteChangeLock(p) == pc[p] = "demote.changelock" /\ TakeChangeLock(p, "demote.commit")

DemoteCommit(p) ==
    /\ pc[p] = "demote.commit"
    /\ IF ~(Owns(op[p].actor) /\ Owns(op[p].who))
         THEN Refuse(p)
         ELSE /\ owners' = owners \ {op[p].who}
              /\ log' = Append(log, Entry("member.role", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<olgaStatus, olgaGen, svcStatus, svcGen, legacy, op, l, left, given>>

\* Promoting her back, the same way: `member.role` about her, an Owner again.
PromoteLock(p) == pc[p] = "promote.lock" /\ LockNext(p, "promote.changelock")

PromoteChangeLock(p) == pc[p] = "promote.changelock" /\ TakeChangeLock(p, "promote.commit")

PromoteCommit(p) ==
    /\ pc[p] = "promote.commit"
    /\ IF ~(Owns(op[p].actor) /\ op[p].who \notin owners /\ olgaStatus = "active")
         THEN Refuse(p)
         ELSE /\ owners' = owners \cup {op[p].who}
              /\ log' = Append(log, Entry("member.role", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<olgaStatus, olgaGen, svcStatus, svcGen, legacy, op, l, left, given>>

\* Removing the service account: its row, the change lock, its generation on.
RemoveLock(p) == pc[p] = "remove.lock" /\ LockNext(p, "remove.changelock")

RemoveChangeLock(p) == pc[p] = "remove.changelock" /\ TakeChangeLock(p, "remove.commit")

RemoveCommit(p) ==
    /\ pc[p] = "remove.commit"
    /\ IF svcStatus # "active"
         THEN Refuse(p)
         ELSE /\ svcStatus' = "removed"
              /\ svcGen' = svcGen + 1
              /\ log' = Append(log, Entry("member.remove", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<owners, olgaStatus, olgaGen, legacy, op, l, left, given>>

\* Removing Olga and admitting her again, an Owner again: her row and the
\* actor's, the change lock, her generation on, `member.remove` and
\* `member.add`. One decision here, two in the code: nothing in between decides
\* more.
ReadmitLock(p) == pc[p] = "readmit.lock" /\ LockNext(p, "readmit.changelock")

ReadmitChangeLock(p) == pc[p] = "readmit.changelock" /\ TakeChangeLock(p, "readmit.commit")

ReadmitCommit(p) ==
    /\ pc[p] = "readmit.commit"
    /\ IF olgaStatus # "active"
         THEN Refuse(p)
         ELSE /\ olgaGen' = olgaGen + 1
              /\ owners' = owners \cup {"olga"}
              /\ log' = log \o <<Entry("member.remove", p), Entry("member.add", p)>>
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<olgaStatus, svcStatus, svcGen, legacy, op, l, left, given>>

-----------------------------------------------------------------------------

Init ==
    /\ owners = People
    /\ olgaStatus = "active"
    /\ olgaGen = 0
    /\ svcStatus = "active"
    /\ svcGen = 0
    /\ legacy = "unsealed"
    /\ log = <<>>
    /\ rowLock = [m \in Members |-> None]
    /\ changeLock = None
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ given = {}

Step(p) ==
    \/ Begin(p)
    \/ IssueAuth(p) \/ IssueLoad(p) \/ IssueAccess(p) \/ IssueChangeLock(p) \/ IssueCommit(p)
    \/ SealRead(p) \/ SealAccess(p) \/ SealChangeLock(p) \/ SealCommit(p)
    \/ DemoteLock(p) \/ DemoteChangeLock(p) \/ DemoteCommit(p)
    \/ PromoteLock(p) \/ PromoteChangeLock(p) \/ PromoteCommit(p)
    \/ RemoveLock(p) \/ RemoveChangeLock(p) \/ RemoveCommit(p)
    \/ ReadmitLock(p) \/ ReadmitChangeLock(p) \/ ReadmitCommit(p)

Finished == \A p \in Procs : pc[p] = "idle" /\ left[p] = 0

Next == (\E p \in Procs : Step(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* What must hold in every state.                                          *)
(***************************************************************************)

TypeOK ==
    /\ owners \subseteq People
    /\ legacy \in {"unsealed", "sensitive", "secret"}
    /\ rowLock \in [Members -> Procs \cup {None}]
    /\ changeLock \in Procs \cup {None}

\* A scope reads the project's sensitive values only if whoever issued it
\* is an Owner of the project when it commits: a person demoted before
\* never hands a service account what they could no longer give it (R32).
SensitiveOnlyFromOwners == \A g \in given : g.sensitive => g.owner

\* The older release's token is sealed once, however many first uses race.
SealedOnce == Cardinality({i \in 1..Len(log) : log[i].kind = "token.seal"}) <= 1

\* A token is issued to an active account, at its generation as it is when
\* the token commits.
TokensAtCurrentGeneration == \A g \in given : g.current

\* And by the membership its request came in as: removed and admitted
\* again, the issuer holds what that request's credential never did.
IssuedAsAuthenticated == \A g \in given : g.authenticated

=============================================================================
