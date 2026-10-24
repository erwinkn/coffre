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
(* in principal order, which a vault decision takes first, and the log's   *)
(* head, which every app transaction takes first.                          *)
(*                                                                         *)
(* Olga is an Owner of the project, and so is Omar, who may demote her.    *)
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
    \* them, read after the newest entry about their access, and committed
    \* only while that entry is still the newest, under the head (server
    \* api/services.ts, freshIssuer and issuerStill).
    IssuerFence,
    \* Issuing reads the service account's standing again under the head
    \* (server api/signin.ts, issueServiceToken, #stillMember).
    ServiceRecheckInIssue,
    \* A seal updates the row only as it read it, unsealed (server
    \* api/services.ts, sealCredentials, updateAuth's match on its scope).
    SealCompareAndSet

None == "none"
People == {"olga", "omar"}
Members == People \cup {"svc"}
\* Lock order: `ORDER BY principal`.
Rank == [m \in Members |-> CASE m = "olga" -> 1 [] m = "omar" -> 2 [] m = "svc" -> 3]

VARIABLES
    \* vault rows
    owners,         \* the people who are Owners of the project
    svcStatus,      \* the service account's status
    svcGen,         \* and generation
    \* app rows
    legacy,         \* the older release's token: "unsealed", or sealed, reading sensitive values or not
    \* both
    log,            \* the audit log, in seq order
    \* locks
    rowLock,        \* rowLock[m]: the process holding m's row, or None
    head,           \* the process holding the log's head, or None
    \* processes
    pc, op, l, left,
    \* history, for the invariants
    given           \* a record per scope committed: whether it reads sensitive values, and whether its issuer is an Owner then

rows == <<owners, svcStatus, svcGen, legacy>>
locks == <<rowLock, head>>
procs == <<pc, op, l, left>>
vars == <<rows, log, locks, procs, given>>

-----------------------------------------------------------------------------
(* Access entries *)

\* The vault's entries that change someone's access: their role, grants or
\* membership (core vault.ts, ACCESS_ACTIONS).
AccessKinds == {"member.role", "access.revoke", "access.grant", "member.remove"}

\* The newest entry about m's access, by its place in the log; 0 for none
\* (server db/queries.ts, newestAccessSeq).
NewestAbout(m) ==
    LET about == {i \in 1..Len(log) : log[i].kind \in AccessKinds /\ log[i].who = m} IN
    IF about = {} THEN 0 ELSE CHOOSE i \in about : \A j \in about : j <= i

\* Whether the vault answers that m is an Owner of the project
\* (core access.ts, ownsProject).
Owns(m) == m \in owners

-----------------------------------------------------------------------------
(* Processes *)

NoOp == [kind |-> "none", actor |-> None, who |-> None]

L0 == [id |-> <<None, 0>>,
       seq |-> 0,             \* the newest entry about the issuer's access, as read before the vault was asked
       owner |-> FALSE,       \* whether the vault answered that the issuer is an Owner
       gen |-> 0,             \* the service account's generation, as the vault answered
       sealed |-> FALSE,      \* whether the seal read the row sealed already
       toLock |-> <<>>]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Release(p) ==
    /\ rowLock' = [m \in Members |-> IF rowLock[m] = p THEN None ELSE rowLock[m]]
    /\ head' = IF head = p THEN None ELSE head

Sorted(S) == [i \in 1..Cardinality(S) |-> CHOOSE m \in S : Cardinality({n \in S : Rank[n] < Rank[m]}) = i - 1]

LockNext(p, then) ==
    LET m == Head(l[p].toLock) IN
    /\ rowLock[m] \in {None, p}
    /\ rowLock' = [rowLock EXCEPT ![m] = p]
    /\ l' = [l EXCEPT ![p].toLock = Tail(@)]
    /\ Goto(p, IF Tail(l[p].toLock) = <<>> THEN then ELSE pc[p])
    /\ UNCHANGED <<rows, log, head, op, left, given>>

TakeHead(p, then) ==
    /\ head \in {None, p}
    /\ head' = p
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
    CASE kind = "issue"  -> "issue.load"
      [] kind = "seal"   -> "seal.read"
      [] kind = "demote" -> "demote.lock"
      [] kind = "remove" -> "remove.lock"

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = [L0 EXCEPT !.id = <<p, left[p]>>,
                                             !.toLock = CASE o.kind = "demote" -> Sorted({o.actor, o.who})
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

\* The newest entry about the issuer's access, before the vault is asked.
IssueLoad(p) ==
    /\ pc[p] = "issue.load"
    /\ Read(p, "issue.access", [l[p] EXCEPT !.seq = NewestAbout(op[p].actor)])

\* The vault's answers, outside any transaction: whether the issuer is an
\* Owner of the project, which is whether the scope reads its sensitive
\* values; and the account's standing (managedAccount).
IssueAccess(p) ==
    /\ pc[p] = "issue.access"
    /\ IF svcStatus = "active"
         THEN Read(p, "issue.head", [l[p] EXCEPT !.owner = Owns(op[p].actor), !.gen = svcGen])
         ELSE Refuse(p)

IssueHead(p) == pc[p] = "issue.head" /\ TakeHead(p, "issue.commit")

\* Under the head: the account again, the issuer's newest access entry
\* again, then the token and `token.create`.
IssueCommit(p) ==
    /\ pc[p] = "issue.commit"
    /\ IF \/ ServiceRecheckInIssue /\ ~(svcStatus = "active" /\ svcGen = l[p].gen)
          \/ IssuerFence /\ NewestAbout(op[p].actor) # l[p].seq
         THEN Refuse(p)
         ELSE /\ log' = Append(log, [Entry("token.create", p) EXCEPT !.who = op[p].actor, !.sensitive = l[p].owner])
              /\ given' = given \cup {[id |-> l[p].id, sensitive |-> l[p].owner, owner |-> Owns(op[p].actor),
                                       current |-> svcStatus = "active" /\ svcGen = l[p].gen]}
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<rows, op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Sealing the older release's token at its first use (server             *)
(* api/services.ts, sealScopes and sealCredentials; api/signin.ts, verify). *)
(***************************************************************************)

\* The row, unsealed, and the newest entry about its issuer's access.
SealRead(p) ==
    /\ pc[p] = "seal.read"
    /\ IF legacy # "unsealed"
         THEN Refuse(p)
         ELSE Read(p, "seal.access", [l[p] EXCEPT !.seq = NewestAbout(op[p].who)])

\* The vault's answer about the issuer, outside any transaction.
SealAccess(p) ==
    /\ pc[p] = "seal.access"
    /\ Read(p, "seal.head", [l[p] EXCEPT !.owner = Owns(op[p].who)])

SealHead(p) == pc[p] = "seal.head" /\ TakeHead(p, "seal.commit")

\* Under the head: the issuer's newest access entry again, then the row,
\* only if it is still as read, and `token.seal`. One sealed meanwhile is
\* left as it is, and logs nothing.
SealCommit(p) ==
    /\ pc[p] = "seal.commit"
    /\ IF IssuerFence /\ NewestAbout(op[p].who) # l[p].seq
         THEN Refuse(p)
         ELSE IF SealCompareAndSet /\ legacy # "unsealed"
           THEN Refuse(p)
           ELSE /\ legacy' = IF l[p].owner THEN "sensitive" ELSE "secret"
                /\ log' = Append(log, [Entry("token.seal", p) EXCEPT !.sensitive = l[p].owner])
                /\ given' = given \cup {[id |-> l[p].id, sensitive |-> l[p].owner, owner |-> Owns(op[p].who), current |-> TRUE]}
                /\ Release(p)
                /\ Goto(p, "idle")
                /\ UNCHANGED <<owners, svcStatus, svcGen, op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Changing access, in the vault (vault vault.ts, setAccess and remove).   *)
(***************************************************************************)

\* Demoting an Owner of the project: the actor's row and theirs, in
\* principal order, then the head, then `member.role` about them.
DemoteLock(p) == pc[p] = "demote.lock" /\ LockNext(p, "demote.head")

DemoteHead(p) == pc[p] = "demote.head" /\ TakeHead(p, "demote.commit")

DemoteCommit(p) ==
    /\ pc[p] = "demote.commit"
    /\ IF ~(Owns(op[p].actor) /\ Owns(op[p].who))
         THEN Refuse(p)
         ELSE /\ owners' = owners \ {op[p].who}
              /\ log' = Append(log, Entry("member.role", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<svcStatus, svcGen, legacy, op, l, left, given>>

\* Removing the service account: its row, the head, its generation on.
RemoveLock(p) == pc[p] = "remove.lock" /\ LockNext(p, "remove.head")

RemoveHead(p) == pc[p] = "remove.head" /\ TakeHead(p, "remove.commit")

RemoveCommit(p) ==
    /\ pc[p] = "remove.commit"
    /\ IF svcStatus # "active"
         THEN Refuse(p)
         ELSE /\ svcStatus' = "removed"
              /\ svcGen' = svcGen + 1
              /\ log' = Append(log, Entry("member.remove", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<owners, legacy, op, l, left, given>>

-----------------------------------------------------------------------------

Init ==
    /\ owners = People
    /\ svcStatus = "active"
    /\ svcGen = 0
    /\ legacy = "unsealed"
    /\ log = <<>>
    /\ rowLock = [m \in Members |-> None]
    /\ head = None
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ given = {}

Step(p) ==
    \/ Begin(p)
    \/ IssueLoad(p) \/ IssueAccess(p) \/ IssueHead(p) \/ IssueCommit(p)
    \/ SealRead(p) \/ SealAccess(p) \/ SealHead(p) \/ SealCommit(p)
    \/ DemoteLock(p) \/ DemoteHead(p) \/ DemoteCommit(p)
    \/ RemoveLock(p) \/ RemoveHead(p) \/ RemoveCommit(p)

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
    /\ head \in Procs \cup {None}

\* A scope reads the project's sensitive values only if whoever issued it
\* is an Owner of the project when it commits: a person demoted before
\* never hands a service account what they could no longer give it (R32).
SensitiveOnlyFromOwners == \A g \in given : g.sensitive => g.owner

\* The older release's token is sealed once, however many first uses race.
SealedOnce == Cardinality({i \in 1..Len(log) : log[i].kind = "token.seal"}) <= 1

\* A token is issued to an active account, at its generation as it is when
\* the token commits.
TokensAtCurrentGeneration == \A g \in given : g.current

=============================================================================
