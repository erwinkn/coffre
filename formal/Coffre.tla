------------------------------- MODULE Coffre -------------------------------
(***************************************************************************)
(* coffre's concurrency core: the app and the vault on one database, the   *)
(* locks they take, and the order they take them in. docs/formal.md says   *)
(* what this covers, what it abstracts and what it does not prove.         *)
(*                                                                         *)
(* One step is one SQL statement, or a run of statements nothing else can  *)
(* interleave with because the step holds the lock they need. Isolation is *)
(* READ COMMITTED, Postgres's default (single-database.md, question 2): a  *)
(* statement reads what was committed when it ran, and a transaction's     *)
(* writes become visible at its commit, which is one step with its last    *)
(* statement. Locks are row locks, held to the end of the transaction:     *)
(*                                                                         *)
(*   - a member's row, vault_members, FOR NO KEY UPDATE, taken one row at  *)
(*     a time in principal order (vault store.ts, lockMembers);            *)
(*   - the log's head, audit_chain_head, the one row every append and      *)
(*     every change to a place takes (db log.ts, lockLogHead).             *)
(*                                                                         *)
(* The app's own rows are only ever locked under the head (server          *)
(* context.ts, audited), so they never decide who waits and are left out.  *)
(*                                                                         *)
(* The places are one project and its one environment, which holds one    *)
(* secret. A grant is on the project, the environment, or every project    *)
(* ("*"). A place is deleted when its slug, or its project's, is a         *)
(* tombstone's: "tomb" here, `market~deleted-2026-10-05` in coffre.        *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Members,        \* principals with a vault_members row
    Rank,           \* Rank[m]: the principal's place in lock order
    Owners,         \* instance owners, who manage access and delete places
    Roots,          \* root admins, from the vault's configuration
    Procs,          \* concurrent requests, each one a process
    Ops,            \* Ops[p]: the operations process p may run
    Budget,         \* Budget[p]: how many it runs, one after another
    InitArchived,   \* the places archived at the start
    InitGrants      \* the grants at the start

(***************************************************************************)
(* The protections the code has, each a switch, so a run with one turned   *)
(* off shows the race it closes. The configurations in formal/ turn them   *)
(* all on, as the code is, and scripts/formal.sh requires each run with    *)
(* one off to fail.                                                        *)
(***************************************************************************)
CONSTANTS
    \* deletePlace re-reads the place's grants under the head and refuses
    \* if any is left (server api/projects.ts, `granted_meanwhile`). #134.
    GrantRereadInDeletion,
    \* setAccess takes the head before it reads whether the place is
    \* deleted (vault vault.ts, setAccess). #134.
    PlaceReadUnderHead,
    \* deletePlace checks under the head that the place is still archived
    \* (server api/projects.ts, `restored`). #134.
    ArchivedRecheckInDeletion,
    \* A rename, archive or restore resolves the place again under the head,
    \* rather than trust the path the router resolved before (server
    \* api/projects.ts, stillThere). #147.
    PatchRecheckUnderHead,
    \* A key decision checks again, under the head, that its place was not
    \* deleted while it decided (vault vault.ts, #keys). #147.
    KeyPlaceRecheckUnderHead,
    \* Sign-in reads the member's generation again under the head (server
    \* api/signin.ts, #stillMember).
    MemberRecheckInSignin,
    \* Members' rows are locked in principal order (vault store.ts,
    \* lockMembers, `ORDER BY principal`), not in the order a call names them.
    SortedMemberLocks

None == "none"
Places == {"proj", "env"}
GrantPlaces == Places \cup {"*"}
Slugs == {"s1", "s2", "tomb"}

VARIABLES
    \* app rows
    slug,           \* slug[x]: the place's slug, "tomb" once deleted
    archived,       \* archived[x]: archived_at is set
    held,           \* the secret's versions still hold their value: not erased
    version,        \* the secret's current version number
    \* vault rows
    status,         \* status[m]: "active" or "removed"
    gen,            \* gen[m]: the member's generation
    grants,         \* a set of [who, at]
    \* both
    log,            \* the audit log, in seq order: the entries the invariants read
    creds,          \* credentials sign-in issued
    \* locks
    memberLock,     \* memberLock[m]: the process holding m's row, or None
    head,           \* the process holding the log's head, or None
    \* processes
    pc, op, l, left,
    \* history, for the invariants
    revealed,       \* ids of reads whose value reached the caller
    deletions,      \* a record per deletion that committed
    everDeleted     \* everDeleted[x]: a deletion of x committed

rows == <<slug, archived, held, version, status, gen, grants>>
locks == <<memberLock, head>>
procs == <<pc, op, l, left>>
history == <<revealed, deletions, everDeleted>>
vars == <<rows, log, creds, locks, procs, history>>

-----------------------------------------------------------------------------
(* Places *)

\* Whether a place is deleted: its slug, or for the environment its
\* project's, is a tombstone's (vault store.ts, environmentsById and places).
Gone(x) ==
    CASE x = "*"    -> FALSE
      [] x = "proj" -> slug["proj"] = "tomb"
      [] x = "env"  -> slug["env"] = "tomb" \/ slug["proj"] = "tomb"

\* A grant at g covers place x (core access.ts, covers).
Covers(g, x) == g = "*" \/ g = x \/ (g = "proj" /\ x = "env")

\* The places a deletion of x takes, whose grants it revokes (server
\* db/queries.ts, deletionScope): a project's environments go with it.
Scope(x) == IF x = "proj" THEN {"proj", "env"} ELSE {"env"}

\* The slugs a request named, which it resolves again later by.
Named == [x \in Places |-> slug[x]]

\* A path to x resolves to the same place it named: the slugs are the ones
\* it named, and none is a tombstone's (server db/queries.ts, resolvePath).
Resolves(x, named) ==
    /\ slug["proj"] = named["proj"] /\ slug["proj"] # "tomb"
    /\ x = "env" => (slug["env"] = named["env"] /\ slug["env"] # "tomb")

\* The secret's environment serves secrets: neither it nor its project is
\* archived or deleted (server api/secrets.ts, liveEnvironment).
AppLive == ~Gone("env") /\ ~archived["proj"] /\ ~archived["env"]

-----------------------------------------------------------------------------
(* Members *)

\* `principals` in lock order.
Sorted(S) == [i \in 1..Cardinality(S) |->
                CHOOSE m \in S : Cardinality({n \in S : Rank[n] < Rank[m]}) = i - 1]

\* The rows a decision about `actor` and `who` locks, in the order it locks them.
LockOrder(actor, who) ==
    IF actor = who THEN <<actor>>
    ELSE IF SortedMemberLocks THEN Sorted({actor, who})
    ELSE <<actor, who>>

Active(m) == m \in Roots \/ status[m] = "active"

\* Whether m may read or write the secret (core access.ts, allows): root
\* admins always, others by a grant that covers the environment. Roles are
\* left out: which role grants what is a pure function, which the property
\* tests hold to its rules.
MayUseSecret(m) ==
    \/ m \in Roots
    \/ status[m] = "active" /\ \E g \in grants : g.who = m /\ Covers(g.at, "env")

\* Whether `actor` may manage grants, as an owner (core access.ts, mayManageAccess).
MayManage(actor) == (actor \in Owners /\ status[actor] = "active") \/ actor \in Roots

-----------------------------------------------------------------------------
(* Processes *)

NoOp == [kind |-> "none", actor |-> None, who |-> None, at |-> None]

\* A call to setAccess: who changes, where, and whether it grants or revokes.
NoCall == [actor |-> None, who |-> None, at |-> {}, grant |-> FALSE]

L0 == [id |-> <<None, 0>>,
       named |-> [x \in Places |-> None],
       toLock |-> <<>>,       \* the members' rows still to lock, in order
       nver |-> 0,            \* the version a write prepared against
       gen |-> 0,             \* the generation sign-in read
       queue |-> <<>>,        \* the members a deletion still has to revoke
       scope |-> {},          \* the grants a deletion read
       call |-> NoCall,       \* the setAccess call in progress
       ret |-> "idle",        \* where it returns
       ok |-> TRUE]           \* whether it was allowed

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

\* Commit or roll back: every lock the process holds goes.
Release(p) ==
    /\ memberLock' = [m \in Members |-> IF memberLock[m] = p THEN None ELSE memberLock[m]]
    /\ head' = IF head = p THEN None ELSE head

\* Lock the next member's row, waiting while another holds it, and go to
\* `then` once the last is held.
LockNext(p, then) ==
    LET m == Head(l[p].toLock) IN
    /\ memberLock[m] \in {None, p}
    /\ memberLock' = [memberLock EXCEPT ![m] = p]
    /\ l' = [l EXCEPT ![p].toLock = Tail(@)]
    /\ Goto(p, IF Tail(l[p].toLock) = <<>> THEN then ELSE pc[p])
    /\ UNCHANGED <<rows, log, creds, head, op, left, history>>

\* Lock the log's head, waiting while another holds it.
TakeHead(p, then) ==
    /\ head \in {None, p}
    /\ head' = p
    /\ Goto(p, then)
    /\ UNCHANGED <<rows, log, creds, memberLock, op, l, left, history>>

\* A step that only reads, outside any lock.
Read(p, then, locals) ==
    /\ Goto(p, then)
    /\ l' = [l EXCEPT ![p] = locals]
    /\ UNCHANGED <<rows, log, creds, locks, op, left, history>>

\* The operation ends, or is refused: its transaction rolls back. A refusal's
\* own entries commit in a transaction of their own that takes the head
\* alone (vault.ts, #decideOnce; context.ts, audited), which can wait for no
\* one and decides nothing, so it is left out.
Refuse(p) ==
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<rows, log, creds, op, l, left, history>>

Entry(kind, at, p) == [kind |-> kind, at |-> at, id |-> l[p].id]

-----------------------------------------------------------------------------
(* Starting an operation *)

FirstLabel(kind) ==
    CASE kind = "read"      -> "read.resolve"
      [] kind = "write"     -> "write.resolve"
      [] kind = "grant"     -> "grant.resolve"
      [] kind = "revoke"    -> "grant.resolve"
      [] kind = "delete"    -> "delete.resolve"
      [] kind = "archive"   -> "patch.resolve"
      [] kind = "unarchive" -> "patch.resolve"
      [] kind = "rename"    -> "patch.resolve"
      [] kind = "signin"    -> "signin.access"
      [] kind = "remove"    -> "remove.lock"
      [] kind = "rotate"    -> "rotate.read"

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = [L0 EXCEPT !.id = <<p, left[p]>>,
                                             !.toLock = IF o.kind \in {"read", "write", "remove"}
                                                          THEN LockOrder(o.actor, o.who) ELSE <<>>]]
         /\ Goto(p, FirstLabel(o.kind))
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<rows, log, creds, locks, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Reading a value (server api/secrets.ts and keys.ts, openValues; vault   *)
(* vault.ts, unwrap, #versions and #keys).                                 *)
(***************************************************************************)

\* The app resolves the path and reads the ciphertext, outside any
\* transaction; an archived or deleted place serves nothing.
ReadResolve(p) ==
    /\ pc[p] = "read.resolve"
    /\ IF AppLive /\ held
         THEN Read(p, "read.versions", l[p])
         ELSE Refuse(p)

\* The vault reads the version and its wrapped key, unlocked (#versions):
\* a deleted place's is refused as `deleted`, an erased one is no version.
ReadVersions(p) ==
    /\ pc[p] = "read.versions"
    /\ IF ~Gone("env") /\ held
         THEN Read(p, "read.lock", l[p])
         ELSE Refuse(p)

ReadLock(p) == pc[p] = "read.lock" /\ LockNext(p, "read.check")

\* Under the reader's row: their standing and grants, and whether the place
\* was deleted (environmentsById), then the bulk limit and the key service.
ReadCheck(p) ==
    /\ pc[p] = "read.check"
    /\ IF MayUseSecret(op[p].who) /\ ~Gone("env")
         THEN Read(p, "read.head", l[p])
         ELSE Refuse(p)

ReadHead(p) == pc[p] = "read.head" /\ TakeHead(p, "read.commit")

\* Under the head: the place again, which a deletion renames under the
\* same lock, then append `secret.read` and commit; then the key leaves the
\* vault. Without the recheck, a place deleted since the check above is
\* read all the same.
ReadCommit(p) ==
    /\ pc[p] = "read.commit"
    /\ IF KeyPlaceRecheckUnderHead /\ Gone("env")
         THEN Refuse(p)
         ELSE /\ log' = Append(log, Entry("secret.read", "env", p))
              /\ Release(p)
              /\ Goto(p, "read.answer")
              /\ UNCHANGED <<rows, creds, op, l, left, history>>

\* The app decrypts with the released key and answers.
ReadAnswer(p) ==
    /\ pc[p] = "read.answer"
    /\ revealed' = revealed \cup {l[p].id}
    /\ Goto(p, "idle")
    /\ UNCHANGED <<rows, log, creds, locks, op, l, left, deletions, everDeleted>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Writing a value (server api/secrets.ts, setSecrets): prepare, have the  *)
(* vault wrap, then one short app transaction under the head.              *)
(***************************************************************************)

WriteResolve(p) ==
    /\ pc[p] = "write.resolve"
    /\ IF AppLive
         THEN Read(p, "write.lock", [l[p] EXCEPT !.named = Named, !.nver = version])
         ELSE Refuse(p)

WriteLock(p) == pc[p] = "write.lock" /\ LockNext(p, "write.check")

WriteCheck(p) ==
    /\ pc[p] = "write.check"
    /\ IF MayUseSecret(op[p].who) /\ ~Gone("env")
         THEN Read(p, "write.head", l[p])
         ELSE Refuse(p)

WriteHead(p) == pc[p] = "write.head" /\ TakeHead(p, "write.wrap")

\* The vault appends `key.wrap` and commits; the wrapped key goes to the app.
WriteWrap(p) ==
    /\ pc[p] = "write.wrap"
    /\ IF KeyPlaceRecheckUnderHead /\ Gone("env")
         THEN Refuse(p)
         ELSE /\ log' = Append(log, Entry("key.wrap", "env", p))
              /\ Release(p)
              /\ Goto(p, "write.tx")
              /\ UNCHANGED <<rows, creds, op, l, left, history>>

WriteTx(p) == pc[p] = "write.tx" /\ TakeHead(p, "write.store")

\* Under the head: the path again, still live (checkEnvironment), the
\* secret's version as prepared, then the new version and its entry. A
\* version that moved prepares again (PrepareAgain); here the write ends.
WriteStore(p) ==
    /\ pc[p] = "write.store"
    /\ IF Resolves("env", l[p].named) /\ AppLive /\ version = l[p].nver
         THEN /\ version' = version + 1
              /\ held' = TRUE
              /\ log' = Append(log, Entry("secret.write", "env", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<slug, archived, status, gen, grants, creds, op, l, left, history>>
         ELSE Refuse(p)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Changing access (vault vault.ts, setAccess): one decision, the actor's  *)
(* and the subject's rows locked first. The API and a deletion call it.    *)
(***************************************************************************)

\* The API resolves the place among the standing ones, outside any
\* transaction (server api/access.ts): a deleted place is no path, so
\* nothing can revoke a grant left on one.
GrantResolve(p) ==
    /\ pc[p] = "grant.resolve"
    /\ IF Gone(op[p].at)
         THEN Refuse(p)
         ELSE Read(p, "call.lock",
                   [l[p] EXCEPT !.call = [actor |-> op[p].actor, who |-> op[p].who,
                                          at |-> {op[p].at}, grant |-> op[p].kind = "grant"],
                                !.toLock = LockOrder(op[p].actor, op[p].who),
                                !.ret = "idle"])

OnPlaces(call) == call.at \cap Places # {}

CallLock(p) ==
    /\ pc[p] = "call.lock"
    /\ LockNext(p, IF PlaceReadUnderHead /\ OnPlaces(l[p].call) THEN "call.headfirst" ELSE "call.check")

CallHeadFirst(p) == pc[p] = "call.headfirst" /\ TakeHead(p, "call.check")

\* Return from setAccess to the caller, with whether it was allowed.
Return(p, ok) ==
    /\ Release(p)
    /\ l' = [l EXCEPT ![p].ok = ok]
    /\ Goto(p, l[p].ret)

\* Whether the place is there to be granted (store.places), then the
\* actor's and the subject's standing, under their rows. A revocation, as a
\* deletion makes, is not refused for a deleted place; a grant is.
CallCheck(p) ==
    LET c == l[p].call IN
    /\ pc[p] = "call.check"
    /\ IF /\ ~(c.grant /\ \E x \in c.at : Gone(x))
          /\ MayManage(c.actor)
          /\ c.who \notin Roots
          /\ status[c.who] = "active"
         THEN Read(p, "call.head", l[p])
         ELSE /\ Return(p, FALSE)
              /\ UNCHANGED <<rows, log, creds, op, left, history>>

CallHead(p) == pc[p] = "call.head" /\ TakeHead(p, "call.commit")

\* Append the entries under the head, change the grants, seal, commit.
CallCommit(p) ==
    LET c == l[p].call
        changed == {x \in c.at : ([who |-> c.who, at |-> x] \in grants) # c.grant}
    IN
    /\ pc[p] = "call.commit"
    /\ grants' = IF c.grant THEN grants \cup {[who |-> c.who, at |-> x] : x \in c.at}
                 ELSE grants \ {[who |-> c.who, at |-> x] : x \in c.at}
    /\ log' = IF c.grant /\ changed # {}
                THEN Append(log, Entry("access.grant", CHOOSE x \in changed : TRUE, p))
                ELSE log
    /\ Return(p, TRUE)
    /\ UNCHANGED <<slug, archived, held, version, status, gen, creds, op, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Deleting an archived place for good (server api/projects.ts,            *)
(* deletePlace): its scope read, one vault revocation per member, then one *)
(* app transaction under the head that erases and renames.                 *)
(***************************************************************************)

DeleteResolve(p) ==
    LET x == op[p].at IN
    /\ pc[p] = "delete.resolve"
    /\ IF ~Gone(x) /\ archived[x]
         THEN Read(p, "delete.scope", [l[p] EXCEPT !.named = Named])
         ELSE Refuse(p)

\* deletionScope, unlocked: the grants on the place, lapsed ones too.
DeleteScope(p) ==
    LET doomed == {g \in grants : g.at \in Scope(op[p].at)} IN
    /\ pc[p] = "delete.scope"
    /\ Read(p, "delete.next", [l[p] EXCEPT !.scope = doomed,
                                           !.queue = Sorted({g.who : g \in doomed})])

\* The next member's revocation, or the transaction once none is left.
DeleteNext(p) ==
    LET m == Head(l[p].queue) IN
    /\ pc[p] = "delete.next"
    /\ IF ~l[p].ok
         THEN Refuse(p)
         ELSE IF l[p].queue = <<>>
         THEN Read(p, "delete.head", l[p])
         ELSE Read(p, "call.lock",
                   [l[p] EXCEPT !.queue = Tail(@),
                                !.call = [actor |-> op[p].actor, who |-> m,
                                          at |-> {g.at : g \in {h \in l[p].scope : h.who = m}},
                                          grant |-> FALSE],
                                !.toLock = LockOrder(op[p].actor, m),
                                !.ret = "delete.next"])

DeleteHead(p) == pc[p] = "delete.head" /\ TakeHead(p, "delete.commit")

\* Under the head: the path again; still archived; no grant left there.
\* Then erase every version, rename to the tombstone, log, commit.
DeleteCommit(p) ==
    LET x == op[p].at IN
    /\ pc[p] = "delete.commit"
    /\ IF \/ ~Resolves(x, l[p].named)
          \/ ArchivedRecheckInDeletion /\ ~archived[x]
          \/ GrantRereadInDeletion /\ \E g \in grants : g.at \in Scope(x)
         THEN Refuse(p)
         ELSE /\ slug' = [slug EXCEPT ![x] = "tomb"]
              /\ held' = FALSE
              /\ log' = Append(log, Entry("delete", x, p))
              /\ deletions' = deletions \cup {[at |-> x, archived |-> archived[x]]}
              /\ everDeleted' = [everDeleted EXCEPT ![x] = TRUE]
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<archived, version, status, gen, grants, creds, op, l, left, revealed>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Archiving, restoring and renaming a place (server api/projects.ts,      *)
(* patchProject and patchEnvironment): the router resolves the path before *)
(* the transaction; the update is by id, under the head.                   *)
(***************************************************************************)

PatchResolve(p) ==
    /\ pc[p] = "patch.resolve"
    /\ IF Resolves(op[p].at, Named)
         THEN Read(p, "patch.head", [l[p] EXCEPT !.named = Named])
         ELSE Refuse(p)

PatchHead(p) == pc[p] = "patch.head" /\ TakeHead(p, "patch.commit")

PatchCommit(p) ==
    LET x == op[p].at
        k == op[p].kind
    IN
    /\ pc[p] = "patch.commit"
    /\ IF PatchRecheckUnderHead /\ ~Resolves(x, l[p].named)
         THEN Refuse(p)
         ELSE /\ archived' = IF k = "archive" THEN [archived EXCEPT ![x] = TRUE]
                             ELSE IF k = "unarchive" THEN [archived EXCEPT ![x] = FALSE]
                             ELSE archived
              /\ slug' = IF k = "rename"
                           THEN [slug EXCEPT ![x] = IF l[p].named[x] = "s1" THEN "s2" ELSE "s1"]
                           ELSE slug
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<held, version, status, gen, grants, log, creds, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Signing in (server api/signin.ts): the member's standing from the vault,*)
(* unlocked, then one app transaction under the head that issues a         *)
(* credential at that generation.                                          *)
(***************************************************************************)

SigninAccess(p) ==
    /\ pc[p] = "signin.access"
    /\ IF Active(op[p].who)
         THEN Read(p, "signin.head", [l[p] EXCEPT !.gen = gen[op[p].who]])
         ELSE Refuse(p)

SigninHead(p) == pc[p] = "signin.head" /\ TakeHead(p, "signin.commit")

SigninCommit(p) ==
    LET m == op[p].who
        current == Active(m) /\ gen[m] = l[p].gen
    IN
    /\ pc[p] = "signin.commit"
    /\ IF MemberRecheckInSignin /\ ~current
         THEN Refuse(p)
         ELSE /\ creds' = creds \cup {[who |-> m, gen |-> l[p].gen, current |-> current]}
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<rows, log, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Removing a member (vault vault.ts, remove): one decision under both     *)
(* rows; their grants go and their generation moves on.                    *)
(***************************************************************************)

RemoveLock(p) == pc[p] = "remove.lock" /\ LockNext(p, "remove.check")

RemoveCheck(p) ==
    /\ pc[p] = "remove.check"
    /\ IF MayManage(op[p].actor) /\ op[p].who \notin Roots /\ status[op[p].who] = "active"
         THEN Read(p, "remove.head", l[p])
         ELSE Refuse(p)

RemoveHead(p) == pc[p] = "remove.head" /\ TakeHead(p, "remove.commit")

RemoveCommit(p) ==
    LET m == op[p].who IN
    /\ pc[p] = "remove.commit"
    /\ grants' = {g \in grants : g.who # m}
    /\ status' = [status EXCEPT ![m] = "removed"]
    /\ gen' = [gen EXCEPT ![m] = @ + 1]
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<slug, archived, held, version, log, creds, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Moving to a new vault key (vault vault.ts, #rotate): every member's row *)
(* locked, as a decision locks one, then the head.                         *)
(***************************************************************************)

RotateRead(p) ==
    /\ pc[p] = "rotate.read"
    /\ Read(p, "rotate.lock", [l[p] EXCEPT !.toLock = Sorted(Members)])

RotateLock(p) == pc[p] = "rotate.lock" /\ LockNext(p, "rotate.head")

RotateHead(p) == pc[p] = "rotate.head" /\ TakeHead(p, "rotate.commit")

RotateCommit(p) ==
    /\ pc[p] = "rotate.commit"
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<rows, log, creds, op, l, left, history>>

-----------------------------------------------------------------------------

Init ==
    /\ slug = [x \in Places |-> "s1"]
    /\ archived = [x \in Places |-> x \in InitArchived]
    /\ held = TRUE
    /\ version = 1
    /\ status = [m \in Members |-> "active"]
    /\ gen = [m \in Members |-> 0]
    /\ grants = InitGrants
    /\ log = <<>>
    /\ creds = {}
    /\ memberLock = [m \in Members |-> None]
    /\ head = None
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ revealed = {}
    /\ deletions = {}
    /\ everDeleted = [x \in Places |-> FALSE]

Step(p) ==
    \/ Begin(p)
    \/ ReadResolve(p) \/ ReadVersions(p) \/ ReadLock(p) \/ ReadCheck(p)
    \/ ReadHead(p) \/ ReadCommit(p) \/ ReadAnswer(p)
    \/ WriteResolve(p) \/ WriteLock(p) \/ WriteCheck(p) \/ WriteHead(p)
    \/ WriteWrap(p) \/ WriteTx(p) \/ WriteStore(p)
    \/ GrantResolve(p) \/ CallLock(p) \/ CallHeadFirst(p) \/ CallCheck(p)
    \/ CallHead(p) \/ CallCommit(p)
    \/ DeleteResolve(p) \/ DeleteScope(p) \/ DeleteNext(p) \/ DeleteHead(p) \/ DeleteCommit(p)
    \/ PatchResolve(p) \/ PatchHead(p) \/ PatchCommit(p)
    \/ SigninAccess(p) \/ SigninHead(p) \/ SigninCommit(p)
    \/ RemoveLock(p) \/ RemoveCheck(p) \/ RemoveHead(p) \/ RemoveCommit(p)
    \/ RotateRead(p) \/ RotateLock(p) \/ RotateHead(p) \/ RotateCommit(p)

\* Every process has run its operations: the run is over. Without this
\* step a finished run would look like a deadlock to TLC.
Finished == \A p \in Procs : pc[p] = "idle" /\ left[p] = 0

Next == (\E p \in Procs : Step(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* What must hold in every state.                                          *)
(***************************************************************************)

TypeOK ==
    /\ slug \in [Places -> Slugs]
    /\ archived \in [Places -> BOOLEAN]
    /\ held \in BOOLEAN
    /\ status \in [Members -> {"active", "removed"}]
    /\ grants \subseteq [who : Members, at : GrantPlaces]
    /\ memberLock \in [Members -> Procs \cup {None}]
    /\ head \in Procs \cup {None}

\* The process p waits for: the holder of the lock its next step takes.
LockLabels == {"read.lock", "write.lock", "call.lock", "remove.lock", "rotate.lock"}
HeadLabels == {"read.head", "write.head", "write.tx", "call.headfirst", "call.head",
               "delete.head", "patch.head", "signin.head", "remove.head", "rotate.head"}
WaitsFor(p) ==
    IF pc[p] \in LockLabels /\ l[p].toLock # <<>> /\ memberLock[Head(l[p].toLock)] \notin {None, p}
      THEN {memberLock[Head(l[p].toLock)]}
    ELSE IF pc[p] \in HeadLabels /\ head \notin {None, p}
      THEN {head}
    ELSE {}

RECURSIVE Waited(_, _)
Waited(p, n) == IF n = 0 THEN {} ELSE WaitsFor(p) \cup UNION {Waited(q, n - 1) : q \in WaitsFor(p)}

\* No process waits, however indirectly, for itself. TLC's own deadlock
\* check finds a run that cannot finish; this names the cycle sooner.
NoWaitCycle == \A p \in Procs : p \notin Waited(p, Cardinality(Procs))

\* Every grant is on a place that is standing, where the API can name it,
\* and so revoke it. A grant on a deleted place would outlive it.
EveryGrantRevocable == \A g \in grants : ~Gone(g.at)

\* Once a deletion is in the log, no key is released there after it.
NothingReleasedAfterDeletion ==
    \A i, j \in 1..Len(log) :
        (i < j /\ log[i].kind = "delete" /\ log[j].kind = "secret.read") => ~Covers(log[i].at, log[j].at)

\* Nor does anything after it read, wrap, write or grant there.
Reaches == {"secret.read", "key.wrap", "secret.write", "access.grant"}
DeletedStaysUnreachable ==
    \A i, j \in 1..Len(log) :
        (i < j /\ log[i].kind = "delete" /\ log[j].kind \in Reaches) => ~Covers(log[i].at, log[j].at)

\* A deletion erases only a place that was archived when it committed.
DeletedOnlyWhenArchived == \A d \in deletions : d.archived

\* A deleted place stays deleted: its tombstone keeps its slug, which no
\* live place can hold, so nothing lists it, grants on it or opens a key there.
TombstonesKeepTheirSlug == \A x \in Places : everDeleted[x] => slug[x] = "tomb"

\* And it stays archived, as it was when it was deleted.
TombstonesStayArchived == \A x \in Places : everDeleted[x] => archived[x]

\* A value reaches its caller only once its `secret.read` entry has committed.
AuditBeforeRelease == \A id \in revealed : \E i \in 1..Len(log) : log[i].kind = "secret.read" /\ log[i].id = id

\* Every credential was issued at the member's generation as it was when
\* the credential committed, to an active member.
CredentialsAtCurrentGeneration == \A c \in creds : c.current

=============================================================================
