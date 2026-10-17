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
(* secret, and a third environment, in another project, whose one key is a *)
(* reference to that secret: the holder. A grant is on the project, either *)
(* environment, or every project ("*"): an instance role, whose scope     *)
(* takes in every place, made later too, and which is set under the same  *)
(* locks a grant is (vault.ts, admit and setAccess). A place is deleted    *)
(* when its slug,                                                          *)
(* or its project's, is a tombstone's: "tomb" here,                        *)
(* `market~deleted-2026-10-05` in coffre.                                  *)
(*                                                                         *)
(* The environment's secret has a key name, "k1" until a rename, and a     *)
(* fork of the environment inherits it, which a regenerate there replaces  *)
(* with an override of its own: the fork is no place of the model, only    *)
(* whether it holds its own row under "k1".                                *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Members,        \* principals with a vault_members row
    Rank,           \* Rank[m]: the principal's place in lock order
    InitOwners,     \* the Owners of the whole instance at the start
    Listed,         \* those the deployment names Owners: nobody demotes or removes them
    Admins,         \* Admins of the whole instance: they manage access and roles too
    Procs,          \* concurrent requests, each one a process
    Ops,            \* Ops[p]: the operations process p may run
    Budget,         \* Budget[p]: how many it runs, one after another
    InitArchived,   \* the places archived at the start
    InitGrants,     \* the grants at the start
    InitRef         \* the holder's reference at the start, or NoRef

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
    \* Adding an environment resolves its project again under the head, and
    \* reads whether it is archived there (server api/projects.ts,
    \* putEnvironment, stillThere).
    EnvCreateRecheckUnderHead,
    \* Renaming, archiving or restoring a key resolves its environment again
    \* under the head (server api/secrets.ts, patchSecret, checkEnvironment).
    SecretPatchRecheckUnderHead,
    \* Sign-in reads the member's generation again under the head (server
    \* api/signin.ts, #stillMember).
    MemberRecheckInSignin,
    \* Members' rows are locked in principal order (vault store.ts,
    \* lockMembers, `ORDER BY principal`), not in the order a call names them.
    SortedMemberLocks,
    \* A read decides under the reader's row, which a change to their grants
    \* or their removal locks too (vault vault.ts, #keys through #decide).
    ReaderRowLocked,
    \* A read through a reference checks again, under the head, that no
    \* `reference.end` committed since it decided (vault vault.ts, unwrap's
    \* `vet`, run again in #keys' `underLock`).
    EndRecheckUnderHead,
    \* Making a reference checks its source again under the head, where the
    \* app writes its row: archived or deleted since, it is no source
    \* (server api/secrets.ts, setSecrets). #152.
    SourceRecheckInReference,
    \* Archiving a place is refused while a live reference from elsewhere
    \* reads it (server api/references.ts, refuseIfRead). #152.
    ArchiveRefusedWhileRead,
    \* deletePlace reads the references into and out of the place again under
    \* the head, and refuses if one is live (server api/projects.ts,
    \* `referenced_meanwhile`).
    ReferenceRereadInDeletion,
    \* Demoting or removing an Owner counts the other Owners under the head,
    \* not only under the rows it locks (vault vault.ts, #keepAnOwner).
    LastOwnerCheckUnderHead,
    \* A regenerate in a fork resolves each key it replaces again under the
    \* head, the parent's rows included, and refuses if the name no longer
    \* resolves to the version it was listed with (server api/secrets.ts,
    \* setSecrets, `regenerated`), not only before the vault wraps.
    InheritedRecheckUnderHead

None == "none"
\* No reference. A reference is named by the operation that made it, as
\* entries are, or is the one a scenario starts with.
NoRef == <<None, 0>>
Places == {"proj", "env", "hold"}
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
    owners,         \* the members whose instance role is Owner, everywhere
    refRow,         \* the holder's newest reference row (secret_references), or NoRef
    keyName,        \* the secret's key name: "k1", or "k2" once renamed
    forkOwn,        \* the fork holds a row of its own under "k1": an override
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
    everDeleted,    \* everDeleted[x]: a deletion of x committed
    excused,        \* the reference whose holder was archived when its source last was
    declared,       \* those the vault has made Owners as the deployment names them
    regens          \* a record per regenerate that committed in the fork

rows == <<slug, archived, held, version, status, gen, grants, owners, refRow, keyName, forkOwn>>
locks == <<memberLock, head>>
procs == <<pc, op, l, left>>
history == <<revealed, deletions, everDeleted, excused, declared, regens>>
vars == <<rows, log, creds, locks, procs, history>>

-----------------------------------------------------------------------------
(* Places *)

\* The rows a path to x goes through: the environment's project, then it.
\* The holder's project is left out: nothing in the model changes it.
Path(x) == CASE x = "proj" -> {"proj"} [] x = "env" -> {"proj", "env"} [] x = "hold" -> {"hold"} [] x = "*" -> {}

\* Whether a place is deleted: its slug, or for an environment its
\* project's, is a tombstone's (vault store.ts, environmentsById and places).
Gone(x) == \E y \in Path(x) : slug[y] = "tomb"

\* Whether it is archived, itself or with its project.
Archived(x) == \E y \in Path(x) : archived[y]

\* A grant at g covers place x (core access.ts, covers).
Covers(g, x) == g = "*" \/ g = x \/ (g = "proj" /\ x = "env")

\* The places a deletion of x takes, whose grants it revokes (server
\* db/queries.ts, deletionScope): a project's environments go with it.
Scope(x) == CASE x = "proj" -> {"proj", "env"} [] x = "env" -> {"env"} [] x = "hold" -> {"hold"}

\* The slugs a request named, which it resolves again later by.
Named == [x \in Places |-> slug[x]]

\* A path to x resolves to the same place it named: the slugs are the ones
\* it named, and none is a tombstone's (server db/queries.ts, resolvePath).
Resolves(x, named) == \A y \in Path(x) : slug[y] = named[y] /\ slug[y] # "tomb"

\* An environment serves secrets: neither it nor its project is archived or
\* deleted (server api/secrets.ts, liveEnvironment).
Live(x) == ~Gone(x) /\ ~Archived(x)
AppLive == Live("env")

\* A reference is ended once its `reference.end` is in the log (vault
\* store.ts, endedReferences; server db/queries.ts, referenceRows).
Ended(r) == \E i \in 1..Len(log) : log[i].kind = "reference.end" /\ log[i].via = r

\* The holder's reference, while it reads: not ended, its source live and
\* holding a value (server api/references.ts, stateOf).
LiveRef == refRow # NoRef /\ ~Ended(refRow) /\ Live("env") /\ held

\* The holder's reference, not ended, if it goes into or out of the
\* places a deletion of x takes (server api/references.ts, referencesAt).
RefAt(x) ==
    IF refRow # NoRef /\ ~Ended(refRow) /\ {"env", "hold"} \cap Scope(x) # {} THEN refRow ELSE NoRef

\* Archiving x would stop a live reference held outside it from reading
\* (server api/references.ts, archiveBlockers). One held inside is
\* archived with it, and one held in an archived place serves nobody's
\* run: neither stops nobody's read.
ReadFromOutside(x) == LiveRef /\ ~Archived("hold") /\ "env" \in Scope(x) /\ "hold" \notin Scope(x)

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

Active(m) == status[m] = "active"

\* Whether m may read or write secrets at x (core access.ts, allows): by a
\* grant that covers the environment, or an instance role ("*"). Roles are
\* left out: which role grants what is a pure function, which the property
\* tests hold to its rules.
MayUse(m, x) == status[m] = "active" /\ \E g \in grants : g.who = m /\ Covers(g.at, x)

\* Whether `actor` runs the instance, as an Owner or Admin of all of it:
\* they manage grants (core access.ts, mayManageAccess) and roles.
MayManage(actor) == status[actor] = "active" /\ (actor \in owners \/ actor \in Admins)

\* The active Owners of the whole instance, as the rows say now.
ActiveOwners == {m \in owners : status[m] = "active"}

\* Whether an Owner other than m would be left (vault.ts, #anOwner).
AnotherOwner(m) == ActiveOwners \ {m} # {}

\* Whether `actor` may unmake an Owner: an Owner of the whole instance, read
\* under their row's lock as the rest of the check is (vault.ts, OWNERS_ONLY).
ChangesOwners(actor) == status[actor] = "active" /\ actor \in owners

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
       ref |-> NoRef,         \* the reference a read goes through, or a new one replaces
       end |-> NoRef,         \* the reference an endReferences call ends
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

\* A log entry: what it is, where, the operation that wrote it, whom it
\* is about. A read's names the reference it went through, if any.
Entry(kind, at, p) == [kind |-> kind, at |-> at, id |-> l[p].id, who |-> op[p].who, via |-> NoRef]

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
      [] kind = "addenv"    -> "addenv.resolve"
      [] kind = "renamekey" -> "renamekey.resolve"
      [] kind = "signin"    -> "signin.access"
      [] kind = "remove"    -> "remove.lock"
      [] kind = "demote"    -> "demote.lock"
      [] kind = "declare"   -> "declare.lock"
      [] kind = "rotate"    -> "rotate.read"
      [] kind = "refer"     -> "refer.resolve"
      [] kind = "break"     -> "break.resolve"
      [] kind = "regenerate" -> "regen.resolve"
      [] kind = "override"  -> "override.head"

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = [L0 EXCEPT !.id = <<p, left[p]>>,
                                             !.toLock = CASE o.kind \in {"read", "write", "remove", "demote"} -> LockOrder(o.actor, o.who)
                                                           [] o.kind = "declare" -> <<o.who>>
                                                           [] o.kind = "refer" -> <<o.actor>>
                                                           [] OTHER -> <<>>]]
         /\ Goto(p, FirstLabel(o.kind))
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<rows, log, creds, locks, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Reading a value (server api/secrets.ts and keys.ts, openValues; vault   *)
(* vault.ts, unwrap, #versions and #keys). A read of the environment opens *)
(* its secret's value; a read of the holder opens the source's value       *)
(* through the reference (server api/references.ts, readableValues), and   *)
(* the reader's grants on the holder decide.                               *)
(***************************************************************************)

\* The app resolves the path and reads the ciphertext, outside any
\* transaction; an archived or deleted place serves nothing. Through the
\* reference, the holder serves, and the reference reads.
ReadResolve(p) ==
    /\ pc[p] = "read.resolve"
    /\ IF op[p].at = "env"
         THEN IF AppLive /\ held
                THEN Read(p, "read.versions", l[p])
                ELSE Refuse(p)
         ELSE IF Live("hold") /\ LiveRef
                THEN Read(p, "read.versions", [l[p] EXCEPT !.ref = refRow])
                ELSE Refuse(p)

\* The vault reads the version and its wrapped key, unlocked (#versions):
\* a deleted place's is refused as `deleted`, an erased one is no version.
\* Then, unlocked too, the reference's `reference.create` (#referencesAt).
ReadVersions(p) ==
    /\ pc[p] = "read.versions"
    /\ IF ~Gone("env") /\ held
         THEN Read(p, IF ReaderRowLocked THEN "read.lock" ELSE "read.check", l[p])
         ELSE Refuse(p)

ReadLock(p) == pc[p] = "read.lock" /\ LockNext(p, "read.check")

\* Under the reader's row: their standing and grants where they read, and
\* whether either place was deleted (environmentsById); through a
\* reference, whether it ended (`vet`). Then the bulk limit and the key
\* service. Without the row's lock, a revocation or a removal can commit
\* between this check and the entry.
ReadCheck(p) ==
    /\ pc[p] = "read.check"
    /\ IF /\ MayUse(op[p].who, op[p].at)
          /\ ~Gone("env") /\ ~Gone(op[p].at)
          /\ l[p].ref # NoRef => ~Ended(l[p].ref)
         THEN Read(p, "read.head", l[p])
         ELSE Refuse(p)

ReadHead(p) == pc[p] = "read.head" /\ TakeHead(p, "read.commit")

\* Under the head: both places again, which a deletion renames under the
\* same lock, and the reference's end again (`underLock`), then append
\* `secret.read` and commit; then the key leaves the vault. Without the
\* rechecks, a place deleted or a reference ended since the check above is
\* read all the same.
ReadCommit(p) ==
    /\ pc[p] = "read.commit"
    /\ IF \/ KeyPlaceRecheckUnderHead /\ (Gone("env") \/ Gone(op[p].at))
          \/ EndRecheckUnderHead /\ l[p].ref # NoRef /\ Ended(l[p].ref)
         THEN Refuse(p)
         ELSE /\ log' = Append(log, [Entry("secret.read", "env", p) EXCEPT !.via = l[p].ref])
              /\ Release(p)
              /\ Goto(p, "read.answer")
              /\ UNCHANGED <<rows, creds, op, l, left, history>>

\* The app decrypts with the released key and answers.
ReadAnswer(p) ==
    /\ pc[p] = "read.answer"
    /\ revealed' = revealed \cup {l[p].id}
    /\ Goto(p, "idle")
    /\ UNCHANGED <<rows, log, creds, locks, op, l, left, deletions, everDeleted, excused, declared, regens>>

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
    /\ IF MayUse(op[p].who, "env") /\ ~Gone("env")
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
              /\ UNCHANGED <<refRow, slug, archived, status, gen, grants, owners, creds, op, l, left, history, keyName, forkOwn>>
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
          /\ status[c.who] = "active"
         THEN Read(p, "call.head", l[p])
         ELSE /\ Return(p, FALSE)
              /\ UNCHANGED <<rows, log, creds, op, left, history>>

CallHead(p) == pc[p] = "call.head" /\ TakeHead(p, "call.commit")

\* Append the entries under the head, change the grants, seal, commit: an
\* `access.grant` or an `access.revoke` for each place that changed.
CallCommit(p) ==
    LET c == l[p].call
        changed == SelectSeq(<<"*", "proj", "env", "hold">>,
                             LAMBDA x : x \in c.at /\ ([who |-> c.who, at |-> x] \in grants) # c.grant)
        entry(x) == [Entry(IF c.grant THEN "access.grant" ELSE "access.revoke", x, p) EXCEPT !.who = c.who]
    IN
    /\ pc[p] = "call.commit"
    /\ grants' = IF c.grant THEN grants \cup {[who |-> c.who, at |-> x] : x \in c.at}
                 ELSE grants \ {[who |-> c.who, at |-> x] : x \in c.at}
    /\ log' = log \o [i \in 1..Len(changed) |-> entry(changed[i])]
    /\ Return(p, TRUE)
    /\ UNCHANGED <<refRow, slug, archived, held, version, status, gen, owners, creds, op, left, history, keyName, forkOwn>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Deleting an archived place for good (server api/projects.ts,            *)
(* deletePlace): its scope read, one vault revocation per member, the      *)
(* references into and out of it ended, then one app transaction under    *)
(* the head that erases and renames.                                       *)
(***************************************************************************)

DeleteResolve(p) ==
    LET x == op[p].at IN
    /\ pc[p] = "delete.resolve"
    /\ IF ~Gone(x) /\ archived[x]
         THEN Read(p, "delete.scope", [l[p] EXCEPT !.named = Named])
         ELSE Refuse(p)

\* deletionScope and referencesAt, unlocked: the grants on the place, lapsed
\* ones too, and the references into and out of it.
DeleteScope(p) ==
    LET doomed == {g \in grants : g.at \in Scope(op[p].at)} IN
    /\ pc[p] = "delete.scope"
    /\ Read(p, "delete.next", [l[p] EXCEPT !.scope = doomed,
                                           !.queue = Sorted({g.who : g \in doomed}),
                                           !.end = RefAt(op[p].at)])

\* The next member's revocation, then the references' end, then the
\* transaction once nothing is left.
DeleteNext(p) ==
    LET m == Head(l[p].queue) IN
    /\ pc[p] = "delete.next"
    /\ IF ~l[p].ok
         THEN Refuse(p)
         ELSE IF l[p].queue = <<>> /\ l[p].end # NoRef
         THEN Read(p, "end.lock", [l[p] EXCEPT !.toLock = <<op[p].actor>>, !.ret = "delete.next"])
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

\* Under the head: the path again; still archived; no grant left there, nor
\* a live reference. Then erase every version, rename to the tombstone,
\* log, commit.
DeleteCommit(p) ==
    LET x == op[p].at IN
    /\ pc[p] = "delete.commit"
    /\ IF \/ ~Resolves(x, l[p].named)
          \/ ArchivedRecheckInDeletion /\ ~archived[x]
          \/ GrantRereadInDeletion /\ \E g \in grants : g.at \in Scope(x)
          \/ ReferenceRereadInDeletion /\ RefAt(x) # NoRef
         THEN Refuse(p)
         ELSE /\ slug' = [slug EXCEPT ![x] = "tomb"]
              /\ held' = IF "env" \in Scope(x) THEN FALSE ELSE held
              /\ log' = Append(log, Entry("delete", x, p))
              /\ deletions' = deletions \cup {[at |-> x, archived |-> archived[x]]}
              /\ everDeleted' = [everDeleted EXCEPT ![x] = TRUE]
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<refRow, archived, version, status, gen, grants, owners, creds, op, l, left, revealed, excused, declared, keyName, forkOwn, regens>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Archiving, restoring and renaming a place (server api/projects.ts,      *)
(* patchProject and patchEnvironment): the router resolves the path before *)
(* the transaction; the update is by id, under the head. Archiving is      *)
(* refused while a live reference from elsewhere reads the place.          *)
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
    /\ IF \/ PatchRecheckUnderHead /\ ~Resolves(x, l[p].named)
          \/ ArchiveRefusedWhileRead /\ k = "archive" /\ ReadFromOutside(x)
         THEN Refuse(p)
         ELSE /\ archived' = IF k = "archive" THEN [archived EXCEPT ![x] = TRUE]
                             ELSE IF k = "unarchive" THEN [archived EXCEPT ![x] = FALSE]
                             ELSE archived
              /\ slug' = IF k = "rename"
                           THEN [slug EXCEPT ![x] = IF l[p].named[x] = "s1" THEN "s2" ELSE "s1"]
                           ELSE slug
              \* The archive that takes the source out of service excuses the
              \* reference whose holder it finds archived.
              /\ excused' = IF k = "archive" /\ "env" \in Scope(x) /\ Live("env")
                               THEN IF refRow # NoRef /\ ~Ended(refRow) /\ Archived("hold") THEN {refRow} ELSE {}
                               ELSE excused
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<refRow, held, version, status, gen, grants, owners, log, creds, op, l, left, revealed, deletions, everDeleted, declared, keyName, forkOwn, regens>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Adding an environment (server api/projects.ts, putEnvironment), and     *)
(* renaming, archiving or restoring a key (server api/secrets.ts,          *)
(* patchSecret). Each writes under a place the router resolved before its  *)
(* transaction, under the head. A new environment is a log entry here: the *)
(* model's places are fixed, and the entry is what the invariant reads.    *)
(***************************************************************************)

AddEnvResolve(p) ==
    /\ pc[p] = "addenv.resolve"
    /\ IF Resolves("proj", Named) /\ ~archived["proj"]
         THEN Read(p, "addenv.head", [l[p] EXCEPT !.named = Named])
         ELSE Refuse(p)

AddEnvHead(p) == pc[p] = "addenv.head" /\ TakeHead(p, "addenv.commit")

\* Without the recheck, the project as the router saw it: not archived.
AddEnvCommit(p) ==
    /\ pc[p] = "addenv.commit"
    /\ IF EnvCreateRecheckUnderHead /\ (~Resolves("proj", l[p].named) \/ archived["proj"])
         THEN Refuse(p)
         ELSE /\ log' = Append(log, Entry("environment.create", "proj", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<rows, creds, op, l, left, history>>

RenameKeyResolve(p) ==
    /\ pc[p] = "renamekey.resolve"
    /\ IF AppLive
         THEN Read(p, "renamekey.head", [l[p] EXCEPT !.named = Named])
         ELSE Refuse(p)

RenameKeyHead(p) == pc[p] = "renamekey.head" /\ TakeHead(p, "renamekey.commit")

RenameKeyCommit(p) ==
    /\ pc[p] = "renamekey.commit"
    /\ IF SecretPatchRecheckUnderHead /\ ~(Resolves("env", l[p].named) /\ AppLive)
         THEN Refuse(p)
         ELSE /\ log' = Append(log, Entry("secret.rename", "env", p))
              /\ keyName' = IF keyName = "k1" THEN "k2" ELSE "k1"
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<slug, archived, held, version, status, gen, grants, owners, refRow, forkOwn, creds, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Making the holder's key a reference to the secret (server               *)
(* api/secrets.ts, setSecrets with `{ ref }`): the app checks both sides,  *)
(* the vault seals the reference with its `reference.create` (vault        *)
(* vault.ts, reference), ends the one it replaces, if live, as `replaced`, *)
(* then one app transaction under the head writes the row.                 *)
(***************************************************************************)

\* referenceTargets, outside any transaction: the holder's environment and
\* the source live; the holder's newest reference, which the transaction
\* checks no other write replaced meanwhile.
ReferResolve(p) ==
    /\ pc[p] = "refer.resolve"
    /\ IF Live("hold") /\ Live("env")
         THEN Read(p, "refer.lock", [l[p] EXCEPT !.named = Named, !.ref = refRow,
                                                 !.end = IF refRow # NoRef /\ ~Ended(refRow) THEN refRow ELSE NoRef])
         ELSE Refuse(p)

ReferLock(p) == pc[p] = "refer.lock" /\ LockNext(p, "refer.check")

\* Under the maker's row: they write the holder and read the source, and
\* neither side is deleted.
ReferCheck(p) ==
    /\ pc[p] = "refer.check"
    /\ IF MayUse(op[p].actor, "hold") /\ MayUse(op[p].actor, "env") /\ ~Gone("hold") /\ ~Gone("env")
         THEN Read(p, "refer.head", l[p])
         ELSE Refuse(p)

ReferHead(p) == pc[p] = "refer.head" /\ TakeHead(p, "refer.seal")

\* Under the head (`underLock`): neither side deleted since. Append
\* `reference.create`, which is the reference, and commit.
ReferSeal(p) ==
    /\ pc[p] = "refer.seal"
    /\ IF Gone("hold") \/ Gone("env")
         THEN Refuse(p)
         ELSE /\ log' = Append(log, [Entry("reference.create", "hold", p) EXCEPT !.via = l[p].id])
              /\ Release(p)
              /\ Goto(p, IF l[p].end # NoRef THEN "end.lock" ELSE "refer.tx")
              /\ l' = [l EXCEPT ![p].toLock = <<op[p].actor>>, ![p].ret = "refer.tx"]
              /\ UNCHANGED <<rows, creds, op, left, history>>

ReferTx(p) ==
    /\ pc[p] = "refer.tx"
    /\ IF l[p].ok
         THEN TakeHead(p, "refer.commit")
         ELSE Refuse(p)

\* Under the head: the holder's environment still live (checkEnvironment),
\* the source still live, no reference made there meanwhile; then the row,
\* which points at the vault's entry. Without the source's recheck, a source
\* archived since, and deleted next, is read by a row nothing ends.
ReferCommit(p) ==
    /\ pc[p] = "refer.commit"
    /\ IF \/ ~(Resolves("hold", l[p].named) /\ Live("hold"))
          \/ SourceRecheckInReference /\ ~Live("env")
          \/ refRow # l[p].ref
         THEN Refuse(p)
         ELSE /\ refRow' = l[p].id
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<slug, archived, held, version, status, gen, grants, owners, keyName, forkOwn, log, creds, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Breaking the reference (server api/references.ts, breakReference): the  *)
(* app resolves the holder and its reference, then the vault ends it.      *)
(***************************************************************************)

BreakResolve(p) ==
    /\ pc[p] = "break.resolve"
    /\ IF Resolves("hold", Named) /\ refRow # NoRef /\ ~Ended(refRow)
         THEN Read(p, "end.lock", [l[p] EXCEPT !.end = refRow, !.toLock = <<op[p].actor>>, !.ret = "idle"])
         ELSE Refuse(p)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Ending a reference (vault vault.ts, endReferences): one decision under  *)
(* the actor's row. Breaking, replacing and deleting call it.              *)
(***************************************************************************)

EndLock(p) == pc[p] = "end.lock" /\ LockNext(p, "end.check")

\* The actor writes the holder or manages access, and the reference has not
\* ended. Ending is allowed in a deleted place.
EndCheck(p) ==
    /\ pc[p] = "end.check"
    /\ IF (MayManage(op[p].actor) \/ MayUse(op[p].actor, "hold")) /\ ~Ended(l[p].end)
         THEN Read(p, "end.head", l[p])
         ELSE /\ Return(p, FALSE)
              /\ UNCHANGED <<rows, log, creds, op, left, history>>

EndHead(p) == pc[p] = "end.head" /\ TakeHead(p, "end.commit")

\* Under the head: not ended meanwhile, by another end; then `reference.end`.
EndCommit(p) ==
    /\ pc[p] = "end.commit"
    /\ IF Ended(l[p].end)
         THEN /\ Return(p, FALSE)
              /\ UNCHANGED <<rows, log, creds, op, left, history>>
         ELSE /\ log' = Append(log, [Entry("reference.end", "hold", p) EXCEPT !.via = l[p].end])
              /\ Release(p)
              /\ l' = [l EXCEPT ![p].ok = TRUE, ![p].end = NoRef]
              /\ Goto(p, l[p].ret)
              /\ UNCHANGED <<rows, creds, op, left, history>>

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
(* rows; their grants go and their generation moves on. Only an Owner      *)
(* removes an Owner, themselves included, and leaves another, or is        *)
(* refused (#keepAnOwner): the code counts the others under the head,      *)
(* which the commit step holds. Nobody removes one the deployment names.   *)
(***************************************************************************)

RemoveLock(p) == pc[p] = "remove.lock" /\ LockNext(p, "remove.check")

\* With the count under the rows alone, it is made here, before the head.
KeepsAnOwnerUnderRows(m) == LastOwnerCheckUnderHead \/ m \notin owners \/ AnotherOwner(m)
KeepsAnOwnerUnderHead(m) == ~LastOwnerCheckUnderHead \/ m \notin owners \/ AnotherOwner(m)

RemoveCheck(p) ==
    /\ pc[p] = "remove.check"
    /\ IF /\ MayManage(op[p].actor)
          /\ status[op[p].who] = "active"
          /\ op[p].who \notin Listed
          /\ (op[p].who \notin owners \/ ChangesOwners(op[p].actor))
          /\ KeepsAnOwnerUnderRows(op[p].who)
         THEN Read(p, "remove.head", l[p])
         ELSE Refuse(p)

RemoveHead(p) == pc[p] = "remove.head" /\ TakeHead(p, "remove.commit")

RemoveCommit(p) ==
    LET m == op[p].who IN
    /\ pc[p] = "remove.commit"
    /\ IF KeepsAnOwnerUnderHead(m)
         THEN /\ grants' = {g \in grants : g.who # m}
              /\ status' = [status EXCEPT ![m] = "removed"]
              /\ gen' = [gen EXCEPT ![m] = @ + 1]
              /\ owners' = owners \ {m}
              /\ log' = Append(log, Entry("member.remove", "*", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<refRow, slug, archived, held, version, creds, op, l, left, history, keyName, forkOwn>>
         ELSE Refuse(p)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Taking someone's Owner role away (vault vault.ts, admit with another    *)
(* role, or a narrower scope): one decision under both rows, by an Owner,  *)
(* their own included. It leaves another Owner, or is refused, as it is    *)
(* about one the deployment names.                                         *)
(***************************************************************************)

DemoteLock(p) == pc[p] = "demote.lock" /\ LockNext(p, "demote.check")

DemoteCheck(p) ==
    LET m == op[p].who IN
    /\ pc[p] = "demote.check"
    /\ IF ChangesOwners(op[p].actor) /\ status[m] = "active" /\ m \in owners /\ m \notin Listed /\ KeepsAnOwnerUnderRows(m)
         THEN Read(p, "demote.head", l[p])
         ELSE Refuse(p)

DemoteHead(p) == pc[p] = "demote.head" /\ TakeHead(p, "demote.commit")

DemoteCommit(p) ==
    LET m == op[p].who IN
    /\ pc[p] = "demote.commit"
    /\ IF KeepsAnOwnerUnderHead(m)
         THEN /\ owners' = owners \ {m}
              /\ log' = Append(log, Entry("member.role", "*", p))
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<slug, archived, held, version, status, gen, grants, refRow, creds, op, l, left, history, keyName, forkOwn>>
         ELSE Refuse(p)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Making someone the deployment names an Owner (vault vault.ts,          *)
(* #declare), as it starts and when they sign in: one decision under their *)
(* row, whoever else owns the instance, then the head its entry takes.     *)
(***************************************************************************)

DeclareLock(p) == pc[p] = "declare.lock" /\ LockNext(p, "declare.head")

DeclareHead(p) == pc[p] = "declare.head" /\ TakeHead(p, "declare.commit")

DeclareCommit(p) ==
    LET m == op[p].who IN
    /\ pc[p] = "declare.commit"
    /\ owners' = owners \cup {m}
    /\ status' = [status EXCEPT ![m] = "active"]
    /\ log' = Append(log, Entry("member.declare", "*", p))
    /\ declared' = declared \cup {m}
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<slug, archived, held, version, gen, grants, refRow, creds, op, l, left, revealed, deletions, everDeleted, excused, keyName, forkOwn, regens>>

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
(***************************************************************************)
(* Regenerating, in a fork, the key it inherits (server api/secrets.ts,    *)
(* setSecrets with `replaces`): the listing names the version "k1"         *)
(* resolves to, the app checks it again before the vault wraps, then once  *)
(* more under the head, where it writes the fork's override. A value typed *)
(* in the fork is an override too, written under the head.                 *)
(***************************************************************************)

\* The version the fork's "k1" resolves to, as the listing gives it: the
\* parent's, while the fork holds none of its own; 0 for none.
Inherited == IF keyName = "k1" /\ ~forkOwn THEN version ELSE 0

\* Listed, and checked before the vault wraps, outside any transaction.
RegenResolve(p) ==
    /\ pc[p] = "regen.resolve"
    /\ IF Inherited # 0
         THEN Read(p, "regen.tx", [l[p] EXCEPT !.nver = Inherited])
         ELSE Refuse(p)

RegenTx(p) == pc[p] = "regen.tx" /\ TakeHead(p, "regen.store")

\* Under the head: the fork's own rows as prepared (PrepareAgain), and the
\* parent's resolved again. Without that, a rename or a write in the parent
\* since leaves an override under a name that no longer holds what it
\* replaced.
RegenStore(p) ==
    /\ pc[p] = "regen.store"
    /\ IF forkOwn \/ (InheritedRecheckUnderHead /\ Inherited # l[p].nver)
         THEN Refuse(p)
         ELSE /\ regens' = regens \cup {[listed |-> l[p].nver, key |-> keyName, version |-> version]}
              /\ forkOwn' = TRUE
              /\ Release(p)
              /\ Goto(p, "idle")
              /\ UNCHANGED <<slug, archived, held, version, status, gen, grants, owners, refRow, keyName,
                             log, creds, op, l, left, revealed, deletions, everDeleted, excused, declared>>

OverrideHead(p) == pc[p] = "override.head" /\ TakeHead(p, "override.commit")

OverrideCommit(p) ==
    /\ pc[p] = "override.commit"
    /\ forkOwn' = TRUE
    /\ Release(p)
    /\ Goto(p, "idle")
    /\ UNCHANGED <<slug, archived, held, version, status, gen, grants, owners, refRow, keyName, log, creds, op, l, left, history>>

-----------------------------------------------------------------------------

Init ==
    /\ slug = [x \in Places |-> "s1"]
    /\ archived = [x \in Places |-> x \in InitArchived]
    /\ held = TRUE
    /\ version = 1
    /\ status = [m \in Members |-> "active"]
    /\ gen = [m \in Members |-> 0]
    /\ grants = InitGrants
    /\ owners = InitOwners
    /\ refRow = InitRef
    /\ keyName = "k1"
    /\ forkOwn = FALSE
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
    /\ excused = {}
    /\ declared = {}
    /\ regens = {}

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
    \/ AddEnvResolve(p) \/ AddEnvHead(p) \/ AddEnvCommit(p)
    \/ RenameKeyResolve(p) \/ RenameKeyHead(p) \/ RenameKeyCommit(p)
    \/ SigninAccess(p) \/ SigninHead(p) \/ SigninCommit(p)
    \/ RemoveLock(p) \/ RemoveCheck(p) \/ RemoveHead(p) \/ RemoveCommit(p)
    \/ DemoteLock(p) \/ DemoteCheck(p) \/ DemoteHead(p) \/ DemoteCommit(p)
    \/ DeclareLock(p) \/ DeclareHead(p) \/ DeclareCommit(p)
    \/ RotateRead(p) \/ RotateLock(p) \/ RotateHead(p) \/ RotateCommit(p)
    \/ ReferResolve(p) \/ ReferLock(p) \/ ReferCheck(p) \/ ReferHead(p) \/ ReferSeal(p)
    \/ ReferTx(p) \/ ReferCommit(p)
    \/ BreakResolve(p) \/ EndLock(p) \/ EndCheck(p) \/ EndHead(p) \/ EndCommit(p)
    \/ RegenResolve(p) \/ RegenTx(p) \/ RegenStore(p) \/ OverrideHead(p) \/ OverrideCommit(p)

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
    /\ owners \subseteq Members
    /\ declared \subseteq Listed
    /\ memberLock \in [Members -> Procs \cup {None}]
    /\ head \in Procs \cup {None}

\* The process p waits for: the holder of the lock its next step takes.
LockLabels == {"read.lock", "write.lock", "call.lock", "remove.lock", "demote.lock", "declare.lock", "rotate.lock", "refer.lock", "end.lock"}
HeadLabels == {"read.head", "write.head", "write.tx", "call.headfirst", "call.head",
               "delete.head", "patch.head", "addenv.head", "renamekey.head",
               "signin.head", "remove.head", "demote.head", "declare.head", "rotate.head", "refer.head", "refer.tx", "end.head",
               "regen.tx", "override.head"}
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

\* Nor does anything after it read, wrap, write or grant there, add an
\* environment to it, or rename, archive or restore a key in it.
Reaches == {"secret.read", "key.wrap", "secret.write", "access.grant", "environment.create", "secret.rename"}
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

\* The grants as the first n entries of the log leave them: the ones at the
\* start, then each `access.grant`, `access.revoke` and `member.remove`.
RECURSIVE GrantsAfter(_)
GrantsAfter(n) ==
    IF n = 0 THEN InitGrants
    ELSE LET e == log[n]
             before == GrantsAfter(n - 1)
         IN CASE e.kind = "access.grant"  -> before \cup {[who |-> e.who, at |-> e.at]}
              [] e.kind = "access.revoke" -> before \ {[who |-> e.who, at |-> e.at]}
              [] e.kind = "member.remove" -> {g \in before : g.who # e.who}
              [] OTHER                    -> before

\* Where a read was decided: through a reference, at its holder.
DecidedAt(e) == IF e.via # NoRef THEN "hold" ELSE e.at

\* No `secret.read` for a member follows, in the log, the revocation or the
\* removal that took their last grant covering where it was decided, unless
\* a grant covering it again comes between.
NothingReleasedAfterRevocation ==
    \A j \in 1..Len(log) :
        log[j].kind = "secret.read" =>
            \E g \in GrantsAfter(j - 1) : g.who = log[j].who /\ Covers(g.at, DecidedAt(log[j]))

\* No `secret.read` through a reference follows its `reference.end`, or the
\* deletion of its source's place or its holder's, in the log.
NothingReleasedThroughEndedReference ==
    \A i, j \in 1..Len(log) :
        (i < j /\ log[j].kind = "secret.read" /\ log[j].via # NoRef) =>
            ~(\/ log[i].kind = "reference.end" /\ log[i].via = log[j].via
              \/ log[i].kind = "delete" /\ (Covers(log[i].at, "env") \/ Covers(log[i].at, "hold")))

\* A reference that has not ended is held in a standing place, where the API
\* can name its holder, and so break it. One held in a deleted place would
\* keep its source from being archived, with no path left to break it.
EveryReferenceBreakable == (refRow # NoRef /\ ~Ended(refRow)) => ~Gone("hold")

\* And one held in a live place reads a live source: a reference is made
\* only to a live source, and archiving one is refused while a reference
\* held in a live place elsewhere reads it. Unless its holder was archived
\* when the source was, and was restored since: then it reads an archived
\* source, and its reads refuse, as any broken reference's.
ReferencedSourcesStayLive ==
    (refRow # NoRef /\ ~Ended(refRow) /\ Live("hold") /\ refRow \notin excused) => Live("env")

\* Once the instance has an Owner of all of it, it always does: the last
\* one is never demoted or removed, by anyone, themselves included.
OwnerStays ==
    (InitOwners # {} \/ declared # {}) => ActiveOwners # {}

\* Someone the deployment names, once made an Owner, stays one: nobody
\* demotes or removes them, themselves included.
DeclaredStay == declared \subseteq ActiveOwners

\* A regenerate in a fork commits only over what it was listed with: the
\* parent's key still under the name it regenerates, at the version it
\* replaces. Otherwise the fork would hold an override named after a key
\* the parent no longer has, beside the renamed one it still inherits.
RegeneratesReplaceWhatTheyListed == \A r \in regens : r.key = "k1" /\ r.version = r.listed

=============================================================================
