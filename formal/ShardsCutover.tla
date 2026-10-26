---------------------------- MODULE ShardsCutover ----------------------------
(* The cutover from 0.14 to 0.15 (formal/Shards.md), two ways: close and
   carry (B), and the chain continued (A). Each is its own spec over its own
   variables; the other's stay as they start (each action keeps them).

   0.14 has one audit
   chain, appended under its head's lock by both its logins: the app's
   (sign-ins, writes) and the vault's (every decision, and every change to
   members and grants, in the transaction that makes it). A 0.14 vault
   releases a value only once the read's entry has committed. 0.14
   instances still run while the deploy goes out, and do anything at any
   time.

   B: `coffre migrate` carries the grant into 0.15's layout (copy), closes the
   old chain with a final vault-signed checkpoint at its head (close), and
   revokes INSERT on the old audit table (revoke); then 0.15 starts and
   releases from its own layout, each release an entry in a shard's lane
   (Shards.tla).

   A: no copy and no closing checkpoint. 0.14's chain goes on as the control
   lane, and 0.14 and 0.15 share the tables. One migration transaction
   installs the revision row and a trigger on every table uses decide on.
   0.14 instances still run: their reads decide under the head on the
   current rows and append to the chain; their writes to what uses decide
   on fail on the trigger, which takes only a fenced change's. 0.15's
   changes take the head and the revision's row, fence the shard, commit
   (the change, the revision and a control entry) and answer; its shard
   answers uses as in Shards.tla.

   Protections, each turned off by a constant to show TLC finds the race:
     OldLoginRevoked         revoke takes the 0.14 vault login's INSERT
     AppLoginRevoked         and the 0.14 app login's, which has one too
                             (packages/db's baseline grants it)
     CutoverInOneTransaction copy, close and revoke are one transaction under
                             the old head's lock (off: three, in that order)
     FencedWritesOnly        from the copy (B) or the migration (A), Postgres
                             refuses a write to what uses decide on from a
                             transaction that has not fenced (Shards.tla), the
                             old tables' included
     TriggerInstalledWithRevision  (A) the trigger comes in the transaction
                             that installs the revision row (off: in a later
                             step, which may come after 0.15 started)
     ChangeTakesHead         (A) a 0.15 change holds the chain's head from
                             before its fences to its commit *)
EXTENDS Integers, Sequences, TLC

CONSTANTS MaxOld, MaxNew, Uses
CONSTANTS OldLoginRevoked, AppLoginRevoked, CutoverInOneTransaction, FencedWritesOnly,
          TriggerInstalledWithRevision, ChangeTakesHead

VARIABLES
  oldLog,     \* the old chain: [by, kind]
  closedAt,   \* the closing checkpoint's head, or -1 before it
  inserts,    \* the logins that may still append to the old chain
  oldGrant,   \* 0.14's grant
  newGrant,   \* 0.15's copy of it
  fenced,     \* Postgres refuses unfenced writes to the grants
  step,       \* the migration's next step
  olds,       \* what the 0.14 instances did
  answered,   \* ghost: a 0.14 revocation was answered
  released    \* ghost: each value released: [ver, k (its entry), after]

\* A's.
VARIABLES
  grant,      \* the tables' grant, and how many times it changed (a ghost)
  revision,   \* the revision row
  installed,  \* what the migration installed: "revision", "trigger"
  started,    \* 0.15 runs
  lane,       \* the chain, 0.14's and now the control lane: [by, kind, prev]
  aOlds,      \* what the 0.14 instances did
  chg,        \* the 0.15 change: [st, kind, rev, prev, base, acked, gen, n]
  floor,      \* the shard's floor
  standing,   \* the shard's kept standing: [has, grant, rev]
  use,        \* each use the shard serves: [st, after, rg, rr]
  shardLane,  \* the uses with an entry in the shard's lane
  lastRevoke, \* ghost: the grant's generation at the newest revocation answered
  aReleased,  \* ghost: each value released: [ver, gen, after, k, u]
  lost        \* ghost: a change wrote over a revocation it had not seen

vars == <<oldLog, closedAt, inserts, oldGrant, newGrant, fenced, step, olds, answered, released>>
varsA == <<grant, revision, installed, started, lane, aOlds, chg, floor, standing, use, shardLane, lastRevoke, aReleased, lost>>

Revoked == (IF OldLoginRevoked THEN {"vault"} ELSE {}) \cup (IF AppLoginRevoked THEN {"app"} ELSE {})

Init ==
  /\ oldLog = <<>>
  /\ closedAt = -1
  /\ inserts = {"app", "vault"}
  /\ oldGrant = TRUE
  /\ newGrant = FALSE
  /\ fenced = FALSE
  /\ step = IF CutoverInOneTransaction THEN "cutover" ELSE "copy"
  /\ olds = 0
  /\ answered = FALSE
  /\ released = {}

-----------------------------------------------------------------------------
(* 0.14, still running. *)

Old == olds < MaxOld /\ olds' = olds + 1

\* An entry of the app's or the vault's own: a sign-in, a write.
OldEntry(by) ==
  /\ Old /\ by \in inserts
  /\ oldLog' = Append(oldLog, [by |-> by, kind |-> "event"])
  /\ UNCHANGED <<varsA, closedAt, inserts, oldGrant, newGrant, fenced, step, answered, released>>

\* A read: decided under the head, its entry committed, then the value.
OldRead ==
  /\ Old /\ "vault" \in inserts /\ oldGrant
  /\ oldLog' = Append(oldLog, [by |-> "vault", kind |-> "read"])
  /\ released' = released \cup {[ver |-> 14, k |-> Len(oldLog) + 1, after |-> answered]}
  /\ UNCHANGED <<varsA, closedAt, inserts, oldGrant, newGrant, fenced, step, answered>>

\* A revocation: the grant and its entry in one transaction, then the answer.
OldRevoke ==
  /\ Old /\ "vault" \in inserts /\ oldGrant /\ ~fenced
  /\ oldGrant' = FALSE
  /\ oldLog' = Append(oldLog, [by |-> "vault", kind |-> "revoke"])
  /\ answered' = TRUE
  /\ UNCHANGED <<varsA, closedAt, inserts, newGrant, fenced, step, released>>

-----------------------------------------------------------------------------
(* The migration. *)

\* One transaction, under the old head's lock: no 0.14 append between.
Cutover ==
  /\ step = "cutover"
  /\ inserts' = inserts \ Revoked
  /\ newGrant' = oldGrant
  /\ fenced' = FencedWritesOnly
  /\ closedAt' = Len(oldLog)
  /\ step' = "started"
  /\ UNCHANGED <<varsA, oldLog, oldGrant, olds, answered, released>>

Copy ==
  /\ step = "copy"
  /\ newGrant' = oldGrant
  /\ fenced' = FencedWritesOnly
  /\ step' = "close"
  /\ UNCHANGED <<varsA, oldLog, closedAt, inserts, oldGrant, olds, answered, released>>

Close ==
  /\ step = "close"
  /\ closedAt' = Len(oldLog)
  /\ step' = "revoke"
  /\ UNCHANGED <<varsA, oldLog, inserts, oldGrant, newGrant, fenced, olds, answered, released>>

Revoke ==
  /\ step = "revoke"
  /\ inserts' = inserts \ Revoked
  /\ step' = "started"
  /\ UNCHANGED <<varsA, oldLog, closedAt, oldGrant, newGrant, fenced, olds, answered, released>>

\* 0.15 releases from its own layout, each release its own entry.
NewRead ==
  /\ step = "started" /\ newGrant
  /\ released' = released \cup {[ver |-> 15, k |-> 0, after |-> answered]}
  /\ UNCHANGED <<varsA, oldLog, closedAt, inserts, oldGrant, newGrant, fenced, step, olds, answered>>

Next ==
  \/ \E by \in {"app", "vault"} : OldEntry(by)
  \/ OldRead \/ OldRevoke
  \/ Cutover \/ Copy \/ Close \/ Revoke
  \/ NewRead

-----------------------------------------------------------------------------
(* A: the chain continued. *)

NoGrant == [on |-> FALSE, gen |-> 0]
NoStanding == [has |-> FALSE, grant |-> NoGrant, rev |-> 0]

InitA ==
  /\ grant = [on |-> TRUE, gen |-> 0]
  /\ revision = 0
  /\ installed = {}
  /\ started = FALSE
  /\ lane = <<>>
  /\ aOlds = 0
  /\ chg = [st |-> "idle", kind |-> "none", rev |-> 0, prev |-> 0, base |-> 0, acked |-> FALSE, gen |-> 0, n |-> 0]
  /\ floor = 0
  /\ standing = NoStanding
  /\ use = [u \in Uses |-> [st |-> "idle", after |-> 0, rg |-> NoGrant, rr |-> 0]]
  /\ shardLane = {}
  /\ lastRevoke = 0
  /\ aReleased = {}
  /\ lost = FALSE

\* A 0.15 change holds the head: 0.14's appends wait.
HeadHeld == ChangeTakesHead /\ chg.st = "fencing"

Entry(by, kind) == [by |-> by, kind |-> kind, prev |-> Len(lane)]

\* 0.14: an entry of the app's or the vault's own, under the head.
AOldEntry(by) ==
  /\ aOlds < MaxOld /\ ~HeadHeld
  /\ aOlds' = aOlds + 1
  /\ lane' = Append(lane, Entry(by, "event"))
  /\ UNCHANGED <<vars, grant, revision, installed, started, chg, floor, standing, use, shardLane, lastRevoke, aReleased, lost>>

\* 0.14: a read, decided under the head on the rows as they are, its entry
\* committed, then the value.
AOldRead ==
  /\ aOlds < MaxOld /\ ~HeadHeld /\ grant.on
  /\ aOlds' = aOlds + 1
  /\ lane' = Append(lane, Entry("vault", "read"))
  /\ aReleased' = aReleased \cup {[ver |-> 14, gen |-> grant.gen, after |-> lastRevoke, k |-> Len(lane) + 1, u |-> "none"]}
  /\ UNCHANGED <<vars, grant, revision, installed, started, chg, floor, standing, use, shardLane, lastRevoke, lost>>

\* 0.14: a revocation or a grant, the rows and their entry under the head,
\* then the answer. It does not fence: the trigger refuses it.
AOldChange ==
  /\ aOlds < MaxOld /\ ~HeadHeld /\ "trigger" \notin installed
  /\ aOlds' = aOlds + 1
  /\ grant' = [on |-> ~grant.on, gen |-> grant.gen + 1]
  /\ lane' = Append(lane, Entry("vault", "change"))
  /\ lastRevoke' = IF grant.on THEN grant.gen + 1 ELSE lastRevoke
  /\ UNCHANGED <<vars, revision, installed, started, chg, floor, standing, use, shardLane, aReleased, lost>>

\* The migration: the revision row and the trigger, in one transaction; or,
\* without TriggerInstalledWithRevision, the trigger in a step of its own.
Install ==
  /\ installed = {}
  /\ installed' = {"revision"} \cup (IF TriggerInstalledWithRevision /\ FencedWritesOnly THEN {"trigger"} ELSE {})
  /\ UNCHANGED <<vars, grant, revision, started, lane, aOlds, chg, floor, standing, use, shardLane, lastRevoke, aReleased, lost>>

InstallTrigger ==
  /\ ~TriggerInstalledWithRevision /\ FencedWritesOnly
  /\ "revision" \in installed /\ "trigger" \notin installed
  /\ installed' = installed \cup {"trigger"}
  /\ UNCHANGED <<vars, grant, revision, started, lane, aOlds, chg, floor, standing, use, shardLane, lastRevoke, aReleased, lost>>

\* 0.15 deploys once the revision row is there.
StartNew ==
  /\ "revision" \in installed /\ ~started
  /\ started' = TRUE
  /\ UNCHANGED <<vars, grant, revision, installed, lane, aOlds, chg, floor, standing, use, shardLane, lastRevoke, aReleased, lost>>

\* 0.15: a change takes the head and the revision's row, reads the rows.
ABegin ==
  /\ started /\ chg.st = "idle" /\ chg.n < MaxNew
  /\ chg' = [st |-> "fencing", kind |-> IF grant.on THEN "revoke" ELSE "grant", rev |-> revision + 1,
              prev |-> Len(lane), base |-> grant.gen, acked |-> FALSE, gen |-> 0, n |-> chg.n + 1]
  /\ UNCHANGED <<vars, grant, revision, installed, started, lane, aOlds, floor, standing, use, shardLane, lastRevoke, aReleased, lost>>

\* It fences the shard.
AFence ==
  /\ chg.st = "fencing" /\ ~chg.acked
  /\ floor' = IF chg.rev > floor THEN chg.rev ELSE floor
  /\ chg' = [chg EXCEPT !.acked = TRUE]
  /\ UNCHANGED <<vars, grant, revision, installed, started, lane, aOlds, standing, use, shardLane, lastRevoke, aReleased, lost>>

\* It commits the change, the revision and its control entry, sealed from
\* the head it read: fenced, so the trigger takes it.
ACommit ==
  /\ chg.st = "fencing" /\ chg.acked
  /\ grant' = [on |-> chg.kind = "grant", gen |-> grant.gen + 1]
  /\ revision' = chg.rev
  /\ lane' = Append(lane, [by |-> "0.15", kind |-> "change", prev |-> chg.prev])
  /\ lost' = (lost \/ (grant.gen # chg.base /\ ~grant.on))
  /\ chg' = [chg EXCEPT !.st = "committed", !.gen = grant.gen + 1]
  /\ UNCHANGED <<vars, installed, started, aOlds, floor, standing, use, shardLane, lastRevoke, aReleased>>

AAnswer ==
  /\ chg.st = "committed"
  /\ chg' = [chg EXCEPT !.st = "idle"]
  /\ lastRevoke' = IF chg.kind = "revoke" THEN chg.gen ELSE lastRevoke
  /\ UNCHANGED <<vars, grant, revision, installed, started, lane, aOlds, floor, standing, use, shardLane, aReleased, lost>>

\* The shard: a use arrives.
AInvoke(u) ==
  /\ started /\ use[u].st = "idle"
  /\ use' = [use EXCEPT ![u].st = "new", ![u].after = lastRevoke]
  /\ UNCHANGED <<vars, grant, revision, installed, started, lane, aOlds, chg, floor, standing, shardLane, lastRevoke, aReleased, lost>>

\* The decision on grant g read at r: its entry in the shard's lane, then the reply.
ADecide(u, g, r) ==
  /\ use' = [use EXCEPT ![u].st = "replied"]
  /\ shardLane' = shardLane \cup {u}
  /\ aReleased' = IF g.on THEN aReleased \cup {[ver |-> 15, gen |-> g.gen, after |-> use[u].after, k |-> 0, u |-> u]}
                   ELSE aReleased

\* Answered from what it keeps if read at the floor or later; else read again.
AServe(u) ==
  /\ use[u].st = "new"
  /\ IF standing.has /\ standing.rev >= floor
     THEN /\ ADecide(u, standing.grant, standing.rev)
          /\ UNCHANGED standing
     ELSE /\ use' = [use EXCEPT ![u].st = "loaded", ![u].rg = grant, ![u].rr = revision]
          /\ UNCHANGED <<vars, standing, shardLane, aReleased>>
  /\ UNCHANGED <<vars, grant, revision, installed, started, lane, aOlds, chg, floor, lastRevoke, lost>>

\* The read is back: at the floor or later, kept and decided on; else 503.
ACheck(u) ==
  /\ use[u].st = "loaded"
  /\ IF use[u].rr >= floor
     THEN /\ ADecide(u, use[u].rg, use[u].rr)
          /\ standing' = [has |-> TRUE, grant |-> use[u].rg, rev |-> use[u].rr]
     ELSE /\ use' = [use EXCEPT ![u].st = "new"]
          /\ UNCHANGED <<vars, standing, shardLane, aReleased>>
  /\ UNCHANGED <<vars, grant, revision, installed, started, lane, aOlds, chg, floor, lastRevoke, lost>>

NextA ==
  \/ \E by \in {"app", "vault"} : AOldEntry(by)
  \/ AOldRead \/ AOldChange
  \/ Install \/ InstallTrigger \/ StartNew
  \/ ABegin \/ AFence \/ ACommit \/ AAnswer
  \/ \E u \in Uses : AInvoke(u) \/ AServe(u) \/ ACheck(u)

\* B, close and carry.
Spec == Init /\ InitA /\ [][Next]_<<vars, varsA>>

\* A, the chain continued.
ContinueSpec == Init /\ InitA /\ [][NextA]_<<vars, varsA>>

-----------------------------------------------------------------------------

\* Nothing is appended to the old chain after its closing checkpoint.
NothingAfterClose == closedAt >= 0 => Len(oldLog) = closedAt

\* Every value released has its entry: B, 0.14's in the old chain, before
\* the closing checkpoint, where a verification from it finds it; A, 0.14's
\* in the chain, 0.15's in the shard's lane.
EveryReleaseAudited ==
  /\ \A r \in released : r.ver = 14 =>
       /\ r.k <= Len(oldLog) /\ oldLog[r.k].kind = "read"
       /\ (closedAt >= 0 => r.k <= closedAt)
  /\ \A r \in aReleased :
       IF r.ver = 14 THEN r.k <= Len(lane) /\ lane[r.k].kind = "read" ELSE r.u \in shardLane

\* No revocation answered is lost: B, no value is released after it, by
\* either version; A, no change writes over it unseen.
RevocationCarried == (\A r \in released : ~r.after) /\ ~lost

\* A: no value is released, by a 0.14 reader or a 0.15 shard, on a grant
\* read before a revocation answered before the use arrived.
NothingReleasedAfterRevocation == \A r \in aReleased : r.gen >= r.after

\* A: the chain, appended by both versions, is chained: each entry sealed
\* from the one before it.
LanesHold == \A k \in 1..Len(lane) : lane[k].prev = k - 1
=============================================================================
