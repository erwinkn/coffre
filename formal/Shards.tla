---------------------------- MODULE Shards ----------------------------
(* 0.15's hot path: uses answered by shards from what they keep, and the
   changes that fence them (formal/Shards.md).

   Postgres holds the truth: here, whether one principal holds its grant,
   and the revision every change raises. A change takes the revision's row,
   fences every shard at the next revision, commits the change and the
   revision together, and answers. Rolled back, it tells the shards
   (unfence), best effort.

   A shard is an actor with a storage of its own. It keeps in memory the
   principal's standing (what Postgres said, and at which revision) and its
   floor, the lowest revision it may answer from; a fence raises the floor
   and writes it to the storage before acknowledging. An instance may stop
   at any step, losing its memory but not its storage, and a second may
   start while the first still runs: the storage takes only the newest
   instance's writes, so the older one breaks at its next write.

   A use is answered from the standing kept if it was read at the floor or
   later. Otherwise it reads the standing again, in one statement with the
   revision; read below the floor, it probes the revision's row (FOR UPDATE
   NOWAIT): free and below the floor, the change that fenced rolled back,
   and the floor comes down to it; else 503, and the client tries again.
   A decision is an entry in the shard's storage, durable before the reply.

   Messages are lost, duplicated and delayed. Every change may roll back at
   any step before it commits, and the answer to its COMMIT may be lost.

   Protections, each turned off by a constant to show TLC finds the race:
     FencePersisted     a fence is in the storage before it is acknowledged
     FenceBeforeCommit  every shard is fenced before the change commits
     AllAcked           the change commits only once every shard acknowledged
     FloorChecked       a standing is used only if read at the floor or later
     NowaitProbe        the floor comes down only through the probe (off: a
                        timer lowers it to the committed revision)
     ProbeKeepsFence    the probe lowers the floor only if no fence came
                        while it was out (a count of fences, not the floor's
                        value: a change rolled back and the next one fence
                        at the same revision)
     UnfenceProbes      an unfence starts a probe (off: it lowers the floor
                        it names, as experiments/lanes does)
     OneSnapshot        the standing and its revision are read in one statement
     DurableBeforeReply the entry is in the storage before the reply leaves
     StorageArbiter     the storage takes only the newest instance's writes
                        (Cloudflare's guarantee; on Node, a lease's epoch
                        checked in every write)
     FencedWritesOnly   Postgres refuses a write to what uses decide on from
                        a transaction that has not fenced (a trigger, and a
                        marker only the change function sets once its
                        fences are acknowledged); off, a writer that does
                        not fence (a 0.14 instance during the deploy, or a
                        path that forgot) revokes and answers *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Shards,       \* the shards that serve the principal (its fan-out)
  Slots,        \* instances a shard may run, at most two at once
  Uses,         \* the uses
  MaxChanges,   \* changes begun, committed or rolled back
  MaxStarts,    \* instances started after the first
  Losses,       \* messages may be lost
  Duplicates,   \* messages may be delivered twice
  LostCommits   \* the answer to a COMMIT may be lost

CONSTANTS
  FencePersisted, FenceBeforeCommit, AllAcked, FloorChecked, NowaitProbe,
  ProbeKeepsFence, UnfenceProbes, OneSnapshot, DurableBeforeReply, StorageArbiter,
  FencedWritesOnly

VARIABLES
  grant,        \* Postgres: whether the principal holds its grant, and how many
                \* times that changed (a ghost: what a standing was read from)
  revision,     \* Postgres: the committed revision
  locked,       \* Postgres: the revision's row is locked by a change
  ch,           \* the changer: [st, rev, kind, acks, n, gen]
  rogue,        \* the writer that does not fence has revoked
  lastRevoke,   \* the grant's generation at the newest revocation answered
  net,          \* fences and unfences in flight: [k, rev, s, id]
  inst,         \* each shard's instances, in memory: [alive, floor, standing]
  sFloor,       \* each shard's storage: its floor
  sOwner,       \* each shard's storage: the instance whose writes it takes
  sEntries,     \* each shard's storage: its entries, [u, rev, allow]
  starts,       \* instances started
  probes,       \* probes an unfence started: [s, i, free, value, overtaken]
  use           \* each use

vars == <<grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

Max(a, b) == IF a > b THEN a ELSE b

NoGrant == [on |-> FALSE, gen |-> 0]
NoStanding == [has |-> FALSE, grant |-> NoGrant, rev |-> 0]
Fresh == [alive |-> FALSE, floor |-> 0, standing |-> NoStanding]
First == CHOOSE i \in Slots : \A j \in Slots : i <= j

\* A use between its arrival and its decision, in an instance's memory.
Out == {"loading", "half", "loaded", "probed"}

\* A use: where it is, what it read, what its probe found, what it was answered.
Blank == [st |-> "idle", s |-> CHOOSE s \in Shards : TRUE, i |-> First, after |-> 0,
          rg |-> NoGrant, rr |-> 0, free |-> FALSE, value |-> 0, overtaken |-> FALSE,
          allow |-> FALSE, gen |-> 0, rev |-> 0, revAt |-> 0]

\* The use tried again: all it keeps is when it arrived.
Again(r) == [Blank EXCEPT !.st = "new", !.after = r.after]

Init ==
  /\ grant = [on |-> TRUE, gen |-> 0]
  /\ revision = 0
  /\ locked = FALSE
  /\ ch = [st |-> "idle", rev |-> 0, kind |-> "none", acks |-> {}, n |-> 0, gen |-> 0]
  /\ rogue = FALSE
  /\ lastRevoke = 0
  /\ net = {}
  /\ inst = [s \in Shards |-> [i \in Slots |-> [Fresh EXCEPT !.alive = (i = First)]]]
  /\ sFloor = [s \in Shards |-> 0]
  /\ sOwner = [s \in Shards |-> First]
  /\ sEntries = [s \in Shards |-> {}]
  /\ starts = 0
  /\ probes = {}
  /\ use = [u \in Uses |-> Blank]

Alive(s, i) == inst[s][i].alive
\* The storage takes this instance's writes.
Writes(s, i) == ~StorageArbiter \/ sOwner[s] = i

\* An instance stops, or breaks at a write its storage refused: its memory
\* goes, the uses it held are tried again by their clients, its probes die.
Down(s, i) ==
  /\ inst' = [inst EXCEPT ![s][i] = Fresh]
  /\ use' = [u \in Uses |-> IF use[u].s = s /\ use[u].i = i /\ use[u].st \in Out
                            THEN Again(use[u]) ELSE use[u]]
  /\ probes' = {p \in probes : p.s # s \/ p.i # i}

-----------------------------------------------------------------------------
(* The changer: one at a time, under the revision's row. *)

Fences(R, id) == {[k |-> "fence", rev |-> R, s |-> s, id |-> id] : s \in Shards}

\* It takes the row and fences every shard at the next revision; or, without
\* FenceBeforeCommit, commits first and fences after.
Begin ==
  /\ ch.st = "idle" /\ ch.n < MaxChanges /\ ~locked
  /\ LET R == revision + 1
         id == ch.n + 1
         kind == IF grant.on THEN "revoke" ELSE "grant"
     IN /\ net' = net \cup Fences(R, id)
        /\ IF FenceBeforeCommit
           THEN /\ locked' = TRUE
                /\ ch' = [st |-> "fencing", rev |-> R, kind |-> kind, acks |-> {}, n |-> id, gen |-> 0]
                /\ UNCHANGED <<grant, revision>>
           ELSE /\ grant' = [on |-> kind = "grant", gen |-> grant.gen + 1]
                /\ revision' = R
                /\ ch' = [st |-> "after", rev |-> R, kind |-> kind, acks |-> {}, n |-> id, gen |-> grant.gen + 1]
                /\ UNCHANGED locked
  /\ UNCHANGED <<rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* A fence not acknowledged is sent again.
Resend(s) ==
  LET m == [k |-> "fence", rev |-> ch.rev, s |-> s, id |-> ch.n] IN
  /\ ch.st \in {"fencing", "after"} /\ s \notin ch.acks /\ m \notin net
  /\ net' = net \cup {m}
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* The change and the revision commit together.
Commit ==
  /\ ch.st = "fencing"
  /\ IF AllAcked THEN ch.acks = Shards ELSE ch.acks # {}
  /\ grant' = [on |-> ch.kind = "grant", gen |-> grant.gen + 1]
  /\ revision' = ch.rev
  /\ locked' = FALSE
  /\ ch' = [ch EXCEPT !.st = "committed", !.gen = grant.gen + 1]
  /\ UNCHANGED <<rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* The commit's answer is lost: the changer unfences as if it had rolled
\* back, and tries again with the change's id, which finds it done and
\* answers.
Unsure ==
  /\ LostCommits /\ ch.st = "committed"
  /\ net' = net \cup {[k |-> "unfence", rev |-> ch.rev, s |-> s, id |-> ch.n] : s \in Shards}
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* Then it answers: "revoke returned".
Answer ==
  /\ \/ ch.st = "committed"
     \/ ch.st = "after" /\ ch.acks = Shards
  /\ ch' = [ch EXCEPT !.st = "idle"]
  /\ lastRevoke' = IF ch.kind = "revoke" THEN ch.gen ELSE lastRevoke
  /\ UNCHANGED <<grant, revision, locked, rogue, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* A writer that does not fence revokes, without the revision's row, and
\* answers. With FencedWritesOnly, Postgres refuses it.
Unfenced ==
  /\ ~FencedWritesOnly /\ ~rogue /\ grant.on
  /\ grant' = [on |-> FALSE, gen |-> grant.gen + 1]
  /\ rogue' = TRUE
  /\ lastRevoke' = grant.gen + 1
  /\ UNCHANGED <<revision, locked, ch, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* Anything fails before the commit: it rolls back and unfences, best effort.
Abort ==
  /\ ch.st = "fencing"
  /\ locked' = FALSE
  /\ ch' = [ch EXCEPT !.st = "idle"]
  /\ net' = net \cup {[k |-> "unfence", rev |-> ch.rev, s |-> s, id |-> ch.n] : s \in Shards}
  /\ UNCHANGED <<grant, revision, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

-----------------------------------------------------------------------------
(* The shards. *)

\* A fence raises the floor, writes it to the storage and acknowledges.
Fence(m, i) ==
  LET s == m.s IN
  IF FencePersisted /\ ~Writes(s, i)
  THEN /\ Down(s, i)
       /\ UNCHANGED <<ch, sFloor>>
  ELSE /\ inst' = [inst EXCEPT ![s][i].floor = Max(@, m.rev)]
       /\ sFloor' = IF FencePersisted THEN [sFloor EXCEPT ![s] = Max(@, m.rev)] ELSE sFloor
       /\ ch' = IF ch.n = m.id /\ ch.st \in {"fencing", "after"} THEN [ch EXCEPT !.acks = @ \cup {s}] ELSE ch
       \* Every probe this instance has out is overtaken.
       /\ use' = [u \in Uses |-> IF use[u].s = s /\ use[u].i = i /\ use[u].st = "probed"
                                 THEN [use[u] EXCEPT !.overtaken = TRUE] ELSE use[u]]
       /\ probes' = {IF p.s = s /\ p.i = i THEN [p EXCEPT !.overtaken = TRUE] ELSE p : p \in probes}

\* An unfence starts a probe; or, without UnfenceProbes, lowers the floor it names.
Unfence(m, i) ==
  LET s == m.s IN
  /\ IF UnfenceProbes
     THEN /\ probes' = probes \cup {[s |-> s, i |-> i, free |-> ~locked, value |-> revision, overtaken |-> FALSE]}
          /\ UNCHANGED inst
     ELSE /\ inst' = [inst EXCEPT ![s][i].floor = IF @ = m.rev THEN m.rev - 1 ELSE @]
          /\ UNCHANGED probes
  /\ UNCHANGED <<ch, sFloor, use>>

\* A message delivered, and kept in flight to be delivered again (Duplicates).
Keeps == IF Duplicates THEN BOOLEAN ELSE {FALSE}

Deliver(m, i, keep) ==
  /\ m \in net /\ Alive(m.s, i)
  /\ net' = IF keep THEN net ELSE net \ {m}
  /\ IF m.k = "fence" THEN Fence(m, i) ELSE Unfence(m, i)
  /\ UNCHANGED <<grant, revision, locked, rogue, lastRevoke, sOwner, sEntries, starts>>

Delivered == \E m \in net, i \in Slots, keep \in Keeps : Deliver(m, i, keep)

Drop(m) ==
  /\ Losses /\ m \in net
  /\ net' = net \ {m}
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* Lower the floor to what the probe found, if the row was free, below the
\* floor, and (ProbeKeepsFence) no fence came while the probe was out.
Lowered(s, i, free, value, overtaken) ==
  LET fl == inst[s][i].floor IN
  IF free /\ value < fl /\ (~ProbeKeepsFence \/ ~overtaken) THEN value ELSE fl

ApplyUnfenceProbe(p) ==
  /\ p \in probes /\ Alive(p.s, p.i)
  /\ probes' = probes \ {p}
  /\ inst' = [inst EXCEPT ![p.s][p.i].floor = Lowered(p.s, p.i, p.free, p.value, p.overtaken)]
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts, use>>

UnfenceProbed == \E p \in probes : ApplyUnfenceProbe(p)

\* Without the probe, a timer lowers the floor to the committed revision.
Timer(s, i) ==
  /\ ~NowaitProbe /\ Alive(s, i) /\ inst[s][i].floor > revision
  /\ inst' = [inst EXCEPT ![s][i].floor = revision]
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts, probes, use>>

\* An instance starts, from its storage, and the storage takes its writes
\* from now: the one running before, if any, still runs until it writes.
Start(s, i) ==
  /\ ~Alive(s, i) /\ starts < MaxStarts
  /\ inst' = [inst EXCEPT ![s][i] = [Fresh EXCEPT !.alive = TRUE, !.floor = sFloor[s]]]
  /\ sOwner' = [sOwner EXCEPT ![s] = i]
  /\ starts' = starts + 1
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sEntries, probes, use>>

Crash(s, i) ==
  /\ Alive(s, i) /\ starts < MaxStarts
  /\ Down(s, i)
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts>>

-----------------------------------------------------------------------------
(* The uses. *)

Invoke(u) ==
  /\ use[u].st = "idle"
  /\ use' = [use EXCEPT ![u] = [@ EXCEPT !.st = "new", !.after = lastRevoke]]
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

Entry(u, g, r) == [u |-> u, rev |-> r, allow |-> g]

\* The decision, on grant g read at revision r, by instance i, whose memory
\* is then me: an entry in the storage, then the reply. A storage that
\* refuses the write breaks the instance, and the client tries again.
Decide(u, s, i, g, r, me) ==
  LET replied == [Blank EXCEPT !.st = "replied", !.s = s, !.i = i, !.after = use[u].after,
                               !.allow = g.on, !.gen = g.gen, !.rev = r, !.revAt = revision] IN
  /\ IF ~DurableBeforeReply
     THEN /\ inst' = [inst EXCEPT ![s][i] = me]
          /\ use' = [use EXCEPT ![u] = replied]
          /\ UNCHANGED <<sEntries, probes>>
     ELSE IF Writes(s, i)
     THEN /\ sEntries' = [sEntries EXCEPT ![s] = @ \cup {Entry(u, g.on, r)}]
          /\ inst' = [inst EXCEPT ![s][i] = me]
          /\ use' = [use EXCEPT ![u] = replied]
          /\ UNCHANGED probes
     ELSE /\ Down(s, i)
          /\ UNCHANGED sEntries
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, starts>>

\* The use reaches an instance: answered from the standing kept, or read again.
Serve(u, s, i) ==
  LET sd == inst[s][i].standing IN
  /\ use[u].st = "new" /\ Alive(s, i)
  /\ IF sd.has /\ (~FloorChecked \/ sd.rev >= inst[s][i].floor)
     THEN Decide(u, s, i, sd.grant, sd.rev, inst[s][i])
     ELSE /\ use' = [use EXCEPT ![u] = [@ EXCEPT !.st = "loading", !.s = s, !.i = i]]
          /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

\* The standing and the revision, in one statement; or, without OneSnapshot,
\* the rows first and the revision after.
Load(u) ==
  /\ use[u].st = "loading" /\ Alive(use[u].s, use[u].i)
  /\ use' = [use EXCEPT ![u] = IF OneSnapshot THEN [@ EXCEPT !.st = "loaded", !.rg = grant, !.rr = revision]
                                              ELSE [@ EXCEPT !.st = "half", !.rg = grant]]
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

LoadRevision(u) ==
  /\ use[u].st = "half" /\ Alive(use[u].s, use[u].i)
  /\ use' = [use EXCEPT ![u] = [@ EXCEPT !.st = "loaded", !.rr = revision]]
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

\* The read is back: at the floor or later, kept and decided on; below it,
\* the probe (the row taken NOWAIT and let go: whether it was free, and the
\* revision); without NowaitProbe, 503.
Check(u) ==
  LET s == use[u].s
      i == use[u].i
      fl == inst[s][i].floor
      r == use[u].rr
      g == use[u].rg
  IN
  /\ use[u].st = "loaded" /\ Alive(s, i)
  /\ IF ~FloorChecked \/ r >= fl
     THEN Decide(u, s, i, g, r, [inst[s][i] EXCEPT !.standing = [has |-> TRUE, grant |-> g, rev |-> r]])
     ELSE /\ use' = [use EXCEPT ![u] = IF NowaitProbe
                                      THEN [@ EXCEPT !.st = "probed", !.free = ~locked, !.value = revision, !.overtaken = FALSE]
                                      ELSE Again(@)]
          /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

\* The probe is back: the floor perhaps lower, and the use tried again (read
\* again, or 503 and the client's retry: the same here).
ApplyProbe(u) ==
  LET s == use[u].s
      i == use[u].i
  IN
  /\ use[u].st = "probed" /\ Alive(s, i)
  /\ inst' = [inst EXCEPT ![s][i].floor = Lowered(s, i, use[u].free, use[u].value, use[u].overtaken)]
  /\ use' = [use EXCEPT ![u] = Again(@)]
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts, probes>>

\* Without DurableBeforeReply, the entry is written after the reply, if the
\* instance still runs and its storage takes it.
Persist(u) ==
  LET s == use[u].s
      i == use[u].i
  IN
  /\ ~DurableBeforeReply
  /\ use[u].st = "replied" /\ Entry(u, use[u].allow, use[u].rev) \notin sEntries[s]
  /\ Alive(s, i) /\ Writes(s, i)
  /\ sEntries' = [sEntries EXCEPT ![s] = @ \cup {Entry(u, use[u].allow, use[u].rev)}]
  /\ UNCHANGED <<grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, starts, probes, use>>

-----------------------------------------------------------------------------

UseStep(u) ==
  \/ \E s \in Shards, i \in Slots : Serve(u, s, i)
  \/ Load(u) \/ LoadRevision(u) \/ Check(u) \/ ApplyProbe(u) \/ Persist(u)

Next ==
  \/ Begin \/ Commit \/ Unsure \/ Answer \/ Abort \/ Unfenced
  \/ \E s \in Shards : Resend(s)
  \/ \E m \in net : Drop(m)
  \/ Delivered
  \/ UnfenceProbed
  \/ \E s \in Shards, i \in Slots : Timer(s, i) \/ Start(s, i) \/ Crash(s, i)
  \/ \E u \in Uses : Invoke(u) \/ UseStep(u)

Spec == Init /\ [][Next]_vars

\* Every step but a use's arrival, a change's start, a rollback, a loss, a
\* stop and a start is taken eventually; a shard sent messages again and
\* again gets some (each delivery takes one, and only a fence not yet
\* acknowledged is sent again).
Fairness ==
  /\ \A u \in Uses : WF_vars(UseStep(u))
  /\ WF_vars(Commit \/ Answer)
  /\ \A s \in Shards : WF_vars(Resend(s))
  /\ \A s \in Shards : SF_vars(\E m \in net, i \in Slots, keep \in Keeps : m.s = s /\ Deliver(m, i, keep))
  /\ WF_vars(\E p \in probes : ApplyUnfenceProbe(p))

LiveSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* What must hold. *)

Replied(u) == use[u].st = "replied"

\* No use that arrived after a revocation was answered is allowed on a
\* grant read before it.
NothingReleasedAfterRevocation ==
  \A u \in Uses : Replied(u) /\ use[u].allow => use[u].gen >= use[u].after

\* A use's entry names revision r: change r committed before it was decided,
\* and change r + 1 after. Uses and changes are one order.
UsesOrderedAgainstChanges ==
  \A u \in Uses : Replied(u) => use[u].rev = use[u].revAt

\* A reply with a value has its entry in the shard's storage, or one about
\* to be written by an instance that runs and whose writes the storage takes.
EveryReplyAudited ==
  \A u \in Uses : Replied(u) /\ use[u].allow =>
    \/ Entry(u, TRUE, use[u].rev) \in sEntries[use[u].s]
    \/ Alive(use[u].s, use[u].i) /\ Writes(use[u].s, use[u].i)

\* No floor is past the revision a change in flight would commit: a probe
\* that finds the revision more than one below its floor has found a
\* database restored from an older backup, not a rollback.
FloorsAtMostNext ==
  /\ \A s \in Shards : sFloor[s] <= revision + 1
  /\ \A s \in Shards, i \in Slots : inst[s][i].floor <= revision + 1

\* A change begun ends, answered or rolled back.
ChangesEnd == ch.st # "idle" ~> ch.st = "idle"

\* Every use is answered, a value or a refusal: no fence, a rolled back
\* one's included, refuses forever. (With finitely many changes.)
UsesAnswered == \A u \in Uses : use[u].st # "idle" ~> Replied(u)
=============================================================================
