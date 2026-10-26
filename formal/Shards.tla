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
                        path that forgot) revokes and answers
     EpochChecked       the revision is (epoch, n), and the migration and a
                        database restore write a new epoch; fences, standings
                        and probes carry it, and a shard that meets a newer
                        epoch drops its floor and standing, adopts it and
                        reads again (off: a restore sets the revision back,
                        and floors and standings from before it stand)

   Postgres may be restored once from an earlier backup (Restores): the
   grant and the revision go back to what the backup holds. The restore
   fences every shard first, as a change does, at the backup's revision in
   the new epoch; it is not rolled back once begun. *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Shards,       \* the shards that serve the principal (its fan-out)
  Slots,        \* instances a shard may run, at most two at once
  Uses,         \* the uses
  MaxChanges,   \* changes begun, committed or rolled back
  MaxStarts,    \* instances started after the first
  Losses,       \* messages may be lost
  Duplicates,   \* messages may be delivered twice
  LostCommits,  \* the answer to a COMMIT may be lost
  Restores,     \* restores of Postgres from a backup
  Repeats       \* a use answered arrives again (the client's next request)

CONSTANTS
  FencePersisted, FenceBeforeCommit, AllAcked, FloorChecked, NowaitProbe,
  ProbeKeepsFence, UnfenceProbes, OneSnapshot, DurableBeforeReply, StorageArbiter,
  FencedWritesOnly, EpochChecked

VARIABLES
  grant,        \* Postgres: whether the principal holds its grant, and how many
                \* times that changed (a ghost: what a standing was read from)
  revision,     \* Postgres: the committed revision
  epoch,        \* Postgres: the revision's epoch
  backup,       \* a backup of Postgres: [taken, on, rev]
  restores,     \* restores of it
  locked,       \* Postgres: the revision's row is locked by a change
  ch,           \* the changer: [st, rev, kind, acks, n, gen]
  rogue,        \* the writer that does not fence has revoked
  lastRevoke,   \* the grant's generation at the newest revocation answered
  net,          \* fences and unfences in flight: [k, rev, s, id]
  inst,         \* each shard's instances, in memory: [alive, floor, standing]
  sFloor,       \* each shard's storage: its floor
  sEpoch,       \* each shard's storage: its floor's epoch
  sOwner,       \* each shard's storage: the instance whose writes it takes
  sEntries,     \* each shard's storage: its entries, [u, rev, allow]
  starts,       \* instances started
  probes,       \* probes an unfence started: [s, i, free, value, overtaken]
  use           \* each use

vars == <<grant, revision, epoch, backup, restores, sEpoch, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

Max(a, b) == IF a > b THEN a ELSE b

NoGrant == [on |-> FALSE, gen |-> 0]
NoStanding == [has |-> FALSE, grant |-> NoGrant, rev |-> 0, ep |-> 0]
Fresh == [alive |-> FALSE, floor |-> 0, epoch |-> 0, standing |-> NoStanding]
First == CHOOSE i \in Slots : \A j \in Slots : i <= j

\* A use between its arrival and its decision, in an instance's memory.
Out == {"loading", "half", "loaded", "probed"}

\* A use: where it is, what it read, what its probe found, what it was answered.
Blank == [st |-> "idle", s |-> CHOOSE s \in Shards : TRUE, i |-> First, after |-> 0,
          rg |-> NoGrant, rr |-> 0, re |-> 0, free |-> FALSE, value |-> 0, pe |-> 0, overtaken |-> FALSE,
          allow |-> FALSE, gen |-> 0, rev |-> 0, ep |-> 0, revAt |-> 0, epAt |-> 0]

\* The use tried again: all it keeps is when it arrived.
Again(r) == [Blank EXCEPT !.st = "new", !.after = r.after]

Init ==
  /\ grant = [on |-> TRUE, gen |-> 0]
  /\ revision = 0
  /\ epoch = 0
  /\ backup = [taken |-> FALSE, on |-> FALSE, rev |-> 0]
  /\ restores = 0
  /\ locked = FALSE
  /\ ch = [st |-> "idle", rev |-> 0, ep |-> 0, kind |-> "none", acks |-> {}, n |-> 0, gen |-> 0]
  /\ rogue = FALSE
  /\ lastRevoke = 0
  /\ net = {}
  /\ inst = [s \in Shards |-> [i \in Slots |-> [Fresh EXCEPT !.alive = (i = First)]]]
  /\ sFloor = [s \in Shards |-> 0]
  /\ sEpoch = [s \in Shards |-> 0]
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

Msg(k, R, e, s, id) == [k |-> k, rev |-> R, ep |-> e, s |-> s, id |-> id]
Fences(R, e, id) == {Msg("fence", R, e, s, id) : s \in Shards}
Unfences == {Msg("unfence", ch.rev, ch.ep, s, ch.n) : s \in Shards}

\* What a change does: the opposite of what stands; with restores, either
\* (a change to anything else raises the revision too), or a restore of
\* Postgres from the backup, once one is taken and changes followed it.
Kinds ==
  (IF Restores > 0 THEN {"revoke", "grant"} ELSE {IF grant.on THEN "revoke" ELSE "grant"})
  \cup (IF restores < Restores /\ backup.taken /\ backup.rev < revision THEN {"restore"} ELSE {})

\* It takes the row and fences every shard at the next revision; or, without
\* FenceBeforeCommit, commits first and fences after. A restore (`coffre
\* restore`) fences at the backup's revision in a new epoch (EpochChecked;
\* off, in the same one), then puts the backup in place.
Begin ==
  /\ ch.st = "idle" /\ ch.n < MaxChanges /\ ~locked
  /\ \E kind \in Kinds :
     LET R == IF kind = "restore" THEN backup.rev ELSE revision + 1
         e == IF kind = "restore" /\ EpochChecked THEN epoch + 1 ELSE epoch
         id == ch.n + 1
     IN /\ net' = net \cup Fences(R, e, id)
        /\ IF FenceBeforeCommit \/ kind = "restore"
           THEN /\ locked' = TRUE
                /\ ch' = [st |-> "fencing", rev |-> R, ep |-> e, kind |-> kind, acks |-> {}, n |-> id, gen |-> 0]
                /\ UNCHANGED <<grant, revision>>
           ELSE /\ grant' = [on |-> kind = "grant", gen |-> grant.gen + 1]
                /\ revision' = R
                /\ ch' = [st |-> "after", rev |-> R, ep |-> epoch, kind |-> kind, acks |-> {}, n |-> id, gen |-> grant.gen + 1]
                /\ UNCHANGED locked
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* A fence not acknowledged is sent again.
Resend(s) ==
  LET m == Msg("fence", ch.rev, ch.ep, s, ch.n) IN
  /\ ch.st \in {"fencing", "after"} /\ s \notin ch.acks /\ m \notin net
  /\ net' = net \cup {m}
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* The change and the revision commit together. A restore puts the backup in
\* place: the grant as it was (a new generation: what was revoked since may
\* stand again), its revision, and the new epoch.
Commit ==
  /\ ch.st = "fencing"
  /\ IF AllAcked THEN ch.acks = Shards ELSE ch.acks # {}
  /\ grant' = [on |-> IF ch.kind = "restore" THEN backup.on ELSE ch.kind = "grant", gen |-> grant.gen + 1]
  /\ revision' = ch.rev
  /\ epoch' = ch.ep
  /\ restores' = IF ch.kind = "restore" THEN restores + 1 ELSE restores
  /\ locked' = FALSE
  /\ ch' = [ch EXCEPT !.st = "committed", !.gen = grant.gen + 1]
  /\ UNCHANGED <<backup, sEpoch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* The commit's answer is lost: the changer unfences as if it had rolled
\* back, and tries again with the change's id, which finds it done and
\* answers.
Unsure ==
  /\ LostCommits /\ ch.st = "committed"
  /\ net' = net \cup Unfences
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* Then it answers: "revoke returned".
Answer ==
  /\ \/ ch.st = "committed"
     \/ ch.st = "after" /\ ch.acks = Shards
  /\ ch' = [ch EXCEPT !.st = "idle"]
  /\ lastRevoke' = IF ch.kind = "revoke" THEN ch.gen ELSE lastRevoke
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, rogue, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* A writer that does not fence revokes, without the revision's row, and
\* answers. With FencedWritesOnly, Postgres refuses it.
Unfenced ==
  /\ ~FencedWritesOnly /\ ~rogue /\ grant.on
  /\ grant' = [on |-> FALSE, gen |-> grant.gen + 1]
  /\ rogue' = TRUE
  /\ lastRevoke' = grant.gen + 1
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, revision, locked, ch, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* A backup of Postgres is taken.
Backup ==
  /\ restores < Restores /\ ~backup.taken
  /\ backup' = [taken |-> TRUE, on |-> grant.on, rev |-> revision]
  /\ UNCHANGED <<grant, revision, epoch, restores, sEpoch, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* Anything fails before the commit: it rolls back and unfences, best effort.
Abort ==
  /\ ch.st = "fencing" /\ ch.kind # "restore"
  /\ locked' = FALSE
  /\ ch' = [ch EXCEPT !.st = "idle"]
  /\ net' = net \cup Unfences
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

-----------------------------------------------------------------------------
(* The shards. *)

\* A floor and its epoch after a fence: raised in the same epoch; with
\* EpochChecked, replaced by a newer epoch's, and an older's ignored.
Fenced(fl, ep, m) ==
  IF ~EpochChecked \/ m.ep = ep THEN [floor |-> Max(fl, m.rev), epoch |-> ep]
  ELSE IF m.ep > ep THEN [floor |-> m.rev, epoch |-> m.ep]
  ELSE [floor |-> fl, epoch |-> ep]

\* A fence raises the floor, writes it to the storage and acknowledges. One
\* from an older epoch is ignored: its change died with the restore.
Fence(m, i) ==
  LET s == m.s
      me == inst[s][i]
      mem == Fenced(me.floor, me.epoch, m)
      sto == Fenced(sFloor[s], sEpoch[s], m)
  IN
  IF FencePersisted /\ ~Writes(s, i)
  THEN /\ Down(s, i)
       /\ UNCHANGED <<ch, sFloor, sEpoch>>
  ELSE IF EpochChecked /\ m.ep < me.epoch
  THEN UNCHANGED <<inst, ch, sFloor, sEpoch, use, probes>>
  ELSE /\ inst' = [inst EXCEPT ![s][i] = [me EXCEPT !.floor = mem.floor, !.epoch = mem.epoch,
                                          !.standing = IF mem.epoch = me.epoch THEN me.standing ELSE NoStanding]]
       /\ sFloor' = IF FencePersisted THEN [sFloor EXCEPT ![s] = sto.floor] ELSE sFloor
       /\ sEpoch' = IF FencePersisted THEN [sEpoch EXCEPT ![s] = sto.epoch] ELSE sEpoch
       /\ ch' = IF ch.n = m.id /\ ch.st \in {"fencing", "after"} THEN [ch EXCEPT !.acks = @ \cup {s}] ELSE ch
       \* Every probe this instance has out is overtaken.
       /\ use' = [u \in Uses |-> IF use[u].s = s /\ use[u].i = i /\ use[u].st = "probed"
                                 THEN [use[u] EXCEPT !.overtaken = TRUE] ELSE use[u]]
       /\ probes' = {IF p.s = s /\ p.i = i THEN [p EXCEPT !.overtaken = TRUE] ELSE p : p \in probes}

\* An unfence starts a probe; or, without UnfenceProbes, lowers the floor it names.
Unfence(m, i) ==
  LET s == m.s IN
  /\ IF UnfenceProbes
     THEN /\ probes' = probes \cup {[s |-> s, i |-> i, free |-> ~locked, value |-> revision, pe |-> epoch, overtaken |-> FALSE]}
          /\ UNCHANGED inst
     ELSE /\ inst' = [inst EXCEPT ![s][i].floor = IF @ = m.rev /\ m.ep = inst[s][i].epoch THEN m.rev - 1 ELSE @]
          /\ UNCHANGED probes
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, ch, sFloor, use>>

\* A message delivered, and kept in flight to be delivered again (Duplicates).
Keeps == IF Duplicates THEN BOOLEAN ELSE {FALSE}

Deliver(m, i, keep) ==
  /\ m \in net /\ Alive(m.s, i)
  /\ net' = IF keep THEN net ELSE net \ {m}
  /\ IF m.k = "fence" THEN Fence(m, i) ELSE Unfence(m, i)
  /\ UNCHANGED <<epoch, backup, restores, grant, revision, locked, rogue, lastRevoke, sOwner, sEntries, starts>>

Delivered == \E m \in net, i \in Slots, keep \in Keeps : Deliver(m, i, keep)

Drop(m) ==
  /\ Losses /\ m \in net
  /\ net' = net \ {m}
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, inst, sFloor, sOwner, sEntries, starts, probes, use>>

\* Lower the floor to what the probe found, if the row was free, below the
\* floor, in the instance's epoch, and (ProbeKeepsFence) no fence came while
\* the probe was out.
Lowered(s, i, free, value, pe, overtaken) ==
  LET fl == inst[s][i].floor IN
  IF free /\ value < fl /\ (~EpochChecked \/ pe = inst[s][i].epoch) /\ (~ProbeKeepsFence \/ ~overtaken)
  THEN value ELSE fl

ApplyUnfenceProbe(p) ==
  /\ p \in probes /\ Alive(p.s, p.i)
  /\ probes' = probes \ {p}
  /\ inst' = [inst EXCEPT ![p.s][p.i].floor = Lowered(p.s, p.i, p.free, p.value, p.pe, p.overtaken)]
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts, use>>

UnfenceProbed == \E p \in probes : ApplyUnfenceProbe(p)

\* Without the probe, a timer lowers the floor to the committed revision.
Timer(s, i) ==
  /\ ~NowaitProbe /\ Alive(s, i) /\ inst[s][i].floor > revision
  /\ inst' = [inst EXCEPT ![s][i].floor = revision]
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts, probes, use>>

\* An instance starts, from its storage, and the storage takes its writes
\* from now: the one running before, if any, still runs until it writes.
Start(s, i) ==
  /\ ~Alive(s, i) /\ starts < MaxStarts
  /\ inst' = [inst EXCEPT ![s][i] = [Fresh EXCEPT !.alive = TRUE, !.floor = sFloor[s], !.epoch = sEpoch[s]]]
  /\ sOwner' = [sOwner EXCEPT ![s] = i]
  /\ starts' = starts + 1
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sEntries, probes, use>>

Crash(s, i) ==
  /\ Alive(s, i) /\ starts < MaxStarts
  /\ Down(s, i)
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts>>

-----------------------------------------------------------------------------
(* The uses. *)

Invoke(u) ==
  /\ \/ use[u].st = "idle"
     \/ Repeats /\ use[u].st = "replied"
  /\ use' = [use EXCEPT ![u] = [Blank EXCEPT !.st = "new", !.after = lastRevoke]]
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

Entry(u, g, r) == [u |-> u, rev |-> r, allow |-> g]

\* The decision, on grant g read at revision (e, r), by instance i, whose
\* memory is then me: an entry in the storage, then the reply. A storage
\* that refuses the write breaks the instance, and the client tries again.
Decide(u, s, i, g, r, e, me) ==
  LET replied == [Blank EXCEPT !.st = "replied", !.s = s, !.i = i, !.after = use[u].after,
                               !.allow = g.on, !.gen = g.gen, !.rev = r, !.ep = e, !.revAt = revision, !.epAt = epoch] IN
  /\ IF ~DurableBeforeReply
     THEN /\ inst' = [inst EXCEPT ![s][i] = me]
          /\ use' = [use EXCEPT ![u] = replied]
          /\ UNCHANGED <<epoch, backup, restores, sEpoch, sEntries, probes>>
     ELSE IF Writes(s, i)
     THEN /\ sEntries' = [sEntries EXCEPT ![s] = @ \cup {Entry(u, g.on, r)}]
          /\ inst' = [inst EXCEPT ![s][i] = me]
          /\ use' = [use EXCEPT ![u] = replied]
          /\ UNCHANGED probes
     ELSE /\ Down(s, i)
          /\ UNCHANGED sEntries
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, starts>>

\* The use reaches an instance: answered from the standing kept, or read again.
Serve(u, s, i) ==
  LET sd == inst[s][i].standing IN
  /\ use[u].st = "new" /\ Alive(s, i)
  /\ IF sd.has /\ (~FloorChecked \/ sd.rev >= inst[s][i].floor)
     THEN Decide(u, s, i, sd.grant, sd.rev, sd.ep, inst[s][i])
     ELSE /\ use' = [use EXCEPT ![u] = [@ EXCEPT !.st = "loading", !.s = s, !.i = i]]
          /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

\* The standing and the revision, in one statement; or, without OneSnapshot,
\* the rows first and the revision after.
Load(u) ==
  /\ use[u].st = "loading" /\ Alive(use[u].s, use[u].i)
  /\ use' = [use EXCEPT ![u] = IF OneSnapshot THEN [@ EXCEPT !.st = "loaded", !.rg = grant, !.rr = revision, !.re = epoch]
                                              ELSE [@ EXCEPT !.st = "half", !.rg = grant]]
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

LoadRevision(u) ==
  /\ use[u].st = "half" /\ Alive(use[u].s, use[u].i)
  /\ use' = [use EXCEPT ![u] = [@ EXCEPT !.st = "loaded", !.rr = revision, !.re = epoch]]
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

\* The read is back. With EpochChecked, read in another epoch: a newer one
\* is adopted (floor and standing dropped), and the use reads again. At the
\* floor or later, kept and decided on; below it, the probe (the row taken
\* NOWAIT and let go: whether it was free, and the revision); without
\* NowaitProbe, 503.
Check(u) ==
  LET s == use[u].s
      i == use[u].i
      me == inst[s][i]
      fl == me.floor
      r == use[u].rr
      e == use[u].re
      g == use[u].rg
  IN
  /\ use[u].st = "loaded" /\ Alive(s, i)
  /\ IF EpochChecked /\ e # me.epoch
     THEN /\ inst' = IF e > me.epoch
                     THEN [inst EXCEPT ![s][i] = [me EXCEPT !.epoch = e, !.floor = 0, !.standing = NoStanding]]
                     ELSE inst
          /\ use' = [use EXCEPT ![u] = Again(@)]
          /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts, probes>>
     ELSE IF ~FloorChecked \/ r >= fl
     THEN Decide(u, s, i, g, r, e, [me EXCEPT !.standing = [has |-> TRUE, grant |-> g, rev |-> r, ep |-> e]])
     ELSE /\ use' = [use EXCEPT ![u] = IF NowaitProbe
                                      THEN [@ EXCEPT !.st = "probed", !.free = ~locked, !.value = revision, !.pe = epoch, !.overtaken = FALSE]
                                      ELSE Again(@)]
          /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, sEntries, starts, probes>>

\* The probe is back: the floor perhaps lower, and the use tried again (read
\* again, or 503 and the client's retry: the same here).
ApplyProbe(u) ==
  LET s == use[u].s
      i == use[u].i
  IN
  /\ use[u].st = "probed" /\ Alive(s, i)
  /\ inst' = [inst EXCEPT ![s][i].floor = Lowered(s, i, use[u].free, use[u].value, use[u].pe, use[u].overtaken)]
  /\ use' = [use EXCEPT ![u] = Again(@)]
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, sFloor, sOwner, sEntries, starts, probes>>

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
  /\ UNCHANGED <<epoch, backup, restores, sEpoch, grant, revision, locked, ch, rogue, lastRevoke, net, inst, sFloor, sOwner, starts, probes, use>>

-----------------------------------------------------------------------------

UseStep(u) ==
  \/ \E s \in Shards, i \in Slots : Serve(u, s, i)
  \/ Load(u) \/ LoadRevision(u) \/ Check(u) \/ ApplyProbe(u) \/ Persist(u)

Next ==
  \/ Begin \/ Commit \/ Unsure \/ Answer \/ Abort \/ Unfenced \/ Backup
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
  \A u \in Uses : Replied(u) => use[u].rev = use[u].revAt /\ use[u].ep = use[u].epAt

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
  /\ \A s \in Shards : sEpoch[s] = epoch => sFloor[s] <= revision + 1
  /\ \A s \in Shards, i \in Slots : inst[s][i].epoch = epoch => inst[s][i].floor <= revision + 1

\* A change begun ends, answered or rolled back.
ChangesEnd == ch.st # "idle" ~> ch.st = "idle"

\* Every use is answered, a value or a refusal: no fence, a rolled back
\* one's included, refuses forever. (With finitely many changes.)
UsesAnswered == \A u \in Uses : use[u].st # "idle" ~> Replied(u)
=============================================================================
