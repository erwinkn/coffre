---------------------------- MODULE ShardsLanes ----------------------------
(* A shard's lane of the audit log, from its storage to Postgres
   (formal/Shards.md). The shard is the lane's only writer: each entry is
   sealed from the head before it (its hash covers the previous one's) and
   written to the shard's storage, which takes only the newest instance's
   writes (Shards.tla's StorageArbiter). A flusher copies the tail Postgres
   lacks, a batch at a time, in one statement that writes only where
   Postgres's head for the lane is what the instance last flushed: the same
   next seq and the same head hash. Postgres ahead (a flush whose answer was
   lost, or another instance's), the flusher adopts Postgres's head only if
   it is at most its own head and its hash is its own entry's at that seq.
   Anything else, Postgres rewound below what it flushed or a history not
   its own, raises the alarm: the shard stops flushing and serving. It then
   records in its storage how far it flushed.

   An instance stops at any step; a second starts while the first runs,
   and the first, which kept what the lane was when it lost the storage,
   may still flush. An instance may start with the storage lost: its lane
   empty while Postgres holds what the lost one flushed. Postgres is
   restored from any earlier backup of it, Rewinds times.

   An entry is [seq, h, prev]: h stands for its hash (each write's is new),
   prev for the hash it was sealed from (0 for the first).

   Protections, each turned off by a constant to show TLC finds the race:
     HeadCAS            the flush writes only where Postgres's head is what
                        the instance last flushed
     CasComparesHash    and compares the head's hash, not only its seq
     AdoptOnlyOwnPrefix Postgres ahead is adopted only up to the shard's own
                        head and only if the hashes agree (off: by seq)
     RewindChecked      Postgres behind what was flushed raises the alarm
                        (off: the flusher adopts Postgres's head and fills it
                        again)
     FlushGated         a flush leaves only once a write to the storage
                        commits (the output gate), so an instance the storage
                        no longer takes flushes nothing *)
EXTENDS Naturals, Sequences, TLC

CONSTANTS Slots, MaxEntries, MaxStarts, Rewinds, StorageLosses
CONSTANTS HeadCAS, CasComparesHash, AdoptOnlyOwnPrefix, RewindChecked, FlushGated

VARIABLES
  lane,       \* the storage: the lane's entries
  sFlushed,   \* the storage: how far the shard knows Postgres has the lane
  owner,      \* the storage: the instance whose writes it takes
  inst,       \* each instance, in memory: [alive, view, flushed]
  pg,         \* Postgres: the lane's entries
  backups,    \* backups of Postgres's lane
  alarm,      \* the shard found a lane not its own, and stopped
  starts,     \* instances started
  losses,     \* storages lost
  rewinds,    \* restores of Postgres
  made,       \* entries written, ever (each one's hash)
  written,    \* ghost: every entry the shard wrote
  rewound,    \* ghost: Postgres lacks entries the shard recorded as flushed
  refilled,   \* ghost: a flush wrote to the lane after that
  falseClaim  \* ghost: a flusher took for flushed what Postgres does not hold

vars == <<lane, sFlushed, owner, inst, pg, backups, alarm, starts, losses, rewinds, made, written, rewound, refilled, falseClaim>>

Min(a, b) == IF a < b THEN a ELSE b
First == CHOOSE i \in Slots : \A j \in Slots : i <= j
Gone == [alive |-> FALSE, view |-> <<>>, flushed |-> 0]
Top(s) == IF s = <<>> THEN 0 ELSE s[Len(s)].h

Init ==
  /\ lane = <<>>
  /\ sFlushed = 0
  /\ owner = First
  /\ inst = [i \in Slots |-> IF i = First THEN [Gone EXCEPT !.alive = TRUE] ELSE Gone]
  /\ pg = <<>>
  /\ backups = {<<>>}
  /\ alarm = FALSE
  /\ starts = 0
  /\ losses = 0
  /\ rewinds = 0
  /\ made = 0
  /\ written = {}
  /\ rewound = FALSE
  /\ refilled = FALSE
  /\ falseClaim = FALSE

Alive(i) == inst[i].alive

\* A use's entry, sealed from the head and written to the storage. An
\* instance the storage no longer takes breaks at the write.
Write(i) ==
  LET e == [seq |-> Len(lane) + 1, h |-> made + 1, prev |-> Top(lane)] IN
  /\ Alive(i) /\ ~alarm /\ made < MaxEntries
  /\ IF owner = i
     THEN /\ lane' = Append(lane, e)
          /\ inst' = [inst EXCEPT ![i].view = lane']
          /\ made' = made + 1
          /\ written' = written \cup {e}
     ELSE /\ inst' = [inst EXCEPT ![i] = Gone]
          /\ UNCHANGED <<lane, made, written>>
  /\ UNCHANGED <<sFlushed, owner, pg, backups, alarm, starts, losses, rewinds, rewound, refilled, falseClaim>>

\* The flusher copies a batch of what Postgres lacks.
Flush(i) ==
  LET me == inst[i]
      v == me.view
      f == me.flushed
      head == Len(pg)
      \* The statement's compare-and-swap: Postgres's next seq, and its head's hash.
      placed == head = f /\ (~CasComparesHash \/ f = 0 \/ pg[f].h = v[f].h)
      \* Postgres ahead, adopted: up to the shard's own head, with its hash.
      ahead == head > f /\ (~AdoptOnlyOwnPrefix \/ (head <= Len(v) /\ pg[head].h = v[head].h))
  IN
  /\ Alive(i) /\ ~alarm /\ f < Len(v)
  /\ IF FlushGated /\ owner # i
     THEN \* Its storage write refused: it breaks before the flush leaves.
          /\ inst' = [inst EXCEPT ![i] = Gone]
          /\ UNCHANGED <<pg, alarm, refilled, falseClaim>>
     ELSE IF ~HeadCAS \/ placed
     THEN \E b \in 1..(Len(v) - f) :
            /\ pg' = pg \o SubSeq(v, f + 1, f + b)
            /\ inst' = [inst EXCEPT ![i].flushed = f + b]
            /\ refilled' = (refilled \/ rewound)
            /\ UNCHANGED <<alarm, falseClaim>>
     ELSE IF ahead
     THEN /\ inst' = [inst EXCEPT ![i].flushed = head]
          /\ falseClaim' = (falseClaim \/ head > Len(v) \/ \E k \in 1..head : pg[k] # v[k])
          /\ UNCHANGED <<pg, alarm, refilled>>
     ELSE IF head < f /\ ~RewindChecked
     THEN /\ inst' = [inst EXCEPT ![i].flushed = head]
          /\ UNCHANGED <<pg, alarm, refilled, falseClaim>>
     ELSE \* Rewound, or a history not its own: the alarm, and the shard stops.
          /\ alarm' = TRUE
          /\ UNCHANGED <<pg, inst, refilled, falseClaim>>
  /\ UNCHANGED <<lane, sFlushed, owner, backups, starts, losses, rewinds, made, written, rewound>>

\* It records how far it flushed.
Record(i) ==
  /\ Alive(i) /\ owner = i /\ sFlushed < inst[i].flushed
  /\ sFlushed' = inst[i].flushed
  /\ UNCHANGED <<lane, owner, inst, pg, backups, alarm, starts, losses, rewinds, made, written, rewound, refilled, falseClaim>>

Start(i) ==
  /\ ~Alive(i) /\ starts < MaxStarts
  /\ inst' = [inst EXCEPT ![i] = [alive |-> TRUE, view |-> lane, flushed |-> sFlushed]]
  /\ owner' = i
  /\ starts' = starts + 1
  /\ UNCHANGED <<lane, sFlushed, pg, backups, alarm, losses, rewinds, made, written, rewound, refilled, falseClaim>>

\* An instance starts with the storage lost: no lane, nothing flushed. A
\* rewind of Postgres from before is no longer the shard's to see (it kept
\* no record of it): the checkpoints, which signed the lane's head, find it.
StartLost(i) ==
  /\ ~Alive(i) /\ starts < MaxStarts /\ losses < StorageLosses
  /\ lane' = <<>>
  /\ sFlushed' = 0
  /\ inst' = [inst EXCEPT ![i] = [alive |-> TRUE, view |-> <<>>, flushed |-> 0]]
  /\ owner' = i
  /\ starts' = starts + 1
  /\ losses' = losses + 1
  /\ rewound' = FALSE
  /\ UNCHANGED <<pg, backups, alarm, rewinds, made, written, refilled, falseClaim>>

Crash(i) ==
  /\ Alive(i) /\ starts < MaxStarts
  /\ inst' = [inst EXCEPT ![i] = Gone]
  /\ UNCHANGED <<lane, sFlushed, owner, pg, backups, alarm, starts, losses, rewinds, made, written, rewound, refilled, falseClaim>>

\* A backup of Postgres is taken.
Backup ==
  /\ rewinds < Rewinds /\ pg \notin backups
  /\ backups' = backups \cup {pg}
  /\ UNCHANGED <<lane, sFlushed, owner, inst, pg, alarm, starts, losses, rewinds, made, written, rewound, refilled, falseClaim>>

\* Postgres restored from an earlier backup.
Restore ==
  /\ rewinds < Rewinds
  /\ \E b \in backups \ {pg} :
       /\ pg' = b
       /\ rewound' = (Len(b) < sFlushed \/ \E k \in 1..Min(Min(Len(b), sFlushed), Len(lane)) : b[k] # lane[k])
  /\ rewinds' = rewinds + 1
  /\ UNCHANGED <<lane, sFlushed, owner, inst, backups, alarm, starts, losses, made, written, refilled, falseClaim>>

Next ==
  \/ \E i \in Slots : Write(i) \/ Flush(i) \/ Record(i) \/ Start(i) \/ StartLost(i) \/ Crash(i)
  \/ Backup \/ Restore

Spec == Init /\ [][Next]_vars

\* The instance the storage takes flushes and records, and one starts when
\* that one has stopped (the next request starts it).
LiveSpec ==
  /\ Spec
  /\ \A i \in Slots : WF_vars(owner = i /\ (Flush(i) \/ Record(i)))
  /\ WF_vars(~Alive(owner) /\ \E i \in Slots : Start(i))

-----------------------------------------------------------------------------

\* Postgres's copy of the lane is numbered without gap or repeat, each entry
\* sealed from the one before it, and holds nothing the shard did not write;
\* and no flusher takes for flushed what Postgres does not hold.
LanesHold ==
  /\ \A k \in 1..Len(pg) :
       /\ pg[k].seq = k
       /\ pg[k] \in written
       /\ pg[k].prev = (IF k = 1 THEN 0 ELSE pg[k - 1].h)
  /\ ~falseClaim

\* Postgres rewound below what the shard recorded, nothing more is written
\* to the lane: the shard raises the alarm instead.
RewindStops == ~refilled

\* Every entry in the storage reaches Postgres.
EveryEntryFlushed == \A k \in 1..MaxEntries : Len(lane) >= k ~> Len(pg) >= k
=============================================================================
