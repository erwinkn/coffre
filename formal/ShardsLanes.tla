---------------------------- MODULE ShardsLanes ----------------------------
(* A shard's lane of the audit log, from its storage to Postgres
   (formal/Shards.md). The shard is the lane's only writer: each entry is
   sealed from the head before it and written to the shard's storage,
   which takes only the newest instance's writes (Shards.tla's
   StorageArbiter). A flusher copies the tail Postgres lacks, a batch at a
   time, in one statement that writes only where Postgres's head for the
   lane is what the instance last flushed; Postgres ahead with the same
   entries (a flush whose answer was lost, or another instance's), it
   adopts Postgres's head; Postgres behind what it flushed, the database
   was rewound: it raises the alarm and stops. It then records in its
   storage how far it flushed.

   An instance stops at any step; a second starts while the first runs,
   and the first, which kept what the lane was when it lost the storage,
   may still flush. Postgres is rewound once, to any shorter prefix, as a
   restore from an older backup would.

   An entry is its sequence number: the storage's lane is 1, 2, 3, ... by
   construction, and the chain is "a prefix of it".

   Protections, each turned off by a constant to show TLC finds the race:
     HeadCAS        the flush writes only where Postgres's head is what the
                    instance last flushed
     RewindChecked  Postgres behind what was flushed raises the alarm (off:
                    the flusher adopts Postgres's head and fills it again)
     FlushGated     a flush leaves only once a write to the storage commits
                    (the output gate), so an instance the storage no longer
                    takes flushes nothing *)
EXTENDS Naturals, Sequences, TLC

CONSTANTS Slots, MaxEntries, MaxStarts, Rewinds
CONSTANTS HeadCAS, RewindChecked, FlushGated

VARIABLES
  lane,       \* the storage: the lane's entries
  sFlushed,   \* the storage: how far the shard knows Postgres has the lane
  owner,      \* the storage: the instance whose writes it takes
  inst,       \* each instance, in memory: [alive, view, flushed]
  pg,         \* Postgres: the lane's entries
  alarm,      \* the shard found Postgres rewound, and stopped
  starts,     \* instances started
  rewinds,    \* rewinds of Postgres
  rewound,    \* ghost: Postgres lost entries the shard recorded as flushed
  refilled    \* ghost: a flush wrote to the lane after that

vars == <<lane, sFlushed, owner, inst, pg, alarm, starts, rewinds, rewound, refilled>>

Min(a, b) == IF a < b THEN a ELSE b
First == CHOOSE i \in Slots : \A j \in Slots : i <= j
Gone == [alive |-> FALSE, view |-> <<>>, flushed |-> 0]

Init ==
  /\ lane = <<>>
  /\ sFlushed = 0
  /\ owner = First
  /\ inst = [i \in Slots |-> IF i = First THEN [Gone EXCEPT !.alive = TRUE] ELSE Gone]
  /\ pg = <<>>
  /\ alarm = FALSE
  /\ starts = 0
  /\ rewinds = 0
  /\ rewound = FALSE
  /\ refilled = FALSE

Alive(i) == inst[i].alive

\* A use's entry, sealed from the head and written to the storage. An
\* instance the storage no longer takes breaks at the write.
Write(i) ==
  /\ Alive(i) /\ Len(lane) < MaxEntries
  /\ IF owner = i
     THEN /\ lane' = Append(lane, Len(lane) + 1)
          /\ inst' = [inst EXCEPT ![i].view = lane']
     ELSE /\ inst' = [inst EXCEPT ![i] = Gone]
          /\ UNCHANGED lane
  /\ UNCHANGED <<sFlushed, owner, pg, alarm, starts, rewinds, rewound, refilled>>

\* The flusher copies a batch of what Postgres lacks.
Flush(i) ==
  LET me == inst[i]
      f == me.flushed
      head == Len(pg)
      shared == Min(head, Len(me.view))
  IN
  /\ Alive(i) /\ ~alarm /\ f < Len(me.view)
  /\ IF FlushGated /\ owner # i
     THEN \* Its storage write refused: it breaks before the flush leaves.
          /\ inst' = [inst EXCEPT ![i] = Gone]
          /\ UNCHANGED <<pg, alarm, refilled>>
     ELSE IF ~HeadCAS \/ head = f
     THEN \E b \in 1..(Len(me.view) - f) :
            /\ pg' = pg \o SubSeq(me.view, f + 1, f + b)
            /\ inst' = [inst EXCEPT ![i].flushed = f + b]
            /\ refilled' = (refilled \/ rewound)
            /\ UNCHANGED alarm
     ELSE IF head > f /\ SubSeq(pg, 1, shared) = SubSeq(me.view, 1, shared)
     THEN \* Postgres is ahead with the same entries: take its head.
          /\ inst' = [inst EXCEPT ![i].flushed = head]
          /\ UNCHANGED <<pg, alarm, refilled>>
     ELSE IF head < f /\ ~RewindChecked
     THEN /\ inst' = [inst EXCEPT ![i].flushed = head]
          /\ UNCHANGED <<pg, alarm, refilled>>
     ELSE \* Rewound, or another history: the alarm, and the shard stops flushing.
          /\ alarm' = TRUE
          /\ UNCHANGED <<pg, inst, refilled>>
  /\ UNCHANGED <<lane, sFlushed, owner, starts, rewinds, rewound>>

\* It records how far it flushed.
Record(i) ==
  /\ Alive(i) /\ owner = i /\ sFlushed < inst[i].flushed
  /\ sFlushed' = inst[i].flushed
  /\ UNCHANGED <<lane, owner, inst, pg, alarm, starts, rewinds, rewound, refilled>>

Start(i) ==
  /\ ~Alive(i) /\ starts < MaxStarts
  /\ inst' = [inst EXCEPT ![i] = [alive |-> TRUE, view |-> lane, flushed |-> sFlushed]]
  /\ owner' = i
  /\ starts' = starts + 1
  /\ UNCHANGED <<lane, sFlushed, pg, alarm, rewinds, rewound, refilled>>

Crash(i) ==
  /\ Alive(i) /\ starts < MaxStarts
  /\ inst' = [inst EXCEPT ![i] = Gone]
  /\ UNCHANGED <<lane, sFlushed, owner, pg, alarm, starts, rewinds, rewound, refilled>>

\* Postgres restored from an older backup: the lane cut to a shorter prefix.
Rewind ==
  /\ rewinds < Rewinds /\ pg # <<>>
  /\ \E keep \in 0..(Len(pg) - 1) :
       /\ pg' = SubSeq(pg, 1, keep)
       /\ rewound' = (rewound \/ keep < sFlushed)
  /\ rewinds' = rewinds + 1
  /\ UNCHANGED <<lane, sFlushed, owner, inst, alarm, starts, refilled>>

Next ==
  \/ \E i \in Slots : Write(i) \/ Flush(i) \/ Record(i) \/ Start(i) \/ Crash(i)
  \/ Rewind

Spec == Init /\ [][Next]_vars

\* The instance the storage takes flushes and records, and one starts when
\* that one has stopped (the next request starts it).
LiveSpec ==
  /\ Spec
  /\ \A i \in Slots : WF_vars(owner = i /\ (Flush(i) \/ Record(i)))
  /\ WF_vars(~Alive(owner) /\ \E i \in Slots : Start(i))

-----------------------------------------------------------------------------

\* Postgres's copy of the lane is numbered without gap or repeat, chained,
\* and a prefix of the shard's own: it holds nothing the shard did not write.
LanesHold ==
  /\ Len(pg) <= Len(lane)
  /\ \A k \in 1..Len(pg) : pg[k] = lane[k]

\* Postgres rewound below what the shard recorded, nothing more is written
\* to the lane: the shard raises the alarm instead.
RewindStops == ~refilled

\* Every entry in the storage reaches Postgres.
EveryEntryFlushed == \A k \in 1..MaxEntries : Len(lane) >= k ~> Len(pg) >= k
=============================================================================
