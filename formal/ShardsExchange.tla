---------------------------- MODULE ShardsExchange ----------------------------
(* A token exchange (a CI run's sign-in) through the shards
   (formal/Shards.md). The run's ID token names a one-time id (jti); the
   shard that takes the exchange checks the id is unspent, spends it and
   answers with a credential. Clients try again when an answer is lost, so
   the same token arrives more than once; a hot principal is served by
   several shards (its fan-out); a shard restarts, and may run two
   instances at once, its storage taking only the newest one's writes
   (Shards.tla's StorageArbiter).

   Protections, each turned off by a constant to show TLC finds the race:
     JtiSpentInShard  the spent id is written to the shard's storage before
                      the answer leaves (off: kept in memory)
     JtiAtHome        an exchange goes to the principal's home shard, never
                      to another of its fan-out *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Shards, Slots, Jtis, Attempts, MaxStarts
CONSTANTS JtiSpentInShard, JtiAtHome

VARIABLES
  spent,    \* each shard's storage: the ids spent
  owner,    \* each shard's storage: the instance whose writes it takes
  inst,     \* each shard's instances, in memory: [alive, spent]
  tries,    \* exchanges attempted
  issued,   \* credentials issued for each id
  starts    \* instances started

vars == <<spent, owner, inst, tries, issued, starts>>

First == CHOOSE i \in Slots : \A j \in Slots : i <= j
Home == CHOOSE s \in Shards : TRUE
Gone == [alive |-> FALSE, spent |-> {}]

Init ==
  /\ spent = [s \in Shards |-> {}]
  /\ owner = [s \in Shards |-> First]
  /\ inst = [s \in Shards |-> [i \in Slots |-> IF i = First THEN [Gone EXCEPT !.alive = TRUE] ELSE Gone]]
  /\ tries = 0
  /\ issued = [j \in Jtis |-> 0]
  /\ starts = 0

Alive(s, i) == inst[s][i].alive

\* Where an exchange may go.
Targets == IF JtiAtHome THEN {Home} ELSE Shards

\* An exchange, in one turn of the shard's actor: refused if the id is
\* spent, else spent and answered.
Exchange(j, s, i) ==
  LET known == IF JtiSpentInShard THEN j \in spent[s] ELSE j \in inst[s][i].spent IN
  /\ tries < Attempts /\ s \in Targets /\ Alive(s, i)
  /\ tries' = tries + 1
  /\ IF known
     THEN UNCHANGED <<spent, inst, issued>>
     ELSE IF ~JtiSpentInShard
     THEN /\ inst' = [inst EXCEPT ![s][i].spent = @ \cup {j}]
          /\ issued' = [issued EXCEPT ![j] = @ + 1]
          /\ UNCHANGED spent
     ELSE IF owner[s] = i
     THEN /\ spent' = [spent EXCEPT ![s] = @ \cup {j}]
          /\ inst' = [inst EXCEPT ![s][i].spent = @ \cup {j}]
          /\ issued' = [issued EXCEPT ![j] = @ + 1]
     ELSE \* The storage refuses its write: it breaks, and answers nothing.
          /\ inst' = [inst EXCEPT ![s][i] = Gone]
          /\ UNCHANGED <<spent, issued>>
  /\ UNCHANGED <<owner, starts>>

Start(s, i) ==
  /\ ~Alive(s, i) /\ starts < MaxStarts
  /\ inst' = [inst EXCEPT ![s][i] = [alive |-> TRUE, spent |-> {}]]
  /\ owner' = [owner EXCEPT ![s] = i]
  /\ starts' = starts + 1
  /\ UNCHANGED <<spent, tries, issued>>

Crash(s, i) ==
  /\ Alive(s, i) /\ starts < MaxStarts
  /\ inst' = [inst EXCEPT ![s][i] = Gone]
  /\ UNCHANGED <<spent, owner, tries, issued, starts>>

Next ==
  \/ \E j \in Jtis, s \in Shards, i \in Slots : Exchange(j, s, i)
  \/ \E s \in Shards, i \in Slots : Start(s, i) \/ Crash(s, i)

Spec == Init /\ [][Next]_vars

\* An id is spent once: one credential for it, however often it arrives and
\* wherever it goes.
SingleUseExchange == \A j \in Jtis : issued[j] <= 1
=============================================================================
