-------------------------------- MODULE Seal --------------------------------
(***************************************************************************)
(* W209: sealing 0.15's audit log into a Merkle tree, holding its heads    *)
(* outside the database, and what an attacker with write access to the    *)
(* database (no key) can and cannot hide (experiments/merkle/schema.sql,   *)
(* src/log.ts, src/verify.ts).                                             *)
(*                                                                         *)
(* An append is one statement: it takes the fence's advisory lock shared,  *)
(* takes its number from the sequence, inserts its entry and commits, or   *)
(* aborts and leaves a gap. Nothing makes numbers unique in the table. An  *)
(* entry's MAC covers everything but its number, its request ID included.  *)
(* Some appends are changes (a revoke): the admin who made one is          *)
(* answered.                                                               *)
(*                                                                         *)
(* The signer (the checkpointer) runs from the head it holds in memory.    *)
(* Each tick it takes the lock exclusively (waiting for every append that  *)
(* holds it), reads the sequence's last value as `upto`, lets go, reads    *)
(* the committed entries in (its head's upto, upto], checks their MACs,    *)
(* appends them to the tree, signs the new head, remembers it (its own     *)
(* memory, outside the database), writes it to the database, and queues   *)
(* it for the witness. While it runs it never reads the database's         *)
(* checkpoints: only at a restart (`Open`) does it compare them with its   *)
(* memory, as Checkpointer.open does:                                      *)
(*   no row at all          refused if it remembers a head but genesis;    *)
(*                          else a new log, its genesis at 0;              *)
(*   memory ahead of the db the entries between the newest row and the     *)
(*                          remembered head must give it again: then its   *)
(*                          row is written, else the signer refuses;       *)
(*   the same upto          the same head, else it refuses;                *)
(*   the db ahead           the remembered head must be a prefix, else it  *)
(*                          refuses.                                       *)
(* Without SignerMemory the restart takes the database's newest row.       *)
(*                                                                         *)
(* The witness holds the newest head published to it and takes a new one  *)
(* only if it extends that one (a consistency proof). Publication runs     *)
(* behind the tick, newest head only, and what is queued is lost in a      *)
(* crash.                                                                  *)
(*                                                                         *)
(* The verifier (verifyLog) starts from the genesis row it requires (upto  *)
(* 0, no leaves), walks every entry in number order, and requires every    *)
(* checkpoint row and the witness's head on the way: the entries at or     *)
(* below a head's upto must be exactly its leaves. It also requires the    *)
(* database not to end before the witness's head, every number and (with   *)
(* RequestIdChecked) every request ID to appear once, and it reads the     *)
(* signer's and the witness's refusals as alarms.                          *)
(*                                                                         *)
(* The tree is abstracted to the set of its leaves, each a whole entry:    *)
(* number, request ID, whether its MAC holds. Leaves go in number order    *)
(* and every window lies above the head before it, so a head [upto,        *)
(* leaves] names one leaf sequence, and one head is a prefix of another    *)
(* exactly when `Prefix` says so (a consistency proof).                    *)
(*                                                                         *)
(* The protections, each a constant (scripts/formal-seal.sh shows each     *)
(* necessary):                                                             *)
(*   NumberUnderLock   the append takes its number after the shared lock;  *)
(*   CloseLocks        the tick reads the sequence under the exclusive     *)
(*                     lock;                                               *)
(*   SignerMemory      the signer remembers its newest head outside the    *)
(*                     database and checks the database against it at a    *)
(*                     restart (core, R40 without the plugin);             *)
(*   RowChecked        each tick, a running signer requires the database's *)
(*                     newest checkpoint to be its head in memory;         *)
(*   Witness           a head held outside, consistency-checked at each    *)
(*                     publication, which the verifier requires (the       *)
(*                     plugin);                                            *)
(*   RememberFirst     the signer remembers a head before writing it;      *)
(*   MacChecked        the signer seals no entry whose MAC fails;          *)
(*   RequestIdChecked  the verifier flags two entries with one request ID. *)
(*                     It is a check of the verifier's: removing it is     *)
(*                     exactly removing the protection. It catches a       *)
(*                     replay, a copy of an entry under another number,    *)
(*                     whose MAC holds since it does not cover the number; *)
(*   WaitForSeal       a change answers only once the signer has written   *)
(*                     a head holding it and, with a witness, the witness  *)
(*                     holds one.                                          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Appends,      \* the appends, each one statement; an append's request ID is its name
    Changes,      \* the appends that are changes, answered to an admin
    MaxTicks,     \* checkpointer ticks in a behaviour
    MaxAttacks,   \* attacker steps in a behaviour
    MaxCrashes,   \* checkpointer crashes (losing what it held in memory, its memory outside kept)
    NumberUnderLock, CloseLocks, SignerMemory, RowChecked, Witness, RememberFirst, MacChecked, RequestIdChecked, WaitForSeal

ASSUME Changes \subseteq Appends

Genesis == [upto |-> 0, leaves |-> {}]
Forged == "forged"                           \* the request ID of an entry the attacker made up

VARIABLES
    seq,       \* the sequence's last value
    shared,    \* the appends holding the fence's lock shared
    a,         \* each append: pc and number
    db,        \* the committed entries: [n, rid, ok], ok = its MAC holds; numbers may repeat
    cps,       \* the database's checkpoint rows (a set: one per upto, the primary key)
    cp,        \* the signer: pc, the upto it read, its head in memory, the head it is sealing
    memory,    \* SignerMemory: the newest head the signer remembers, outside the database
    queued,    \* the head waiting to be published to the witness: [on, head]
    witness,   \* Witness: the newest head the witness holds
    ticks, attacks, crashes,
    refused,   \* sticky: the signer refused the database at a restart (an alarm)
    macAlarm,  \* sticky: the signer met an entry whose MAC fails (an alarm)
    witnessRefused, \* sticky: the witness refused a head that does not extend its own (an alarm)
    rowAlarm,  \* sticky: a running signer found the database's newest checkpoint is not its head (an alarm)
    signed,    \* ghost: every head ever signed
    shown,     \* ghost: every head ever written to the database or published: what readers may have been shown
    committed, \* ghost: every entry an honest append committed
    answered,  \* ghost: the changes answered to their admin
    forgerySealed, \* ghost: a head was signed over an entry whose MAC fails
    late,      \* ghost: an honest entry committed at a number a signed head already covered
    settling   \* ghost: the attacker acted, and the signer has not ticked, written, published or restarted since

vars == <<seq, shared, a, db, cps, cp, memory, queued, witness, ticks, attacks, crashes, refused, macAlarm, witnessRefused, rowAlarm,
          signed, shown, committed, answered, forgerySealed, late, settling>>

Numbers == {e.n : e \in db}
Prefix(h1, h2) == h1.upto <= h2.upto /\ h1.leaves = {e \in h2.leaves : e.n <= h1.upto}
Holds(h, rid) == \E e \in h.leaves : e.rid = rid
Newest == CHOOSE r \in cps : \A s \in cps : s.upto <= r.upto   \* only when cps # {}
\* The entries the database holds above `from` and up to `upto`.
Window(from, upto) == {e \in db : from < e.n /\ e.n <= upto}

Init ==
    /\ seq = 0
    /\ shared = {}
    /\ a = [x \in Appends |-> [pc |-> "idle", n |-> 0]]
    /\ db = {}
    /\ cps = {Genesis}
    /\ cp = [pc |-> "idle", upto |-> 0, head |-> Genesis, next |-> Genesis]
    /\ memory = Genesis
    /\ queued = [on |-> FALSE, head |-> Genesis]
    /\ witness = Genesis
    /\ ticks = 0 /\ attacks = 0 /\ crashes = 0
    /\ refused = FALSE /\ macAlarm = FALSE /\ witnessRefused = FALSE /\ rowAlarm = FALSE
    /\ signed = {Genesis} /\ shown = {Genesis}
    /\ committed = {} /\ answered = {} /\ forgerySealed = FALSE /\ late = FALSE /\ settling = FALSE

Outside == <<memory, queued, witness, refused, macAlarm, witnessRefused, rowAlarm>>
Ghosts == <<signed, shown, committed, answered, forgerySealed, late, settling>>

-----------------------------------------------------------------------------
(* An append. With NumberUnderLock: lock, number, commit. Without: number, lock, commit. *)

Lock(x) ==
    /\ a[x].pc = IF NumberUnderLock THEN "idle" ELSE "numbered"
    /\ shared' = shared \cup {x}
    /\ a' = [a EXCEPT ![x].pc = IF NumberUnderLock THEN "locked" ELSE "ready"]
    /\ UNCHANGED <<seq, db, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside /\ UNCHANGED Ghosts

Number(x) ==
    /\ a[x].pc = IF NumberUnderLock THEN "locked" ELSE "idle"
    /\ seq' = seq + 1
    /\ a' = [a EXCEPT ![x] = [pc |-> IF NumberUnderLock THEN "ready" ELSE "numbered", n |-> seq + 1]]
    /\ UNCHANGED <<shared, db, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside /\ UNCHANGED Ghosts

\* Commits, or aborts (a gap). No key makes the number unique: it commits whatever the attacker put there.
Finish(x) ==
    /\ a[x].pc = "ready"
    /\ \E commit \in BOOLEAN :
        LET e == [n |-> a[x].n, rid |-> x, ok |-> TRUE] IN
        IF commit
        THEN /\ db' = db \cup {e}
             /\ committed' = committed \cup {e}
             /\ late' = (late \/ \E h \in signed : a[x].n <= h.upto)
             /\ a' = [a EXCEPT ![x].pc = IF x \in Changes THEN "committed" ELSE "done"]
        ELSE /\ a' = [a EXCEPT ![x].pc = "done"]
             /\ UNCHANGED <<db, committed, late>>
    /\ shared' = shared \ {x}
    /\ UNCHANGED <<seq, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside
    /\ UNCHANGED <<signed, shown, answered, forgerySealed, settling>>

\* A change answers its admin: at once, or (WaitForSeal) once the running signer has written a head holding it and, with
\* a witness, the witness holds one. (The code answers anyway after a deadline, saying "not witnessed": not modelled.)
Answer(x) ==
    /\ a[x].pc = "committed"
    /\ WaitForSeal => /\ cp.pc \notin {"down", "refused"}
                      /\ Holds(cp.head, x)
                      /\ Witness => Holds(witness, x)
    /\ a' = [a EXCEPT ![x].pc = "answered"]
    /\ answered' = answered \cup {x}
    /\ UNCHANGED <<seq, shared, db, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside
    /\ UNCHANGED <<signed, shown, committed, forgerySealed, late, settling>>

-----------------------------------------------------------------------------
(* The signer. *)

\* The exclusive lock (waiting for every append holding it shared), the sequence read, the lock let go. The same
\* statement returns the database's newest checkpoint: with RowChecked, a signer whose head is not that one raises an
\* alarm and signs nothing (a row deleted, with no traffic to write the next one, is seen within a tick).
TickRead ==
    /\ cp.pc = "idle"
    /\ ticks < MaxTicks
    /\ CloseLocks => shared = {}
    /\ ticks' = ticks + 1
    /\ settling' = FALSE
    /\ IF RowChecked /\ (cps = {} \/ Newest.upto # cp.head.upto)
       THEN rowAlarm' = TRUE /\ UNCHANGED cp
       ELSE cp' = [cp EXCEPT !.pc = "read", !.upto = seq] /\ UNCHANGED rowAlarm
    /\ UNCHANGED <<seq, shared, a, db, cps, attacks, crashes, memory, queued, witness, refused, macAlarm, witnessRefused>>
    /\ UNCHANGED <<signed, shown, committed, answered, forgerySealed, late>>

\* From the head in memory: the window, checked, sealed and signed; then remembered (RememberFirst) or written.
TickSign ==
    /\ cp.pc = "read"
    /\ LET w == Window(cp.head.upto, cp.upto)
           h == [upto |-> cp.upto, leaves |-> cp.head.leaves \cup w]
       IN IF MacChecked /\ \E e \in w : ~e.ok
          THEN /\ macAlarm' = TRUE
               /\ cp' = [cp EXCEPT !.pc = "idle"]
               /\ UNCHANGED <<cps, memory, signed, shown, forgerySealed, settling>>
          ELSE IF cp.upto <= cp.head.upto
          THEN /\ cp' = [cp EXCEPT !.pc = "idle"]
               /\ UNCHANGED <<macAlarm, cps, memory, signed, shown, forgerySealed, settling>>
          ELSE /\ signed' = signed \cup {h}
               /\ forgerySealed' = (forgerySealed \/ \E e \in w : ~e.ok)
               /\ IF RememberFirst
                  THEN /\ memory' = IF SignerMemory THEN h ELSE memory
                       /\ cp' = [cp EXCEPT !.pc = "remembered", !.next = h]
                       /\ UNCHANGED <<cps, settling, shown>>
                  ELSE /\ cps' = cps \cup {h}
                       /\ shown' = shown \cup {h}
                       /\ cp' = [cp EXCEPT !.pc = "written", !.next = h]
                       /\ settling' = FALSE
                       /\ UNCHANGED memory
               /\ UNCHANGED macAlarm
    /\ UNCHANGED <<seq, shared, a, db, queued, witness, ticks, attacks, crashes, refused, witnessRefused, rowAlarm, committed, answered, late>>

\* The second half: written (RememberFirst) or remembered; the head in memory moves on, and is queued for the witness.
TickFinish ==
    /\ cp.pc \in {"remembered", "written"}
    /\ IF cp.pc = "remembered"
       THEN cps' = cps \cup {cp.next} /\ shown' = shown \cup {cp.next} /\ settling' = FALSE /\ UNCHANGED memory
       ELSE memory' = (IF SignerMemory THEN cp.next ELSE memory) /\ UNCHANGED <<cps, settling, shown>>
    /\ cp' = [cp EXCEPT !.pc = "idle", !.head = cp.next]
    /\ queued' = [on |-> Witness, head |-> cp.next]
    /\ UNCHANGED <<seq, shared, a, db, witness, ticks, attacks, crashes, refused, macAlarm, witnessRefused, rowAlarm>>
    /\ UNCHANGED <<signed, committed, answered, forgerySealed, late>>

\* The witness takes the queued head if it extends its own.
Publish ==
    /\ queued.on
    /\ IF Prefix(witness, queued.head) THEN witness' = queued.head /\ UNCHANGED witnessRefused
       ELSE witnessRefused' = TRUE /\ UNCHANGED witness
    /\ queued' = [queued EXCEPT !.on = FALSE]
    /\ settling' = FALSE
    /\ UNCHANGED <<seq, shared, a, db, cps, cp, memory, ticks, attacks, crashes, refused, macAlarm, rowAlarm>>
    /\ UNCHANGED <<signed, shown, committed, answered, forgerySealed, late>>

\* The signer dies and loses what it held in memory (its head, what it was sealing, the witness's queue); its memory
\* outside the database stays.
Crash ==
    /\ cp.pc \notin {"down", "refused"}
    /\ crashes < MaxCrashes
    /\ crashes' = crashes + 1
    /\ cp' = [cp EXCEPT !.pc = "down"]
    /\ queued' = [queued EXCEPT !.on = FALSE]
    /\ UNCHANGED <<seq, shared, a, db, cps, memory, witness, ticks, attacks, refused, macAlarm, witnessRefused, rowAlarm>> /\ UNCHANGED Ghosts

\* Checkpointer.open.
Open ==
    /\ cp.pc = "down"
    /\ settling' = FALSE
    /\ IF cps = {}
       THEN \* No row at all: refused if the signer remembers any head but genesis; else a new log, its genesis at 0
            \* (sealing nothing: the first tick seals every entry there is).
            IF SignerMemory /\ memory # Genesis
            THEN /\ refused' = TRUE
                 /\ cp' = [cp EXCEPT !.pc = "refused"]
                 /\ UNCHANGED <<cps, memory, signed, shown>>
            ELSE /\ cps' = {Genesis}
                 /\ cp' = [cp EXCEPT !.pc = "idle", !.head = Genesis]
                 /\ UNCHANGED <<memory, signed, shown, refused>>
       ELSE LET d == Newest
                m == memory
            IN IF ~SignerMemory
               THEN /\ cp' = [cp EXCEPT !.pc = "idle", !.head = d]
                    /\ UNCHANGED <<cps, memory, signed, shown, refused>>
               ELSE IF m.upto > d.upto
               THEN IF d.leaves \cup Window(d.upto, m.upto) = m.leaves
                    THEN /\ cps' = cps \cup {m}
                         /\ shown' = shown \cup {m}
                         /\ cp' = [cp EXCEPT !.pc = "idle", !.head = m]
                         /\ UNCHANGED <<memory, signed, refused>>
                    ELSE /\ refused' = TRUE
                         /\ cp' = [cp EXCEPT !.pc = "refused"]
                         /\ UNCHANGED <<cps, memory, signed, shown>>
               ELSE IF (m.upto = d.upto /\ m = d) \/ (m.upto < d.upto /\ Prefix(m, d))
               THEN /\ cp' = [cp EXCEPT !.pc = "idle", !.head = d]
                    /\ UNCHANGED <<cps, memory, signed, shown, refused>>
               ELSE /\ refused' = TRUE
                    /\ cp' = [cp EXCEPT !.pc = "refused"]
                    /\ UNCHANGED <<cps, memory, signed, shown>>
    /\ UNCHANGED <<seq, shared, a, db, queued, witness, ticks, attacks, crashes, macAlarm, witnessRefused, rowAlarm>>
    /\ UNCHANGED <<committed, answered, forgerySealed, late>>

-----------------------------------------------------------------------------
(* The attacker: write access to the database, no key. Each step changes `db` or `cps` only. *)

Attack(dbNext, cpsNext) ==
    /\ attacks < MaxAttacks
    /\ attacks' = attacks + 1
    /\ db' = dbNext
    /\ cps' = cpsNext
    /\ settling' = TRUE
    /\ UNCHANGED <<seq, shared, a, cp, ticks, crashes>> /\ UNCHANGED Outside
    /\ UNCHANGED <<signed, shown, committed, answered, forgerySealed, late>>

Delete == \E e \in db : Attack(db \ {e}, cps)

DeleteCheckpoint == \E r \in cps : Attack(db, cps \ {r})

\* An entry made up, at any number handed out: its MAC fails.
Forge == \E n \in 1..seq : Attack(db \cup {[n |-> n, rid |-> Forged, ok |-> FALSE]}, cps)

\* An entry copied under any number handed out, a live one included: its MAC holds, since it does not cover the number.
Replay == \E e \in db, n \in 1..seq : n # e.n /\ Attack(db \cup {[e EXCEPT !.n = n]}, cps)

\* Two entries' numbers swapped: both MACs still hold.
Swap == \E e1, e2 \in db : e1.n < e2.n /\ Attack((db \ {e1, e2}) \cup {[e1 EXCEPT !.n = e2.n], [e2 EXCEPT !.n = e1.n]}, cps)

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Appends : Lock(x) \/ Number(x) \/ Finish(x) \/ Answer(x)
    \/ TickRead \/ TickSign \/ TickFinish \/ Publish \/ Crash \/ Open
    \/ Delete \/ DeleteCheckpoint \/ Forge \/ Replay \/ Swap

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The verifier, from the database and the witness's head alone. *)

\* The heads the walk must meet: every checkpoint row, and the witness's.
Stops == cps \cup (IF Witness THEN {witness} ELSE {})

Alarm ==
    \/ refused \/ macAlarm \/ witnessRefused \/ rowAlarm
    \/ Genesis \notin cps                                         \* no start where the walk must start
    \/ Witness /\ \A r \in cps : r.upto < witness.upto            \* the database ends before the witness's head
    \/ \E s \in Stops : {e \in db : e.n <= s.upto} # s.leaves     \* the walk does not give a head on its way
    \/ \E e1, e2 \in db : e1 # e2 /\ e1.n = e2.n                  \* a number twice
    \/ RequestIdChecked /\ \E e1, e2 \in db : e1 # e2 /\ e1.rid = e2.rid   \* a request twice

-----------------------------------------------------------------------------
(* Invariants. The ones about the attacker's deletions hold once the signer has acted after the attack (ticked,     *)
(* written, published, restarted): until then nothing outside the database has looked, and a verifier cannot tell a   *)
(* deleted newest checkpoint from one never written. With RowChecked that is at most one tick, traffic or not.       *)

\* Nothing commits under a seal: no honest entry commits at a number a signed head already covers.
Complete ==
    ~late

\* An entry ever sealed into a head readers may have been shown that is gone from the database, or no longer at its number, is seen.
SealedDeletionDetected ==
    (~settling /\ \E h \in shown : \E e \in h.leaves : e \notin db) => Alarm

\* Two heads readers may have been shown that are not one a prefix of the other (a split view) are seen.
SplitViewDetected ==
    (~settling /\ \E h1, h2 \in shown : ~Prefix(h1, h2) /\ ~Prefix(h2, h1)) => Alarm

\* A change its admin was told is done cannot vanish unseen.
AnsweredChangeKept ==
    (~settling /\ \E x \in answered : ~\E e \in db : e.rid = x) => Alarm

\* No forged entry is ever sealed.
NoForgerySealed ==
    ~forgerySealed

\* A replay that gets sealed (two sealed entries with one request ID, both MACs valid) is seen.
NoUndetectedReplay ==
    (~settling /\ \E h \in shown : \E e1, e2 \in h.leaves : e1 # e2 /\ e1.rid = e2.rid) => Alarm

\* No alarm without an attack.
NoFalseAlarm ==
    attacks = 0 => ~Alarm

\* EXPECTED TO FAIL, with every protection: the window, from an entry's commit to the tick that seals it.
\*   An honest entry deleted before any head sealed it is never seen.
UnsealedDeletionDetected ==
    (\E e \in committed : ~\E f \in db : f.rid = e.rid) => Alarm
\*   Nor is one moved to another number before it is sealed (two swapped, or a replay and the original deleted).
UnsealedReorderDetected ==
    (\E e \in committed : e \notin db /\ \E f \in db : f.rid = e.rid /\ f.n # e.n) => Alarm

=============================================================================
