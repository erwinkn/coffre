-------------------------------- MODULE Seal --------------------------------
(***************************************************************************)
(* W209: sealing 0.15's audit log into a Merkle tree, anchoring its heads, *)
(* and what an attacker with write access to the database (no key) can    *)
(* and cannot hide (experiments/merkle/schema.sql, src/log.ts).            *)
(*                                                                         *)
(* An append is one statement: it takes the fence's advisory lock shared,  *)
(* takes its number from the sequence, inserts its entry and commits, or   *)
(* aborts and leaves a gap. An entry's MAC covers everything but its       *)
(* number (the INSERT takes it), its request ID included. Some appends are *)
(* changes (a revoke): the admin who made one is answered.                 *)
(*                                                                         *)
(* The checkpointer, each tick, takes the lock exclusively (waiting for    *)
(* every append that holds it), reads the sequence's last value as `upto`  *)
(* and lets go; then reads the committed entries in (the last head's upto, *)
(* upto], checks their MACs, appends them to the tree, signs the new head, *)
(* records it outside the database (the anchor) and writes it to the       *)
(* database.                                                               *)
(*                                                                         *)
(* The tree is abstracted to the set of its leaves, each a whole entry:    *)
(* number, request ID, whether its MAC holds. Leaves go in number order    *)
(* and every new window lies above the last head's upto, so a head         *)
(* [upto, leaves] names one leaf sequence, and one head is a prefix of     *)
(* another exactly when `Prefix` says so (a consistency proof).            *)
(*                                                                         *)
(* The anchor stands for what the signer keeps outside the database (a     *)
(* Durable Object's storage, a witness that checks consistency): the       *)
(* newest head it signed. Without it the signer is stateless and starts    *)
(* each tick from the database's newest checkpoint row.                    *)
(*                                                                         *)
(* The protections, each a constant (scripts/formal-seal.sh shows each     *)
(* necessary):                                                             *)
(*   NumberUnderLock   the append takes its number after the shared lock;  *)
(*                     off, before it (e.g. nextval in the use's read);    *)
(*   CloseLocks        the tick reads the sequence under the exclusive     *)
(*                     lock;                                               *)
(*   Anchored          the signer's newest head lives outside the          *)
(*                     database, and it signs only an extension of it.     *)
(*                     Off is R40's degraded mode: no anchor plugin;       *)
(*   RememberFirst     the head is recorded outside before it is written   *)
(*                     to the database;                                    *)
(*   MacChecked        the checkpointer seals no entry whose MAC fails;    *)
(*   RequestIdChecked  the verifier refuses two sealed entries with one    *)
(*                     request ID (a replay: the MAC does not cover the    *)
(*                     number, so a copy under a new number has a valid    *)
(*                     one);                                               *)
(*   WaitForSeal       a change answers only once a head holding its       *)
(*                     entry is anchored (without the anchor: once it is   *)
(*                     in the database's newest checkpoint).               *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Appends,      \* the appends, each one statement; an append's request ID is its name
    Changes,      \* the appends that are changes, answered to an admin
    MaxTicks,     \* checkpointer ticks in a behaviour
    MaxAttacks,   \* attacker steps in a behaviour
    MaxCrashes,   \* checkpointer crashes (losing what it held in memory)
    NumberUnderLock, CloseLocks, Anchored, RememberFirst, MacChecked, RequestIdChecked, WaitForSeal

ASSUME Changes \subseteq Appends

Genesis == [upto |-> 0, leaves |-> {}]
Forged == "forged"   \* the request ID of an entry the attacker made up

VARIABLES
    seq,       \* the sequence's last value
    shared,    \* the appends holding the fence's lock shared
    a,         \* each append: pc and number
    db,        \* the committed entries: [n, rid, ok], ok = its MAC holds
    cps,       \* the database's checkpoint rows, oldest first
    anchor,    \* the newest head held outside the database (Anchored)
    cp,        \* the checkpointer: pc, the upto it read, the head it holds
    ticks, attacks, crashes,
    refused,   \* sticky: the signer or the witness refused a head (an alarm)
    macAlarm,  \* sticky: the checkpointer met an entry whose MAC fails (an alarm)
    signed,    \* ghost: every head ever signed (what readers may have been shown)
    committed, \* ghost: every entry an honest append committed, as committed
    answered,  \* ghost: the changes answered to their admin
    forgerySealed, \* ghost: a head was signed over an entry whose MAC fails
    late       \* ghost: an honest entry committed at a number a signed head already covered

vars == <<seq, shared, a, db, cps, anchor, cp, ticks, attacks, crashes, refused, macAlarm, signed, committed, answered, forgerySealed, late>>

Numbers == {e.n : e \in db}
Newest(s) == IF s = <<>> THEN Genesis ELSE s[Len(s)]
Prefix(h1, h2) == h1.upto <= h2.upto /\ h1.leaves = {e \in h2.leaves : e.n <= h1.upto}
Holds(h, rid) == \E e \in h.leaves : e.rid = rid

Init ==
    /\ seq = 0
    /\ shared = {}
    /\ a = [x \in Appends |-> [pc |-> "idle", n |-> 0]]
    /\ db = {}
    /\ cps = <<Genesis>>
    /\ anchor = Genesis
    /\ cp = [pc |-> "idle", upto |-> 0, head |-> Genesis]
    /\ ticks = 0 /\ attacks = 0 /\ crashes = 0
    /\ refused = FALSE /\ macAlarm = FALSE
    /\ signed = {Genesis}
    /\ committed = {} /\ answered = {} /\ forgerySealed = FALSE /\ late = FALSE

-----------------------------------------------------------------------------
(* An append. With NumberUnderLock: lock, number, commit. Without: number, lock, commit. *)

Lock(x) ==
    /\ a[x].pc = IF NumberUnderLock THEN "idle" ELSE "numbered"
    /\ shared' = shared \cup {x}
    /\ a' = [a EXCEPT ![x].pc = IF NumberUnderLock THEN "locked" ELSE "ready"]
    /\ UNCHANGED <<seq, db, cps, anchor, cp, ticks, attacks, crashes, refused, macAlarm, signed, committed, answered, forgerySealed, late>>

Number(x) ==
    /\ a[x].pc = IF NumberUnderLock THEN "locked" ELSE "idle"
    /\ seq' = seq + 1
    /\ a' = [a EXCEPT ![x] = [pc |-> IF NumberUnderLock THEN "ready" ELSE "numbered", n |-> seq + 1]]
    /\ UNCHANGED <<shared, db, cps, anchor, cp, ticks, attacks, crashes, refused, macAlarm, signed, committed, answered, forgerySealed, late>>

\* Commits, or aborts (a gap); a number the attacker filled first makes it abort (primary key).
Finish(x) ==
    /\ a[x].pc = "ready"
    /\ \E commit \in BOOLEAN :
        LET e == [n |-> a[x].n, rid |-> x, ok |-> TRUE] IN
        IF commit /\ a[x].n \notin Numbers
        THEN /\ db' = db \cup {e}
             /\ committed' = committed \cup {e}
             /\ late' = (late \/ \E h \in signed : a[x].n <= h.upto)
             /\ a' = [a EXCEPT ![x].pc = IF x \in Changes THEN "committed" ELSE "done"]
        ELSE /\ a' = [a EXCEPT ![x].pc = "done"]
             /\ UNCHANGED <<db, committed, late>>
    /\ shared' = shared \ {x}
    /\ UNCHANGED <<seq, cps, anchor, cp, ticks, attacks, crashes, refused, macAlarm, signed, answered, forgerySealed>>

\* A change answers its admin: at once, or (WaitForSeal) once a head holding it is anchored, or, with no anchor, once
\* the database's newest checkpoint holds it.
Answer(x) ==
    /\ a[x].pc = "committed"
    /\ WaitForSeal => Holds(IF Anchored THEN anchor ELSE Newest(cps), x)
    /\ a' = [a EXCEPT ![x].pc = "answered"]
    /\ answered' = answered \cup {x}
    /\ UNCHANGED <<seq, shared, db, cps, anchor, cp, ticks, attacks, crashes, refused, macAlarm, signed, committed, forgerySealed, late>>

-----------------------------------------------------------------------------
(* The checkpointer. *)

\* The exclusive lock (waiting for every append holding it shared), the sequence read, the lock let go.
TickRead ==
    /\ cp.pc = "idle"
    /\ ticks < MaxTicks
    /\ CloseLocks => shared = {}
    /\ cp' = [cp EXCEPT !.pc = "read", !.upto = seq]
    /\ ticks' = ticks + 1
    /\ UNCHANGED <<seq, shared, a, db, cps, anchor, attacks, crashes, refused, macAlarm, signed, committed, answered, forgerySealed, late>>

\* The entries the database holds above `d`'s upto and up to `upto`.
Window(d, upto) == {e \in db : d.upto < e.n /\ e.n <= upto}

\* Where the signer goes on from. Stateless: the database's newest row. Anchored: the newest row if it extends the
\* anchor (the signer crashed after writing it, before recording it); the anchor if the database is behind it and the
\* entries the anchor sealed above the row are all still there (crashed after recording, before writing: the row is
\* written again); otherwise nothing: the database lost or changed what was signed, and the signer refuses.
TickSign ==
    /\ cp.pc = "read"
    /\ LET d == Newest(cps) IN
       IF Anchored /\ ~Prefix(anchor, d)
       THEN IF Prefix(d, anchor) /\ Window(d, anchor.upto) = anchor.leaves \ d.leaves
            THEN \* Write the remembered head again, and seal on the next tick.
                 /\ cps' = Append(cps, anchor)
                 /\ cp' = [cp EXCEPT !.pc = "idle"]
                 /\ UNCHANGED <<anchor, refused, macAlarm, signed, forgerySealed>>
            ELSE /\ refused' = TRUE
                 /\ cp' = [cp EXCEPT !.pc = "idle"]
                 /\ UNCHANGED <<cps, anchor, macAlarm, signed, forgerySealed>>
       ELSE LET w == Window(d, cp.upto)
                h == [upto |-> cp.upto, leaves |-> d.leaves \cup w]
            IN IF MacChecked /\ \E e \in w : ~e.ok
               THEN /\ macAlarm' = TRUE
                    /\ cp' = [cp EXCEPT !.pc = "idle"]
                    /\ UNCHANGED <<cps, anchor, refused, signed, forgerySealed>>
               ELSE IF cp.upto <= d.upto
               THEN /\ cp' = [cp EXCEPT !.pc = "idle"]
                    /\ UNCHANGED <<cps, anchor, refused, macAlarm, signed, forgerySealed>>
               ELSE /\ signed' = signed \cup {h}
                    /\ forgerySealed' = (forgerySealed \/ \E e \in w : ~e.ok)
                    /\ IF Anchored /\ RememberFirst
                       THEN /\ anchor' = h
                            /\ cp' = [cp EXCEPT !.pc = "remembered", !.head = h]
                            /\ UNCHANGED cps
                       ELSE /\ cps' = Append(cps, h)
                            /\ cp' = [cp EXCEPT !.pc = "written", !.head = h]
                            /\ UNCHANGED anchor
                    /\ UNCHANGED <<refused, macAlarm>>
    /\ UNCHANGED <<seq, shared, a, db, ticks, attacks, crashes, committed, answered, late>>

\* RememberFirst: the head, recorded outside, now written to the database.
TickWrite ==
    /\ cp.pc = "remembered"
    /\ cps' = Append(cps, cp.head)
    /\ cp' = [cp EXCEPT !.pc = "idle"]
    /\ UNCHANGED <<seq, shared, a, db, anchor, ticks, attacks, crashes, refused, macAlarm, signed, committed, answered, forgerySealed, late>>

\* Not RememberFirst: the head, written to the database, now recorded outside; the witness takes only an extension.
TickPublish ==
    /\ cp.pc = "written"
    /\ IF ~Anchored THEN UNCHANGED <<anchor, refused>>
       ELSE IF Prefix(anchor, cp.head) THEN anchor' = cp.head /\ UNCHANGED refused
       ELSE refused' = TRUE /\ UNCHANGED anchor
    /\ cp' = [cp EXCEPT !.pc = "idle"]
    /\ UNCHANGED <<seq, shared, a, db, cps, ticks, attacks, crashes, macAlarm, signed, committed, answered, forgerySealed, late>>

\* The checkpointer dies mid-tick and loses what it held in memory; the next tick starts over.
Crash ==
    /\ cp.pc \in {"read", "remembered", "written"}
    /\ crashes < MaxCrashes
    /\ crashes' = crashes + 1
    /\ cp' = [cp EXCEPT !.pc = "idle"]
    /\ UNCHANGED <<seq, shared, a, db, cps, anchor, ticks, attacks, refused, macAlarm, signed, committed, answered, forgerySealed, late>>

-----------------------------------------------------------------------------
(* The attacker: write access to the database, no key. Each step changes `db` or `cps` only. *)

Attack(dbNext, cpsNext) ==
    /\ attacks < MaxAttacks
    /\ attacks' = attacks + 1
    /\ db' = dbNext
    /\ cps' = cpsNext
    /\ UNCHANGED <<seq, shared, a, anchor, cp, ticks, crashes, refused, macAlarm, signed, committed, answered, forgerySealed, late>>

Free == (1..seq) \ Numbers   \* numbers handed out and not in the table: gaps, and appends in flight

Delete == \E e \in db : Attack(db \ {e}, cps)

DeleteNewestCheckpoint == cps # <<>> /\ Attack(db, SubSeq(cps, 1, Len(cps) - 1))

\* An entry made up: its MAC fails.
Forge == \E n \in Free : Attack(db \cup {[n |-> n, rid |-> Forged, ok |-> FALSE]}, cps)

\* An entry copied under a free number: its MAC holds, since it does not cover the number.
Replay == \E e \in db, n \in Free : Attack(db \cup {[e EXCEPT !.n = n]}, cps)

\* Two entries' numbers swapped: both MACs still hold.
Swap == \E e1, e2 \in db : e1.n < e2.n /\ Attack((db \ {e1, e2}) \cup {[e1 EXCEPT !.n = e2.n], [e2 EXCEPT !.n = e1.n]}, cps)

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Appends : Lock(x) \/ Number(x) \/ Finish(x) \/ Answer(x)
    \/ TickRead \/ TickSign \/ TickWrite \/ TickPublish \/ Crash
    \/ Delete \/ DeleteNewestCheckpoint \/ Forge \/ Replay \/ Swap

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The verifier, from the database and the anchor alone: the newest head it can trust is the longer of the database's
   newest row and the anchor (one must extend the other); the entries at or below that head's upto must be exactly its
   leaves, each with one request ID; the rows must each extend the one before. *)

Trusted ==
    LET d == Newest(cps) IN
    IF ~Anchored \/ Prefix(anchor, d) THEN d ELSE anchor

Alarm ==
    \/ refused
    \/ macAlarm
    \/ Anchored /\ ~Prefix(anchor, Newest(cps)) /\ ~Prefix(Newest(cps), anchor)
    \/ {e \in db : e.n <= Trusted.upto} # Trusted.leaves
    \/ \E i, j \in 1..Len(cps) : i < j /\ ~Prefix(cps[i], cps[j])
    \/ RequestIdChecked /\ \E e1, e2 \in Trusted.leaves : e1 # e2 /\ e1.rid = e2.rid

-----------------------------------------------------------------------------
(* Invariants. *)

\* Nothing commits under a seal: no honest entry commits at a number a signed head already covers (it would never be
\* sealed, and a verifier would take it for a forgery).
Complete ==
    ~late

\* An entry ever sealed into a signed head that is gone from the database, or no longer at its number, is seen.
SealedDeletionDetected ==
    (\E h \in signed : \E e \in h.leaves : e \notin db) => Alarm

\* Two signed heads that are not one a prefix of the other (a split view) are seen.
SplitViewDetected ==
    (\E h1, h2 \in signed : ~Prefix(h1, h2) /\ ~Prefix(h2, h1)) => Alarm

\* No forged entry is ever sealed.
NoForgerySealed ==
    ~forgerySealed

\* A replay that gets sealed (two sealed entries with one request ID) is seen.
NoUndetectedReplay ==
    (\E h \in signed : \E e1, e2 \in h.leaves : e1 # e2 /\ e1.rid = e2.rid) => Alarm

\* A change its admin was told is done cannot vanish unseen.
AnsweredChangeKept ==
    (\E x \in answered : ~\E e \in db : e.rid = x) => Alarm

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
