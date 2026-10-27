-------------------------------- MODULE Seal --------------------------------
(***************************************************************************)
(* W209: sealing 0.15's audit log into Merkle trees, holding their heads   *)
(* outside the database, and what an attacker with write access to the    *)
(* database (no key) can and cannot hide (experiments/merkle/schema.sql,   *)
(* src/log.ts, src/verify.ts). W212: two trees, one per retention class,   *)
(* whose heads behave as one pair (docs/design/merkle-checkpoints.md,      *)
(* "What `split` needs to stay one log").                                  *)
(*                                                                         *)
(* An append is one statement: it takes the fence's advisory lock shared,  *)
(* takes its number from the sequence, inserts its entry and commits, or   *)
(* aborts and leaves a gap. Nothing makes numbers unique in the table. An  *)
(* entry's MAC covers everything but its number: its request ID and (with  *)
(* KindInMac) its kind. An entry is a change (a revoke, kept for good, its *)
(* admin answered) or a use (pruned by day); its kind is its partition.    *)
(* Every append's MAC holds under the signer's one key: in the code both   *)
(* writers, the change path and the use path, MAC with `entryMac` under    *)
(* `logMacKey` (packages/vault/src/log-entry.ts), the kind in what it      *)
(* covers, never in which key made it (T128).                              *)
(*                                                                         *)
(* Two trees: the changes tree seals the changes, the uses tree the uses.  *)
(* A head is a pair, one note per tree, [upto, leaves] each; a tick signs  *)
(* both at one upto. The database holds a checkpoint row per tree and      *)
(* upto.                                                                   *)
(*                                                                         *)
(* The signer (the checkpointer) runs from the pair it holds in memory.    *)
(* Each tick it takes the lock exclusively (waiting for every append that  *)
(* holds it), reads the sequence's last value as `upto`, lets go, reads    *)
(* each tree's committed entries in (its note's upto, upto], checks their  *)
(* MACs, appends each to the tree of its kind, signs the new pair,         *)
(* remembers it (its own memory, outside the database), writes it to the   *)
(* database, and queues it for the witness. Remembering and writing are    *)
(* one step each for the pair, or (without PairRemembered,                 *)
(* PairWrittenTogether) a step per tree, the changes tree first: a crash   *)
(* can fall between them. While it runs it never reads the database's      *)
(* checkpoints but at each tick (RowChecked): only at a restart (`Open`)   *)
(* does it compare them with its memory, each tree's newest row with the   *)
(* remembered note of that tree, as Checkpointer.open does:                *)
(*   no row of the tree     refused if it remembers a note but genesis;    *)
(*                          else a new log, its genesis at 0;              *)
(*   memory ahead of the db the tree's entries between the newest row and  *)
(*                          the remembered note must give it again: then   *)
(*                          its row is written, else the signer refuses;   *)
(*   the same upto          the same note, else it refuses;                *)
(*   the db ahead           the remembered note must be a prefix, else it  *)
(*                          refuses.                                       *)
(* Without SignerMemory the restart takes each tree's newest row.          *)
(*                                                                         *)
(* The witness holds the newest pair published to it, a note per origin,   *)
(* and takes a new note only if it extends its own (a consistency proof),  *)
(* as a standard witness of each log does. Publication runs behind the     *)
(* tick, the newest pair only, both notes in one publication, and what is  *)
(* queued is lost in a crash.                                              *)
(*                                                                         *)
(* The verifier (verifyLog) starts from the genesis pair it requires (upto *)
(* 0, no leaves), walks every entry in number order, both trees merged,    *)
(* and requires every checkpoint row and the witness's notes on the way:   *)
(* the entries of a tree's kind at or below a note's upto must be exactly  *)
(* its leaves. It also requires the database not to end before either of  *)
(* the witness's notes, every number and (with RequestIdChecked) every     *)
(* request ID to appear once across both trees, (with PairVerified) every  *)
(* row to have its pair, the other tree's row at its upto, and it reads    *)
(* the signer's and the witness's refusals as alarms.                      *)
(*                                                                         *)
(* A tree is abstracted to the set of its leaves, each a whole entry:      *)
(* number, request ID, kind, whether its MAC holds. Leaves go in number    *)
(* order and every window lies above the note before it, so a note        *)
(* [upto, leaves] names one leaf sequence, and one note is a prefix of     *)
(* another exactly when `Prefix` says so (a consistency proof).            *)
(*                                                                         *)
(* The protections, each a constant (scripts/formal.sh shows each          *)
(* necessary):                                                             *)
(*   NumberUnderLock   the append takes its number after the shared lock;  *)
(*   CloseLocks        the tick reads the sequence under the exclusive     *)
(*                     lock;                                               *)
(*   SignerMemory      the signer remembers its newest pair outside the    *)
(*                     database and checks the database against it at a    *)
(*                     restart (core, R40 without the plugin);             *)
(*   RowChecked        each tick, a running signer requires the database's *)
(*                     newest checkpoint to be its head in memory;         *)
(*   PairChecked       ... that check reads each tree's newest row, not    *)
(*                     the newest row of either tree;                      *)
(*   PairVerified      the verifier requires every row's pair;             *)
(*   Witness           a pair held outside, consistency-checked at each    *)
(*                     publication, which the verifier requires (the       *)
(*                     plugin);                                            *)
(*   RememberFirst     the signer remembers a pair before writing it;      *)
(*   PairRemembered    the pair is remembered in one write;                *)
(*   PairWrittenTogether both rows of a pair are written in one statement; *)
(*   MacChecked        the signer seals no entry whose MAC fails;          *)
(*   KindInMac         the MAC covers the entry's kind: an entry moved to  *)
(*                     the other partition (the other tree) fails it;      *)
(*   RequestIdChecked  the verifier flags two entries with one request ID. *)
(*                     It is a check of the verifier's: removing it is     *)
(*                     exactly removing the protection. It catches a       *)
(*                     replay, a copy of an entry under another number,    *)
(*                     whose MAC holds since it does not cover the number; *)
(*   WaitForSeal       a change answers only once the signer has written   *)
(*                     a pair whose changes note holds it and, with a      *)
(*                     witness, the witness's changes note holds it.       *)
(*                                                                         *)
(* Retention (plan PR 7, W229; with Retention, SealRetention.cfg). Time is *)
(* a clock that each barrier moves on a step, or not (two barriers in one  *)
(* instant): an entry's `at` is its commit's, a pair's its barrier's (an   *)
(* honest entry of a window is never stamped before the barrier that       *)
(* closed the window below it: the deadline and its floor, HotPathOneClock,*)
(* abstracted here to "at the commit"). Uses go by day of `at`: a day is a *)
(* partition, dropped whole, the uses stamped before a cut pair's barrier, *)
(* whatever their numbers; those stamped at its instant, numbered below    *)
(* it, are the next day's stragglers. One retention run:                   *)
(*   choose   a cut: a pair the signer signed, both rows in the database,  *)
(*            on its history, at or below its head; only a signer that     *)
(*            keeps its memory retains (its pair bounds freshness);        *)
(*   entry    the retention change, naming the cut, appended (RetAppend);  *)
(*   drop     the day's uses partition dropped, and the uses tree's tiles  *)
(*            below the cut, one tile per level kept (an abstraction: the  *)
(*            kept tiles give the cut's head and every proof above it,     *)
(*            which packages/core's tests check exhaustively; here, only   *)
(*            whether they are kept).                                      *)
(* The verifier walks the changes tree from genesis, and the uses tree     *)
(* from the newest cut a retention change names: the cut row's uses note  *)
(* is its start, and each uses note above it must be that note and the     *)
(* entries between.                                                        *)
(*                                                                         *)
(* Retention's protections:                                                *)
(*   DropAfterSeal     the day goes only once the retention change is      *)
(*                     sealed in the signer's pair;                        *)
(*   FreshChecked      the signer seals no entry stamped more than Fresh   *)
(*                     before the pair it holds (FRESH_MS): a copy of a    *)
(*                     dropped use has no original left for a request-ID   *)
(*                     check to find. (The code also reads each window     *)
(*                     from the floor of `at`, HotPathOne's                *)
(*                     BarrierChecksFloor, which leaves such a copy unread *)
(*                     in the first place: two lines, this the second.)    *)
(*   FreshBeforeDrop   the day goes only once the pair that sealed the     *)
(*                     retention change is Fresh past the cut: every copy  *)
(*                     of a dropped use is then too old for the signer;    *)
(*   CutSealed         the verifier honours a retention change only once   *)
(*                     sealed in the changes tree, never one the database  *)
(*                     merely holds;                                       *)
(*   CutUsesOnly       a cut drops uses alone: changes are kept for good   *)
(*                     (the changes tree is never cut);                    *)
(*   KeepCutTiles      the tiles holding the cut, one per level, are kept: *)
(*                     the verifier starts the uses tree there.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Appends,      \* the appends, each one statement; an append's request ID is its name
    Changes,      \* the appends that are changes, answered to an admin; the others are uses
    MaxTicks,     \* checkpointer ticks in a behaviour
    MaxAttacks,   \* attacker steps in a behaviour
    MaxCrashes,   \* checkpointer crashes (losing what it held in memory, its memory outside kept)
    NumberUnderLock, CloseLocks, SignerMemory, RowChecked, PairChecked, PairVerified, Witness, RememberFirst,
    PairRemembered, PairWrittenTogether, MacChecked, KindInMac, RequestIdChecked, WaitForSeal,
    Retention,    \* whether a retention run is in the behaviours; without it, the clock stands at 0
    RetAppend,    \* the retention change, one of Changes when Retention is on
    MaxTime,      \* clock steps in a behaviour (each at a barrier)
    Fresh,        \* FRESH_MS, in clock steps
    FreshChecked, DropAfterSeal, FreshBeforeDrop, CutSealed, CutUsesOnly, KeepCutTiles

ASSUME Changes \subseteq Appends
ASSUME Retention => RetAppend \in Changes

Kinds == {"c", "u"}                          \* the changes tree and the uses tree, and an entry's kind
Other(t) == IF t = "c" THEN "u" ELSE "c"
KindOf(x) == IF x \in Changes THEN "c" ELSE "u"
\* A note: its upto, its leaves, and the time of the barrier it was sealed at (both notes of a pair carry it).
GenesisNote == [upto |-> 0, leaves |-> {}, at |-> 0]
Genesis == [t \in Kinds |-> GenesisNote]      \* a pair: a note per tree
\* A pair's row (or note, as a witness or reader holds it) for one tree.
Row(h, t) == [t |-> t, upto |-> h[t].upto, leaves |-> h[t].leaves, at |-> h[t].at]
GenesisRows == {Row(Genesis, t) : t \in Kinds}
Forged == "forged"                           \* the request ID of an entry the attacker made up

VARIABLES
    seq,       \* the sequence's last value
    shared,    \* the appends holding the fence's lock shared
    a,         \* each append: pc and number
    db,        \* the committed entries: [n, rid, kind, ok, at, cut], ok = its MAC holds; numbers may repeat; cut, the
               \* upto a retention change names (0 for any other entry)
    cps,       \* the database's checkpoint rows, [t, upto, leaves, at] (a set: one per tree and upto, the primary key)
    cp,        \* the signer: pc, the upto and time it read, its pair in memory, the pair it is sealing, the steps left
    memory,    \* SignerMemory: the newest pair the signer remembers, outside the database
    queued,    \* the pair waiting to be published to the witness: [on, head]
    witness,   \* Witness: the newest pair the witness holds
    ticks, attacks, crashes,
    refused,   \* sticky: the signer refused the database at a restart (an alarm)
    macAlarm,  \* sticky: the signer met an entry whose MAC fails (an alarm)
    witnessRefused, \* sticky: the witness refused a note that does not extend its own (an alarm)
    rowAlarm,  \* sticky: a running signer found the database's newest checkpoint is not its head (an alarm)
    staleAlarm, \* sticky: the signer met an entry stamped too long before its pair (an alarm: a replay)
    signed,    \* ghost: every pair ever signed
    shown,     \* ghost: every row ever written to the database or published: what readers may have been shown
    committed, \* ghost: every entry an honest append committed
    answered,  \* ghost: the changes answered to their admin
    forgerySealed, \* ghost: a pair was signed over an entry whose MAC fails
    late,      \* ghost: an honest entry committed at a number a signed pair already covered
    settling,  \* ghost: the attacker acted, and the signer has not ticked, written, published or restarted since
    now,       \* the clock
    rt,        \* the retention run: pc ("idle", "entry", "done") and the cut pair it chose
    tilesGone, \* the tiles at the cut were dropped with the rest below it
    dropped,   \* ghost: the entries retention dropped
    resealed   \* ghost: a pair was signed over an entry with the request ID of one retention dropped

vars == <<seq, shared, a, db, cps, cp, memory, queued, witness, ticks, attacks, crashes, refused, macAlarm, witnessRefused, rowAlarm,
          staleAlarm, signed, shown, committed, answered, forgerySealed, late, settling, now, rt, tilesGone, dropped, resealed>>

Max(x, y) == IF x >= y THEN x ELSE y
Min(x, y) == IF x <= y THEN x ELSE y
\* For notes and rows alike: n1 is n2's prefix.
Prefix(n1, n2) == n1.upto <= n2.upto /\ n1.leaves = {e \in n2.leaves : e.n <= n1.upto}
Holds(note, rid) == \E e \in note.leaves : e.rid = rid
RowsOf(t) == {r \in cps : r.t = t}
NewestOf(t) == CHOOSE r \in RowsOf(t) : \A s \in RowsOf(t) : s.upto <= r.upto   \* only when RowsOf(t) # {}
NewestAny == CHOOSE r \in cps : \A s \in cps : s.upto <= r.upto                 \* only when cps # {}
\* The entries of kind t the database holds above `from` and up to `upto`.
Window(t, from, upto) == {e \in db : e.kind = t /\ from < e.n /\ e.n <= upto}
\* The pair h sealed up to `upto`, at the barrier's time `at`: each tree takes the entries of its kind above its note.
Sealed(h, upto, at) == [t \in Kinds |-> [upto |-> upto, leaves |-> h[t].leaves \cup Window(t, h[t].upto, upto), at |-> at]]

Init ==
    /\ seq = 0
    /\ shared = {}
    /\ a = [x \in Appends |-> [pc |-> "idle", n |-> 0]]
    /\ db = {}
    /\ cps = GenesisRows
    /\ cp = [pc |-> "idle", upto |-> 0, at |-> 0, head |-> Genesis, next |-> Genesis, todo |-> <<>>]
    /\ memory = Genesis
    /\ queued = [on |-> FALSE, head |-> Genesis]
    /\ witness = Genesis
    /\ ticks = 0 /\ attacks = 0 /\ crashes = 0
    /\ refused = FALSE /\ macAlarm = FALSE /\ witnessRefused = FALSE /\ rowAlarm = FALSE /\ staleAlarm = FALSE
    /\ signed = {Genesis} /\ shown = GenesisRows
    /\ committed = {} /\ answered = {} /\ forgerySealed = FALSE /\ late = FALSE /\ settling = FALSE
    /\ now = 0 /\ rt = [pc |-> "idle", cut |-> Genesis] /\ tilesGone = FALSE /\ dropped = {} /\ resealed = FALSE

Outside == <<memory, queued, witness, refused, macAlarm, witnessRefused, rowAlarm, staleAlarm>>
Ghosts == <<signed, shown, committed, answered, forgerySealed, late, settling>>
Retained == <<now, rt, tilesGone, dropped, resealed>>

-----------------------------------------------------------------------------
(* An append. With NumberUnderLock: lock, number, commit. Without: number, lock, commit. *)

\* The retention change is appended by its run, once it has chosen its cut.
Lock(x) ==
    /\ a[x].pc = IF NumberUnderLock THEN "idle" ELSE "numbered"
    /\ x = RetAppend => rt.pc = "entry"
    /\ shared' = shared \cup {x}
    /\ a' = [a EXCEPT ![x].pc = IF NumberUnderLock THEN "locked" ELSE "ready"]
    /\ UNCHANGED <<seq, db, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside /\ UNCHANGED Ghosts /\ UNCHANGED Retained

Number(x) ==
    /\ a[x].pc = IF NumberUnderLock THEN "locked" ELSE "idle"
    /\ x = RetAppend => rt.pc = "entry"
    /\ seq' = seq + 1
    /\ a' = [a EXCEPT ![x] = [pc |-> IF NumberUnderLock THEN "ready" ELSE "numbered", n |-> seq + 1]]
    /\ UNCHANGED <<shared, db, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside /\ UNCHANGED Ghosts /\ UNCHANGED Retained

\* Commits, or aborts (a gap). No key makes the number unique: it commits whatever the attacker put there. Stamped at
\* the commit; the retention change names its run's cut.
Finish(x) ==
    /\ a[x].pc = "ready"
    /\ \E commit \in BOOLEAN :
        LET e == [n |-> a[x].n, rid |-> x, kind |-> KindOf(x), ok |-> TRUE, at |-> now,
                  cut |-> IF x = RetAppend THEN rt.cut.u.upto ELSE 0] IN
        IF commit
        THEN /\ db' = db \cup {e}
             /\ committed' = committed \cup {e}
             /\ late' = (late \/ \E h \in signed : a[x].n <= h.c.upto)
             /\ a' = [a EXCEPT ![x].pc = IF x \in Changes THEN "committed" ELSE "done"]
        ELSE /\ a' = [a EXCEPT ![x].pc = "done"]
             /\ UNCHANGED <<db, committed, late>>
    /\ shared' = shared \ {x}
    /\ UNCHANGED <<seq, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside
    /\ UNCHANGED <<signed, shown, answered, forgerySealed, settling>> /\ UNCHANGED Retained

\* A change answers its admin: at once, or (WaitForSeal) once the running signer has written a pair whose changes note
\* holds it (its inclusion proof, in the changes tree) and, with a witness, the witness's changes note holds it. (The
\* code answers anyway after a deadline, saying "not witnessed": not modelled.)
Answer(x) ==
    /\ a[x].pc = "committed"
    /\ WaitForSeal => /\ cp.pc \notin {"down", "refused"}
                      /\ Holds(cp.head.c, x)
                      /\ Witness => Holds(witness.c, x)
    /\ a' = [a EXCEPT ![x].pc = "answered"]
    /\ answered' = answered \cup {x}
    /\ UNCHANGED <<seq, shared, db, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside
    /\ UNCHANGED <<signed, shown, committed, forgerySealed, late, settling>> /\ UNCHANGED Retained

-----------------------------------------------------------------------------
(* The signer. *)

\* The exclusive lock (waiting for every append holding it shared), the sequence read, the lock let go. The same
\* statement returns the database's newest checkpoint: with RowChecked, a signer whose head is not that one raises an
\* alarm and signs nothing (a row deleted, with no traffic to write the next one, is seen within a tick). With
\* PairChecked it reads each tree's newest row; without, #365's query, the newest row of either tree.
RowOff ==
    IF PairChecked
    THEN \E t \in Kinds : RowsOf(t) = {} \/ NewestOf(t).upto # cp.head[t].upto
    ELSE cps = {} \/ NewestAny.upto # Max(cp.head.c.upto, cp.head.u.upto)

\* With Retention the clock moves on at the barrier, a step or none; the pair is sealed at its time.
TickRead ==
    /\ cp.pc = "idle"
    /\ ticks < MaxTicks
    /\ CloseLocks => shared = {}
    /\ ticks' = ticks + 1
    /\ settling' = FALSE
    /\ \E t \in IF Retention THEN {now, Min(now + 1, MaxTime)} ELSE {now} :
        /\ now' = t
        /\ IF RowChecked /\ RowOff
           THEN rowAlarm' = TRUE /\ UNCHANGED cp
           ELSE cp' = [cp EXCEPT !.pc = "read", !.upto = seq, !.at = t] /\ UNCHANGED rowAlarm
    /\ UNCHANGED <<seq, shared, a, db, cps, attacks, crashes, memory, queued, witness, refused, macAlarm, witnessRefused, staleAlarm>>
    /\ UNCHANGED <<signed, shown, committed, answered, forgerySealed, late>> /\ UNCHANGED <<rt, tilesGone, dropped, resealed>>

\* What a tick does once it has signed a pair: remember it and write it, in this order with RememberFirst; each as one
\* step for the pair, or a step per tree, the changes tree first.
Remember == IF PairRemembered THEN <<"m">> ELSE <<"mc", "mu">>
Write == IF PairWrittenTogether THEN <<"w">> ELSE <<"wc", "wu">>
Plan == IF RememberFirst THEN Remember \o Write ELSE Write \o Remember

\* One step of the plan, for the pair h.
Do(s, h) ==
    LET rows == CASE s = "w"  -> {Row(h, "c"), Row(h, "u")}
                  [] s = "wc" -> {Row(h, "c")}
                  [] s = "wu" -> {Row(h, "u")}
                  [] OTHER    -> {}
    IN /\ memory' = IF ~SignerMemory THEN memory
                    ELSE CASE s = "m"  -> h
                           [] s = "mc" -> [memory EXCEPT !.c = h.c]
                           [] s = "mu" -> [memory EXCEPT !.u = h.u]
                           [] OTHER    -> memory
       /\ cps' = cps \cup rows
       /\ shown' = shown \cup rows
       /\ settling' = IF rows = {} THEN settling ELSE FALSE

\* An entry stamped more than Fresh before the pair the signer holds (FRESH_MS): a replay, which no request-ID check can
\* match once its original is dropped.
Stale(e) == e.at + Fresh < cp.head.c.at

\* The request IDs of the uses retention dropped.
DroppedRids == {d.rid : d \in dropped}

\* From the pair in memory: each tree's window, checked, sealed and signed at the barrier's time; then the plan's first
\* step. Any entry that fails a check (its MAC, or with FreshChecked its stamp) refuses the window, an alarm.
TickSign ==
    /\ cp.pc = "read"
    /\ LET w == Window("c", cp.head.c.upto, cp.upto) \cup Window("u", cp.head.u.upto, cp.upto)
           h == Sealed(cp.head, cp.upto, cp.at)
           forged == MacChecked /\ \E e \in w : ~e.ok
           stale == FreshChecked /\ \E e \in w : Stale(e)
       IN IF forged \/ stale
          THEN /\ macAlarm' = (macAlarm \/ forged)
               /\ staleAlarm' = (staleAlarm \/ stale)
               /\ cp' = [cp EXCEPT !.pc = "idle"]
               /\ UNCHANGED <<cps, memory, signed, shown, forgerySealed, settling, resealed>>
          ELSE IF cp.upto <= Min(cp.head.c.upto, cp.head.u.upto)
          THEN /\ cp' = [cp EXCEPT !.pc = "idle"]
               /\ UNCHANGED <<macAlarm, staleAlarm, cps, memory, signed, shown, forgerySealed, settling, resealed>>
          ELSE /\ signed' = signed \cup {h}
               /\ forgerySealed' = (forgerySealed \/ \E e \in w : ~e.ok)
               /\ resealed' = (resealed \/ \E e \in w : e.rid \in DroppedRids)
               /\ Do(Head(Plan), h)
               /\ cp' = [cp EXCEPT !.pc = "sealing", !.next = h, !.todo = Tail(Plan)]
               /\ UNCHANGED <<macAlarm, staleAlarm>>
    /\ UNCHANGED <<seq, shared, a, db, queued, witness, ticks, attacks, crashes, refused, witnessRefused, rowAlarm, committed, answered, late>>
    /\ UNCHANGED <<now, rt, tilesGone, dropped>>

\* The plan's next step; after its last, the pair in memory moves on, and is queued for the witness.
TickStep ==
    /\ cp.pc = "sealing"
    /\ Do(Head(cp.todo), cp.next)
    /\ IF Len(cp.todo) = 1
       THEN /\ cp' = [cp EXCEPT !.pc = "idle", !.head = cp.next, !.todo = <<>>]
            /\ queued' = [on |-> Witness, head |-> cp.next]
       ELSE /\ cp' = [cp EXCEPT !.todo = Tail(cp.todo)]
            /\ UNCHANGED queued
    /\ UNCHANGED <<seq, shared, a, db, witness, ticks, attacks, crashes, refused, macAlarm, witnessRefused, rowAlarm, staleAlarm>>
    /\ UNCHANGED <<signed, committed, answered, forgerySealed, late>> /\ UNCHANGED Retained

\* The witness takes each queued note that extends its own (a witness per origin).
Publish ==
    /\ queued.on
    /\ LET ok(t) == Prefix(witness[t], queued.head[t]) IN
       /\ witness' = [t \in Kinds |-> IF ok(t) THEN queued.head[t] ELSE witness[t]]
       /\ witnessRefused' = (witnessRefused \/ \E t \in Kinds : ~ok(t))
    /\ queued' = [queued EXCEPT !.on = FALSE]
    /\ settling' = FALSE
    /\ UNCHANGED <<seq, shared, a, db, cps, cp, memory, ticks, attacks, crashes, refused, macAlarm, rowAlarm, staleAlarm>>
    /\ UNCHANGED <<signed, shown, committed, answered, forgerySealed, late>> /\ UNCHANGED Retained

\* The signer dies and loses what it held in memory (its pair, what it was sealing, the witness's queue); its memory
\* outside the database stays.
Crash ==
    /\ cp.pc \notin {"down", "refused"}
    /\ crashes < MaxCrashes
    /\ crashes' = crashes + 1
    /\ cp' = [pc |-> "down", upto |-> 0, at |-> 0, head |-> Genesis, next |-> Genesis, todo |-> <<>>]
    /\ queued' = [queued EXCEPT !.on = FALSE]
    /\ UNCHANGED <<seq, shared, a, db, cps, memory, witness, ticks, attacks, refused, macAlarm, witnessRefused, rowAlarm, staleAlarm>>
    /\ UNCHANGED Ghosts /\ UNCHANGED Retained

\* Checkpointer.open, for one tree: whether it accepts the database, the note it runs from, the row it writes.
Refuse == [ok |-> FALSE, note |-> GenesisNote, rows |-> {}]
OpenTree(t) ==
    LET m == memory[t] IN
    IF RowsOf(t) = {}
    THEN \* No row of the tree: refused if the signer remembers any note but genesis; else a new log, its genesis at 0
         \* (sealing nothing: the first tick seals every entry there is).
         IF SignerMemory /\ m # GenesisNote THEN Refuse
         ELSE [ok |-> TRUE, note |-> GenesisNote, rows |-> {Row(Genesis, t)}]
    ELSE LET r == NewestOf(t)
             d == [upto |-> r.upto, leaves |-> r.leaves, at |-> r.at]
         IN IF ~SignerMemory
            THEN [ok |-> TRUE, note |-> d, rows |-> {}]
            ELSE IF m.upto > d.upto
            THEN IF d.leaves \cup Window(t, d.upto, m.upto) = m.leaves
                 THEN [ok |-> TRUE, note |-> m, rows |-> {[t |-> t, upto |-> m.upto, leaves |-> m.leaves, at |-> m.at]}]
                 ELSE Refuse
            ELSE IF m = d \/ (m.upto < d.upto /\ Prefix(m, d))
            THEN [ok |-> TRUE, note |-> d, rows |-> {}]
            ELSE Refuse

\* Checkpointer.open: each tree as above; refused if either is.
Open ==
    /\ cp.pc = "down"
    /\ settling' = FALSE
    /\ LET res == [t \in Kinds |-> OpenTree(t)]
           rows == res.c.rows \cup res.u.rows
       IN IF \A t \in Kinds : res[t].ok
          THEN /\ cps' = cps \cup rows
               /\ shown' = shown \cup rows
               /\ cp' = [cp EXCEPT !.pc = "idle", !.head = [t \in Kinds |-> res[t].note]]
               /\ UNCHANGED refused
          ELSE /\ refused' = TRUE
               /\ cp' = [cp EXCEPT !.pc = "refused"]
               /\ UNCHANGED <<cps, shown>>
    /\ UNCHANGED <<seq, shared, a, db, memory, queued, witness, ticks, attacks, crashes, macAlarm, witnessRefused, rowAlarm, staleAlarm>>
    /\ UNCHANGED <<signed, committed, answered, forgerySealed, late>> /\ UNCHANGED Retained

-----------------------------------------------------------------------------
(* The attacker: write access to the database, no key. Each step changes `db` or `cps` only. *)

Attack(dbNext, cpsNext) ==
    /\ attacks < MaxAttacks
    /\ attacks' = attacks + 1
    /\ db' = dbNext
    /\ cps' = cpsNext
    /\ settling' = TRUE
    /\ UNCHANGED <<seq, shared, a, cp, ticks, crashes>> /\ UNCHANGED Outside
    /\ UNCHANGED <<signed, shown, committed, answered, forgerySealed, late>> /\ UNCHANGED Retained

Delete == \E e \in db : Attack(db \ {e}, cps)

\* One statement: a pair's rows (every row at one upto), or one tree's row without the other's.
DeleteCheckpoint == \E r \in cps : \/ Attack(db, cps \ {r})
                                    \/ Attack(db, {s \in cps : s.upto # r.upto})

\* An entry made up, at any number handed out: its MAC fails. (A use: a forged change fails the same check.)
Forge == \E n \in 1..seq : Attack(db \cup {[n |-> n, rid |-> Forged, kind |-> "u", ok |-> FALSE, at |-> now, cut |-> 0]}, cps)

\* An entry copied under any number handed out, a live one included: its MAC holds, since it does not cover the number.
Replay == \E e \in db, n \in 1..seq : n # e.n /\ Attack(db \cup {[e EXCEPT !.n = n]}, cps)

\* Two entries' numbers swapped: both MACs still hold.
Swap == \E e1, e2 \in db : e1.n < e2.n /\ Attack((db \ {e1, e2}) \cup {[e1 EXCEPT !.n = e2.n], [e2 EXCEPT !.n = e1.n]}, cps)

\* A change moved to the uses partition, so to the uses tree, pruned with them: its MAC fails if it covers the kind.
\* (A use moved among the changes is kept longer, not lost: the same check, not modelled.)
Move == \E e \in db : e.kind = "c" /\ Attack((db \ {e}) \cup {[e EXCEPT !.kind = "u", !.ok = (e.ok /\ ~KindInMac)]}, cps)

\* With retention: a retention change made up, naming any checkpoint as its cut (one naming none is seen), at any number
\* handed out: its MAC fails.
ForgeCut == Retention /\ \E n \in 1..seq, k \in {r.upto : r \in cps} \ {0} :
    Attack(db \cup {[n |-> n, rid |-> Forged, kind |-> "c", ok |-> FALSE, at |-> now, cut |-> k]}, cps)

\* A use retention dropped, put back (the attacker read it before), at its number or any other handed out: its MAC
\* holds, and no original is left for a request-ID check to match.
Resurrect == \E d \in dropped, n \in 1..seq : Attack(db \cup {[d EXCEPT !.n = n]}, cps)

-----------------------------------------------------------------------------
(* Retention: one run (plan PR 7). *)

\* The cut: a pair the signer signed whose two rows the database holds, on the signer's history in both trees (a
\* consistency proof to its head), at or below it. Only a running signer that keeps its memory retains: the freshness
\* bound is the pair it holds, which without its memory a restart takes from the database's rows.
RetainChoose ==
    /\ Retention /\ rt.pc = "idle" /\ SignerMemory
    /\ cp.pc \notin {"down", "refused"}
    /\ \E h \in signed :
        /\ Row(h, "c") \in cps /\ Row(h, "u") \in cps
        /\ 0 < h.u.upto
        /\ Prefix(h.c, cp.head.c) /\ Prefix(h.u, cp.head.u)
        /\ rt' = [pc |-> "entry", cut |-> h]
    /\ UNCHANGED <<seq, shared, a, db, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside /\ UNCHANGED Ghosts
    /\ UNCHANGED <<now, tilesGone, dropped, resealed>>

\* Once the retention change is sealed in the signer's pair (DropAfterSeal; without, once committed), and (FreshBeforeDrop)
\* that pair is Fresh past the cut: the day's partition goes, every use stamped before the cut's barrier whatever its
\* number (or, without CutUsesOnly, every entry, as one tree of both kinds would), and the uses tree's tiles below the
\* cut, those holding it kept or not.
RetainDrop ==
    /\ rt.pc = "entry"
    /\ cp.pc \notin {"down", "refused"}
    /\ IF DropAfterSeal THEN Holds(cp.head.c, RetAppend) ELSE a[RetAppend].pc \in {"committed", "answered"}
    /\ FreshBeforeDrop => cp.head.c.at >= rt.cut.c.at + Fresh
    /\ LET day == {e \in db : e.at < rt.cut.c.at /\ (CutUsesOnly => e.kind = "u")} IN
       /\ db' = db \ day
       /\ dropped' = dropped \cup day
    /\ tilesGone' = ~KeepCutTiles
    /\ rt' = [rt EXCEPT !.pc = "done"]
    /\ UNCHANGED <<seq, shared, a, cps, cp, ticks, attacks, crashes>> /\ UNCHANGED Outside /\ UNCHANGED Ghosts
    /\ UNCHANGED <<now, resealed>>

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Appends : Lock(x) \/ Number(x) \/ Finish(x) \/ Answer(x)
    \/ TickRead \/ TickSign \/ TickStep \/ Publish \/ Crash \/ Open
    \/ Delete \/ DeleteCheckpoint \/ Forge \/ Replay \/ Swap \/ Move
    \/ RetainChoose \/ RetainDrop \/ ForgeCut \/ Resurrect

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The verifier, from the database and the witness's pair alone. *)

\* The notes the walk must meet: every checkpoint row, and the witness's two.
Stops == cps \cup (IF Witness THEN {Row(witness, t) : t \in Kinds} ELSE {})

\* The retention changes the verifier honours: with CutSealed, those sealed in a changes note on its walk; without, any
\* the database holds. Their newest cut is where it starts the uses tree (0: none, from genesis).
Honoured == {e \in db : e.kind = "c" /\ e.cut > 0 /\ (CutSealed => \E s \in Stops : s.t = "c" /\ e \in s.leaves)}
VCut == IF Honoured = {} THEN 0 ELSE (CHOOSE e \in Honoured : \A f \in Honoured : f.cut <= e.cut).cut
CutRows == {r \in cps : r.t = "u" /\ r.upto = VCut}

\* The walk does not give note s. The changes tree, and the uses tree with no cut, from genesis; with a cut, a uses note
\* below it is not walked (its leaves are gone), and one at or above it must be the cut row's note and the uses between.
Off(s) ==
    IF s.t = "c" \/ VCut = 0
    THEN {e \in db : e.kind = s.t /\ e.n <= s.upto} # s.leaves
    ELSE s.upto >= VCut /\ \E c \in CutRows :
             \/ {e \in s.leaves : e.n <= VCut} # c.leaves
             \/ {e \in db : e.kind = "u" /\ VCut < e.n /\ e.n <= s.upto} # {e \in s.leaves : e.n > VCut}

Alarm ==
    \/ refused \/ macAlarm \/ witnessRefused \/ rowAlarm \/ staleAlarm
    \/ ~(GenesisRows \subseteq cps)                                \* no start where the walk must start
    \/ Witness /\ \E t \in Kinds : \A r \in RowsOf(t) : r.upto < witness[t].upto   \* a tree ends before the witness's note
    \/ VCut > 0 /\ (CutRows = {} \/ tilesGone)                     \* a cut with no row or no tiles to start the uses tree from
    \/ \E s \in Stops : Off(s)                                      \* the walk does not give a note on its way
    \/ \E e1, e2 \in db : e1 # e2 /\ e1.n = e2.n                   \* a number twice
    \/ RequestIdChecked /\ \E e1, e2 \in db : e1 # e2 /\ e1.rid = e2.rid   \* a request twice
    \/ PairVerified /\ \E r \in cps : ~\E s \in cps : s.t # r.t /\ s.upto = r.upto   \* a row without its pair

-----------------------------------------------------------------------------
(* Invariants. The ones about the attacker's deletions hold once the signer has acted after the attack (ticked,     *)
(* written, published, restarted): until then nothing outside the database has looked, and a verifier cannot tell a   *)
(* deleted newest checkpoint from one never written. With RowChecked that is at most one tick, traffic or not.       *)

\* Nothing commits under a seal: no honest entry commits at a number a signed pair already covers.
Complete ==
    ~late

\* The cut the honest retention change names, once committed (0: none): the uses at or below it are retention's to drop.
RetainedUpto == IF \E e \in committed : e.rid = RetAppend THEN (CHOOSE e \in committed : e.rid = RetAppend).cut ELSE 0
\* What is kept for good, or until a later cut: every change, and every use above the cut.
Kept(e) == ~(e.kind = "u" /\ e.n <= RetainedUpto)

\* An entry ever sealed into a note readers may have been shown that is gone from the database, or no longer at its
\* number or of its kind, is seen.
SealedDeletionDetected ==
    (~settling /\ \E r \in shown : \E e \in r.leaves : e \notin db) => Alarm

\* Two notes of one tree readers may have been shown that are not one a prefix of the other (a split view) are seen.
SplitViewDetected ==
    (~settling /\ \E r1, r2 \in shown : r1.t = r2.t /\ ~Prefix(r1, r2) /\ ~Prefix(r2, r1)) => Alarm

\* A change its admin was told is done cannot vanish unseen, nor leave the changes tree.
AnsweredChangeKept ==
    (~settling /\ \E x \in answered : ~\E e \in db : e.rid = x /\ e.kind = "c") => Alarm

\* No forged entry is ever sealed.
NoForgerySealed ==
    ~forgerySealed

\* A replay that gets sealed (two sealed entries with one request ID, both MACs valid, in one tree or across a pair
\* readers may have been shown) is seen, both being kept (below a cut, see ReplayAcrossCutSeen).
Replayed(both) ==
    \E h \in signed, t1, t2 \in Kinds :
        /\ Row(h, t1) \in shown /\ Row(h, t2) \in shown
        /\ \E e1 \in h[t1].leaves, e2 \in h[t2].leaves : e1 # e2 /\ e1.rid = e2.rid /\ IF both THEN Kept(e1) /\ Kept(e2) ELSE Kept(e1) \/ Kept(e2)
NoUndetectedReplay ==
    (~settling /\ Replayed(TRUE)) => Alarm

\* Every entry is sealed in the tree of the kind its append gave it: no change is ever sealed among the uses.
KindKept ==
    \A r \in shown : \A e \in r.leaves : e.rid \in Appends => KindOf(e.rid) = r.t

\* The pair: every pair signed has both notes at one upto, and every note readers may have been shown (written or
\* published) is one of a signed pair whose other note they may have been shown too.
PairConsistent ==
    /\ \A h \in signed : h.c.upto = h.u.upto
    /\ \A r \in shown : \E h \in signed : Row(h, r.t) = r /\ Row(h, Other(r.t)) \in shown

\* No alarm without an attack.
NoFalseAlarm ==
    attacks = 0 => ~Alarm

\* Retention. Nothing kept is lost: an entry sealed into a note readers may have been shown, every change and every use
\* above the cut, gone from the database (or moved) is seen. (SealedDeletionDetected, less what retention drops.)
KeptNotLost ==
    (~settling /\ \E r \in shown : \E e \in r.leaves : e \notin db /\ Kept(e)) => Alarm

\* A use retention dropped is never sealed again: no pair signed after the drop seals an entry with its request ID.
DroppedNeverResealed ==
    ~resealed

\* A cut touches only the uses: no change is ever dropped.
ChangesUntouched ==
    \A e \in dropped : e.kind = "u"

\* EXPECTED TO FAIL, with every protection: the window, from an entry's commit to the tick that seals it.
\*   An honest entry deleted before any pair sealed it is never seen.
UnsealedDeletionDetected ==
    (\E e \in committed : ~\E f \in db : f.rid = e.rid) => Alarm
\*   Nor is one moved to another number before it is sealed (two swapped, or a replay and the original deleted).
UnsealedReorderDetected ==
    (\E e \in committed : e \notin db /\ \E f \in db : f.rid = e.rid /\ f.n # e.n) => Alarm
\*   With retention, a use below the cut that its day did not hold (a straggler: one of the next day's, stamped at the
\*   cut's barrier or after), or one deleted once the cut was announced, is not seen: below a cut only changes are kept.
BelowCutKept ==
    (~settling /\ \E r \in shown : \E e \in r.leaves : e \notin db /\ e \notin dropped) => Alarm
\*   Nor is one copied above the cut, before the drop, and the original deleted: the copy reads as a use made once, at
\*   another place (TLC, W229). The copy keeps its stamp, so a copy made once the signer's pair is Fresh past it, as it
\*   is by the time a day is dropped (weeks), is refused; and until the cut is announced the original is walked, and
\*   the two are seen.
ReplayAcrossCutSeen ==
    (~settling /\ Replayed(FALSE)) => Alarm

=============================================================================
