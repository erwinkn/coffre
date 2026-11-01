------------------------------ MODULE Rotation ------------------------------
(***************************************************************************)
(* T168: the vault's signing key rotated under 0.15's log (W277; docs/     *)
(* design/audit-tree.md, "A rotation"). A deployment moves to a new key B  *)
(* (a new local KEK, or a new `signingKey` beside a key service) and keeps *)
(* the old one, A, configured as previous. Everything the log's integrity  *)
(* rests on derives from the key: the trees' signing keys, so every pair   *)
(* (a checkpoint), and the entries' MAC key. The deploy is all at once,    *)
(* but isolates still under A serve beside those under B for a while.      *)
(*                                                                         *)
(* An entry is a row: its number, the key its MAC is under (which the MAC  *)
(* names: its first four bytes are the key's tag, log-entry.ts), and, for  *)
(* the log's own rotation entry, the key it moves the log from. A writer   *)
(* (an isolate) appends as Seal.tla's appends do, its number taken under   *)
(* the fence's lock, shared; it may commit or abort (a gap). The database  *)
(* holds the fence's `retired` set, the keys the log moved on from: a      *)
(* writer under one is refused (RetiredRefused), in the statement that     *)
(* takes its number, under the lock (RefusedUnderLock): `use_credential`'s *)
(* `superseded`, and the trigger on log_changes (migration 0049).          *)
(*                                                                         *)
(* The signer (the checkpointer) holds a pair, remembers the newest pair   *)
(* it signed outside the database, and opens as Checkpointer.open does: it *)
(* compares its memory with the database's newest row, each opened under  *)
(* a key it is configured with. Then, when the log is under another key    *)
(* than its own (the `to` of the newest rotation entry, else the key of    *)
(* its head), it writes the rotation entry, under its key, from that key,  *)
(* adding that key to `retired`, in one transaction under the locks the    *)
(* barrier takes, exclusive (RotateUnderLock). Each tick then seals the    *)
(* window as Seal.tla's does, signing under its key; it remembers the pair *)
(* before the database has it (RememberFirst), so a crash can fall between *)
(* the two, as it can between the rotation and the first pair under B.     *)
(*                                                                         *)
(* Which key vouches for what (BoundaryChecked, `macKeys` in log-entry.ts):*)
(* an entry under the signer's key always; under a previous key only below *)
(* that key's rotation entry, never above it. A previous key's pair is     *)
(* taken (at open, and by the verifier) only below its own rotation        *)
(* (RotationProbed) and never over a pair under the current key held       *)
(* outside (AnchorKeyHeld).                                                *)
(*                                                                         *)
(* The verifier (verifier.ts) checks the database's newest pair, the pair  *)
(* held outside (the signer's memory) and every entry above the newest     *)
(* pair, with the keys the vault is configured with. Between the deploy    *)
(* and the rotation's first seal the newest pair is under A: taken as a    *)
(* rotation under way while no rotation from A is at or below it           *)
(* (PendingAccepted), the entries above it under A while none from A is    *)
(* below them.                                                             *)
(*                                                                         *)
(* Who else acts:                                                          *)
(*   Eve        holds A (it leaked: why one rotates) and writes the        *)
(*              database: entries under A at any number she takes, pairs   *)
(*              under A at any place, sealing whatever entries she likes,  *)
(*              rows deleted, entries deleted;                             *)
(*   Restore    a backup taken at any moment is restored, the signer's     *)
(*              memory reset by hand (docs/restore.md);                    *)
(*   Rollback   after the deploy the signer is started again under A, B    *)
(*              previous: a deployment's config rolled back.               *)
(*                                                                         *)
(* The protections, each a constant (scripts/formal.sh shows each          *)
(* necessary):                                                             *)
(*   BoundaryChecked     a previous key vouches for entries only below its *)
(*                       rotation entry, in a tick and in the verifier;    *)
(*   RetiredRefused      a writer under a retired key is refused;          *)
(*   RefusedUnderLock    ... in the statement that takes its number, under *)
(*                       the lock, never by a check before it;             *)
(*   RotateUnderLock     the rotation entry is written under the barrier's *)
(*                       locks, exclusive: no number is in flight;         *)
(*   MemoryUnderPrevious the signer opens its memory under a previous key; *)
(*   RowUnderPrevious    ... and the database's newest row;                *)
(*   RotationProbed      a pair under a previous key is taken only below   *)
(*                       that key's rotation entry;                        *)
(*   AnchorKeyHeld       ... and never above a pair under the current key  *)
(*                       held outside (the memory);                        *)
(*   PendingAccepted     the verifier takes a rotation under way;          *)
(*   KeyNeverBack        a signer whose key the log moved on from signs    *)
(*                       nothing (a replaced key, once retired, cannot     *)
(*                       come back).                                       *)
(*                                                                         *)
(* Not modelled: two signers at once, which the hosts rule out (one Durable*)
(* Object; one runner per memory), though the rotation's transaction reads *)
(* the log's key again under its locks; the kinds of entries and the two   *)
(* trees, retention, witnesses and time (Seal.tla's), the same here for    *)
(* every key; a rotation through a third key (the code's rule is the same  *)
(* for each).                                                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxN,         \* the numbers the sequence hands out: 1..MaxN
    Writers,      \* the isolates
    KeyOf,        \* [w \in Writers |-> "A" or "B"]: the key each holds; one under B serves only after the deploy
    MaxCrashes,   \* the signer's crashes, beside the deploy's restart
    Eve,          \* BOOLEAN: someone holds A and writes the database
    EveBudget,
    EveDeletes,   \* what Eve deletes besides rows: "none", "sealed" (entries the signer's memory seals) or "any"
    Restore,      \* BOOLEAN: a backup, restored with the signer's memory reset
    Rollback,     \* BOOLEAN: the signer started again under A after the deploy
    BoundaryChecked, RetiredRefused, RefusedUnderLock, RotateUnderLock, MemoryUnderPrevious, RowUnderPrevious,
    RotationProbed, AnchorKeyHeld, PendingAccepted, KeyNeverBack

Keys == {"A", "B"}
None == "none"
\* An entry: its number, the key its MAC is under, the key a rotation entry moves the log from (None for any other),
\* and whether an honest writer made it (a ghost: no reader sees it).
Entry(n, k, from, honest) == [n |-> n, key |-> k, from |-> from, honest |-> honest]
\* A pair: its place, the key that signed it, the entries it seals (a tree, abstracted to its leaves).
Pair(u, k, s) == [upto |-> u, key |-> k, sealed |-> s]
Genesis == Pair(0, "A", {})
NoPair == Pair(0, None, {})
NoBackup == [seq |-> 0, entries |-> {}, rows |-> {}, retired |-> {}]
Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Never == 100   \* past every number

VARIABLES
    seq,      \* the sequence's last value
    entries,  \* the committed entries the database holds
    rows,     \* the checkpoint rows the database holds: pairs
    retired,  \* the fence's retired keys
    w,        \* each writer: pc ("idle", "checked", "numbered"), its number, what its early check read
    cfg,      \* the signer's keys: the one it signs under, those it verifies with
    s,        \* the signer: pc ("down", "rotate", "tick", "write", "stuck"), its head, the pair it is writing
    memory,   \* the newest pair it remembers, outside the database (NoPair: none, as after a reset)
    crashes, eve,
    deployed, rolled, backup, restored,
    badSeal,  \* ghost: the signer signed a pair sealing an entry under a key above that key's rotation
    oldPair,  \* ghost: the signer signed a pair under a key sealing that key's own rotation
    rotations,\* ghost: every rotation entry committed since the last restore
    gone      \* ghost: the entries Eve deleted, which she can still name (a row's leaves are in its tiles)

vars == <<seq, entries, rows, retired, w, cfg, s, memory, crashes, eve, deployed, rolled, backup, restored, badSeal, oldPair, rotations, gone>>

Newest == CHOOSE r \in rows : \A x \in rows : x.upto <= r.upto
RotationsFrom(S, k) == {e \in S : e.from = k}
\* The number of k's rotation entry in S; past every number when there is none.
RetiredAt(S, k) == IF RotationsFrom(S, k) = {} THEN Never ELSE Min({e.n : e \in RotationsFrom(S, k)})
\* The key the log is under, as the signer reads it at its open: the newest rotation's, else its head's.
LogKey(h) == IF {e \in entries : e.from # None} = {} THEN h.key
             ELSE (CHOOSE e \in entries : e.from # None /\ \A x \in entries : x.from # None => x.n <= e.n).key
Configured(k) == k = cfg.cur \/ k \in cfg.prev
\* Whether the entries of a pair sealing up to u extend those of p: p's place and leaves are its prefix.
Extends(sealed, u, p) == p.upto <= u /\ p.sealed = {e \in sealed : e.n <= p.upto}

\* An entry a key vouches for (BoundaryChecked), given the key k of the pair it lies above and the number of k's
\* rotation: the current key's always; k's below its rotation, when k is a previous key (the rotation under way); no
\* other's. Above a pair under the current key, the current key's alone: every rotation to it is sealed at or below that
\* pair, whether or not the database still holds the rotation's row. The signer counts from the rotation it wrote or
\* read at its open (`bound`); the verifier, which keeps nothing, from the database's.
VouchedBy(e, k, bound) ==
    \/ e.key = cfg.cur
    \/ /\ e.key \in cfg.prev
       /\ BoundaryChecked => (e.key = k /\ e.n < bound)

\* A pair under a previous key, taken as the newest: below its own rotation (RotationProbed), and never above a pair
\* under the current key held outside (AnchorKeyHeld).
PreviousTaken(r, held) ==
    /\ RotationProbed => r.upto < RetiredAt(entries, r.key)
    /\ AnchorKeyHeld => ~(held.key = cfg.cur /\ held.upto < r.upto)

Down == [pc |-> "down", head |-> NoPair, next |-> NoPair, bound |-> Never]

Init ==
    /\ seq = 0
    /\ entries = {}
    /\ rows = {Genesis}
    /\ retired = {}
    /\ w = [x \in Writers |-> [pc |-> "idle", n |-> 0, ok |-> TRUE]]
    /\ cfg = [cur |-> "A", prev |-> {}]
    /\ s = [pc |-> "tick", head |-> Genesis, next |-> NoPair, bound |-> Never]
    /\ memory = Genesis
    /\ crashes = 0 /\ eve = 0
    /\ deployed = FALSE /\ rolled = FALSE /\ backup = NoBackup /\ restored = FALSE
    /\ badSeal = FALSE /\ oldPair = FALSE
    /\ rotations = {}
    /\ gone = {}

Signer == <<cfg, s, memory, crashes, deployed, rolled>>
Db == <<seq, entries, rows, retired>>
Ghosts == <<badSeal, oldPair, rotations, gone>>

-----------------------------------------------------------------------------
(* A writer: the fence's lock taken shared, then its number, then its commit, the lock held throughout (Seal.tla's
   NumberUnderLock). With RefusedUnderLock its key is checked against `retired` once it holds the lock, in the
   statement that then takes its number; without, before it (an isolate that asked whether it may write, then wrote). *)

Serves(x) == deployed \/ KeyOf[x] = "A"
Refused(x) == RetiredRefused /\ KeyOf[x] \in retired

Check(x) ==
    /\ ~RefusedUnderLock
    /\ w[x].pc = "idle" /\ seq < MaxN /\ Serves(x)
    /\ w' = [w EXCEPT ![x] = [pc |-> "checked", n |-> 0, ok |-> ~Refused(x)]]
    /\ UNCHANGED <<Db, Signer, eve, backup, restored, Ghosts>>

\* The lock, and the check under it; a writer refused lets it go, its statement failed (`superseded`, the trigger).
Lock(x) ==
    /\ w[x].pc = IF RefusedUnderLock THEN "idle" ELSE "checked"
    /\ seq < MaxN /\ Serves(x)
    /\ w' = [w EXCEPT ![x] = IF (IF RefusedUnderLock THEN ~Refused(x) ELSE w[x].ok)
                             THEN [pc |-> "locked", n |-> 0, ok |-> TRUE]
                             ELSE [pc |-> "idle", n |-> 0, ok |-> TRUE]]
    /\ UNCHANGED <<Db, Signer, eve, backup, restored, Ghosts>>

Number(x) ==
    /\ w[x].pc = "locked" /\ seq < MaxN
    /\ seq' = seq + 1
    /\ w' = [w EXCEPT ![x] = [pc |-> "numbered", n |-> seq + 1, ok |-> TRUE]]
    /\ UNCHANGED <<entries, rows, retired, Signer, eve, backup, restored, Ghosts>>

\* Commits under its key, or aborts (a gap); the lock let go. One that finds no number left (the model's bound) aborts.
Finish(x) ==
    /\ w[x].pc = "numbered" \/ (w[x].pc = "locked" /\ seq >= MaxN)
    /\ \E commit \in BOOLEAN :
        entries' = IF commit /\ w[x].pc = "numbered" THEN entries \cup {Entry(w[x].n, KeyOf[x], None, TRUE)} ELSE entries
    /\ w' = [w EXCEPT ![x] = [pc |-> "idle", n |-> 0, ok |-> TRUE]]
    /\ UNCHANGED <<seq, rows, retired, Signer, eve, backup, restored, Ghosts>>

InFlight == \E x \in Writers : w[x].pc \in {"locked", "numbered"}

-----------------------------------------------------------------------------
(* The signer. *)

\* Checkpointer.open: its memory and the database's newest row, each opened under a key it holds, then compared as
\* Seal.tla's Open compares them. A refusal leaves it stuck until it is started again.
Open ==
    /\ s.pc = "down"
    /\ LET r == Newest
           m == memory
           mOpens == m = NoPair \/ m.key = cfg.cur \/ (MemoryUnderPrevious /\ m.key \in cfg.prev)
           rOpens == r.key = cfg.cur \/ (RowUnderPrevious /\ r.key \in cfg.prev /\ PreviousTaken(r, m))
           \* The head it takes, or None when it refuses.
           head == IF ~mOpens \/ ~rOpens THEN NoPair
                   ELSE IF m = NoPair THEN r                                     \* no memory: the database's word
                   ELSE IF m.upto = r.upto THEN (IF m = r THEN r ELSE NoPair)
                   ELSE IF m.upto > r.upto                                       \* memory ahead: the entries give it again
                        THEN (IF Extends(m.sealed, m.upto, r) /\ m.sealed \ r.sealed = {e \in entries : r.upto < e.n /\ e.n <= m.upto}
                              THEN m ELSE NoPair)
                   ELSE IF Extends(r.sealed, r.upto, m) THEN r ELSE NoPair     \* the database ahead: a prefix
           back == KeyNeverBack /\ RotationsFrom(entries, cfg.cur) # {}
       IN IF head = NoPair \/ back
          THEN s' = [s EXCEPT !.pc = "stuck"] /\ UNCHANGED <<rows, memory>>
          ELSE /\ rows' = rows \cup {head}
               /\ memory' = head
               /\ s' = [pc |-> IF LogKey(head) # cfg.cur THEN "rotate" ELSE "tick", head |-> head, next |-> NoPair,
                        bound |-> RetiredAt(entries, head.key)]
    /\ UNCHANGED <<seq, entries, retired, w, cfg, crashes, deployed, rolled, eve, backup, restored, Ghosts>>

\* The rotation entry, under the signer's key, from the log's, and that key retired, in one transaction: under the
\* barrier's locks (RotateUnderLock), the log's key read again there. The trigger refuses an entry under a retired key,
\* the signer's own included (a rolled-back key): its open fails.
Rotate ==
    /\ s.pc = "rotate"
    /\ RotateUnderLock => ~InFlight
    /\ IF LogKey(s.head) = cfg.cur
       THEN s' = [s EXCEPT !.pc = "tick"] /\ UNCHANGED <<seq, entries, retired, rotations>>
       ELSE IF RetiredRefused /\ cfg.cur \in retired
       THEN s' = [s EXCEPT !.pc = "stuck"] /\ UNCHANGED <<seq, entries, retired, rotations>>
       ELSE LET e == Entry(seq + 1, cfg.cur, LogKey(s.head), TRUE) IN
            /\ seq' = seq + 1
            /\ entries' = entries \cup {e}
            /\ retired' = retired \cup {LogKey(s.head)}
            /\ rotations' = rotations \cup {e}
            /\ s' = [s EXCEPT !.pc = "tick", !.bound = e.n]
    /\ UNCHANGED <<rows, w, cfg, memory, crashes, deployed, rolled, eve, backup, restored, badSeal, oldPair, gone>>

\* A tick: the barrier (no number in flight), the window, each entry vouched for, the pair signed and remembered. A
\* database whose newest row is not its head, or an entry no key vouches for, is refused (an alarm).
Tick ==
    /\ s.pc = "tick"
    /\ ~InFlight
    /\ seq > s.head.upto
    /\ LET window == {e \in entries : s.head.upto < e.n /\ e.n <= seq}
           next == Pair(seq, cfg.cur, s.head.sealed \cup window) IN
       IF Newest # s.head \/ \E e \in window : ~VouchedBy(e, s.head.key, s.bound)
       THEN s' = [s EXCEPT !.pc = "stuck"] /\ UNCHANGED <<memory, badSeal, oldPair>>
       ELSE /\ s' = [s EXCEPT !.pc = "write", !.next = next]
            /\ memory' = next
            /\ badSeal' = (badSeal \/ \E e, r \in next.sealed : r.from # None /\ e.key = r.from /\ e.n > r.n)
            /\ oldPair' = (oldPair \/ \E r \in next.sealed : r.from = next.key)
    /\ UNCHANGED <<Db, w, cfg, crashes, deployed, rolled, eve, backup, restored, rotations, gone>>

\* The pair written, over the head the database still holds.
Write ==
    /\ s.pc = "write"
    /\ IF Newest = s.head
       THEN rows' = rows \cup {s.next} /\ s' = [pc |-> "tick", head |-> s.next, next |-> NoPair, bound |-> Never]
       ELSE s' = [s EXCEPT !.pc = "stuck"] /\ UNCHANGED rows
    /\ UNCHANGED <<seq, entries, retired, w, cfg, memory, crashes, deployed, rolled, eve, backup, restored, Ghosts>>

Crash ==
    /\ s.pc # "down" /\ crashes < MaxCrashes
    /\ s' = Down
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<Db, w, cfg, memory, deployed, rolled, eve, backup, restored, Ghosts>>

\* The deploy: the signer restarts under B, A previous, whatever it was doing (a pair remembered and not written: the
\* rotation mid-tick). Isolates under A serve on.
Deploy ==
    /\ ~deployed
    /\ deployed' = TRUE
    /\ cfg' = [cur |-> "B", prev |-> {"A"}]
    /\ s' = Down
    /\ UNCHANGED <<Db, w, memory, crashes, rolled, eve, backup, restored, Ghosts>>

RollBack ==
    /\ Rollback /\ deployed /\ ~rolled
    /\ rolled' = TRUE
    /\ cfg' = [cur |-> "A", prev |-> {"B"}]
    /\ s' = Down
    /\ UNCHANGED <<Db, w, memory, crashes, deployed, eve, backup, restored, Ghosts>>

-----------------------------------------------------------------------------
(* A backup, taken at any moment, restored with the signer stopped and its memory reset by hand (docs/restore.md):
   the database as it was, its sequence included. *)

TakeBackup ==
    /\ Restore /\ backup = NoBackup /\ ~InFlight
    /\ backup' = [seq |-> seq, entries |-> entries, rows |-> rows, retired |-> retired]
    /\ UNCHANGED <<Db, w, Signer, eve, restored, Ghosts>>

RestoreBackup ==
    /\ backup # NoBackup /\ ~restored /\ ~InFlight
    /\ restored' = TRUE
    /\ seq' = backup.seq /\ entries' = backup.entries /\ rows' = backup.rows /\ retired' = backup.retired
    /\ memory' = NoPair
    /\ s' = Down
    /\ rotations' = {e \in backup.entries : e.from # None}
    /\ gone' = {}
    /\ UNCHANGED <<w, cfg, crashes, deployed, rolled, eve, backup, badSeal, oldPair>>

-----------------------------------------------------------------------------
(* Eve, who holds A and writes the database, past every lock and trigger. *)

ForgeEntry ==
    /\ Eve /\ eve < EveBudget /\ seq < MaxN
    /\ seq' = seq + 1
    /\ entries' = entries \cup {Entry(seq + 1, "A", None, FALSE)}
    /\ eve' = eve + 1
    /\ UNCHANGED <<rows, retired, w, Signer, backup, restored, Ghosts>>

\* A pair under A at a place past the newest row, sealing what she chooses of what she knows below it, consistent with
\* the newest row (any other fails its consistency proof).
ForgePair ==
    /\ Eve /\ eve < EveBudget
    /\ \E u \in (Newest.upto + 1)..seq : \E keep \in SUBSET {e \in entries \cup gone : Newest.upto < e.n /\ e.n <= u} :
        rows' = rows \cup {Pair(u, "A", Newest.sealed \cup keep)}
    /\ eve' = eve + 1
    /\ UNCHANGED <<seq, entries, retired, w, Signer, backup, restored, Ghosts>>

\* The newest row deleted, down to the genesis at most; an entry deleted: one the signer's memory seals, or any (one
\* not sealed yet is R51's window, Seal.tla's UnsealedDeletionDetected).
DeleteRow ==
    /\ Eve /\ EveDeletes # "none" /\ eve < EveBudget /\ Newest # Genesis
    /\ rows' = rows \ {Newest}
    /\ eve' = eve + 1
    /\ UNCHANGED <<seq, entries, retired, w, Signer, backup, restored, Ghosts>>

DeleteEntry ==
    /\ Eve /\ EveDeletes # "none" /\ eve < EveBudget
    /\ \E e \in IF EveDeletes = "any" THEN entries ELSE entries \cap memory.sealed :
        /\ entries' = entries \ {e}
        /\ gone' = gone \cup {e}
    /\ eve' = eve + 1
    /\ UNCHANGED <<seq, rows, retired, w, Signer, backup, restored, badSeal, oldPair, rotations>>

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Writers : Check(x) \/ Lock(x) \/ Number(x) \/ Finish(x)
    \/ Open \/ Rotate \/ Tick \/ Write \/ Crash \/ Deploy \/ RollBack
    \/ TakeBackup \/ RestoreBackup
    \/ ForgeEntry \/ ForgePair \/ DeleteRow \/ DeleteEntry

\* The signer and a writer holding the lock are fair: a running signer opens, rotates, ticks and writes; a writer with
\* the lock takes its number and commits or aborts. Nothing makes a writer start, Eve act or the operator deploy.
Fairness ==
    /\ WF_vars(Open) /\ WF_vars(Rotate) /\ WF_vars(Tick) /\ WF_vars(Write)
    /\ \A x \in Writers : WF_vars(Number(x)) /\ WF_vars(Finish(x))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* What the verifier (verifyTrees) answers, with the vault's keys (the signer's) and the pair held outside (its
   memory): the newest row, the memory a prefix of it, and every entry above it. *)

Above(r) == {e \in entries : e.n > r.upto}
Verified ==
    LET r == Newest IN
    /\ \/ r.key = cfg.cur
       \/ PendingAccepted /\ r.key \in cfg.prev /\ PreviousTaken(r, memory)
    \* The pair held outside: one it opens, a prefix of the newest, and that very pair at its place (verifyLog).
    /\ memory = NoPair \/ (Configured(memory.key) /\ Extends(r.sealed, r.upto, memory) /\ (memory.upto = r.upto => memory = r))
    /\ \A e \in Above(r) : VouchedBy(e, r.key, RetiredAt(entries, r.key))

-----------------------------------------------------------------------------
(* Invariants. *)

TypeOK ==
    /\ seq \in 0..MaxN + 2
    /\ retired \subseteq Keys
    /\ s.pc \in {"down", "rotate", "tick", "write", "stuck"}

\* One rotation from a key: a second boundary would leave the key vouching up to the later one.
OneRotation == \A k \in Keys : Cardinality(RotationsFrom(entries, k)) <= 1

\* No honest writer commits under a key above that key's rotation: an isolate still under A after it is refused.
OldWritesBelowBoundary == \A e \in entries, r \in rotations : (e.honest /\ e.from = None /\ e.key = r.from) => e.n < r.n

\* R41's shape, the property the rotation is for: no pair the signer signs seals an entry under a key above that key's
\* rotation (in whatever history the pair is of).
SealedBelowBoundary == ~badSeal

\* No pair the signer signs under a key seals that key's own rotation: a replaced key signs nothing after it.
NoOldPairOverRotation == ~oldPair

\* The verifier never passes a database where a key vouches past its rotation: a newest pair under a key, at or past a
\* rotation from it, or an entry above that pair under a key, past a rotation from it (every rotation committed since
\* the last restore, whether or not the database still holds it).
VerifiedSound ==
    Verified =>
        LET r == Newest IN
        /\ ~\E x \in rotations : x.from = r.key /\ x.n <= r.upto
        /\ ~\E e \in Above(r), x \in rotations : x.from = e.key /\ x.n < e.n

\* With nobody but the vault at work, the verifier never alarms, the rotation under way included: but while the
\* database is a moment behind the memory (a pair remembered and not yet written, which a caller asks again about).
NoFalseAlarm == (eve = 0 /\ memory.upto <= Newest.upto) => Verified

\* Liveness: the log keeps working. Every entry an honest writer commits is sealed in time: the signer is never left
\* refusing (a memory or a row it cannot open; an entry no key vouches for, which would hold every tick from then on).
LogWorks == <>[](s.pc \in {"tick", "write", "rotate"} /\ \A e \in entries : e.n <= s.head.upto)

=============================================================================
