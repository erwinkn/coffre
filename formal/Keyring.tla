------------------------------- MODULE Keyring -------------------------------
(***************************************************************************)
(* The keyring of 0.15's log across two rotations of the vault's signing   *)
(* key, A to B to C (T168; packages/vault/src/rotations.ts, `chainOf`).    *)
(* Rotation.tla holds one rotation, A to B, with the signer, the writers'  *)
(* locks, crashes, restores and rollbacks; this module holds what one      *)
(* rotation cannot show: a rotation whose destination is itself a key the  *)
(* log moved on from, so bounded (Fable's review r6 of #444).              *)
(*                                                                         *)
(* A rotation entry carries the MAC of the key it moves the log to, and    *)
(* names the key it moves it from. Every reader of the log (vouch, the     *)
(* reads' projector, `coffre verify log`, retention, the signer's open)    *)
(* bounds each key the vault replaced by the rotations it reads: a key     *)
(* vouches only below its rotation. The question is which rotations count. *)
(* Counting one on its MAC alone lets someone who holds two replaced keys, *)
(* A and B, and writes the database, delete the vault's A-to-B and plant   *)
(* an A-to-B under B's MAC past B's own rotation: A then vouches up to it. *)
(* ChainRule: a rotation is an entry like any other, which counts only     *)
(* where the key whose MAC it carries vouches at its number: a chain from  *)
(* the current key back, found a round at a time as `chainOf` finds it.    *)
(*                                                                         *)
(* What she gains is then bounded by what she holds: no entry she forges   *)
(* is taken at a number where none of her keys vouched (KeyringSound).     *)
(* With nobody but the vault at work, every entry it wrote is taken        *)
(* (NoFalseAlarm).                                                         *)
(*                                                                         *)
(* Not modelled here: the signer's own steps, the writers' locks and the   *)
(* fence (Rotation.tla); a rotation deleted before a pair under its new    *)
(* key seals it (Rotation.tla's RotationWindow, R51's window): Eve deletes *)
(* only sealed rotations here; pairs Eve signs (the newest pair is the     *)
(* vault's: Rotation.tla's ForgePair and AnchorKeyHeld); a deploy before   *)
(* a pair under the current key (two deploys inside one tick).             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    MaxN,       \* the numbers: 1..MaxN
    Eve,        \* BOOLEAN: someone holds the keys in Leaked and writes the database
    EveBudget,
    Leaked,     \* the keys she holds: replaced ones, never the newest
    ChainRule

Order == <<"A", "B", "C">>
Keys == {"A", "B", "C"}
None == "none"
Never == 100
Unset == 0 - 1
Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Max(S) == CHOOSE x \in S : \A y \in S : x >= y

\* An entry: its number, the key its MAC is under, the key a rotation moves the log from (None for any other: a
\* rotation moves the log to the key of its MAC), and whether the vault wrote it (a ghost).
Entry(n, k, from, honest) == [n |-> n, key |-> k, from |-> from, honest |-> honest]

VARIABLES
    seq,        \* the sequence's last value
    entries,    \* the entries the database holds
    cfg,        \* the index in Order of the key the vault signs with
    logk,       \* the index of the key the log is under: behind cfg between a deploy and its rotation
    under,      \* the key the newest pair is under (its signatures': SignerVerified)
    sealed,     \* the number the newest pair seals up to
    rotations,  \* ghost: the vault's rotation entries, whatever the database holds now
    eve

vars == <<seq, entries, cfg, logk, under, sealed, rotations, eve>>

Cur == Order[cfg]
Prev == {Order[i] : i \in 1..(cfg - 1)}
Held == Prev \cup {Cur}
Used == {e.n : e \in entries}
Rot(S) == {e \in S : e.from # None}

\* The rule on its MAC alone: each key's first rotation authentic under a key the vault holds.
MacOnly ==
    [k \in Keys |->
        IF k \notin Prev THEN Never
        ELSE LET c == {e.n : e \in {x \in Rot(entries) : x.from = k /\ x.key \in Held}} IN
             IF c # {} THEN Min(c) ELSE IF under = k THEN Never ELSE 0]

\* ChainRule, a round at a time: each key not bounded yet takes the first rotation from it into a key bounded already,
\* below that key's bound. The current key first; then, the chain from it done, the key the newest pair is under, if no
\* rotation that counts bounded it (the rotation under way).
Round(b) ==
    [k \in Keys |->
        IF b[k] # Unset \/ k \notin Prev THEN b[k]
        ELSE LET c == {e.n : e \in {x \in Rot(entries) : x.from = k /\ b[x.key] # Unset /\ x.n < b[x.key]}} IN
             IF c = {} THEN Unset ELSE Min(c)]
Rounds(b) == Round(Round(Round(b)))
Chain ==
    LET b1 == Rounds([k \in Keys |-> IF k = Cur THEN Never ELSE Unset])
        b2 == IF under \in Prev /\ b1[under] = Unset THEN Rounds([b1 EXCEPT ![under] = Never]) ELSE b1
    IN [k \in Keys |-> IF b2[k] = Unset THEN 0 ELSE b2[k]]

Bound == IF ChainRule THEN Chain ELSE MacOnly

\* Whether a reader takes an entry: under the current key, or under a key it replaced, below that key's bound.
Takes(e) == e.key = Cur \/ (e.key \in Prev /\ e.n < Bound[e.key])

Init ==
    /\ seq = 0
    /\ entries = {}
    /\ cfg = 1 /\ logk = 1
    /\ under = "A" /\ sealed = 0
    /\ rotations = {}
    /\ eve = 0

-----------------------------------------------------------------------------
(* The vault. *)

\* A writer under the log's key, or under the vault's after a deploy: an isolate under the old key serves until the
\* rotation, after which the fence refuses it (Rotation.tla's RetiredRefused).
Write ==
    /\ seq < MaxN
    /\ \E k \in {Order[logk], Order[cfg]} :
        entries' = entries \cup {Entry(seq + 1, k, None, TRUE)}
    /\ seq' = seq + 1
    /\ UNCHANGED <<cfg, logk, under, sealed, rotations, eve>>

\* A number taken and its transaction aborted: a gap, which Eve may fill.
Gap ==
    /\ seq < MaxN
    /\ seq' = seq + 1
    /\ UNCHANGED <<entries, cfg, logk, under, sealed, rotations, eve>>

\* The next key, once the log is under the vault's and a pair under it holds.
Deploy ==
    /\ cfg < Len(Order) /\ logk = cfg /\ under = Cur
    /\ cfg' = cfg + 1
    /\ UNCHANGED <<seq, entries, logk, under, sealed, rotations, eve>>

\* The signer's first open under the new key: the rotation, MAC'd under it, from the log's key.
Rotate ==
    /\ logk < cfg /\ seq < MaxN
    /\ LET e == Entry(seq + 1, Cur, Order[logk], TRUE) IN
       /\ entries' = entries \cup {e}
       /\ rotations' = rotations \cup {e}
    /\ seq' = seq + 1
    /\ logk' = cfg
    /\ UNCHANGED <<cfg, under, sealed, eve>>

\* A pair under the vault's key, sealing what was numbered: after its rotation.
Seal ==
    /\ logk = cfg /\ (sealed < seq \/ under # Cur)
    /\ under' = Cur /\ sealed' = seq
    /\ UNCHANGED <<seq, entries, cfg, logk, rotations, eve>>

-----------------------------------------------------------------------------
(* Eve, who holds Leaked and writes the database, past every lock and trigger: at any number no entry holds. *)

Free == {n \in 1..MaxN : n \notin Used}

ForgeEntry ==
    /\ Eve /\ eve < EveBudget
    /\ \E n \in Free, k \in Leaked :
        /\ entries' = entries \cup {Entry(n, k, None, FALSE)}
        /\ seq' = IF n > seq THEN n ELSE seq
    /\ eve' = eve + 1
    /\ UNCHANGED <<cfg, logk, under, sealed, rotations>>

\* A rotation into a key she holds, under its MAC, from any key (or an origin the vault has none of).
ForgeRotation ==
    /\ Eve /\ eve < EveBudget
    /\ \E n \in Free, to \in Leaked : \E from \in (Keys \cup {"X"}) \ {to} :
        /\ entries' = entries \cup {Entry(n, to, from, FALSE)}
        /\ seq' = IF n > seq THEN n ELSE seq
    /\ eve' = eve + 1
    /\ UNCHANGED <<cfg, logk, under, sealed, rotations>>

\* A rotation's row deleted, once a pair seals it (one deleted before is R51's window, Rotation.tla's RotationWindow).
DeleteRotation ==
    /\ Eve /\ eve < EveBudget
    /\ \E e \in Rot(entries) : e.n <= sealed /\ entries' = entries \ {e}
    /\ eve' = eve + 1
    /\ UNCHANGED <<seq, cfg, logk, under, sealed, rotations>>

Next == Write \/ Gap \/ Deploy \/ Rotate \/ Seal \/ ForgeEntry \/ ForgeRotation \/ DeleteRotation

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Invariants, of a reader at every state (it keeps nothing between calls, and reads the rotations and the newest pair
   in one statement: Rotation.tla's SnapshotRead). *)

TypeOK ==
    /\ seq \in 0..MaxN
    /\ cfg \in 1..Len(Order) /\ logk \in 1..cfg
    /\ under \in Keys

\* The number of the vault's rotation from k: past every number while there is none.
Committed(k) == IF \E r \in rotations : r.from = k THEN Min({r.n : r \in {x \in rotations : x.from = k}}) ELSE Never
\* Where Eve's keys vouched, by the vault's own rotations: below the latest of them.
Reach == Max({Committed(k) : k \in Leaked})

\* No entry Eve forged is taken at a number where none of her keys vouched (R41's, for someone who holds several).
KeyringSound == \A e \in entries : (~e.honest /\ e.from = None /\ Takes(e)) => e.n < Reach

\* With nobody but the vault at work, every entry it wrote is taken, its rotations included.
NoFalseAlarm == eve = 0 => \A e \in entries : e.honest => Takes(e)

=============================================================================
