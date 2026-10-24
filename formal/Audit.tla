-------------------------------- MODULE Audit --------------------------------
(***************************************************************************)
(* The audit chain's verification: heartbeats that walk it, checkpoints    *)
(* the vault signs over it, the anchor that keeps what the beats verified  *)
(* outside the database, and readiness, which reads the anchor, against    *)
(* someone who can write the database but holds no key and cannot reach    *)
(* the anchor: they edit an entry in place, or rewrite one and chain       *)
(* everything after it again. docs/formal.md says what this covers, what   *)
(* it abstracts and what it does not prove.                                *)
(*                                                                         *)
(* Each walk runs in a snapshot of its own (REPEATABLE READ, read only:     *)
(* db dialect.ts, SNAPSHOT), so it is one step here, reading the log as    *)
(* that step finds it. Appends take the log's head; the vault's checkpoint *)
(* decides under it. The anchor's store is one compare-and-set a step.     *)
(*                                                                         *)
(* An entry's hash is abstracted to the chain's version where it is: a     *)
(* rewrite from an entry moves every entry from there on to a new version, *)
(* each hash recomputed and linked, the head row too. An entry's MAC       *)
(* binds its content and the hash before it: one rewritten, or after one,  *)
(* fails it, unless it was appended after the rewrite. An edit in place    *)
(* changes the content and leaves the stored hash: only recomputing the    *)
(* hash finds it. A heartbeat row is an entry like any other: nothing      *)
(* reads what it says, so editing it is an edit like any other.            *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    InitLog,        \* the log at the start
    InitAnchor,     \* the anchor at the start
    Procs,          \* concurrent processes
    Ops,            \* Ops[p]: what p may do
    Budget,         \* Budget[p]: how many times
    MaxLen,         \* no append past this many entries
    Walk,           \* CHAIN_WALK: entries a heartbeat's walk reads at most
    CkptWalk,       \* walks.checkpoint: entries a checkpoint's walk reads at most
    ScrubWalk       \* walks.scrub: entries a scrub reads a call

CONSTANTS
    \* A heartbeat's walk checks first that the entry it goes on from still
    \* has the hash it verified (db audit.ts, walkChain, `from`).
    WalkChecksFrom,
    \* And the app's MAC of each app entry it walks (walkChain, verifyEntries).
    WalkChecksAppMacs,
    \* A checkpoint's walk checks the vault's MAC of each vault entry (vault
    \* log.ts, rehash), and under the head that the prefix signed last still
    \* has its hash (vault.ts, checkpoint, `carries(newest)`).
    CheckpointChecksVault,
    \* Under the head, a checkpoint that another call checkpointed or
    \* refused after its snapshot signs nothing, and a refusal for a broken
    \* log since the last checkpoint stands (checkpoint, `seen`,
    \* #standingRefusal).
    SeenRecheckUnderHead,
    \* The scrub recomputes each hash of the prefixes signed before, a
    \* stretch a call (vault.ts, #scrub, relink).
    Scrubs,
    \* A beat's walk checks first that the log still holds the prefix the
    \* anchor's checkpoint signed, and that the vault signed no shorter one
    \* (server heartbeat.ts, walkToCheckpoint).
    AnchorHeld,
    \* Readiness checks that the log still holds the prefix the anchor's
    \* checkpoint signed (server heartbeat.ts, auditReadiness, `holds`).
    ReadinessChecksHeld,
    \* A beat writes the anchor only over the record it read before its
    \* checkpoint (anchor.ts, AnchorStore.write, `admits`).
    AnchorCas

None == "none"
AppKinds == {"app", "beat"}
VaultKinds == {"vault", "ckpt", "deny"}

VARIABLES
    log,            \* the entries, in seq order
    head,           \* the process holding the log's head, or None
    tampered,       \* what was done to the log, last: [kind, at, n]
    anchor,         \* the anchor, outside the database (anchor.ts)
    pc, op, l, left,
    history         \* what the invariants read

procs == <<pc, op, l, left>>
vars == <<log, head, tampered, anchor, procs, history>>

-----------------------------------------------------------------------------
(* The chain *)

E(kind) == [kind |-> kind, wver |-> 0, ver |-> 0, forged |-> FALSE, edited |-> 0,
            at |-> 0, atVer |-> 0, lap |-> 0, lapEnd |-> 0, lapVer |-> 0]

Ver == IF log = <<>> THEN 0 ELSE log[Len(log)].ver

\* The entry's MAC verifies: its content as its author wrote it, after the
\* hash it was written after.
MacOk(i) == ~log[i].forged /\ log[i].edited = 0 /\ log[i].ver = log[i].wver

\* It is where its author wrote it: neither rewritten nor chained after a
\* rewrite. One edited in place still is, until its hash is recomputed.
Chained(i) == ~log[i].forged /\ log[i].ver = log[i].wver

\* A tamper the vault's walks can find: a hash that is not its entry's, or
\* an entry of its own rewritten or chained after a rewrite. One of the
\* app's entries rewritten, and those after it, which are the app's too,
\* only the app's walk finds.
VaultSees == \E i \in 1..Len(log) : log[i].edited # 0 \/ (log[i].kind \in VaultKinds /\ ~Chained(i))

\* Its stored hash is the one its content gives.
HashOk(i) == log[i].edited = 0

Seqs(a, b) == {i \in 1..Len(log) : a < i /\ i <= b}

\* The newest entry of a kind, 0 for none.
Newest(kinds) == LET s == {i \in 1..Len(log) : log[i].kind \in kinds} IN IF s = {} THEN 0 ELSE CHOOSE i \in s : \A j \in s : j <= i

\* The newest checkpoint the vault signed: where its prefix ends, and its hash.
Signed == Newest({"ckpt"})

\* A point of the chain still holds the hash it had.
Carries(seq, ver) == seq = 0 \/ (seq <= Len(log) /\ log[seq].ver = ver)

\* The vault's walk of (a, b]: each hash recomputed and linked, each vault
\* entry's MAC; the app's entries only for their place in the chain.
VaultWalkOk(a, b) == \A i \in Seqs(a, b) : HashOk(i) /\ (CheckpointChecksVault /\ log[i].kind \in VaultKinds => MacOk(i))

\* The app's: the same, each app entry's MAC and not the vault's.
AppFault(i) == ~HashOk(i) \/ (WalkChecksAppMacs /\ log[i].kind \in AppKinds /\ ~MacOk(i))

\* No entry edited in place: the model's, for `RepairGoesGreen`.
Calm == \A i \in 1..Len(log) : log[i].edited = 0

-----------------------------------------------------------------------------
(* The anchor (anchor.ts): the newest checkpoint a beat saw, where its      *)
(* prefix ends and its hash (`at`, `ver`); how far the app verified         *)
(* (`verified`, `vver`); the entry a walk found (`found`, 0 for none); a    *)
(* vault that refused (`vfound`); the beat that wrote it; and the record's  *)
(* revision, which the compare-and-set compares.                            *)

NoAnchor == [exists |-> FALSE, rev |-> 0, at |-> 0, ver |-> 0, verified |-> 0, vver |-> 0, found |-> 0, vfound |-> FALSE, beat |-> 0]

\* What readiness answers (server heartbeat.ts, auditReadiness): an anchor,
\* no finding, caught up to its checkpoint, which covers the beat that
\* wrote it, and whose prefix the log still holds. Its age, the
\* signature and the key are left out.
ReadyWith(a) ==
    /\ a.exists /\ a.at > 0
    /\ a.found = 0 /\ ~a.vfound
    /\ a.verified = a.at /\ a.vver = a.ver
    /\ a.at >= a.beat
    /\ ReadinessChecksHeld => Carries(a.at, a.ver)
ReadyNow == ReadyWith(anchor)

\* The entry a finding names verifies again, alone (heartbeat.ts, `repaired`):
\* a point the anchor holds by its hash, any other by its own.
Repaired(a) ==
    IF a.found = a.verified THEN Carries(a.verified, a.vver)
    ELSE IF a.found = a.at THEN Carries(a.at, a.ver)
    ELSE a.found <= Len(log) /\ ~AppFault(a.found)

\* The app's walk from a point toward the prefix ending at c, at most Walk
\* entries (walkChain, `to`): where it got to, and the first fault.
WalkTo(r, c) ==
    LET to == IF c - r.at > Walk THEN r.at + Walk ELSE c
        faults == {i \in Seqs(r.at, to) : AppFault(i)}
        fault == IF WalkChecksFrom /\ ~Carries(r.at, r.ver) THEN r.at
                 ELSE IF faults = {} THEN 0 ELSE CHOOSE i \in faults : \A j \in faults : i <= j
    IN [ok |-> fault = 0 /\ r.at <= c, to |-> to, done |-> to = c, fault |-> fault]

-----------------------------------------------------------------------------
(* Processes *)

NoOp == [kind |-> "none", at |-> 0]
L0 == [from |-> 0, fromVer |-> 0, to |-> 0, toVer |-> 0, ok |-> TRUE, seen |-> 0,
       sfrom |-> 0, slap |-> 0, slapEnd |-> 0, slapVer |-> 0, sok |-> TRUE, done |-> TRUE,
       beat |-> 0, prev |-> NoAnchor, next |-> NoAnchor, signed |-> FALSE, c |-> 0, cVer |-> 0, read |-> NoAnchor, fEdit |-> 0]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Add(entry) == log' = Append(log, [entry EXCEPT !.wver = Ver, !.ver = Ver])

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = L0]
         /\ Goto(p, CASE o.kind = "app" -> "append.head"
                      [] o.kind = "vault" -> "append.head"
                      [] o.kind = "beat" -> "beat.head"
                      [] o.kind = "probe" -> "probe.anchor"
                      [] o.kind \in {"rewrite", "edit", "revert"} -> "tamper")
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<log, head, tampered, anchor, history>>

TakeHead(p, then) ==
    /\ head \in {None, p}
    /\ head' = p
    /\ Goto(p, then)
    /\ UNCHANGED <<log, tampered, anchor, op, l, left, history>>

Read(p, then, locals) ==
    /\ Goto(p, then)
    /\ l' = [l EXCEPT ![p] = locals]
    /\ UNCHANGED <<log, head, tampered, anchor, op, left, history>>

-----------------------------------------------------------------------------
(* Requests append the app's entries and the vault's, under the head. *)

AppendHead(p) == pc[p] = "append.head" /\ TakeHead(p, "append.commit")

AppendCommit(p) ==
    /\ pc[p] = "append.commit"
    /\ IF Len(log) < MaxLen THEN Add(E(op[p].kind)) ELSE UNCHANGED log
    /\ head' = None
    /\ Goto(p, "idle")
    /\ UNCHANGED <<tampered, anchor, op, l, left, history>>

-----------------------------------------------------------------------------
(* Someone who writes the database: an entry edited in place, any entry, a
   heartbeat row among them, and put back, as often as they like; or once,
   one rewritten and the chain after it, and the head row, hashed again.
   The anchor is out of their reach. *)

Tamper(p) ==
    /\ pc[p] = "tamper"
    /\ (op[p].kind = "rewrite" => tampered.kind # "rewrite")
    /\ LET targets == {i \in (IF op[p].at = 0 THEN 1..Len(log) ELSE {op[p].at}) : i <= Len(log)}
       IN \/ targets = {} /\ UNCHANGED <<log, tampered>>
          \/ \E i \in targets :
                /\ CASE op[p].kind = "edit" -> log' = [log EXCEPT ![i].edited = tampered.n + 1]
                     [] op[p].kind = "revert" -> log' = [log EXCEPT ![i].edited = 0]
                     [] OTHER -> log' = [j \in 1..Len(log) |-> IF j < i THEN log[j]
                                                        ELSE [log[j] EXCEPT !.ver = @ + 1, !.forged = (j = i) \/ @]]
                /\ tampered' = IF op[p].kind = "revert" THEN tampered ELSE [kind |-> op[p].kind, at |-> i, n |-> tampered.n + 1]
    /\ Goto(p, "idle")
    /\ UNCHANGED <<head, anchor, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A heartbeat (server heartbeat.ts, writeAuditHeartbeat): the beat, the   *)
(* anchor read, the vault's checkpoint, the walk from the anchor to the    *)
(* prefix it signed, then the anchor written over the record it read.      *)
(***************************************************************************)

BeatHead(p) == pc[p] = "beat.head" /\ TakeHead(p, "beat.commit")

BeatCommit(p) ==
    /\ pc[p] = "beat.commit"
    /\ Len(log) < MaxLen
    /\ Add(E("beat"))
    /\ l' = [l EXCEPT ![p].beat = Len(log) + 1]
    /\ head' = None
    /\ Goto(p, "beat.read")
    /\ UNCHANGED <<tampered, anchor, op, left, history>>

\* Before the vault signs: a beat beside it that anchors a later checkpoint
\* first wins the compare-and-set.
BeatRead(p) == pc[p] = "beat.read" /\ Read(p, "ckpt.snapshot", [l[p] EXCEPT !.prev = anchor])

\* In one snapshot: the anchor's prefix still there, then the walk from
\* where the app verified to, toward the prefix the vault just signed. A
\* finding stands until its entry verifies again; a refusal, until the
\* vault signs.
BeatWalk(p) ==
    /\ pc[p] = "beat.walk"
    /\ LET a == l[p].prev
           c == l[p].c
           held == ~AnchorHeld \/ (Carries(a.at, a.ver) /\ c >= a.at)
           w == WalkTo([at |-> a.verified, ver |-> a.vver], c)
           \* The vault signed the hash the app computes there.
           ends == ~w.done \/ Carries(c, l[p].cVer)
           Found(e) == [a EXCEPT !.found = e, !.vfound = FALSE]
           next == CASE ~l[p].signed -> IF a.found > 0 THEN a ELSE [a EXCEPT !.vfound = TRUE]
                     [] a.found > 0 /\ ~Repaired(a) -> a
                     [] ~held -> Found(a.at)
                     [] ~w.ok -> Found(w.fault)
                     [] ~ends -> Found(c)
                     [] OTHER -> [a EXCEPT !.exists = TRUE, !.at = c, !.ver = l[p].cVer, !.verified = w.to,
                                           !.vver = IF w.to = 0 THEN 0 ELSE log[w.to].ver, !.found = 0, !.vfound = FALSE]
       IN /\ l' = [l EXCEPT ![p].next = [next EXCEPT !.beat = l[p].beat],
                             ![p].fEdit = IF next.found > 0 /\ next.found <= Len(log) THEN log[next.found].edited ELSE 0]
          /\ history' = [history EXCEPT !.calmWalks = IF Calm THEN @ + 1 ELSE 0]
    /\ Goto(p, "beat.cas")
    /\ UNCHANGED <<log, head, tampered, anchor, op, left>>

\* The store: the new record only over the one the beat read, unless the
\* write is blind. One that moves a point back is the model's to see.
BeatCas(p) ==
    /\ pc[p] = "beat.cas"
    /\ LET next == [l[p].next EXCEPT !.rev = anchor.rev + 1]
       IN IF ~AnchorCas \/ anchor.rev = l[p].prev.rev
            THEN /\ anchor' = next
                 \* What it found, once it is the anchor's: the edit, as it was then.
                 /\ history' = [history EXCEPT !.back = @ \/ (anchor.exists /\ (next.at < anchor.at \/ next.verified < anchor.verified)),
                                               !.found = @ \cup (IF l[p].fEdit # 0 THEN {<<next.found, l[p].fEdit>>} ELSE {})]
            ELSE UNCHANGED <<anchor, history>>
    /\ Goto(p, "idle")
    /\ UNCHANGED <<log, head, tampered, op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A checkpoint (vault vault.ts, checkpoint): a walk from the newest one in *)
(* a snapshot, a stretch of the scrub in another, then, under the head,    *)
(* the rest and the signature. What it returns, the beat walks to.         *)
(***************************************************************************)

\* The newest checkpoint entry, signed or refused, the newest signed one,
\* its prefix still holding its hash, and the walk from it.
CkptSnapshot(p) ==
    /\ pc[p] = "ckpt.snapshot"
    /\ LET s == Signed
           from == IF s = 0 THEN 0 ELSE log[s].at
           fromVer == IF s = 0 THEN 0 ELSE log[s].atVer
           to == IF Len(log) - from > CkptWalk THEN from + CkptWalk ELSE Len(log)
           ok == Carries(from, fromVer) /\ VaultWalkOk(from, to)
       IN Read(p, "ckpt.scrub", [l[p] EXCEPT !.seen = Newest({"ckpt", "deny"}), !.from = from, !.fromVer = fromVer, !.done = to = Len(log),
                                              !.to = to, !.toVer = IF to = 0 THEN 0 ELSE log[to].ver, !.ok = ok,
                                              !.slap = IF s = 0 THEN 0 ELSE log[s].lap,
                                              !.slapEnd = IF s = 0 THEN 0 ELSE IF log[s].lapEnd = 0 THEN from ELSE log[s].lapEnd,
                                              !.slapVer = IF s = 0 THEN 0 ELSE IF log[s].lapEnd = 0 THEN fromVer ELSE log[s].lapVer])

\* The scrub, in a snapshot of its own: from where the lap is, ScrubWalk
\* entries, each hash recomputed; a lap ends at the prefix signed when it
\* began, which must still have its hash.
CkptScrub(p) ==
    /\ pc[p] = "ckpt.scrub"
    /\ LET a == l[p].slap
           b == IF l[p].slapEnd - a > ScrubWalk THEN a + ScrubWalk ELSE l[p].slapEnd
           ok == ~Scrubs \/ ((\A i \in Seqs(a, b) : HashOk(i)) /\ (b = l[p].slapEnd => Carries(b, l[p].slapVer)))
       IN Read(p, "ckpt.head", [l[p] EXCEPT !.sok = ok, !.sfrom = IF b = l[p].slapEnd THEN 0 ELSE b])

CkptHead(p) == pc[p] = "ckpt.head" /\ TakeHead(p, "ckpt.commit")

\* After the checkpoint, a beat walks: to the prefix it signed, or the newest one.
After(p) == IF op[p].kind = "beat" THEN "beat.walk" ELSE "idle"
Returned(p, s) == [l[p] EXCEPT !.signed = s > 0, !.c = IF s = 0 THEN 0 ELSE log[s].at, !.cVer = IF s = 0 THEN 0 ELSE log[s].atVer]

\* Under the head. A refusal rolls back, and its entry commits in a
\* transaction of its own (`ckpt.deny`).
CkptCommit(p) ==
    /\ pc[p] = "ckpt.commit"
    /\ LET s == Signed
           newest == Newest({"ckpt", "deny"})
           \* A refusal stands only as the vault's own (#standingRefusal, by its MAC).
           standing == Newest({"deny"}) > s /\ MacOk(Newest({"deny"}))
           \* Done, the rest under the head, and the head signed; else where the walk got to, behind it.
           at == IF l[p].done THEN Len(log) ELSE l[p].to
           rest == ~l[p].done \/ VaultWalkOk(l[p].to, Len(log))
           sign == [E("ckpt") EXCEPT !.at = at, !.atVer = log[at].ver, !.lap = l[p].sfrom,
                                     !.lapEnd = IF l[p].sfrom = 0 THEN 0 ELSE l[p].slapEnd,
                                     !.lapVer = IF l[p].sfrom = 0 THEN 0 ELSE l[p].slapVer]
           \* Returns the newest checkpoint, signed by another call or before.
           Idle == /\ head' = None /\ Goto(p, After(p)) /\ l' = [l EXCEPT ![p] = Returned(p, s)]
                   /\ UNCHANGED <<log, tampered, anchor, op, left, history>>
           Deny == /\ head' = None /\ Goto(p, "ckpt.deny") /\ UNCHANGED <<log, tampered, anchor, op, l, left, history>>
       IN CASE ~l[p].ok \/ ~l[p].sok -> Deny
            [] SeenRecheckUnderHead /\ newest # l[p].seen -> IF standing THEN Deny ELSE Idle
            \* Nothing since the newest, which signed all before its own.
            [] s > 0 /\ s = Len(log) /\ log[s].at = s - 1 -> Idle
            [] ~(CheckpointChecksVault => Carries(l[p].from, l[p].fromVer))
               \/ ~Carries(l[p].to, l[p].toVer) \/ ~rest -> Deny
            \* Another call signed as far, or further: that is the newest prefix.
            [] s > 0 /\ log[s].at >= at -> Idle
            [] Len(log) >= MaxLen -> Idle
            [] OTHER -> /\ Add(sign)
                        /\ history' = [history EXCEPT !.signedBad = @ \/ ~\A i \in 1..at : log[i].kind \in VaultKinds => Chained(i),
                                                      !.signedAfterDeny = @ \/ (Newest({"deny"}) > 0 /\ VaultSees),
                                                      !.signedAfterEdit = @ + (IF tampered.kind = "edit" THEN 1 ELSE 0)]
                        /\ head' = None
                        /\ Goto(p, After(p))
                        /\ l' = [l EXCEPT ![p].signed = TRUE, ![p].c = at, ![p].cVer = log[at].ver]
                        /\ UNCHANGED <<tampered, anchor, op, left>>

\* The refusal's entry, `log_broken`, in a transaction of its own.
CkptDenyHead(p) == pc[p] = "ckpt.deny" /\ TakeHead(p, "ckpt.denied")

CkptDenied(p) ==
    /\ pc[p] = "ckpt.denied"
    /\ IF Len(log) < MaxLen THEN Add(E("deny")) ELSE UNCHANGED log
    /\ head' = None
    /\ Goto(p, After(p))
    /\ l' = [l EXCEPT ![p].signed = FALSE]
    /\ UNCHANGED <<tampered, anchor, op, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Readiness, as a monitor asks it (server heartbeat.ts, auditReadiness):  *)
(* the anchor, then, in another read, the log at its checkpoint.           *)
(***************************************************************************)

ProbeAnchor(p) == pc[p] = "probe.anchor" /\ Read(p, "probe.log", [l[p] EXCEPT !.read = anchor])

\* Green on the anchor it read and the log as it is now; real if no entry
\* of the prefix it vouches for is rewritten, or chained after a rewrite.
ProbeLog(p) ==
    /\ pc[p] = "probe.log"
    /\ LET a == l[p].read
       IN history' = [history EXCEPT !.greens = @ \cup (IF ReadyWith(a) THEN {[real |-> \A i \in 1..a.at : i <= Len(log) /\ Chained(i)]} ELSE {})]
    /\ Goto(p, "idle")
    /\ UNCHANGED <<log, head, tampered, anchor, op, l, left>>

-----------------------------------------------------------------------------

Init ==
    /\ log = InitLog
    /\ head = None
    /\ tampered = [kind |-> "none", at |-> 0, n |-> 0]
    /\ anchor = InitAnchor
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ history = [signedBad |-> FALSE, signedAfterDeny |-> FALSE, signedAfterEdit |-> 0, greens |-> {}, back |-> FALSE, calmWalks |-> 0,
                   \* What the anchor the run starts with found, and still holds.
                   found |-> IF InitAnchor.found > 0 /\ InitLog[InitAnchor.found].edited # 0 THEN {<<InitAnchor.found, InitLog[InitAnchor.found].edited>>} ELSE {}]

Step(p) ==
    \/ Begin(p) \/ AppendHead(p) \/ AppendCommit(p) \/ Tamper(p)
    \/ BeatHead(p) \/ BeatCommit(p) \/ BeatRead(p) \/ BeatWalk(p) \/ BeatCas(p)
    \/ CkptSnapshot(p) \/ CkptScrub(p) \/ CkptHead(p) \/ CkptCommit(p) \/ CkptDenyHead(p) \/ CkptDenied(p)
    \/ ProbeAnchor(p) \/ ProbeLog(p)

\* A beat past the log's bound ends the run there.
Stuck(p) == pc[p] = "beat.commit" /\ Len(log) >= MaxLen

Finished == \A p \in Procs : (pc[p] = "idle" /\ left[p] = 0) \/ Stuck(p)

Next == (\E p \in Procs : Step(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK == head \in Procs \cup {None} /\ anchor.found \in 0..MaxLen

\* The vault never signs a prefix holding an entry of its own rewritten, or
\* chained after a rewrite. One edited in place between its walk and its
\* signature it does sign: the scrub finds it (`EditFoundByNextScrub`).
SignsNoForgedVault == ~history.signedBad

\* Once a checkpoint was refused for a broken log, none is signed while
\* the vault could find the tamper: each call finds it again, or sees the
\* refusal stand. One it cannot find, the app's, it signs over; the app's
\* walk keeps readiness red (`FoundEditStaysRed`).
StaysUnsignedOnceFound == ~history.signedAfterDeny

\* While an edit a beat found is still in place, readiness is red, against
\* someone who edits, reverts and edits again, any entry, heartbeat rows
\* among them. Edited again after a revert, it is a new edit behind the
\* anchor, which the scrub finds (`EditFoundByNextScrub`).
FoundEditStaysRed ==
    (\E f \in history.found : f[1] <= Len(log) /\ log[f[1]].edited = f[2]) => ~ReadyNow

\* An entry edited in place is found by the next checkpoint whose scrub
\* starts after it: one in flight may still sign, none after. With a
\* scrub of the whole prefix a call, as the scenarios run it; with
\* `walks.scrub` entries a call, within two laps (docs/formal.md).
EditFoundByNextScrub == history.signedAfterEdit <= 1

\* Readiness never vouches for a prefix holding an entry rewritten, or
\* chained after a rewrite: it is the vault's and the app's, as they wrote it.
GreenIsReal == \A g \in history.greens : g.real

\* The anchor never moves back: neither its checkpoint nor how far the app verified.
AnchorNeverBack == ~history.back

\* Once the edit is put back, readiness is green after five beats have
\* walked with no edit in place: the vault's refusal and the app's finding
\* cleared, and the walks caught up with a backlog of three walks.
RepairGoesGreen == (Finished /\ Calm /\ history.calmWalks >= 5) => ReadyNow

=============================================================================
