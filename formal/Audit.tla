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
(* The vault's scrub runs in a snapshot of its own (REPEATABLE READ, read  *)
(* only: db dialect.ts, SNAPSHOT), so it is one step here. The app's walks *)
(* and the vault's checkpoint walk in no transaction, a batch a statement: *)
(* an entry a step here, each linked to the one before as it was read.     *)
(* Appends take the log's head; the vault's checkpoint decides under it.   *)
(* The anchor's store is one compare-and-set a step.                       *)
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
    AppBatch,       \* entries the app's walk reads a statement (walkChain, BATCH)
    AppWalkSteps,   \* the app's walks a batch a step, in no transaction; else one step, as in a snapshot
    CkptWalk,       \* walks.checkpoint: entries a checkpoint's walk reads at most
    ScrubWalk       \* walks.scrub: entries a scrub reads a call

CONSTANTS
    \* A heartbeat's walk checks first that the entry it goes on from still
    \* has the hash it verified (db audit.ts, walkChain, `from`).
    WalkChecksFrom,
    \* The app's walk, in no transaction, links each batch to the hash it
    \* verified last (walkChain, verifyAppEntries, `startPrevHash`).
    AppLinksWalk,
    \* And the app's MAC of each app entry it walks (walkChain, verifyEntries).
    WalkChecksAppMacs,
    \* A checkpoint's walk checks the vault's MAC of each vault entry (vault
    \* log.ts, rehash), and under the head that the prefix signed last still
    \* has its hash (vault.ts, checkpoint, `carries(newest)`).
    CheckpointChecksVault,
    \* The checkpoint's walk, in no transaction, links each batch to the
    \* hash it verified last (vault log.ts, rehash, `startPrevHash`): what
    \* stands in for a snapshot while the log is rewritten under it.
    CheckpointLinksWalk,
    \* Under the head, a checkpoint that another call checkpointed or
    \* refused after its snapshot signs nothing, and a refusal for a broken
    \* log since the last checkpoint stands (checkpoint, `seen`,
    \* #standingRefusal).
    SeenRecheckUnderHead,
    \* A refusal names the entry it found broken, and a checkpoint whose walk
    \* began after it, while the refusal stands, checks that entry again under
    \* the head before it signs: its hash, its link to the one before, the
    \* vault's MAC of the vault's (vault.ts, checkpoint, #standingRefusal).
    RefusalRecheckedUnderHead,
    \* The scrub recomputes each hash of the prefixes signed before, a
    \* stretch a call (vault.ts, #scrub, relink).
    Scrubs,
    \* A beat's walk checks first that the log still holds the prefix the
    \* anchor's checkpoint signed, and that the vault signed no shorter one
    \* (server plugins/audit-watch.ts, advance).
    AnchorHeld,
    \* Readiness checks that the log still holds the prefix the anchor's
    \* checkpoint signed (server plugins/audit-watch.ts, readiness, `holds`).
    ReadinessChecksHeld,
    \* A beat writes the anchor only over the record it read before its
    \* checkpoint (anchor.ts, AnchorStore.write, `admits`).
    AnchorCas,
    \* A beat that loses the compare-and-set to a walk between beats toward
    \* the same checkpoint walks again from that walk's record (audit-watch.ts,
    \* beat, `WRITES_LOST`). Not a protection: what must hold with it on.
    BeatRetries

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

\* What readiness answers (server plugins/audit-watch.ts, readiness): an anchor,
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

\* The entry a finding names verifies again, alone (audit-watch.ts, `repaired`):
\* its hash and, the app's, its MAC; a point the anchor holds, by the hash
\* it holds too.
Repaired(a) ==
    /\ a.found <= Len(log) /\ ~AppFault(a.found)
    /\ (a.found = a.verified => Carries(a.verified, a.vver))
    /\ (a.found = a.at => Carries(a.at, a.ver))

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
L0 == [from |-> 0, fromVer |-> 0, to |-> 0, toVer |-> 0, ok |-> TRUE, seen |-> 0, failed |-> 0,
       wat |-> 0, wver |-> 0, wend |-> 0,
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
                      [] o.kind = "beat" -> "beat.read"
                      [] o.kind = "walk" -> "walk.read"
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
(* A heartbeat (server plugins/audit-watch.ts, beat): the anchor read, the *)
(* beat, the vault's checkpoint, the walk from the anchor to the prefix it *)
(* signed, then the anchor written over the record it read.                *)
(***************************************************************************)

\* Before the vault signs: a beat beside it that anchors a later checkpoint
\* first wins the compare-and-set.
BeatRead(p) == pc[p] = "beat.read" /\ Read(p, "beat.head", [l[p] EXCEPT !.prev = anchor])

BeatHead(p) == pc[p] = "beat.head" /\ TakeHead(p, "beat.commit")

BeatCommit(p) ==
    /\ pc[p] = "beat.commit"
    /\ Len(log) < MaxLen
    /\ Add(E("beat"))
    /\ l' = [l EXCEPT ![p].beat = Len(log) + 1]
    /\ head' = None
    /\ Goto(p, "ckpt.snapshot")
    /\ UNCHANGED <<tampered, anchor, op, left, history>>

\* What a beat or a walk between beats will write, and what it found, as the log is now.
Decided(p, next, then) ==
    /\ l' = [l EXCEPT ![p].next = IF op[p].kind = "beat" THEN [next EXCEPT !.beat = l[p].beat] ELSE next,
                      ![p].fEdit = IF next.found > 0 /\ next.found <= Len(log) THEN log[next.found].edited ELSE 0]
    /\ history' = IF op[p].kind = "beat" THEN [history EXCEPT !.calmWalks = IF Calm THEN @ + 1 ELSE 0] ELSE history
    /\ Goto(p, then)
    /\ UNCHANGED <<log, head, tampered, anchor, op, left>>

\* What a walk that got to `w.to`, computing there the version `wver`,
\* makes of the anchor: a beat's, toward the prefix the vault signed (`c`,
\* `cVer`); a walk between beats', toward the anchor's own.
BeatNext(p, w, wver) ==
    LET a == l[p].prev
        Found(e) == [a EXCEPT !.found = e, !.vfound = FALSE]
        \* The vault signed the hash the app computes there.
        ends == ~w.done \/ wver = l[p].cVer
    IN CASE ~w.ok -> Found(w.fault)
         [] ~ends -> Found(l[p].c)
         [] OTHER -> [a EXCEPT !.exists = TRUE, !.at = l[p].c, !.ver = l[p].cVer, !.verified = w.to,
                               !.vver = wver, !.found = 0, !.vfound = FALSE]
WalkNext(p, w, wver) ==
    LET a == l[p].prev
    IN CASE ~w.ok -> [a EXCEPT !.found = w.fault]
         [] w.done /\ wver # a.ver -> [a EXCEPT !.found = a.at]
         [] OTHER -> [a EXCEPT !.verified = w.to, !.vver = wver]
Next_(p, w, wver) == IF op[p].kind = "beat" THEN BeatNext(p, w, wver) ELSE WalkNext(p, w, wver)
Cas(p) == IF op[p].kind = "beat" THEN "beat.cas" ELSE "walk.cas"

\* The anchor's prefix still there, read first, then the walk from where the
\* app verified toward the prefix: with `AppWalkSteps`, in no transaction,
\* a batch a step (`AppStep`); otherwise in the same step, as one snapshot.
StartWalk(p, c) ==
    LET a == l[p].prev
        moved == WalkChecksFrom /\ ~Carries(a.verified, a.vver)
        w == WalkTo([at |-> a.verified, ver |-> a.vver], c)
    IN IF AppWalkSteps /\ ~moved /\ a.verified <= c
         THEN Read(p, "app.step", [l[p] EXCEPT !.wat = a.verified, !.wver = a.vver,
                                               !.wend = IF c - a.verified > Walk THEN a.verified + Walk ELSE c])
         \* One step, or a walk that cannot start, decided at once.
         ELSE Decided(p, Next_(p, w, IF w.to = 0 THEN 0 ELSE log[w.to].ver), Cas(p))

\* A finding stands until its entry verifies again; a refusal, until the
\* vault signs: neither walks.
BeatWalk(p) ==
    /\ pc[p] = "beat.walk"
    /\ LET a == l[p].prev
           c == l[p].c
           held == ~AnchorHeld \/ (Carries(a.at, a.ver) /\ c >= a.at)
       IN CASE ~l[p].signed -> Decided(p, IF a.found > 0 THEN a ELSE [a EXCEPT !.vfound = TRUE], "beat.cas")
            [] a.found > 0 /\ ~Repaired(a) -> Decided(p, a, "beat.cas")
            [] ~held -> Decided(p, [a EXCEPT !.found = a.at, !.vfound = FALSE], "beat.cas")
            [] OTHER -> StartWalk(p, c)

\* One statement of the app's walk (db audit.ts, walkChain): up to AppBatch
\* entries, the first linked to the hash computed for the one before, each
\* its own hash and the app's MAC of the app's, read as the log is then.
\* Once it is out of its budget, or faulty, the anchor is decided in the
\* same step: on what the walk computed, nothing read again.
AppStep(p) ==
    /\ pc[p] = "app.step"
    /\ LET a == l[p].wat
           b == IF l[p].wend - a > AppBatch THEN a + AppBatch ELSE l[p].wend
           faults == {i \in Seqs(a, b) : AppFault(i)}
           linked == AppLinksWalk => Carries(a, l[p].wver)
           fault == IF ~linked THEN a + 1 ELSE IF faults = {} THEN 0 ELSE CHOOSE i \in faults : \A j \in faults : i <= j
           c == IF op[p].kind = "beat" THEN l[p].c ELSE l[p].prev.at
           end(at, ok, f, ver) == Decided(p, Next_(p, [ok |-> ok, to |-> at, done |-> at = c, fault |-> f], ver), Cas(p))
       IN CASE a >= l[p].wend -> end(a, TRUE, 0, l[p].wver)
            [] fault # 0 -> end(b, FALSE, fault, log[b].ver)
            [] b = l[p].wend -> end(b, TRUE, 0, log[b].ver)
            [] OTHER -> Read(p, "app.step", [l[p] EXCEPT !.wat = b, !.wver = log[b].ver])

\* The store: the new record only over the one read, unless the write is
\* blind. One that moves a point back is the model's to see. What it
\* found, once it is the anchor's: the edit, as it was then.
Written(p) ==
    LET next == [l[p].next EXCEPT !.rev = anchor.rev + 1]
    IN /\ anchor' = next
       /\ history' = [history EXCEPT !.back = @ \/ (anchor.exists /\ (next.at < anchor.at \/ next.verified < anchor.verified)),
                                     !.found = @ \cup (IF l[p].fEdit # 0 THEN {<<next.found, l[p].fEdit>>} ELSE {})]

\* Lost to a walk between beats toward the same checkpoint, the beat reads
\* that record and walks again from it (`WRITES_LOST`); lost to anything
\* else, it writes nothing.
BeatCas(p) ==
    /\ pc[p] = "beat.cas"
    /\ IF ~AnchorCas \/ anchor.rev = l[p].prev.rev
         THEN Written(p) /\ Goto(p, "idle") /\ UNCHANGED l
         ELSE /\ UNCHANGED <<anchor, history>>
              /\ IF BeatRetries /\ anchor.exists /\ l[p].prev.exists /\ anchor.at = l[p].prev.at /\ anchor.ver = l[p].prev.ver
                   THEN Goto(p, "beat.walk") /\ l' = [l EXCEPT ![p].prev = anchor]
                   ELSE Goto(p, "idle") /\ UNCHANGED l
    /\ UNCHANGED <<log, head, tampered, op, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A walk between beats (server plugins/audit-watch.ts, walkOn; the        *)
(* Durable Object's alarm, Node's job): an anchor with a backlog, walked   *)
(* on toward its own checkpoint, and written over the record it read. Its  *)
(* beat stays the one that wrote the record.                               *)
(***************************************************************************)

Walking(a) == a.exists /\ a.at > 0 /\ a.found = 0 /\ ~a.vfound /\ a.verified # a.at

WalkRead(p) ==
    /\ pc[p] = "walk.read"
    /\ Read(p, IF Walking(anchor) THEN "walk.walk" ELSE "idle", [l[p] EXCEPT !.prev = anchor])

\* As a beat's walk: the anchor's prefix still there, then from where the
\* app verified toward it, ending at its hash.
WalkWalk(p) ==
    /\ pc[p] = "walk.walk"
    /\ LET a == l[p].prev
       IN IF AnchorHeld /\ ~Carries(a.at, a.ver)
            THEN Decided(p, [a EXCEPT !.found = a.at], "walk.cas")
            ELSE StartWalk(p, a.at)

WalkCas(p) ==
    /\ pc[p] = "walk.cas"
    /\ IF ~AnchorCas \/ anchor.rev = l[p].prev.rev THEN Written(p) ELSE UNCHANGED <<anchor, history>>
    /\ Goto(p, "idle")
    /\ UNCHANGED <<log, head, tampered, op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A checkpoint (vault vault.ts, checkpoint): where it resumes, from the   *)
(* newest one, in a snapshot; the walk on from there in no transaction, an *)
(* entry a step; a stretch of the scrub in a snapshot of its own; then,    *)
(* under the head, the rest and the signature. What it returns, the beat   *)
(* walks to.                                                               *)
(***************************************************************************)

\* In one snapshot: the newest checkpoint entry, signed or refused, the
\* newest signed one, and its prefix still holding its hash.
CkptSnapshot(p) ==
    /\ pc[p] = "ckpt.snapshot"
    /\ LET s == Signed
           from == IF s = 0 THEN 0 ELSE log[s].at
           fromVer == IF s = 0 THEN 0 ELSE log[s].atVer
       IN Read(p, "ckpt.walk", [l[p] EXCEPT !.seen = Newest({"ckpt", "deny"}), !.from = from, !.fromVer = fromVer,
                                             !.to = from, !.toVer = fromVer, !.ok = Carries(from, fromVer),
                                             !.slap = IF s = 0 THEN 0 ELSE log[s].lap,
                                             !.slapEnd = IF s = 0 THEN 0 ELSE IF log[s].lapEnd = 0 THEN from ELSE log[s].lapEnd,
                                             !.slapVer = IF s = 0 THEN 0 ELSE IF log[s].lapEnd = 0 THEN fromVer ELSE log[s].lapVer])

\* The walk, an entry a step, at most CkptWalk (vault log.ts, rehash, a
\* batch a statement): each linked to the hash it computed for the one
\* before, its own recomputed, and the vault's by its MAC. Out of entries,
\* or of its budget, it is done if it reached the log's end.
CkptWalkStep(p) ==
    /\ pc[p] = "ckpt.walk"
    /\ LET i == l[p].to + 1
       IN IF l[p].ok /\ i <= Len(log) /\ l[p].to - l[p].from < CkptWalk
            THEN LET ok == (CheckpointLinksWalk => Carries(i - 1, l[p].toVer)) /\ VaultWalkOk(i - 1, i)
                 IN Read(p, "ckpt.walk", [l[p] EXCEPT !.to = i, !.toVer = log[i].ver, !.ok = ok, !.failed = IF ok THEN 0 ELSE i])
            ELSE Read(p, "ckpt.scrub", [l[p] EXCEPT !.done = l[p].to = Len(log)])

\* The scrub, in a snapshot of its own: from where the lap is, ScrubWalk
\* entries, each hash recomputed; a lap ends at the prefix signed when it
\* began, which must still have its hash.
CkptScrub(p) ==
    /\ pc[p] = "ckpt.scrub"
    /\ LET a == l[p].slap
           b == IF l[p].slapEnd - a > ScrubWalk THEN a + ScrubWalk ELSE l[p].slapEnd
           ok == ~Scrubs \/ ((\A i \in Seqs(a, b) : HashOk(i)) /\ (b = l[p].slapEnd => Carries(b, l[p].slapVer)))
           broken == {i \in Seqs(a, b) : ~HashOk(i)}
           \* The entry it names: the first whose hash is not its own, or the lap's end.
           failed == IF broken = {} THEN b ELSE CHOOSE i \in broken : \A j \in broken : i <= j
       IN Read(p, "ckpt.head", [l[p] EXCEPT !.sok = ok, !.sfrom = IF b = l[p].slapEnd THEN 0 ELSE b,
                                            !.failed = IF ok \/ ~l[p].ok THEN @ ELSE failed])

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
           \* The entry the standing refusal names, 0 for none.
           named == IF standing THEN log[Newest({"deny"})].at ELSE 0
           \* That entry as the walk checks each: its hash, its links to the ones either side, the vault's MAC.
           \* A link is a version here, stricter than the code's: a rewrite from i breaks i's link to i - 1,
           \* which the code's prevHash keeps; the vault names no such entry, so the two agree.
           holds(i) == /\ VaultWalkOk(i - 1, i)
                       /\ i = 1 \/ log[i - 1].ver = log[i].ver
                       /\ i = Len(log) \/ log[i].ver = log[i + 1].ver
           \* Done, the rest under the head, and the head signed; else where the walk got to, behind it.
           at == IF l[p].done THEN Len(log) ELSE l[p].to
           rest == ~l[p].done \/ VaultWalkOk(l[p].to, Len(log))
           unrest == {i \in Seqs(l[p].to, Len(log)) : ~VaultWalkOk(i - 1, i)}
           sign == [E("ckpt") EXCEPT !.at = at, !.atVer = log[at].ver, !.lap = l[p].sfrom,
                                     !.lapEnd = IF l[p].sfrom = 0 THEN 0 ELSE l[p].slapEnd,
                                     !.lapVer = IF l[p].sfrom = 0 THEN 0 ELSE l[p].slapVer]
           \* Returns the newest checkpoint, signed by another call or before.
           Idle == /\ head' = None /\ Goto(p, After(p)) /\ l' = [l EXCEPT ![p] = Returned(p, s)]
                   /\ UNCHANGED <<log, tampered, anchor, op, left, history>>
           \* A refusal, naming the entry it found broken, 0 for none.
           Deny(failed) == /\ head' = None /\ Goto(p, "ckpt.deny") /\ l' = [l EXCEPT ![p].failed = failed]
                           /\ UNCHANGED <<log, tampered, anchor, op, left, history>>
       IN CASE ~l[p].ok \/ ~l[p].sok -> Deny(l[p].failed)
            [] SeenRecheckUnderHead /\ newest # l[p].seen -> IF standing THEN Deny(named) ELSE Idle
            \* A refusal that stands, of an entry this walk began after: that entry again.
            [] RefusalRecheckedUnderHead /\ named > 0 /\ named <= l[p].from /\ ~holds(named) -> Deny(named)
            \* Nothing since the newest, which signed all before its own.
            [] s > 0 /\ s = Len(log) /\ log[s].at = s - 1 -> Idle
            \* It names the first entry under the head the vault cannot vouch for, or none. The code names the
            \* walk's end when that changed (`changed while the vault walked it`): an app entry, whose refusal a
            \* later call clears either way, as its rewrite is the app's to find (FoundEditStaysRed).
            [] ~(CheckpointChecksVault => Carries(l[p].from, l[p].fromVer))
               \/ ~Carries(l[p].to, l[p].toVer) \/ ~rest
               -> Deny(IF unrest = {} THEN 0 ELSE CHOOSE i \in unrest : \A j \in unrest : i <= j)
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
    /\ IF Len(log) < MaxLen THEN Add([E("deny") EXCEPT !.at = l[p].failed]) ELSE UNCHANGED log
    /\ head' = None
    /\ Goto(p, After(p))
    /\ l' = [l EXCEPT ![p].signed = FALSE]
    /\ UNCHANGED <<tampered, anchor, op, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Readiness, as a monitor asks it (server audit-watch.ts, readiness):     *)
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
    \/ BeatHead(p) \/ BeatCommit(p) \/ BeatRead(p) \/ BeatWalk(p) \/ AppStep(p) \/ BeatCas(p)
    \/ CkptSnapshot(p) \/ CkptWalkStep(p) \/ CkptScrub(p) \/ CkptHead(p) \/ CkptCommit(p) \/ CkptDenyHead(p) \/ CkptDenied(p)
    \/ WalkRead(p) \/ WalkWalk(p) \/ WalkCas(p)
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
