-------------------------------- MODULE Audit --------------------------------
(***************************************************************************)
(* The audit chain's verification: heartbeats that walk it, checkpoints    *)
(* the vault signs over it, and readiness, which says whether both hold,   *)
(* against someone who can write the database but holds no key: they edit  *)
(* an entry in place, or rewrite one and chain everything after it again.  *)
(* docs/formal.md says what this covers, what it abstracts and what it     *)
(* does not prove.                                                         *)
(*                                                                         *)
(* Each walk runs in a snapshot of its own (REPEATABLE READ, read only:     *)
(* db dialect.ts, SNAPSHOT), so it is one step here, reading the log as    *)
(* that step finds it. Appends take the log's head; the vault's checkpoint *)
(* decides under it.                                                       *)
(*                                                                         *)
(* An entry's hash is abstracted to the chain's version where it is: a     *)
(* rewrite from an entry moves every entry from there on to a new version, *)
(* each hash recomputed and linked, the head row too. An entry's MAC       *)
(* binds its content and the hash before it: one rewritten, or after one,  *)
(* fails it, unless it was appended after the rewrite. An edit in place    *)
(* changes the content and leaves the stored hash: only recomputing the    *)
(* hash finds it.                                                          *)
(*                                                                         *)
(* A heartbeat row is the heartbeat's memory, and they can write it too:   *)
(* hide it (change it so no read of beats finds it), forge it (make it     *)
(* claim a clean walk to the head), and put it back, at any step, as often *)
(* as their budget allows. Either change leaves the row's stored hash, so  *)
(* a walk over it finds it, as it finds any edit in place.                 *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    InitLog,        \* the log at the start
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
    \* Readiness reads the newest heartbeat and the newest checkpoint in one
    \* snapshot (server db/queries.ts, readiness).
    ReadinessInOneSnapshot,
    \* A beat reads where to resume in the snapshot it walks in (server
    \* heartbeat.ts, writeAuditHeartbeat): every beat row past that point is
    \* one the walk reads, so one hidden or forged there is a fault it finds.
    OneSnapshot,
    \* Where to resume is read only from a beat whose MAC verifies, which
    \* covers what it says it verified, and only a point before its own row
    \* (db audit.ts, resumePoint).
    CursorByMac,
    \* And no further than where the walk of any beat after that point began,
    \* if it found the chain broken: a beat that walked the chain as it was
    \* before, and committed after the finder, never moves past its finding
    \* (resumePoint).
    NoResumePastFinding,
    \* Readiness runs the next beat's walk, from where it would resume to
    \* the head, in its snapshot (server heartbeat.ts, auditReadiness).
    ReadinessWalks,
    \* A broken beat past the point lowers it no more once a clean beat
    \* cleared it (resumePoint, `clears`): without it, a finder whose row
    \* lies more than a walk past where its walk began brings every walk
    \* back there, once the entry is put back, and none gets past it.
    Clears,
    \* Cleared only by a walk that went over the entry found, from before
    \* it, in a snapshot that held the finder (`head`); without it, by any
    \* clean beat whose snapshot held the finder, as #296's review proposed.
    ClearsOverFault

None == "none"
AppKinds == {"app", "beat"}
VaultKinds == {"vault", "ckpt", "deny"}

VARIABLES
    log,            \* the entries, in seq order
    head,           \* the process holding the log's head, or None
    tampered,       \* what was done to the log, once: [kind, at], kind "none" before
    pc, op, l, left,
    history         \* [signedBad, greens]: what the invariants read

procs == <<pc, op, l, left>>
vars == <<log, head, tampered, procs, history>>

-----------------------------------------------------------------------------
(* The chain *)

E(kind) == [kind |-> kind, wver |-> 0, ver |-> 0, forged |-> FALSE, edited |-> 0, fEdit |-> 0,
            verified |-> 0, vver |-> 0, broken |-> FALSE, short |-> FALSE, walked |-> FALSE,
            at |-> 0, atVer |-> 0, lap |-> 0, lapEnd |-> 0, lapVer |-> 0, fault |-> 0,
            hidden |-> FALSE, claims |-> 0, claimsVer |-> 0, bfrom |-> 0, bfromVer |-> 0, head |-> 0, calm |-> FALSE]

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
AppWalkOk(a, b) == \A i \in Seqs(a, b) : HashOk(i) /\ (WalkChecksAppMacs /\ log[i].kind \in AppKinds => MacOk(i))

-----------------------------------------------------------------------------
(* Heartbeats, as a read of them finds them *)

\* A row a read of beats finds: one hidden is not.
IsBeat(i) == log[i].kind = "beat" /\ ~log[i].hidden

NewestBeat == LET s == {i \in 1..Len(log) : IsBeat(i)} IN IF s = {} THEN 0 ELSE CHOOSE i \in s : \A j \in s : j <= i

\* What a beat says, as its row says it now: one forged claims a clean
\* walk to where the log was then.
Forged(i) == log[i].edited # 0 /\ log[i].claims > 0
SaysBroken(i) == log[i].broken /\ ~Forged(i)
Point(i) == IF Forged(i) THEN [at |-> log[i].claims, ver |-> log[i].claimsVer] ELSE [at |-> log[i].verified, ver |-> log[i].vver]

First == [at |-> 0, ver |-> 0]

\* Where a beat resumes (db audit.ts, resumePoint): what the newest beat
\* that is the app's says it verified, a broken one where its walk began;
\* and no further than where the walk of any broken one after that began.
\* A beat before the newest is not read again: the newest walked past it,
\* or began where a broken one did.
\* Beat b cleared what beat j found: a clean walk, in a snapshot that held
\* j's row, over the entry j found, from before it; or, j having found the
\* entry its walk began from changed, from there, its hash found again.
ClearedBy(b, j) ==
    /\ ~log[b].broken /\ log[b].head >= j
    /\ ClearsOverFault =>
         IF log[j].fault = log[j].verified
           THEN log[b].bfrom = log[j].verified /\ log[b].bfromVer = log[j].vver
           ELSE log[b].bfrom < log[j].fault /\ log[j].fault <= log[b].verified

\* No entry edited in place: the model's, for `Repair`'s progress, which
\* marks a beat that walked so (`calm`).
Calm == \A i \in 1..Len(log) : log[i].edited = 0

Own == {i \in 1..Len(log) : IsBeat(i) /\ (CursorByMac => MacOk(i) /\ Point(i).at < i)}

\* The newest beat that is the app's, 0 for none.
NewestOwn == IF Own = {} THEN 0 ELSE CHOOSE i \in Own : \A j \in Own : j <= i

Resume ==
    LET own == Own
        b == NewestOwn
        c == IF b = 0 THEN First ELSE Point(b)
        finders == IF NoResumePastFinding THEN {j \in own : j > c.at /\ SaysBroken(j) /\ ~(Clears /\ \E k \in own : ClearedBy(k, j))} ELSE {}
        lowest == {Point(j) : j \in finders} \cup {c}
    IN CHOOSE r \in lowest : \A q \in lowest : r.at <= q.at

\* A walk from a point, as a heartbeat's (db audit.ts, walkChain): at most
\* Walk entries, each link and hash, and the app's MACs; where it got to,
\* and the first fault.
WalkFrom(r) ==
    LET to == IF Len(log) - r.at > Walk THEN r.at + Walk ELSE Len(log)
        ok == (WalkChecksFrom => Carries(r.at, r.ver)) /\ AppWalkOk(r.at, to)
        faults == {i \in Seqs(r.at, to) : ~HashOk(i) \/ (WalkChecksAppMacs /\ log[i].kind \in AppKinds /\ ~MacOk(i))}
        fault == IF WalkChecksFrom /\ ~Carries(r.at, r.ver) THEN r.at
                 ELSE IF faults = {} THEN 0 ELSE CHOOSE i \in faults : \A j \in faults : i <= j
    IN [ok |-> ok, to |-> to, done |-> to = Len(log), fault |-> fault]

\* Readiness as the rows say now (server heartbeat.ts, auditReadiness):
\* the newest beat the app's, saying the chain verified, and a checkpoint
\* after it; and the next beat's walk, run now, finds nothing and reaches
\* the head. A heartbeat's age is left out.
ReadyWith(b, c) ==
    /\ b > 0 /\ c > 0
    /\ MacOk(b) /\ ~log[b].broken /\ ~log[b].short
    /\ log[c].at >= b
DryRunOk == ReadinessWalks => LET w == WalkFrom(Resume) IN w.ok /\ w.done
ReadyNow == ReadyWith(NewestBeat, Signed) /\ DryRunOk

-----------------------------------------------------------------------------
(* Processes *)

NoOp == [kind |-> "none", at |-> 0]
L0 == [from |-> 0, fromVer |-> 0, to |-> 0, toVer |-> 0, ok |-> TRUE, seen |-> 0, bhead |-> 0, calm |-> FALSE,
       sfrom |-> 0, slap |-> 0, slapEnd |-> 0, slapVer |-> 0, sok |-> TRUE, beat |-> 0, ready |-> FALSE,
       done |-> TRUE, after |-> FALSE, fault |-> 0, fEdit |-> 0]

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
                      [] o.kind \in {"beat", "beatonly"} -> "beat.attest"
                      [] o.kind = "probe" -> "probe.beat"
                      [] o.kind \in {"rewrite", "edit", "hide", "forge", "revert"} -> "tamper")
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<log, head, tampered, history>>

TakeHead(p, then) ==
    /\ head \in {None, p}
    /\ head' = p
    /\ Goto(p, then)
    /\ UNCHANGED <<log, tampered, op, l, left, history>>

Read(p, then, locals) ==
    /\ Goto(p, then)
    /\ l' = [l EXCEPT ![p] = locals]
    /\ UNCHANGED <<log, head, tampered, op, left, history>>

-----------------------------------------------------------------------------
(* Requests append the app's entries and the vault's, under the head. *)

AppendHead(p) == pc[p] = "append.head" /\ TakeHead(p, "append.commit")

AppendCommit(p) ==
    /\ pc[p] = "append.commit"
    /\ IF Len(log) < MaxLen THEN Add(E(op[p].kind)) ELSE UNCHANGED log
    /\ head' = None
    /\ Goto(p, "idle")
    /\ UNCHANGED <<tampered, op, l, left, history>>

-----------------------------------------------------------------------------
(* Someone who writes the database: an entry edited in place, a heartbeat
   row hidden or forged, and put back, as often as they like; or once, one
   rewritten and the chain after it, and the head row, hashed again. *)

Tamper(p) ==
    /\ pc[p] = "tamper"
    /\ (op[p].kind = "rewrite" => tampered.kind = "none")
    /\ LET targets == {i \in (IF op[p].at = 0 THEN 1..Len(log) ELSE {op[p].at}) :
                          i <= Len(log) /\ (op[p].kind \in {"hide", "forge"} => log[i].kind = "beat")}
       IN \/ targets = {} /\ UNCHANGED <<log, tampered>>
          \/ \E i \in targets :
                /\ CASE op[p].kind = "edit" -> log' = [log EXCEPT ![i].edited = tampered.n + 1]
                     [] op[p].kind = "hide" -> log' = [log EXCEPT ![i].edited = tampered.n + 1, ![i].hidden = TRUE]
                     [] op[p].kind = "forge" -> log' = [log EXCEPT ![i].edited = tampered.n + 1, ![i].claims = Len(log), ![i].claimsVer = Ver]
                     [] op[p].kind = "revert" -> log' = [log EXCEPT ![i].edited = 0, ![i].hidden = FALSE, ![i].claims = 0]
                     [] OTHER -> log' = [j \in 1..Len(log) |-> IF j < i THEN log[j]
                                                        ELSE [log[j] EXCEPT !.ver = @ + 1, !.forged = (j = i) \/ @]]
                /\ tampered' = IF op[p].kind = "revert" THEN tampered ELSE [kind |-> IF op[p].kind = "rewrite" THEN "rewrite" ELSE "edit", at |-> i, n |-> tampered.n + 1]
    /\ Goto(p, "idle")
    /\ UNCHANGED <<head, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A heartbeat (server heartbeat.ts, writeAuditHeartbeat): where the app   *)
(* verified the chain to, the walk from there, the beat, then the vault's  *)
(* checkpoint.                                                             *)
(***************************************************************************)

\* Where to resume, and the walk from there, in one snapshot; or, without
\* it, where to resume in one and the walk in the next.
BeatAttest(p) ==
    /\ pc[p] = "beat.attest"
    /\ LET r == Resume
           w == WalkFrom(r)
       IN IF OneSnapshot
            THEN Read(p, "beat.head", [l[p] EXCEPT !.from = r.at, !.fromVer = r.ver, !.ok = w.ok, !.fault = w.fault,
                                                    !.bhead = IF w.ok /\ w.to > NewestOwn THEN w.to ELSE NewestOwn, !.calm = Calm,
                                                    !.fEdit = IF w.fault = 0 THEN 0 ELSE log[w.fault].edited,
                                                    !.to = w.to, !.toVer = IF w.to = 0 THEN 0 ELSE log[w.to].ver, !.done = w.done,
                                                    !.after = tampered.kind = "rewrite"])
            ELSE Read(p, "beat.walk", [l[p] EXCEPT !.from = r.at, !.fromVer = r.ver, !.bhead = NewestOwn])

BeatWalk(p) ==
    /\ pc[p] = "beat.walk"
    /\ LET w == WalkFrom([at |-> l[p].from, ver |-> l[p].fromVer])
       IN Read(p, "beat.head", [l[p] EXCEPT !.ok = w.ok, !.fault = w.fault, !.fEdit = IF w.fault = 0 THEN 0 ELSE log[w.fault].edited,
                                             !.bhead = IF w.ok /\ w.to > l[p].bhead THEN w.to ELSE l[p].bhead, !.calm = Calm,
                                             !.to = w.to, !.toVer = IF w.to = 0 THEN 0 ELSE log[w.to].ver, !.done = w.done,
                                             !.after = tampered.kind = "rewrite"])

BeatHead(p) == pc[p] = "beat.head" /\ TakeHead(p, "beat.commit")

\* The beat: how far it verified, or, if the walk found the chain broken,
\* where it began and what it found; or that it stopped short of the head
\* (`unverified`). Readiness reads either as red. Whether a rewrite came
\* before its walk is the model's, for the invariants, and so is what it
\* found (`found`). A beat whose checkpoint is left out ("beatonly") keeps
\* the scenarios small.
BeatCommit(p) ==
    /\ pc[p] = "beat.commit"
    /\ Len(log) < MaxLen
    /\ Add([E("beat") EXCEPT !.verified = IF l[p].ok THEN l[p].to ELSE l[p].from,
                             !.vver = IF l[p].ok THEN l[p].toVer ELSE l[p].fromVer,
                             !.fault = IF l[p].ok THEN 0 ELSE l[p].fault, !.fEdit = IF l[p].ok THEN 0 ELSE l[p].fEdit,
                             !.broken = ~l[p].ok, !.short = l[p].ok /\ ~l[p].done, !.walked = l[p].after,
                             !.bfrom = l[p].from, !.bfromVer = l[p].fromVer, !.head = l[p].bhead, !.calm = l[p].calm])
    /\ history' = [history EXCEPT !.found = @ \cup (IF ~l[p].ok /\ l[p].fEdit # 0 THEN {<<l[p].fault, l[p].fEdit>>} ELSE {})]
    /\ head' = None
    /\ Goto(p, IF op[p].kind = "beatonly" THEN "idle" ELSE "ckpt.snapshot")
    /\ UNCHANGED <<tampered, op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A checkpoint (vault vault.ts, checkpoint): a walk from the newest one in *)
(* a snapshot, a stretch of the scrub in another, then, under the head,    *)
(* the rest and the signature.                                             *)
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
           Idle == /\ head' = None /\ Goto(p, "idle") /\ UNCHANGED <<log, tampered, op, l, left, history>>
           Deny == /\ head' = None /\ Goto(p, "ckpt.deny") /\ UNCHANGED <<log, tampered, op, l, left, history>>
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
                        /\ Goto(p, "idle")
                        /\ UNCHANGED <<tampered, op, l, left>>

\* The refusal's entry, `log_broken`, in a transaction of its own.
CkptDenyHead(p) == pc[p] = "ckpt.deny" /\ TakeHead(p, "ckpt.denied")

CkptDenied(p) ==
    /\ pc[p] = "ckpt.denied"
    /\ IF Len(log) < MaxLen THEN Add(E("deny")) ELSE UNCHANGED log
    /\ head' = None
    /\ Goto(p, "idle")
    /\ UNCHANGED <<tampered, op, l, left, history>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Readiness, as a monitor asks it (server heartbeat.ts, auditReadiness;   *)
(* db queries.ts, readiness): the newest beat, then the newest checkpoint. *)
(***************************************************************************)

ProbeBeat(p) ==
    /\ pc[p] = "probe.beat"
    /\ IF ReadinessInOneSnapshot
         THEN /\ history' = [history EXCEPT !.greens = @ \cup (IF ReadyNow THEN {[real |-> TRUE]} ELSE {})]
              /\ Goto(p, "idle")
              /\ UNCHANGED <<log, head, tampered, op, l, left>>
         ELSE Read(p, "probe.ckpt", [l[p] EXCEPT !.beat = NewestBeat, !.ready = ReadyNow])

\* Green on the beat it read, and the checkpoint and the walk it reads now;
\* real if the rows said so, together, at either read, or as that
\* checkpoint was signed, after the first read: with the newest beat then.
ProbeCkpt(p) ==
    /\ pc[p] = "probe.ckpt"
    /\ LET then == {i \in 1..Signed : log[i].kind = "beat"}
           beatThen == IF then = {} THEN 0 ELSE CHOOSE i \in then : \A j \in then : j <= i
       IN history' = [history EXCEPT !.greens = @ \cup (IF ReadyWith(l[p].beat, Signed) /\ DryRunOk
                                                        THEN {[real |-> l[p].ready \/ ReadyNow \/ (ReadyWith(beatThen, Signed) /\ DryRunOk)]}
                                                        ELSE {})]
    /\ Goto(p, "idle")
    /\ UNCHANGED <<log, head, tampered, op, l, left>>

-----------------------------------------------------------------------------

Init ==
    /\ log = InitLog
    /\ head = None
    /\ tampered = [kind |-> "none", at |-> 0, n |-> 0]
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ history = [signedBad |-> FALSE, signedAfterDeny |-> FALSE, signedAfterEdit |-> 0, greens |-> {},
                   \* What the beats the log starts with found, and still holds.
                   found |-> {<<InitLog[i].fault, InitLog[i].fEdit>> : i \in {j \in 1..Len(InitLog) : InitLog[j].kind = "beat" /\ InitLog[j].broken /\ InitLog[j].fEdit # 0}}]

Step(p) ==
    \/ Begin(p) \/ AppendHead(p) \/ AppendCommit(p) \/ Tamper(p)
    \/ BeatAttest(p) \/ BeatWalk(p) \/ BeatHead(p) \/ BeatCommit(p)
    \/ CkptSnapshot(p) \/ CkptScrub(p) \/ CkptHead(p) \/ CkptCommit(p) \/ CkptDenyHead(p) \/ CkptDenied(p)
    \/ ProbeBeat(p) \/ ProbeCkpt(p)

\* A beat past the log's bound ends the run there.
Stuck(p) == pc[p] = "beat.commit" /\ Len(log) >= MaxLen

Finished == \A p \in Procs : (pc[p] = "idle" /\ left[p] = 0) \/ Stuck(p)

Next == (\E p \in Procs : Step(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK == head \in Procs \cup {None}

\* The vault never signs a prefix holding an entry of its own rewritten, or
\* chained after a rewrite. One edited in place between its walk and its
\* signature it does sign: the scrub finds it (`EditFoundByNextScrub`).
SignsNoForgedVault == ~history.signedBad

\* Once a checkpoint was refused for a broken log, none is signed while
\* the vault could find the tamper: each call finds it again, or sees the
\* refusal stand. One it cannot find, the app's, it signs over; the app's
\* walk keeps readiness red (`FoundStaysRed`).
StaysUnsignedOnceFound == ~history.signedAfterDeny

\* Once a heartbeat found the chain broken, readiness is red from then on,
\* against someone who writes once: the tamper stays, and every beat after
\* finds it again. A refusal of the vault's stands only until it signs
\* again, over an app entry it cannot check: then the next beat finds it.
FoundStaysRed ==
    (\E i \in 1..Len(log) : log[i].kind = "beat" /\ MacOk(i) /\ log[i].broken) => ~ReadyNow

\* And against someone who writes again, edits, hides, forges and puts
\* back: while an edit any beat found is still in place, readiness is red,
\* whatever has become of that beat's row since. Edited again after a
\* revert, it is a new edit behind every cursor, which the scrub finds
\* (`EditFoundByNextScrub`).
FoundEditStaysRed ==
    (\E f \in history.found : log[f[1]].edited = f[2]) => ~ReadyNow

\* A heartbeat whose walk came after a rewrite is never green: it finds the
\* rewrite, or the vault refuses to sign past it.
RewriteNeverGreen == (ReadyNow => ~log[NewestBeat].walked)

\* An entry edited in place is found by the next checkpoint whose scrub
\* starts after it: one in flight may still sign, none after. With a
\* scrub of the whole prefix a call, as the scenarios run it; with
\* `walks.scrub` entries a call, within two laps (docs/formal.md).
EditFoundByNextScrub == history.signedAfterEdit <= 1

\* Readiness answers green only on rows that said so together.
GreenIsReal == \A g \in history.greens : g.real

=============================================================================
