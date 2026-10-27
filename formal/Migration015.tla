---------------------------- MODULE Migration015 ----------------------------
(***************************************************************************)
(* The cutover from 0.14's log to 0.15's (0.15-plan.md, section 9).        *)
(*                                                                         *)
(* One object, a decision input (a member with its grants): it allows or   *)
(* refuses. Its row holds that value, the 0.14 entry it names              *)
(* (`access_seq`) and 0.14's MAC over it (`mac14`). Postgres is one        *)
(* database that both versions share while old isolates still serve.     *)
(*                                                                         *)
(* 0.14 (old isolates, still serving after the deploy):                    *)
(*   - its log is a chain of entries under one head lock, each with the    *)
(*     vault's MAC; only writes are kept here (its uses' entries name no   *)
(*     input);                                                             *)
(*   - a row is as 0.14 wants it when its MAC holds and it names the       *)
(*     newest authentic write (vault.ts, `#integrity`);                    *)
(*   - a write takes the head, checks the row, writes it, appends its      *)
(*     entry and advances the object's fence (`access_seq`), commits and   *)
(*     answers;                                                            *)
(*   - a use reads the row and the fence, then under the head refuses if   *)
(*     the fence moved, else appends and commits. (0.14 does this with the *)
(*     member's row locked shared, which a write waits for; the re-check   *)
(*     is the same guarantee, stated optimistically.)                      *)
(*                                                                         *)
(* 0.15 (HotPathOne.tla's fence, abstracted): an advisory lock, uses       *)
(* shared, changes exclusive; numbers from one sequence under it; each     *)
(* sealing entry seals the row to its content; a use is `stale` (refused)  *)
(* unless the row is the newest sealing entry's content.                   *)
(*                                                                         *)
(* The cutover, at a 0.15 vault's start: if the marker (the `cutover`      *)
(* entry) is there, nothing. Else it takes 0.14's head, then the fence,    *)
(* looks for the marker again, verifies 0.14's chain to its head, checks   *)
(* the row as 0.14 would, and writes `genesis` (sealing the row) and       *)
(* `cutover` (naming the head). Old isolates keep writing; each later      *)
(* write leaves a row no 0.15 entry sealed, which the checkpointer's tick  *)
(* adopts: an `adopt` entry citing each 0.14 write after the anchor.      *)
(*                                                                         *)
(* A database writer without the keys may put back an older row or write  *)
(* one of its own (MaxTampers), or forge a 0.14 entry and the row it names *)
(* (MaxForges): neither carries a valid MAC.                               *)
(*                                                                         *)
(* The protections, each a constant (scripts/formal.sh turns each off):    *)
(*   CutoverHeadLock  the cutover holds 0.14's head lock;                  *)
(*   CutoverFence     ... and the 0.15 fence exclusive;                    *)
(*   Marker           ... and under them, does nothing if the marker is    *)
(*                    there;                                               *)
(*   VerifyChain      ... verifies every 0.14 entry up to the head it      *)
(*                    anchors;                                             *)
(*   VerifyRows       ... and seals the row only if 0.14 would accept it   *)
(*                    (its MAC, and it names the newest authentic write);  *)
(*   DualFence        a 0.15 change also takes 0.14's head and advances    *)
(*                    0.14's fence (a mirror entry, the row's access_seq   *)
(*                    and MAC), until 0.16;                                *)
(*   ChangeHeadFirst  ... taking 0.14's head before the fence, as the      *)
(*                    cutover and 0.14's writes do;                        *)
(*   OldWritesFence   a trigger the migration adds to 0.14's audit_log     *)
(*                    takes the fence exclusive in every 0.14 append that  *)
(*                    changes access (WHEN on its kind; a 0.14 use's       *)
(*                    `credential.use` passes freely), so a 0.14 write     *)
(*                    waits for 0.15 uses in flight (not in the plan:      *)
(*                    this model's finding);                               *)
(*   Adopt            the tick adopts 0.14's writes after the anchor;      *)
(*   AdoptRepeats     ... at every tick, not only the first;               *)
(*   AdoptVerifies    ... only entries whose MAC holds;                    *)
(*   AdoptSealsEntry  ... and seals what 0.14's newest authentic write     *)
(*                    wrote, when that write is the one adopted, whatever  *)
(*                    the row holds: never the row as it finds it;         *)
(*   AdoptAfterSeal   ... only if it is numbered after the 0.14 entry the  *)
(*                    newest seal names: never a write a 0.15 change came  *)
(*                    after, even once the writer deleted that change's    *)
(*                    mirror entry (MaxDrops);                             *)
(*   UsesSeeOldWrites a 0.15 use also reads the object's newest authentic  *)
(*                    0.14 write, and is `stale` while the new log does    *)
(*                    not account for it (the anchor, a mirror or an       *)
(*                    adoption), until 0.16 (not in the plan: this model's *)
(*                    finding): one index probe of audit_log per use;      *)
(*   OldWriteMarksRow the cheaper alternative, without the probe: the      *)
(*                    trigger marks the row with the 0.14 entry's number,  *)
(*                    and a use is `stale` while the mark is past what the *)
(*                    newest seal accounts for. The writer can clear the   *)
(*                    mark (MaxClears): then it holds no better than no    *)
(*                    check at all, as nothing it cannot write backs it.   *)
(*                                                                         *)
(* Some cover for each other. The head lock and the fence each serialize   *)
(* two cutovers. A 0.14 write racing the cutover without its head lock is  *)
(* caught by VerifyRows (the cutover refuses: the head lock is then for    *)
(* progress) and by OldWritesFence (it waits for the fence): TLC finds the *)
(* race only with all three off.                                           *)
(*                                                                         *)
(* "Every 0.14 write ends up in the new log" is checked as an invariant at *)
(* each tick (EveryOldWriteAdopted: what 0.14 had written when a tick ran, *)
(* that tick adopted), which implies the eventual form under a fair tick.  *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Olds,            \* old (0.14) isolates' request processes
    MaxOldOps,       \* requests each makes: uses or writes
    Vaults,          \* 0.15 vault starts (two at once, or one after another: a restart)
    NewUsers,        \* 0.15 use processes
    MaxNewUses,      \* uses each makes
    NewChangers,     \* 0.15 change processes
    MaxNewChanges,   \* changes each makes
    MaxTicks,        \* checkpointer ticks
    MaxTampers,      \* rows the database writer puts there
    MaxForges,       \* 0.14 entries it forges
    MaxClears,       \* marks it clears (OldWriteMarksRow)
    MaxDrops,        \* 0.14 entries it deletes, or edits past their MAC
    CutoverHeadLock, CutoverFence, Marker, VerifyChain, VerifyRows,
    DualFence, ChangeHeadFirst, OldWritesFence,
    Adopt, AdoptRepeats, AdoptVerifies, AdoptSealsEntry, AdoptAfterSeal, UsesSeeOldWrites, OldWriteMarksRow

None == "none"

VARIABLES
    oldLog,    \* 0.14's chain: its writes, in order; seq = index. [v, mac (authentic), mirror (a 0.15 change's)]
    row,       \* the object's row: [v, aseq (the 0.14 entry it names), mac14 (0.14's MAC holds)]
    fence14,   \* 0.14's fence for the object (access_seq's role): each write advances it
    head,      \* 0.14's head lock: its holder, or None
    fx,        \* the 0.15 fence held exclusive: its holder, or None
    fs,        \* ... held shared
    newLog,    \* 0.15's committed entries: [seq, kind, seals, content, cites]
    nextSeq,   \* 0.15's sequence
    o,         \* each old process
    vs,        \* each vault start
    nu,        \* each 0.15 use process
    nc,        \* each 0.15 change process
    ticks,     \* checkpointer ticks so far
    lastTick,  \* 0.14's head at the last tick (0: none yet)
    tampers, forges,
    truth,     \* ghost: the object as its legitimate writers (0.14's and 0.15's) left it, and whose write it was
    committed, \* ghost: legitimate writes committed, old and new
    answered,  \* ghost: how many had committed when the latest one answered
    decisions  \* ghost: each use's outcome, old and new

vars == <<oldLog, row, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, tampers, forges,
          truth, committed, answered, decisions>>

-----------------------------------------------------------------------------
(* Helpers. *)

Max(S) == CHOOSE m \in S : \A s \in S : s <= m
Content(r) == [v |-> r.v, aseq |-> r.aseq]

\* 0.14's newest authentic write at or below k, and the object as it left it (all start allowing).
NewestGenuine(k) == Max({i \in 1..k : oldLog[i].mac} \cup {0})
Content14At(k) == LET i == NewestGenuine(k) IN [v |-> IF i = 0 THEN TRUE ELSE oldLog[i].v, aseq |-> i]
\* The row as 0.14 accepts it: its MAC holds and it names the newest authentic write.
Genuine14(r) == r.mac14 /\ r.aseq = NewestGenuine(Len(oldLog))

\* The content of 0.15's newest sealing entry numbered below s.
SealBelow(s) ==
    LET es == {e \in newLog : e.seals /\ e.seq < s}
    IN IF es = {} THEN [some |-> FALSE, content |-> [v |-> FALSE, aseq |-> 0]]
       ELSE [some |-> TRUE, content |-> (CHOOSE e \in es : \A d \in es : d.seq <= e.seq).content]

Cutovers == {e \in newLog : e.kind = "cutover"}
\* The anchor: the head the (first) cutover named.
Anchor == IF Cutovers = {} THEN 0 ELSE (CHOOSE e \in Cutovers : \A d \in Cutovers : e.seq <= d.seq).cites
Cited == {e.cites : e \in {d \in newLog : d.kind = "adopt"}}
Started == \E v \in Vaults : vs[v].pc = "started"
FenceFree == fx = None /\ fs = {}

Entry(seq, kind, seals, content, cites) == [seq |-> seq, kind |-> kind, seals |-> seals, content |-> content, cites |-> cites]
NoContent == [v |-> FALSE, aseq |-> 0]
Truth0 == [v |-> TRUE, by |-> "0.14"]

Answer == answered' = IF answered > committed' THEN answered ELSE committed'

Init ==
    /\ oldLog = <<>>
    /\ row = [v |-> TRUE, aseq |-> 0, mac14 |-> TRUE, mark |-> 0]
    /\ fence14 = 0
    /\ head = None
    /\ fx = None
    /\ fs = {}
    /\ newLog = {}
    /\ nextSeq = 1
    /\ o = [x \in Olds |-> [pc |-> "idle", n |-> 0, v |-> FALSE, fence |-> 0, allow |-> FALSE, seen |-> 0, truth |-> Truth0]]
    /\ vs = [v \in Vaults |-> [pc |-> "idle", anchor |-> 0]]
    /\ nu = [x \in NewUsers |-> [pc |-> "idle", n |-> 0, seq |-> 0, allow |-> FALSE, read |-> NoContent, seen |-> 0, truth |-> Truth0]]
    /\ nc = [h \in NewChangers |-> [pc |-> "idle", n |-> 0, read |-> NoContent, v |-> FALSE]]
    /\ ticks = 0
    /\ lastTick = 0
    /\ tampers = [rows |-> 0, clears |-> 0, drops |-> 0]
    /\ forges = 0
    /\ truth = Truth0
    /\ committed = 0
    /\ answered = 0
    /\ decisions = {}

-----------------------------------------------------------------------------
(* 0.14, on old isolates. *)

\* A use reads the row and the object's fence, outside the head.
OldUseRead(x) ==
    /\ o[x].pc = "idle"
    /\ o[x].n < MaxOldOps
    /\ o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "read", !.fence = fence14, !.allow = row.v /\ Genuine14(row),
                                         !.seen = committed, !.truth = truth]]
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, fs, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

\* Under the head: refused if the fence moved; appends and commits. The value leaves after. Its
\* entry (`credential.use`) changes no access, so the trigger lets it by: it never waits for the
\* 0.15 fence.
OldUseCommit(x) ==
    /\ o[x].pc = "read"
    /\ head = None
    /\ decisions' = decisions \cup {[ver |-> "0.14", allow |-> o[x].allow /\ fence14 = o[x].fence, seen |-> o[x].seen,
                                     answeredAt |-> answered, truth |-> o[x].truth, read |-> NoContent, seq |-> 0]}
    /\ o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, fs, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered>>

\* A write (a grant or a revoke) takes the head.
OldWriteHead(x) ==
    /\ o[x].pc = "idle"
    /\ o[x].n < MaxOldOps
    /\ head = None
    /\ head' = x
    /\ \E v \in BOOLEAN : o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "headed", !.v = v]]
    /\ UNCHANGED <<oldLog, row, fence14, fx, fs, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

\* Its append (an access entry: with the trigger, once the fence is free; with OldWriteMarksRow,
\* the trigger also marks the row with the entry's number), its row, its fence; commit and answer.
\* A row 0.14 does not accept refuses it.
OldWriteCommit(x) ==
    /\ o[x].pc = "headed"
    /\ OldWritesFence => FenceFree
    /\ IF Genuine14(row)
       THEN /\ oldLog' = Append(oldLog, [v |-> o[x].v, mac |-> TRUE, mirror |-> FALSE])
            /\ row' = [v |-> o[x].v, aseq |-> Len(oldLog) + 1, mac14 |-> TRUE,
                        mark |-> IF OldWriteMarksRow THEN Len(oldLog) + 1 ELSE row.mark]
            /\ fence14' = fence14 + 1
            /\ truth' = [v |-> o[x].v, by |-> "0.14"]
            /\ committed' = committed + 1
            /\ Answer
       ELSE UNCHANGED <<oldLog, row, fence14, truth, committed, answered>>
    /\ head' = None
    /\ o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<fx, fs, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges, decisions>>

-----------------------------------------------------------------------------
(* A 0.15 vault's start: the cutover. *)

\* The marker seen without any lock: nothing to do. Else, to the locks.
VaultStart(v) ==
    /\ vs[v].pc = "idle"
    /\ vs' = [vs EXCEPT ![v].pc = IF Cutovers /= {} THEN "started" ELSE "locking"]
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, fs, newLog, nextSeq, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

VaultHead(v) ==
    /\ vs[v].pc = "locking"
    /\ CutoverHeadLock => head = None
    /\ head' = IF CutoverHeadLock THEN v ELSE head
    /\ vs' = [vs EXCEPT ![v].pc = "headed"]
    /\ UNCHANGED <<oldLog, row, fence14, fx, fs, newLog, nextSeq, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

VaultFence(v) ==
    /\ vs[v].pc = "headed"
    /\ CutoverFence => FenceFree
    /\ fx' = IF CutoverFence THEN v ELSE fx
    /\ vs' = [vs EXCEPT ![v].pc = "locked"]
    /\ UNCHANGED <<oldLog, row, fence14, head, fs, newLog, nextSeq, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

Unlock(p) ==
    /\ head' = IF head = p THEN None ELSE head
    /\ fx' = IF fx = p THEN None ELSE fx

\* The marker again, under the locks; then 0.14's head, and its chain verified up to it.
VaultVerify(v) ==
    /\ vs[v].pc = "locked"
    /\ IF Marker /\ Cutovers /= {}
       THEN /\ vs' = [vs EXCEPT ![v].pc = "started"]
            /\ Unlock(v)
       ELSE IF VerifyChain /\ \E i \in 1..Len(oldLog) : ~oldLog[i].mac
       THEN /\ vs' = [vs EXCEPT ![v].pc = "refused"]
            /\ Unlock(v)
       ELSE /\ vs' = [vs EXCEPT ![v] = [pc |-> "verified", anchor |-> Len(oldLog)]]
            /\ UNCHANGED <<head, fx>>
    /\ UNCHANGED <<oldLog, row, fence14, fs, newLog, nextSeq, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

\* A statement of its own: the row, checked as 0.14 would against the chain it verified; `genesis`
\* sealing it, `cutover` naming the head; the commit lets the locks go.
VaultSeal(v) ==
    /\ vs[v].pc = "verified"
    /\ IF VerifyRows /\ ~(row.mac14 /\ row.aseq = NewestGenuine(vs[v].anchor))
       THEN /\ vs' = [vs EXCEPT ![v].pc = "refused"]
            /\ UNCHANGED <<newLog, nextSeq>>
       ELSE /\ newLog' = newLog \cup {Entry(nextSeq, "genesis", TRUE, Content(row), vs[v].anchor),
                                      Entry(nextSeq + 1, "cutover", FALSE, NoContent, vs[v].anchor)}
            /\ nextSeq' = nextSeq + 2
            /\ vs' = [vs EXCEPT ![v].pc = "started"]
    /\ Unlock(v)
    /\ UNCHANGED <<oldLog, row, fence14, fs, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

-----------------------------------------------------------------------------
(* 0.15 uses, on a started vault. *)

NewUseLock(x) ==
    /\ nu[x].pc = "idle"
    /\ nu[x].n < MaxNewUses
    /\ Started
    /\ fx = None
    /\ fs' = fs \cup {x}
    /\ nu' = [nu EXCEPT ![x].pc = "locked"]
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, newLog, nextSeq, o, vs, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

\* Whether the new log accounts for 0.14's newest authentic write: at or below the anchor, 0.15's
\* own mirror, or adopted.
Accounted ==
    LET i == NewestGenuine(Len(oldLog)) IN i <= Anchor \/ oldLog[i].mirror \/ i \in Cited

\* One statement: the row and the newest seal; `stale` unless the row is it; its number.
NewUseRun(x) ==
    /\ nu[x].pc = "locked"
    /\ LET s == SealBelow(nextSeq)
           ok == /\ s.some /\ s.content = Content(row)
                 /\ UsesSeeOldWrites => Accounted
                 /\ OldWriteMarksRow => row.mark <= s.content.aseq
       IN nu' = [nu EXCEPT ![x] = [@ EXCEPT !.pc = "ran", !.seq = nextSeq, !.allow = ok /\ row.v,
                                             !.read = Content(row), !.seen = committed, !.truth = truth]]
    /\ nextSeq' = nextSeq + 1
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, fs, newLog, o, vs, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

\* The commit, which lets the lock go. Its value leaves after.
NewUseCommit(x) ==
    /\ nu[x].pc = "ran"
    /\ newLog' = newLog \cup {Entry(nu[x].seq, "use", FALSE, NoContent, 0)}
    /\ decisions' = decisions \cup {[ver |-> "0.15", allow |-> nu[x].allow, seen |-> nu[x].seen, answeredAt |-> answered,
                                     truth |-> nu[x].truth, read |-> nu[x].read, seq |-> nu[x].seq]}
    /\ fs' = fs \ {x}
    /\ nu' = [nu EXCEPT ![x] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, nextSeq, o, vs, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered>>

-----------------------------------------------------------------------------
(* 0.15 changes: a grant or a revoke, written as logged. *)

\* The row is read outside the locks.
NewChangeStart(h) ==
    /\ nc[h].pc = "idle"
    /\ nc[h].n < MaxNewChanges
    /\ Started
    /\ \E v \in BOOLEAN : nc' = [nc EXCEPT ![h] = [@ EXCEPT !.pc = "started", !.read = Content(row), !.v = v]]
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

\* Its locks, one at a time: the fence; with DualFence, 0.14's head too, first or second.
Take(h, lock) ==
    IF lock = "head"
    THEN /\ head = None /\ head' = h /\ UNCHANGED <<fx, fs>>
    ELSE /\ FenceFree /\ fx' = h /\ UNCHANGED <<head, fs>>
FirstLock == IF DualFence /\ ChangeHeadFirst THEN "head" ELSE "fence"
SecondLock == IF FirstLock = "head" THEN "fence" ELSE "head"

NewChangeLock1(h) ==
    /\ nc[h].pc = "started"
    /\ Take(h, FirstLock)
    /\ nc' = [nc EXCEPT ![h].pc = IF DualFence THEN "first" ELSE "locked"]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, o, vs, nu, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

NewChangeLock2(h) ==
    /\ nc[h].pc = "first"
    /\ Take(h, SecondLock)
    /\ nc' = [nc EXCEPT ![h].pc = "locked"]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, o, vs, nu, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions>>

\* The CAS (the row is still the one it read, else it reads again); the write, sealed by its
\* entry. With DualFence, also 0.14's: a mirror entry, the row naming it under 0.14's MAC, the
\* fence advanced. Without, 0.14's MAC no longer holds over the row. The commit lets the locks go.
NewChangeRun(h) ==
    /\ nc[h].pc = "locked"
    /\ IF Content(row) /= nc[h].read
       THEN /\ nc' = [nc EXCEPT ![h].pc = "idle"]
            /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, truth, committed>>
       ELSE LET aseq == IF DualFence THEN Len(oldLog) + 1 ELSE row.aseq
                new == [v |-> nc[h].v, aseq |-> aseq, mac14 |-> DualFence, mark |-> row.mark]
            IN /\ oldLog' = IF DualFence THEN Append(oldLog, [v |-> nc[h].v, mac |-> TRUE, mirror |-> TRUE]) ELSE oldLog
               /\ fence14' = IF DualFence THEN fence14 + 1 ELSE fence14
               /\ row' = new
               /\ newLog' = newLog \cup {Entry(nextSeq, "change", TRUE, Content(new), 0)}
               /\ nextSeq' = nextSeq + 1
               /\ truth' = [v |-> nc[h].v, by |-> "0.15"]
               /\ committed' = committed + 1
               /\ nc' = [nc EXCEPT ![h].pc = "committed"]
    /\ Unlock(h)
    /\ UNCHANGED <<fs, o, vs, nu, ticks, lastTick, tampers, forges, answered, decisions>>

NewChangeAnswer(h) ==
    /\ nc[h].pc = "committed"
    /\ answered' = IF answered > committed THEN answered ELSE committed
    /\ nc' = [nc EXCEPT ![h] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, ticks, lastTick, tampers, forges,
                   truth, committed, decisions>>

-----------------------------------------------------------------------------
(* The checkpointer's tick, on a started vault, under both locks: it adopts 0.14's writes after  *)
(* the anchor that no `adopt` cites yet, skipping 0.15's own mirror entries, one `adopt` each, in *)
(* 0.14's order. One seals: with AdoptSealsEntry, the one that is 0.14's newest authentic write,  *)
(* with what it wrote (a row put back is then stale), if no seal names a later 0.14 entry (a 0.15 *)
(* change's mirror, which a writer may have deleted); without, the newest, with the row as found. *)

Tick ==
    /\ Started
    /\ ticks < MaxTicks
    /\ head = None /\ FenceFree
    /\ LET todo == {i \in (Anchor + 1)..Len(oldLog) :
                       ~oldLog[i].mirror /\ i \notin Cited /\ (AdoptVerifies => oldLog[i].mac)}
           adopting == Adopt /\ (ticks = 0 \/ AdoptRepeats) /\ todo /= {}
           rank(i) == Cardinality({j \in todo : j < i})
           seals(i) == IF AdoptSealsEntry
                       THEN i = NewestGenuine(Len(oldLog)) /\ (AdoptAfterSeal => i > SealBelow(nextSeq).content.aseq)
                       ELSE i = Max(todo)
           content(i) == IF AdoptSealsEntry THEN [v |-> oldLog[i].v, aseq |-> i] ELSE Content(row)
       IN IF adopting
          THEN /\ newLog' = newLog \cup {Entry(nextSeq + rank(i), "adopt", seals(i), IF seals(i) THEN content(i) ELSE NoContent, i) : i \in todo}
               /\ nextSeq' = nextSeq + Cardinality(todo)
          ELSE UNCHANGED <<newLog, nextSeq>>
    /\ ticks' = ticks + 1
    /\ lastTick' = Len(oldLog)
    /\ UNCHANGED <<oldLog, row, fence14, head, fx, fs, o, vs, nu, nc, tampers, forges,
                   truth, committed, answered, decisions>>

-----------------------------------------------------------------------------
(* The database writer, without the keys. *)

\* It puts a row there: its own (granting), whose 0.14 MAC fails, or one the vault wrote once that
\* granted, put back.
TamperRow ==
    /\ tampers.rows < MaxTampers
    /\ \E r \in {[v |-> TRUE, aseq |-> row.aseq, mac14 |-> FALSE, mark |-> row.mark]}
                \cup {[v |-> TRUE, aseq |-> i, mac14 |-> TRUE, mark |-> row.mark] : i \in {j \in 1..Len(oldLog) : oldLog[j].mac /\ oldLog[j].v}}
                \cup {[v |-> TRUE, aseq |-> 0, mac14 |-> TRUE, mark |-> row.mark]} :
          /\ r /= row
          /\ row' = r
    /\ tampers' = [tampers EXCEPT !.rows = @ + 1]
    /\ UNCHANGED <<oldLog, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, forges,
                   truth, committed, answered, decisions>>

\* It clears the row's mark (OldWriteMarksRow): an unsigned column, like any other.
ClearMark ==
    /\ tampers.clears < MaxClears
    /\ row.mark /= 0
    /\ row' = [row EXCEPT !.mark = 0]
    /\ tampers' = [tampers EXCEPT !.clears = @ + 1]
    /\ UNCHANGED <<oldLog, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, forges,
                   truth, committed, answered, decisions>>

\* It deletes 0.14's newest entry, or edits it so that its MAC fails: 0.14's own checks, and a
\* probe of the newest authentic entry, then pass it over. (0.14's anchor, outside the database,
\* is what catches this; not modelled.)
DropNewest ==
    /\ tampers.drops < MaxDrops
    /\ Len(oldLog) > 0
    /\ oldLog' = [oldLog EXCEPT ![Len(oldLog)].mac = FALSE]
    /\ tampers' = [tampers EXCEPT !.drops = @ + 1]
    /\ UNCHANGED <<row, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, forges,
                   truth, committed, answered, decisions>>

\* It appends a 0.14 entry granting, and a row naming it: no MAC holds on either.
ForgeEntry ==
    /\ forges < MaxForges
    /\ oldLog' = Append(oldLog, [v |-> TRUE, mac |-> FALSE, mirror |-> FALSE])
    /\ row' = [v |-> TRUE, aseq |-> Len(oldLog) + 1, mac14 |-> FALSE, mark |-> row.mark]
    /\ forges' = forges + 1
    /\ UNCHANGED <<fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, tampers,
                   truth, committed, answered, decisions>>

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Olds : OldUseRead(x) \/ OldUseCommit(x) \/ OldWriteHead(x) \/ OldWriteCommit(x)
    \/ \E v \in Vaults : VaultStart(v) \/ VaultHead(v) \/ VaultFence(v) \/ VaultVerify(v) \/ VaultSeal(v)
    \/ \E x \in NewUsers : NewUseLock(x) \/ NewUseRun(x) \/ NewUseCommit(x)
    \/ \E h \in NewChangers : NewChangeStart(h) \/ NewChangeLock1(h) \/ NewChangeLock2(h) \/ NewChangeRun(h) \/ NewChangeAnswer(h)
    \/ Tick \/ TamperRow \/ ForgeEntry \/ ClearMark \/ DropNewest

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold. *)

\* One cutover, one genesis, whatever the starts.
OneCutover ==
    /\ Cardinality(Cutovers) <= 1
    /\ Cardinality({e \in newLog : e.kind = "genesis"}) <= 1

\* The anchor: the cutover names a head whose chain is all authentic, and precedes every 0.15 entry
\* but the genesis written with it.
AnchorHolds ==
    \A k \in Cutovers :
        /\ k.cites <= Len(oldLog)
        /\ \A i \in 1..k.cites : oldLog[i].mac
        /\ \A e \in newLog : e.kind \notin {"genesis", "cutover"} => e.seq > k.seq

\* What 0.15's log takes from 0.14's is 0.14's: genesis seals the object as 0.14's authentic chain
\* left it at the anchor; each adoption cites an authentic 0.14 write (not 0.15's own mirror), and
\* seals only what that write wrote.
NewLogFollowsOld ==
    \A e \in newLog :
        /\ e.kind = "genesis" => e.content = Content14At(e.cites)
        /\ e.kind = "adopt" =>
              /\ oldLog[e.cites].mac /\ ~oldLog[e.cites].mirror
              /\ e.seals => e.content = [v |-> oldLog[e.cites].v, aseq |-> e.cites]

\* No 0.15 use is decided on a row the new log does not have: an allowed one read the row as the
\* newest sealing entry before it left it.
UsesOnLoggedRows ==
    \A d \in decisions : (d.ver = "0.15" /\ d.allow) =>
        LET s == SealBelow(d.seq) IN s.some /\ s.content = d.read

\* No use, old or new, is allowed on a state its legitimate writers did not leave: the database
\* writer's grants are never served.
AllowedOnlyWhenGranted ==
    \A d \in decisions : d.allow => d.truth.v

\* Whatever the writer does to 0.14's chain, a 0.15 change stands: no 0.15 use is allowed on a
\* state a 0.15 change refused, until a later legitimate write.
NewChangesStand ==
    \A d \in decisions : (d.ver = "0.15" /\ d.allow /\ d.truth.by = "0.15") => d.truth.v

\* Every authentic 0.14 write after the anchor, there by the last tick, is adopted by it.
EveryOldWriteAdopted ==
    \A i \in (Anchor + 1)..lastTick :
        (Cutovers /= {} /\ oldLog[i].mac /\ ~oldLog[i].mirror) => i \in Cited

\* No use, old or new, is allowed after a write it did not see, old or new, has answered.
NothingAllowedAfterAnswer ==
    \A d \in decisions : d.allow => d.answeredAt <= d.seen

\* No two processes each hold the lock the other waits for: a 0.15 change holding the fence and
\* waiting for 0.14's head, while the head's holder waits for the fence.
WaitsForFence(p) ==
    \/ \E v \in Vaults : p = v /\ vs[v].pc = "headed" /\ CutoverFence
    \/ \E x \in Olds : p = x /\ o[x].pc = "headed" /\ OldWritesFence
    \/ \E h \in NewChangers : p = h /\ nc[h].pc = "first" /\ SecondLock = "fence"
NoWaitCycle ==
    ~\E h \in NewChangers :
        /\ nc[h].pc = "first" /\ SecondLock = "head" /\ fx = h
        /\ head /= None /\ WaitsForFence(head)

=============================================================================
