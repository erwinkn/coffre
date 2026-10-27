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
(*   - every decision takes its member's row first (store.lockMembers:     *)
(*     the member queue, FOR SHARE for a use, FOR NO KEY UPDATE for a      *)
(*     write), then waits for the head, and holds both to its commit;      *)
(*   - a write, so locked, checks the row, writes it, appends its entry    *)
(*     and advances the object's fence (`access_seq`), commits and         *)
(*     answers;                                                            *)
(*   - a use, so locked, reads the row and the fence, then under the head  *)
(*     refuses if the fence moved, else appends and commits.               *)
(*                                                                         *)
(* 0.15 (HotPathOne.tla's fence, abstracted): an advisory lock, uses       *)
(* shared, changes exclusive; numbers from one sequence under it; each     *)
(* sealing entry seals the row to its content; a use is `stale` (refused)  *)
(* unless the row is the newest sealing entry's content.                   *)
(*                                                                         *)
(* The cutover, at a 0.15 vault's start: if the marker (the `cutover`      *)
(* entry) is there, nothing. Else it takes every member's row, 0.14's     *)
(* head, then the fence, looks for the marker again, verifies 0.14's       *)
(* chain to its head, checks the row as 0.14 would, and writes `genesis`   *)
(* (sealing the row) and                                                   *)
(* `cutover` (naming the head). Old isolates keep writing; each later      *)
(* write leaves a row no 0.15 entry sealed, which the checkpointer's tick  *)
(* adopts: an `adopt` entry citing each 0.14 write after the anchor.      *)
(*                                                                         *)
(* A database writer without the keys may put back an older row or write  *)
(* one of its own (MaxTampers), or forge a 0.14 entry and the row it names *)
(* (MaxForges): neither carries a valid MAC.                               *)
(*                                                                         *)
(* The protections, each a constant (scripts/formal.sh turns each off):    *)
(*   RowFirst         the cutover and a dual-fenced 0.15 change take the   *)
(*                    member rows first, then 0.14's head, then the fence, *)
(*                    as 0.14 does: row, head, fence everywhere. Without,  *)
(*                    they update the rows last, under the head and fence, *)
(*                    while a 0.14 decision holds a row and waits for the  *)
(*                    head: a cycle Postgres breaks after deadlock_timeout *)
(*                    (1 s), the fence held exclusive and every 0.15 use   *)
(*                    waiting;                                             *)
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
(*                    cutover and 0.14's writes do (a 0.14 write to        *)
(*                    another member holds no row the change waits for:    *)
(*                    OtherWrites);                                        *)
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
(*   AppHeadFirst     with AppObject: a 0.15 change to an object the app's  *)
(*                    rows hold (a credential, a binding, an environment,  *)
(*                    a secret), made in the app's own transaction, takes  *)
(*                    0.14's head before the object's row, then the fence, *)
(*                    as `audited()` and every 0.14 write of the app do    *)
(*                    (plan PR 4b). RowFirst's order there waits for the   *)
(*                    head holding the row, while a 0.14 write of the app  *)
(*                    holds the head and waits for the row: a cycle;       *)
(*   OldWriteMarksRow the cheaper alternative, without the probe: the      *)
(*                    trigger marks the row with the 0.14 entry's number,  *)
(*                    and a use is `stale` while the mark is past what the *)
(*                    newest seal accounts for. The writer can clear the   *)
(*                    mark (MaxClears): then it holds no better than no    *)
(*                    check at all, as nothing it cannot write backs it.   *)
(*                                                                         *)
(* Some cover for each other. The head lock, the fence and (RowFirst) the  *)
(* rows each serialize two cutovers. A 0.14 write racing the cutover       *)
(* without its head lock is caught by VerifyRows (the cutover refuses: the *)
(* head lock is then for progress), by OldWritesFence (it waits for the    *)
(* fence) and by RowFirst (it waits for its row): TLC finds the race only  *)
(* with all four off.                                                      *)
(*                                                                         *)
(* What a seal covers. Here a row's content, which 0.15's seals cover, is  *)
(* its value and the 0.14 entry it names (Content: `access_seq`), so any   *)
(* late 0.14 write leaves the row `stale` until it is adopted, even one    *)
(* that writes back the same value. The real seal may cover the object    *)
(* only (role, grants, status): then a late 0.14 write of the same value   *)
(* leaves a row whose seal still holds. Safe either way: that row is the   *)
(* value the newest seal names, which the object, as 0.14 left it, still   *)
(* has; and a row put back over a late write passes the seal either way    *)
(* (it is the sealed row), so what refuses it is UsesSeeOldWrites, which   *)
(* reads 0.14's newest authentic entry, not the row, and is `stale` until  *)
(* that entry is adopted, whatever the seal covers. With the probe, the    *)
(* choice changes nothing a use sees; without it, covering access_seq      *)
(* would still not refuse the put-back row.                                *)
(*                                                                         *)
(* The object's kind (AppObject). By default a member, which 0.14's vault  *)
(* writes: its decisions lock the member's row before the head. With       *)
(* AppObject, an object of the app's rows instead (plan PR 4b): 0.14's     *)
(* writes of it are the app's, each in `audited()`, which takes the head,  *)
(* then writes the row, then appends (the trigger: the fence); 0.14's uses *)
(* read the row with no lock and check it again under the head            *)
(* (credentialStill). The cutover seals it last, under the head and the    *)
(* fence. Another member's writes (OtherWrites) are the vault's either way.*)
(*                                                                         *)
(* Issues (T123, R58). A sign-in issues a new credential: nobody can name *)
(* it before its issue commits, and it changes no input any other use      *)
(* reads (HotPathOne's IssueOwnLock, NamedAfterIssue). So it never takes   *)
(* the fence: 0.15's change of it takes a lock of its own, the issue lock, *)
(* shared, and 0.14's `token.exchange` takes neither, the trigger letting  *)
(* it by (ExchangeOnlyIssues: its transaction writes the new credential,   *)
(* the spent token and the binding's last use, no decision input; the     *)
(* suites hold the code to it). The checkpointer's barrier waits for the   *)
(* issues in flight on that lock exclusive, then takes the fence; it never *)
(* takes 0.14's head. Every lock in one order: the member's row, 0.14's    *)
(* head, the issue lock (shared), the fence (Barriers, NewIssuers, Mixed): *)
(*   - IssueBeforeFence: whatever takes the fence exclusive in a            *)
(*     transaction that may issue too (0.14's trigger, `app_change`) takes *)
(*     the issue lock shared first. Without, a sign-in that revokes its    *)
(*     account's earlier sessions (its trigger: the fence) and then issues *)
(*     holds the fence and waits for the issue lock, which the barrier     *)
(*     holds, waiting for the fence: a cycle. The vault's own changes      *)
(*     (NewChangers) never issue, and take no issue lock;                  *)
(*   - BarrierIssueFirst: the barrier takes the issue lock before the      *)
(*     fence. Without, it holds the fence and waits for an issue that      *)
(*     waits for the fence: a cycle (and every use waits meanwhile).       *)
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
    OtherWrites,     \* 0.14 writes may be to another member: for the locks only
    AppObject,       \* the object is one of the app's rows, not a member (plan PR 4b)
    Exchanges,       \* an old request may be 0.14's token.exchange, a sign-in
    NewIssuers,      \* 0.15 sign-ins, each issuing once: head, issue lock (for the locks only)
    Mixed,           \* 0.15 sign-ins that also revoke the account's earlier sessions, each once (for the locks only)
    Barriers,        \* the checkpointer's barrier, once each (for the locks only)
    CutoverHeadLock, CutoverFence, Marker, VerifyChain, VerifyRows,
    DualFence, ChangeHeadFirst, RowFirst, OldWritesFence,
    Adopt, AdoptRepeats, AdoptVerifies, AdoptSealsEntry, AdoptAfterSeal, UsesSeeOldWrites, OldWriteMarksRow,
    AppHeadFirst, ExchangeOnlyIssues, IssueBeforeFence, BarrierIssueFirst

None == "none"

VARIABLES
    oldLog,    \* 0.14's chain: its writes, in order; seq = index. [v, mac (authentic), mirror (a 0.15 change's)]
    row,       \* the object's row: [v, aseq (the 0.14 entry it names), mac14 (0.14's MAC holds)]
    fence14,   \* 0.14's fence for the object (access_seq's role): each write advances it
    rx,        \* 0.14's member row locks (the member queue, FOR NO KEY UPDATE): each member's holder, or None
    rs,        \* ... the object's held shared (FOR SHARE), by 0.14 uses
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
    decisions, \* ghost: each use's outcome, old and new
    ix,        \* the issue lock held exclusive: the barrier, or None
    is,        \* ... held shared
    ni,        \* each 0.15 sign-in (NewIssuers, Mixed)
    br,        \* each barrier
    exchanged  \* ghost: 0.14 token.exchange transactions that changed the object

issueVars == <<ix, is, ni, br, exchanged>>
vars == <<rx, rs, oldLog, row, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, tampers, forges,
          truth, committed, answered, decisions, ix, is, ni, br, exchanged>>

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

(* Locks. "obj" and "other" are members' rows (another member's only for the locks), "head" is   *)
(* 0.14's head, "fence" is 0.15's fence. Take: exclusive, once no one else holds it. Release:     *)
(* everything p holds, at its commit or rollback.                                                 *)
(* "issue" is the issue lock shared, "issueX" exclusive (the barrier's).                           *)
Members == {"obj", "other"}
Holds(q, l) ==
    CASE l \in Members -> rx[l] = q \/ (l = "obj" /\ q \in rs)
      [] l = "head" -> head = q
      [] l = "fence" -> fx = q \/ q \in fs
      [] l \in {"issue", "issueX"} -> ix = q \/ q \in is
\* Whether q's hold on l keeps p from taking it: a shared hold of the issue lock keeps out only the
\* exclusive one.
Conflicts(p, q, l) == IF l = "issue" THEN ix = q ELSE Holds(q, l)
Take(p, l) ==
    CASE l \in Members -> /\ rx[l] = None /\ (l = "obj" => rs \subseteq {p})
                         /\ rx' = [rx EXCEPT ![l] = p] /\ UNCHANGED <<rs, head, fx, fs, ix, is>>
      [] l = "head" -> /\ head = None /\ head' = p /\ UNCHANGED <<rx, rs, fx, fs, ix, is>>
      [] l = "fence" -> /\ FenceFree /\ fx' = p /\ UNCHANGED <<rx, rs, head, fs, ix, is>>
      [] l = "issue" -> /\ ix = None /\ is' = is \cup {p} /\ UNCHANGED <<rx, rs, head, fx, fs, ix>>
      [] l = "issueX" -> /\ ix = None /\ is = {} /\ ix' = p /\ UNCHANGED <<rx, rs, head, fx, fs, is>>
Release(p) ==
    /\ rx' = [m \in Members |-> IF rx[m] = p THEN None ELSE rx[m]]
    /\ rs' = rs \ {p}
    /\ head' = IF head = p THEN None ELSE head
    /\ fx' = IF fx = p THEN None ELSE fx
    /\ fs' = fs \ {p}
    /\ ix' = IF ix = p THEN None ELSE ix
    /\ is' = is \ {p}

\* The orders locks are taken in. 0.14's vault takes the member's row first, then the head, then
\* (the trigger) the fence; 0.14's app (AppObject's object) the head, then the row, then the
\* fence. With RowFirst, the cutover (every member's row, in order) and a dual-fenced 0.15 change
\* to a member take the row first too; without, they update it last, under the head and fence.
\* The cutover seals an app's row last either way; a 0.15 change to one takes the head first with
\* AppHeadFirst, else the row first, as for a member.
Rows == IF AppObject THEN <<"other">> ELSE <<"obj", "other">>
AppRows == IF AppObject THEN <<"obj">> ELSE <<>>
CutoverLocks == (IF RowFirst THEN Rows ELSE <<>>) \o (IF CutoverHeadLock THEN <<"head">> ELSE <<>>)
                \o (IF CutoverFence THEN <<"fence">> ELSE <<>>)
SealLocks == (IF RowFirst THEN <<>> ELSE Rows) \o AppRows
ChangeLocks ==
    IF ~DualFence THEN <<"fence">>
    ELSE IF AppObject THEN IF AppHeadFirst THEN <<"head", "obj", "fence">> ELSE <<"obj", "head", "fence">>
    ELSE (IF RowFirst THEN <<"obj">> ELSE <<>>) \o (IF ChangeHeadFirst THEN <<"head", "fence">> ELSE <<"fence", "head">>)
         \o (IF RowFirst THEN <<>> ELSE <<"obj">>)
\* A 0.15 sign-in's locks: 0.14's head (`audited()`), then `app_change`'s issue lock, shared. One
\* that also revokes the account's earlier sessions (Mixed): its append's trigger, for the revokes'
\* 0.14 entries, takes the fence, and `app_change` the issue lock: with IssueBeforeFence, the issue
\* lock first, as both do.
IssuerLocks(p) ==
    IF p \in Mixed THEN IF IssueBeforeFence THEN <<"head", "issue", "fence">> ELSE <<"head", "fence", "issue">>
    ELSE <<"head", "issue">>
\* The barrier's: the issue lock exclusive, then the fence; without BarrierIssueFirst, the other way.
BarrierLocks == IF BarrierIssueFirst THEN <<"issueX", "fence">> ELSE <<"fence", "issueX">>

\* A 0.14 write's two locks before its append: the app's to its row, the head first.
OldFirst(m) == IF AppObject /\ m = "obj" THEN "head" ELSE m
OldSecond(m) == IF AppObject /\ m = "obj" THEN m ELSE "head"

Entry(seq, kind, seals, content, cites) == [seq |-> seq, kind |-> kind, seals |-> seals, content |-> content, cites |-> cites]
NoContent == [v |-> FALSE, aseq |-> 0]
Truth0 == [v |-> TRUE, by |-> "0.14"]

Answer == answered' = IF answered > committed' THEN answered ELSE committed'

Init ==
    /\ oldLog = <<>>
    /\ row = [v |-> TRUE, aseq |-> 0, mac14 |-> TRUE, mark |-> 0]
    /\ fence14 = 0
    /\ rx = [m \in Members |-> None]
    /\ rs = {}
    /\ head = None
    /\ fx = None
    /\ fs = {}
    /\ newLog = {}
    /\ nextSeq = 1
    /\ o = [x \in Olds |-> [pc |-> "idle", n |-> 0, v |-> FALSE, m |-> "obj", fence |-> 0, allow |-> FALSE, seen |-> 0, truth |-> Truth0]]
    /\ vs = [v \in Vaults |-> [pc |-> "idle", anchor |-> 0, got |-> 0]]
    /\ nu = [x \in NewUsers |-> [pc |-> "idle", n |-> 0, seq |-> 0, allow |-> FALSE, read |-> NoContent, seen |-> 0, truth |-> Truth0]]
    /\ nc = [h \in NewChangers |-> [pc |-> "idle", n |-> 0, read |-> NoContent, v |-> FALSE, got |-> 0]]
    /\ ticks = 0
    /\ lastTick = 0
    /\ tampers = [rows |-> 0, clears |-> 0, drops |-> 0]
    /\ forges = 0
    /\ truth = Truth0
    /\ committed = 0
    /\ answered = 0
    /\ decisions = {}
    /\ ix = None
    /\ is = {}
    /\ ni = [p \in NewIssuers \cup Mixed |-> [pc |-> "idle", got |-> 0]]
    /\ br = [b \in Barriers |-> [pc |-> "idle", got |-> 0]]
    /\ exchanged = 0

-----------------------------------------------------------------------------
(* 0.14, on old isolates. *)

\* A use locks the member's row shared, then reads it and the object's fence. The app reads its own
\* row with no lock (AppObject).
OldUseRead(x) ==
    /\ o[x].pc = "idle"
    /\ o[x].n < MaxOldOps
    /\ ~AppObject => rx["obj"] = None
    /\ rs' = IF AppObject THEN rs ELSE rs \cup {x}
    /\ o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "read", !.fence = fence14, !.allow = row.v /\ Genuine14(row),
                                         !.seen = committed, !.truth = truth]]
    /\ UNCHANGED <<rx, oldLog, row, fence14, head, fx, fs, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, issueVars>>

\* Under the head: refused if the fence moved; appends and commits. The value leaves after. Its
\* entry (`credential.use`) changes no access, so the trigger lets it by: it never waits for the
\* 0.15 fence.
OldUseCommit(x) ==
    /\ o[x].pc = "read"
    /\ head = None
    /\ rs' = rs \ {x}
    /\ decisions' = decisions \cup {[ver |-> "0.14", allow |-> o[x].allow /\ fence14 = o[x].fence, seen |-> o[x].seen,
                                     answeredAt |-> answered, truth |-> o[x].truth, read |-> NoContent, seq |-> 0]}
    /\ o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<rx, oldLog, row, fence14, head, fx, fs, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, issueVars>>

\* A write (a grant or a revoke) to the object, or (OtherWrites) to another member, takes its first
\* lock: the member's row; the head, for the app's write to its row (AppObject).
OldWriteRow(x) ==
    /\ o[x].pc = "idle"
    /\ o[x].n < MaxOldOps
    /\ \E m \in IF OtherWrites THEN Members ELSE {"obj"} :
          /\ Take(x, OldFirst(m))
          /\ \E v \in BOOLEAN : o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "rowed", !.v = v, !.m = m]]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, br, exchanged>>

\* Then its second: the head; the row, for the app's.
OldWriteHead(x) ==
    /\ o[x].pc = "rowed"
    /\ Take(x, OldSecond(o[x].m))
    /\ o' = [o EXCEPT ![x].pc = "headed"]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, br, exchanged>>

\* Its append (an access entry: with the trigger, once the fence is free; with OldWriteMarksRow,
\* the trigger also marks the row with the entry's number), its row, its fence; commit and answer.
\* A row 0.14 does not accept refuses it.
OldWriteCommit(x) ==
    /\ o[x].pc = "headed"
    /\ OldWritesFence => FenceFree /\ (IssueBeforeFence => ix = None)
    /\ IF o[x].m = "obj" /\ Genuine14(row)
       THEN /\ oldLog' = Append(oldLog, [v |-> o[x].v, mac |-> TRUE, mirror |-> FALSE])
            /\ row' = [v |-> o[x].v, aseq |-> Len(oldLog) + 1, mac14 |-> TRUE,
                        mark |-> IF OldWriteMarksRow THEN Len(oldLog) + 1 ELSE row.mark]
            /\ fence14' = fence14 + 1
            /\ truth' = [v |-> o[x].v, by |-> "0.14"]
            /\ committed' = committed + 1
            /\ Answer
       ELSE UNCHANGED <<oldLog, row, fence14, truth, committed, answered, ni, br, exchanged>>
    /\ Release(x)
    /\ o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED << newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges, decisions, ni, br, exchanged>>

\* 0.14's token.exchange (Exchanges): under the head (`audited()`), the token spent, a new
\* credential issued, the binding's last use stamped, `token.exchange` appended. The trigger lets
\* it by: it takes no fence and no issue lock. With ExchangeOnlyIssues it writes no decision input;
\* without, it also writes the object, as a revoke or a grant would.
OldExchangeHead(x) ==
    /\ Exchanges
    /\ o[x].pc = "idle"
    /\ o[x].n < MaxOldOps
    /\ Take(x, "head")
    /\ \E v \in BOOLEAN : o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "exchanging", !.v = v]]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, br, exchanged>>

OldExchangeCommit(x) ==
    /\ o[x].pc = "exchanging"
    /\ IF ~ExchangeOnlyIssues /\ Genuine14(row)
       THEN /\ oldLog' = Append(oldLog, [v |-> o[x].v, mac |-> TRUE, mirror |-> FALSE])
            /\ row' = [v |-> o[x].v, aseq |-> Len(oldLog) + 1, mac14 |-> TRUE, mark |-> row.mark]
            /\ fence14' = fence14 + 1
            /\ truth' = [v |-> o[x].v, by |-> "0.14"]
            /\ committed' = committed + 1
            /\ exchanged' = exchanged + 1
            /\ Answer
       ELSE UNCHANGED <<oldLog, row, fence14, truth, committed, answered, exchanged>>
    /\ Release(x)
    /\ o' = [o EXCEPT ![x] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<newLog, nextSeq, vs, nu, nc, ticks, lastTick, tampers, forges, decisions, ni, br>>

-----------------------------------------------------------------------------
(* 0.15 sign-ins, and the checkpointer's barrier: for the locks. *)

\* A sign-in's locks, one at a time; then its credential's change, numbered under them, and the
\* commit, which lets them go. It writes no input of the object.
IssuerLock(p) ==
    /\ ni[p].pc \in {"idle", "locking"}
    /\ Started
    /\ Take(p, IssuerLocks(p)[ni[p].got + 1])
    /\ ni' = [ni EXCEPT ![p] = [pc |-> IF @.got + 1 = Len(IssuerLocks(p)) THEN "locked" ELSE "locking", got |-> @.got + 1]]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, br, exchanged>>

IssuerCommit(p) ==
    /\ ni[p].pc = "locked"
    /\ newLog' = newLog \cup {Entry(nextSeq, "issue", FALSE, NoContent, 0)}
    /\ nextSeq' = nextSeq + 1
    /\ Release(p)
    /\ ni' = [ni EXCEPT ![p].pc = "done"]
    /\ UNCHANGED <<oldLog, row, fence14, o, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, br, exchanged>>

\* The barrier: its first lock, held while it waits for the second; with the second, it closes its
\* numbers and lets both go, in one statement.
BarrierLock(b) ==
    /\ br[b].pc = "idle"
    /\ Started
    /\ Take(b, BarrierLocks[1])
    /\ br' = [br EXCEPT ![b] = [pc |-> "waiting", got |-> 1]]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, exchanged>>

BarrierClose(b) ==
    /\ br[b].pc = "waiting"
    /\ IF BarrierLocks[2] = "fence" THEN FenceFree ELSE ix = None /\ is = {}
    /\ Release(b)
    /\ br' = [br EXCEPT ![b] = [pc |-> "done", got |-> 0]]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, exchanged>>

-----------------------------------------------------------------------------
(* A 0.15 vault's start: the cutover. *)

\* The marker seen without any lock: nothing to do. Else, to the locks.
VaultStart(v) ==
    /\ vs[v].pc = "idle"
    /\ vs' = [vs EXCEPT ![v].pc = IF Cutovers /= {} THEN "started" ELSE IF CutoverLocks = <<>> THEN "locked" ELSE "locking"]
    /\ UNCHANGED <<rx, rs, oldLog, row, fence14, head, fx, fs, newLog, nextSeq, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, issueVars>>

\* Its locks, one at a time, in their order: before the marker's check (`locking`), and, without
\* RowFirst, the rows it seals after it (`sealing`).
VaultLock(v) ==
    /\ vs[v].pc \in {"locking", "sealing"}
    /\ LET ls == IF vs[v].pc = "locking" THEN CutoverLocks ELSE SealLocks
       IN /\ Take(v, ls[vs[v].got + 1])
          /\ vs' = [vs EXCEPT ![v] = [@ EXCEPT !.got = IF @ + 1 = Len(ls) THEN 0 ELSE @ + 1,
                                               !.pc = IF vs[v].got + 1 < Len(ls) THEN @
                                                      ELSE IF @ = "locking" THEN "locked" ELSE "sealready"]]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, br, exchanged>>

\* The marker again, under the locks; then 0.14's head, and its chain verified up to it.
VaultVerify(v) ==
    /\ vs[v].pc = "locked"
    /\ IF Marker /\ Cutovers /= {}
       THEN /\ vs' = [vs EXCEPT ![v].pc = "started"]
            /\ Release(v)
       ELSE IF VerifyChain /\ \E i \in 1..Len(oldLog) : ~oldLog[i].mac
       THEN /\ vs' = [vs EXCEPT ![v].pc = "refused"]
            /\ Release(v)
       ELSE /\ vs' = [vs EXCEPT ![v] = [pc |-> IF SealLocks = <<>> THEN "sealready" ELSE "sealing", anchor |-> Len(oldLog), got |-> 0]]
            /\ UNCHANGED <<rx, rs, head, fx, fs, ix, is>>
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, br, exchanged>>

\* A statement of its own: the row, checked as 0.14 would against the chain it verified; `genesis`
\* sealing it, `cutover` naming the head; the commit lets the locks go.
VaultSeal(v) ==
    /\ vs[v].pc = "sealready"
    /\ IF VerifyRows /\ ~(row.mac14 /\ row.aseq = NewestGenuine(vs[v].anchor))
       THEN /\ vs' = [vs EXCEPT ![v].pc = "refused"]
            /\ UNCHANGED <<newLog, nextSeq, ni, br, exchanged>>
       ELSE /\ newLog' = newLog \cup {Entry(nextSeq, "genesis", TRUE, Content(row), vs[v].anchor),
                                      Entry(nextSeq + 1, "cutover", FALSE, NoContent, vs[v].anchor)}
            /\ nextSeq' = nextSeq + 2
            /\ vs' = [vs EXCEPT ![v].pc = "started"]
    /\ Release(v)
    /\ UNCHANGED <<oldLog, row, fence14, o, nu, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, br, exchanged>>

-----------------------------------------------------------------------------
(* 0.15 uses, on a started vault. *)

NewUseLock(x) ==
    /\ nu[x].pc = "idle"
    /\ nu[x].n < MaxNewUses
    /\ Started
    /\ fx = None
    /\ fs' = fs \cup {x}
    /\ nu' = [nu EXCEPT ![x].pc = "locked"]
    /\ UNCHANGED <<rx, rs, oldLog, row, fence14, head, fx, newLog, nextSeq, o, vs, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, issueVars>>

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
    /\ UNCHANGED <<rx, rs, oldLog, row, fence14, head, fx, fs, newLog, o, vs, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, issueVars>>

\* The commit, which lets the lock go. Its value leaves after.
NewUseCommit(x) ==
    /\ nu[x].pc = "ran"
    /\ newLog' = newLog \cup {Entry(nu[x].seq, "use", FALSE, NoContent, 0)}
    /\ decisions' = decisions \cup {[ver |-> "0.15", allow |-> nu[x].allow, seen |-> nu[x].seen, answeredAt |-> answered,
                                     truth |-> nu[x].truth, read |-> nu[x].read, seq |-> nu[x].seq]}
    /\ fs' = fs \ {x}
    /\ nu' = [nu EXCEPT ![x] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<rx, rs, oldLog, row, fence14, head, fx, nextSeq, o, vs, nc, ticks, lastTick, tampers, forges,
                   truth, committed, answered, issueVars>>

-----------------------------------------------------------------------------
(* 0.15 changes: a grant or a revoke, written as logged. *)

\* The row is read outside the locks.
NewChangeStart(h) ==
    /\ nc[h].pc = "idle"
    /\ nc[h].n < MaxNewChanges
    /\ Started
    /\ \E v \in BOOLEAN : nc' = [nc EXCEPT ![h] = [@ EXCEPT !.pc = "started", !.read = Content(row), !.v = v]]
    /\ UNCHANGED <<rx, rs, oldLog, row, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, issueVars>>

\* Its locks, one at a time, in their order: the fence; with DualFence, 0.14's head and the
\* object's row too.
NewChangeLock(h) ==
    /\ nc[h].pc = "started"
    /\ Take(h, ChangeLocks[nc[h].got + 1])
    /\ nc' = [nc EXCEPT ![h] = [@ EXCEPT !.got = IF @ + 1 = Len(ChangeLocks) THEN 0 ELSE @ + 1,
                                           !.pc = IF nc[h].got + 1 = Len(ChangeLocks) THEN "locked" ELSE "started"]]
    /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, o, vs, nu, ticks, lastTick, tampers, forges,
                   truth, committed, answered, decisions, ni, br, exchanged>>

\* The CAS (the row is still the one it read, else it reads again); the write, sealed by its
\* entry. With DualFence, also 0.14's: a mirror entry, the row naming it under 0.14's MAC, the
\* fence advanced. Without, 0.14's MAC no longer holds over the row. The commit lets the locks go.
NewChangeRun(h) ==
    /\ nc[h].pc = "locked"
    /\ IF Content(row) /= nc[h].read
       THEN /\ nc' = [nc EXCEPT ![h].pc = "idle"]
            /\ UNCHANGED <<oldLog, row, fence14, newLog, nextSeq, truth, committed, ni, br, exchanged>>
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
    /\ Release(h)
    /\ UNCHANGED << o, vs, nu, ticks, lastTick, tampers, forges, answered, decisions, ni, br, exchanged>>

NewChangeAnswer(h) ==
    /\ nc[h].pc = "committed"
    /\ answered' = IF answered > committed THEN answered ELSE committed
    /\ nc' = [nc EXCEPT ![h] = [@ EXCEPT !.pc = "idle", !.n = @ + 1]]
    /\ UNCHANGED <<rx, rs, oldLog, row, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, ticks, lastTick, tampers, forges,
                   truth, committed, decisions, issueVars>>

-----------------------------------------------------------------------------
(* The checkpointer's tick, on a started vault, under both locks: it adopts 0.14's writes after  *)
(* the anchor that no `adopt` cites yet, skipping 0.15's own mirror entries, one `adopt` each, in *)
(* 0.14's order. One seals: with AdoptSealsEntry, the one that is 0.14's newest authentic write,  *)
(* with what it wrote (a row put back is then stale), if no seal names a later 0.14 entry (a 0.15 *)
(* change's mirror, which a writer may have deleted); without, the newest, with the row as found. *)

Tick ==
    /\ Started
    /\ ticks < MaxTicks
    /\ head = None /\ FenceFree /\ rx["obj"] = None /\ rs = {}
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
          ELSE UNCHANGED <<newLog, nextSeq, issueVars>>
    /\ ticks' = ticks + 1
    /\ lastTick' = Len(oldLog)
    /\ UNCHANGED <<rx, rs, oldLog, row, fence14, head, fx, fs, o, vs, nu, nc, tampers, forges,
                   truth, committed, answered, decisions, issueVars>>

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
    /\ UNCHANGED <<rx, rs, oldLog, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, forges,
                   truth, committed, answered, decisions, issueVars>>

\* It clears the row's mark (OldWriteMarksRow): an unsigned column, like any other.
ClearMark ==
    /\ tampers.clears < MaxClears
    /\ row.mark /= 0
    /\ row' = [row EXCEPT !.mark = 0]
    /\ tampers' = [tampers EXCEPT !.clears = @ + 1]
    /\ UNCHANGED <<rx, rs, oldLog, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, forges,
                   truth, committed, answered, decisions, issueVars>>

\* It deletes 0.14's newest entry, or edits it so that its MAC fails: 0.14's own checks, and a
\* probe of the newest authentic entry, then pass it over. (0.14's anchor, outside the database,
\* is what catches this; not modelled.)
DropNewest ==
    /\ tampers.drops < MaxDrops
    /\ Len(oldLog) > 0
    /\ oldLog' = [oldLog EXCEPT ![Len(oldLog)].mac = FALSE]
    /\ tampers' = [tampers EXCEPT !.drops = @ + 1]
    /\ UNCHANGED <<rx, rs, row, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, forges,
                   truth, committed, answered, decisions, issueVars>>

\* It appends a 0.14 entry granting, and a row naming it: no MAC holds on either.
ForgeEntry ==
    /\ forges < MaxForges
    /\ oldLog' = Append(oldLog, [v |-> TRUE, mac |-> FALSE, mirror |-> FALSE])
    /\ row' = [v |-> TRUE, aseq |-> Len(oldLog) + 1, mac14 |-> FALSE, mark |-> row.mark]
    /\ forges' = forges + 1
    /\ UNCHANGED <<rx, rs, fence14, head, fx, fs, newLog, nextSeq, o, vs, nu, nc, ticks, lastTick, tampers,
                   truth, committed, answered, decisions, issueVars>>

-----------------------------------------------------------------------------

Next ==
    \/ \E x \in Olds : OldUseRead(x) \/ OldUseCommit(x) \/ OldWriteRow(x) \/ OldWriteHead(x) \/ OldWriteCommit(x)
                      \/ OldExchangeHead(x) \/ OldExchangeCommit(x)
    \/ \E p \in NewIssuers \cup Mixed : IssuerLock(p) \/ IssuerCommit(p)
    \/ \E b \in Barriers : BarrierLock(b) \/ BarrierClose(b)
    \/ \E v \in Vaults : VaultStart(v) \/ VaultLock(v) \/ VaultVerify(v) \/ VaultSeal(v)
    \/ \E x \in NewUsers : NewUseLock(x) \/ NewUseRun(x) \/ NewUseCommit(x)
    \/ \E h \in NewChangers : NewChangeStart(h) \/ NewChangeLock(h) \/ NewChangeRun(h) \/ NewChangeAnswer(h)
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

\* No 0.14 token.exchange, which the trigger lets by unfenced, changed a decision input.
ExchangeChangesNoInput == exchanged = 0

\* No wait cycle: no process waits for a lock held by one that waits, through at most three, for a
\* lock it holds. (Postgres would break one after deadlock_timeout, 1 s, with the fence held
\* exclusive and every 0.15 use waiting.) What each waits for, holding something:
Wants(p) ==
    CASE p \in Olds /\ o[p].pc = "read" -> "head"
      [] p \in Olds /\ o[p].pc = "rowed" -> OldSecond(o[p].m)
      [] p \in Olds /\ o[p].pc = "headed" /\ OldWritesFence -> IF IssueBeforeFence /\ ix /= None THEN "issue" ELSE "fence"
      [] p \in NewIssuers \cup Mixed /\ ni[p].pc = "locking" -> IssuerLocks(p)[ni[p].got + 1]
      [] p \in Barriers /\ br[p].pc = "waiting" -> BarrierLocks[2]
      [] p \in Vaults /\ vs[p].pc = "locking" -> CutoverLocks[vs[p].got + 1]
      [] p \in Vaults /\ vs[p].pc = "sealing" -> SealLocks[vs[p].got + 1]
      [] p \in NewChangers /\ nc[p].pc = "started" /\ nc[p].got > 0 -> ChangeLocks[nc[p].got + 1]
      [] OTHER -> None
Waiters == Olds \cup Vaults \cup NewChangers \cup NewIssuers \cup Mixed \cup Barriers
Blocks(p, q) == p /= q /\ Wants(p) /= None /\ Conflicts(p, q, Wants(p))
NoWaitCycle ==
    ~\E p, q \in Waiters :
        \/ Blocks(p, q) /\ Blocks(q, p)
        \/ \E w \in Waiters : Blocks(p, q) /\ Blocks(q, w) /\ Blocks(w, p)

\* The barrier never holds 0.14's head, nor waits for it.
BarrierAvoidsHead == \A b \in Barriers : head /= b /\ Wants(b) /= "head"

=============================================================================
