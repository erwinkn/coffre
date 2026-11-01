------------------------------- MODULE Routing -------------------------------
(***************************************************************************)
(* Proxy definitions edited in the UI (T186, 0.16; docs/design/proxy-ui.md). *)
(* A route sends an environment's key to the upstream its definition       *)
(* names. Until 0.16 that definition was deployment code; now an Owner may *)
(* write it in the UI, so it is a row of the database, which can change    *)
(* while uses are in flight, be put back by a database writer, or be       *)
(* shadowed by a code definition of the same name. The question this      *)
(* model answers: where may a key go?                                      *)
(*                                                                         *)
(* One environment, one route `r`, one key `K` it sends, two hosts. The    *)
(* definition is one object of the vault's log (a `proxy` object, sealed): *)
(* `defs[v]` is what change v left, its host and its clearance (the most   *)
(* sensitive nature it may send: "sensitive" when its editor was an Owner  *)
(* covering the place, R32's set, else "secret"). `row` is the version the *)
(* database row holds: always the newest, unless a writer with no key put  *)
(* back an earlier one (it cannot forge a seal, only replay one).          *)
(*                                                                         *)
(* A use, in the code:                                                     *)
(*   the app resolves `r` (Resolve): code first; else the environment's    *)
(*   UI definitions, its per-isolate copy, or read now (an app read, no    *)
(*   seal checked);                                                        *)
(*   the vault's one call, `use_credential` (Decide): under the fence      *)
(*   shared, the definition row, its seal and the newest change's, and     *)
(*   the key's nature, all in one snapshot; it allows or refuses, answers  *)
(*   with the definition it decided on, and the app keeps the values       *)
(*   beside it (`kept`, the value cache);                                  *)
(*   the request goes out (Send): to the kept definition's upstream,       *)
(*   while the kept values serve (`cacheSeconds`, or the use's deadline    *)
(*   with no cache: W ticks after the decision).                           *)
(* An edit (Edit) is a change: under the fence exclusive, so no use        *)
(* overlaps it (HotPathOne.tla proves that part for any input); here it is *)
(* one step. An Owner may route a sensitive key; anyone else with          *)
(* proxy.edit only a key that is secret now (the save's own check).        *)
(*                                                                         *)
(* Code definitions: the live deployment's code may define `r` (code),     *)
(* and then code wins: no use goes through the UI definition, which the    *)
(* page shows locked (it was `shadowed`, a ghost: seen locked by someone,  *)
(* or skipped by a use). A deploy flips `code` and starts new isolates.    *)
(* At its first proxy request each isolate holds the log's code set to its *)
(* own (LogCode): when they differ it writes a `proxy.code` change, which  *)
(* deletes a UI definition its code now shadows, the whole definition in   *)
(* the entry for an Owner to restore. One deployment is live at a time.    *)
(*                                                                         *)
(* Protections, each a constant, TRUE in the code:                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Hosts,          \* where a definition may point: {"good", "evil"}
    W,              \* how long a decision's values serve, in ticks: cacheSeconds, or the deadline
    MaxTime,        \* how far the clock runs
    MaxEdits,       \* edits of `r` in the UI
    MaxTampers,     \* rows a database writer puts back
    MaxMarks,       \* K made sensitive (once)
    MaxDeploys,     \* deployments that flip whether code defines `r`
    Budget          \* proxy requests the isolates make

CONSTANTS
    \* The use reads the definition in the statement after the fence, in
    \* one snapshot with its decision (else: read before, decided after).
    FencedRead,
    \* The definition row's seal must be its newest change's (`stale`).
    SealChecked,
    \* The app sends by the definition the vault decided on, which the call
    \* answers with (or confirms the app's copy of, by its seal), never by a
    \* copy of its own the vault did not see.
    SentAsDecided,
    \* Kept values go only where the definition they were decided under says
    \* (the value cache is keyed by the definition's seal), never where a
    \* newer copy of the app's says.
    BoundToDefinition,
    \* Kept values serve W ticks after their decision, no longer.
    KeptExpires,
    \* The use weighs the key's nature now against the definition's
    \* clearance (else only the save checked it, against the nature then).
    ClearanceAtUse,
    \* A `proxy.code` change deletes the UI definition code shadows.
    ClearSuperseded,
    \* An isolate serves nothing of the proxy before its code set is logged.
    CodeGate

None == [host |-> "none", clearance |-> "none"]
NoKept == [ver |-> 0, host |-> "none", at |-> 0, newest |-> FALSE, nat |-> "none"]
NoSnap == [ver |-> 0, newest |-> 0]

VARIABLES
    now,
    defs,       \* the log: defs[v], what change v left
    row,        \* the version the row holds
    nature,     \* K's nature: "secret" or "sensitive"
    code,       \* the live deployment's code defines `r`
    logged,     \* its code set is the log's (a `proxy.code` change landed, or nothing to change)
    shadowed,   \* ghost: UI versions a deployment defining `r` showed locked
    cached,     \* the app's copy of the definition: the version it read, or 0
    snap,       \* without FencedRead: what the use read before the fence
    kept,       \* the value cache: the version decided, the host the app sends to, when, ghosts
    sent,       \* ghost: every request that went out with K
    edits, tampers, marks, deploys, left

vars == <<now, defs, row, nature, code, logged, shadowed, cached, snap, kept, sent, edits, tampers, marks, deploys, left>>

Newest == Len(defs)

Init ==
    /\ now = 1
    /\ defs = <<[host |-> "good", clearance |-> "sensitive"]>>
    /\ row = 1
    /\ nature = "secret"
    /\ code = FALSE
    /\ logged = TRUE
    /\ shadowed = {}
    /\ cached = 0
    /\ snap = NoSnap
    /\ kept = NoKept
    /\ sent = {}
    /\ edits = 0 /\ tampers = 0 /\ marks = 0 /\ deploys = 0
    /\ left = Budget

\* An edit of `r` in the UI: an Owner's (clearance "sensitive") or another
\* editor's, who may name only a key that is secret now. The page refuses a
\* name the live code defines. A change: it writes the newest version.
Edit(h, c) ==
    /\ edits < MaxEdits /\ ~code
    /\ c = "secret" => nature = "secret"
    /\ defs' = Append(defs, [host |-> h, clearance |-> c])
    /\ row' = Newest + 1
    /\ edits' = edits + 1
    /\ UNCHANGED <<now, nature, code, logged, shadowed, cached, snap, kept, sent, tampers, marks, deploys, left>>

\* K made sensitive (`coffre mark`), a change of its own.
Mark ==
    /\ marks < MaxMarks /\ nature = "secret"
    /\ nature' = "sensitive" /\ marks' = marks + 1
    /\ UNCHANGED <<now, defs, row, code, logged, shadowed, cached, snap, kept, sent, edits, tampers, deploys, left>>

\* A database writer puts back a row the vault once sealed.
Tamper(v) ==
    /\ tampers < MaxTampers /\ v \in 1..Newest /\ v # row
    /\ row' = v /\ tampers' = tampers + 1
    /\ UNCHANGED <<now, defs, nature, code, logged, shadowed, cached, snap, kept, sent, edits, marks, deploys, left>>

\* A deployment whose code defines `r`, or no longer does. New isolates:
\* no cache, and the code set not yet held to the log's.
Deploy ==
    /\ deploys < MaxDeploys
    /\ code' = ~code /\ logged' = FALSE
    /\ cached' = 0 /\ snap' = NoSnap /\ kept' = NoKept
    /\ deploys' = deploys + 1
    /\ UNCHANGED <<now, defs, row, nature, shadowed, sent, edits, tampers, marks, left>>

\* The isolate's first proxy request holds the log's code set to its own:
\* a `proxy.code` change where they differ, deleting a UI definition its
\* code shadows (a change: it writes the newest version).
LogCode ==
    /\ ~logged
    /\ logged' = TRUE
    /\ IF ClearSuperseded /\ code /\ defs[Newest].host # "none"
         THEN /\ defs' = Append(defs, None)
              /\ row' = Newest + 1
         ELSE UNCHANGED <<defs, row>>
    /\ UNCHANGED <<now, nature, code, shadowed, cached, snap, kept, sent, edits, tampers, marks, deploys, left>>

\* A proxy request resolves `r`, or the page shows it: code first, the UI
\* definition shown locked; else the app's copy of the UI definition, read
\* now (an app read: no seal checked) if it has none.
Resolve ==
    /\ left > 0 /\ (CodeGate => logged)
    /\ left' = left - 1
    /\ IF code
         THEN /\ shadowed' = IF defs[Newest].host # "none" THEN shadowed \cup {Newest} ELSE shadowed
              /\ UNCHANGED cached
         ELSE /\ cached' = row
              /\ UNCHANGED shadowed
    /\ UNCHANGED <<now, defs, row, nature, code, logged, snap, kept, sent, edits, tampers, marks, deploys>>

\* Without FencedRead: the use's reads take their snapshot before the fence.
Read ==
    /\ ~FencedRead /\ ~code /\ cached # 0 /\ snap = NoSnap
    /\ snap' = [ver |-> row, newest |-> Newest]
    /\ UNCHANGED <<now, defs, row, nature, code, logged, shadowed, cached, kept, sent, edits, tampers, marks, deploys, left>>

\* The vault's one call decides, on the row it read, against the newest
\* change (in its own snapshot, or the early one without FencedRead), and
\* answers with the definition it decided on, which the app's copy becomes.
\* The app keeps the values with the upstream it will send them to: the
\* decided definition's, or, without SentAsDecided, its own copy's.
Decide ==
    /\ left > 0 /\ ~code /\ cached # 0
    /\ (CodeGate => logged)
    /\ FencedRead \/ snap # NoSnap
    /\ LET v       == IF FencedRead THEN row ELSE snap.ver
           newest  == IF FencedRead THEN Newest ELSE snap.newest
           sealOK  == ~SealChecked \/ v = newest
           clearOK == ~ClearanceAtUse \/ nature = "secret" \/ defs[v].clearance = "sensitive"
           allowed == sealOK /\ defs[v].host # "none" /\ clearOK
       IN /\ kept' = IF allowed
                       THEN [ver |-> v, host |-> IF SentAsDecided THEN defs[v].host ELSE defs[cached].host,
                             at |-> now, newest |-> v = Newest, nat |-> nature]
                       ELSE kept
          /\ cached' = IF SentAsDecided THEN v ELSE cached
    /\ snap' = NoSnap
    /\ left' = left - 1
    /\ UNCHANGED <<now, defs, row, nature, code, logged, shadowed, sent, edits, tampers, marks, deploys>>

\* A request goes out with the kept values: to the kept definition's
\* upstream, or, not bound to it, wherever the app's copy says now.
Send ==
    /\ kept.ver # 0 /\ ~code
    /\ KeptExpires => now < kept.at + W
    /\ BoundToDefinition \/ cached # 0
    /\ LET h == IF BoundToDefinition THEN kept.host ELSE defs[cached].host
       IN /\ h # "none"
          /\ sent' = sent \cup {[host |-> h, ver |-> kept.ver, at |-> kept.at, sentAt |-> now,
                                 newest |-> kept.newest, nat |-> kept.nat, stillNewest |-> kept.ver = Newest,
                                 revived |-> kept.ver \in shadowed]}
    /\ UNCHANGED <<now, defs, row, nature, code, logged, shadowed, cached, snap, kept, edits, tampers, marks, deploys, left>>

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<defs, row, nature, code, logged, shadowed, cached, snap, kept, sent, edits, tampers, marks, deploys, left>>

Done == now = MaxTime /\ left = 0 /\ UNCHANGED vars

Next ==
    \/ \E h \in Hosts, c \in {"secret", "sensitive"} : Edit(h, c)
    \/ Mark
    \/ \E v \in 1..Newest : Tamper(v)
    \/ Deploy \/ LogCode \/ Resolve \/ Read \/ Decide \/ Send \/ Tick \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 1..MaxTime
    /\ row \in 1..Newest
    /\ nature \in {"secret", "sensitive"}
    /\ cached \in 0..Newest
    /\ kept.ver \in 0..Newest

(***************************************************************************)
(* Every request that carried K went where a definition the vault decided  *)
(* on says, a definition that was the log's newest when it decided (not    *)
(* one put back, nor one an edit had replaced), and one cleared for K's    *)
(* nature then: a sensitive key only by an Owner's definition.             *)
(***************************************************************************)
EverySendAllowed ==
    \A s \in sent :
        /\ s.newest
        /\ s.host = defs[s.ver].host
        /\ s.nat = "sensitive" => defs[s.ver].clearance = "sensitive"

\* And within W of that decision: an edit stops the old upstream's requests
\* W after it at the latest (a minute by default, a revocation's bound).
WithinWindow == \A s \in sent : s.sentAt < s.at + W

\* A UI definition that code shadowed never comes back when code drops the
\* name: nobody looked at it while it was locked.
NoRevival == \A s \in sent : ~s.revived

(***************************************************************************)
(* The window the design leaves (EXPECTED): no request goes out under a    *)
(* definition an edit has replaced. Values decided before an edit serve    *)
(* out their W, as a revoked handle's do.                                  *)
(***************************************************************************)
StrictlyCurrent == \A s \in sent : s.stillNewest

=============================================================================
