------------------------------- MODULE Routing -------------------------------
(***************************************************************************)
(* Proxy definitions edited in the UI (T186, 0.16; docs/design/proxy-ui.md). *)
(* A route sends an environment's key to the upstream its definition       *)
(* names. Until 0.16 that definition was deployment code; now an Owner may *)
(* write it in the UI, so it is a row of the database, which can change    *)
(* while uses are in flight, be forged or put back by a database writer,   *)
(* or be shadowed by a code definition of the same name. The question this *)
(* model answers: where may a key go?                                      *)
(*                                                                         *)
(* One environment, one route `r`, two hosts. The route sends its keys    *)
(* (K, and K2 beside it) in one request; with OneVersion they are decided  *)
(* together, so the model tracks K's decision and K2's version only. The   *)
(* definition is one object of the vault's log (a `proxy` object): `defs[v]` *)
(* is what change v left, its host and its clearance (the most sensitive   *)
(* nature it may send: "sensitive" when an Owner covering the place saved  *)
(* it, else "secret"). The row is a version (its seal) and a body (its     *)
(* host). Honest code writes the newest version with its body. A database  *)
(* writer with no key may put back an earlier version, body and seal       *)
(* (Tamper), or change the body under the seal it finds (Forge): a seal is *)
(* a MAC over the body, so the vault refuses a forged row (`tampered`),    *)
(* always; only a row put back passes a MAC. With one route, the version   *)
(* stands for the design's item digest and its sealed index entry          *)
(* (proxy-ui.md, section 2): the copy names it, and the vault omits the    *)
(* body when the row's item still has it.                                  *)
(*                                                                         *)
(* Isolates (Iso): each runs one deployment's code, which defines `r` or   *)
(* not (code[i]); two may serve at once, during a deploy. A use, in the    *)
(* code:                                                                   *)
(*   the app resolves `r` (Resolve): code first; else the environment's    *)
(*   UI definition, by the copy the isolate keeps (copy[i]: a seal and a   *)
(*   body), which only saves bytes;                                        *)
(*   the vault's one call (Decide): under the fence shared, the row, its   *)
(*   MAC, the seal of the newest change, and the key's nature, in one      *)
(*   snapshot; it allows or refuses, and answers with the body decided on, *)
(*   or, when the isolate's copy carries that version, omits the body;     *)
(*   the request goes out (Send): to the kept definition's upstream,       *)
(*   while the kept values serve (`cacheSeconds`, or the use's deadline    *)
(*   with no cache: W ticks after the decision).                           *)
(* An edit (Edit) is a change: under the fence exclusive, so no use        *)
(* overlaps it (HotPathOne.tla proves that part for any input); here it is *)
(* one step. An Owner may route a sensitive key; anyone else with          *)
(* proxy.edit only a key that is secret now (the save's own check). The    *)
(* page refuses a name its own isolate's code defines.                     *)
(*                                                                         *)
(* Code names: the log keeps the names code has reserved (`reserved`, for  *)
(* `r`). An isolate, before its first proxy request, adds its code's names *)
(* to them (LogCode, a `proxy.code` change when it adds one), deleting the *)
(* UI definition of a name it adds, whole in the entry. A reservation is   *)
(* never dropped by a deploy, only by an instance Owner's audited release, *)
(* which the app refuses where its code has the name (Release). A code     *)
(* name is taken in every environment, whatever the code item's scope, so  *)
(* only code, never a rename, changes what is reserved. `shadowed` is a    *)
(* ghost: the UI versions some isolate's code hid, when it reserved the    *)
(* name or showed the version locked.                                      *)
(*                                                                         *)
(* Releases: the app's isolates and the vault each run one (appv, vaultv). *)
(* A deploy or a rollback moves both Workers, one after the other; every   *)
(* call carries the app's release, and the vault refuses one on another    *)
(* release before it reads anything (503 `deploying`, Refused). Code[i]    *)
(* is a deployment's config, not its release: two configs of one release  *)
(* serve together during a deploy that changes `credentialProxy` alone.    *)
(*                                                                         *)
(* Protections, each a constant, TRUE in the code:                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Iso,            \* the isolates
    Hosts,          \* where a definition may point: {"good", "evil"}
    W,              \* how long a decision's values serve, in ticks: cacheSeconds, or the deadline
    MaxTime,        \* how far the clock runs
    MaxEdits,       \* saves of `r` in the UI
    MaxTampers,     \* rows a database writer puts back or forges
    MaxMarks,       \* K made sensitive (once)
    MaxDeploys,     \* isolates restarted on code that flips whether it defines `r`
    MaxReleases,    \* an instance Owner's releases of a reserved name
    MaxMoves,       \* Workers moved to another release (a deploy or a rollback), one at a time
    Budget          \* proxy requests the isolates make

CONSTANTS
    \* The use reads the definition in the statement after the fence, in
    \* one snapshot with its decision (else: read before, decided after).
    FencedRead,
    \* The row's seal must be its newest change's (`stale`).
    SealChecked,
    \* The isolate's copy comes only from the vault's answers, never from a
    \* read of its own (the page's, or a bootstrap): so a digest it sends,
    \* for which the vault omits the body, stands for a body the vault checked.
    CopyFromVault,
    \* The app sends by the definition the vault decided on (its answer's
    \* body, or the copy whose digest made it omit the body), never by a copy
    \* the vault did not check.
    SentAsDecided,
    \* Kept values go only where the definition they were decided under says
    \* (each value-cache entry carries its item and seal), never where a newer
    \* copy says.
    BoundToDefinition,
    \* Kept values serve W ticks after their decision, no longer.
    KeptExpires,
    \* A route's keys are all decided on one version: one statement, and any
    \* later round of the same use must find the same seal (else `moved`);
    \* the app sends only answers that all carry one seal. Else a later
    \* round decides K2 on whatever version is newest then.
    OneVersion,
    \* The use weighs the key's nature now against the definition's
    \* clearance (else only the save checked it, against the nature then).
    ClearanceAtUse,
    \* A `proxy.code` change that reserves `r` deletes its UI definition.
    ClearSuperseded,
    \* The vault refuses a save of a reserved name, whatever the saving
    \* isolate's code says (an older deployment's isolate, still serving).
    SaveChecksReserved,
    \* An isolate serves nothing of the proxy before its code's names are
    \* reserved in the log.
    CodeGate,
    \* The vault refuses a call whose release is not its own, before any read.
    VersionGate

None == "none"
NoCopy == [ver |-> 0, host |-> None]
NoKept == [ver |-> 0, host |-> None, at |-> 0, newest |-> FALSE, nat |-> None, revived |-> FALSE,
           ver2 |-> 0, newest2 |-> FALSE]
NoSnap == [ver |-> 0, host |-> None, newest |-> 0]

VARIABLES
    now,
    defs,       \* the log: defs[v], what change v left: [host, clearance]
    row,        \* the row: [ver (its seal), host (its body)]
    nature,     \* K's nature: "secret" or "sensitive"
    reserved,   \* the log's code names include `r`
    code,       \* code[i]: isolate i's code defines `r`
    logged,     \* logged[i]: isolate i's names are reserved (or it found them so)
    shadowed,   \* ghost: UI versions an isolate's code hid
    copy,       \* copy[i]: the isolate's copy of the definition
    snap,       \* snap[i]: without FencedRead, what its use read before the fence
    kept,       \* kept[i]: its value cache: the version decided, the host it sends to, when, ghosts
    sent,       \* ghost: every request that went out with K
    edits, tampers, marks, deploys, releases, left,
    appv,       \* appv[i]: the release isolate i runs (1 or 2)
    vaultv,     \* the release the vault runs
    moves,
    mismatched  \* ghost: a vault call read or changed state across two releases

gv == <<appv, vaultv, moves, mismatched>>
vars == <<now, defs, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent,
          edits, tampers, marks, deploys, releases, left, appv, vaultv, moves, mismatched>>

Newest == Len(defs)
Body(v) == defs[v].host

Init ==
    /\ now = 1
    /\ defs = <<[host |-> "good", clearance |-> "sensitive"]>>
    /\ row = [ver |-> 1, host |-> "good"]
    /\ nature = "secret"
    /\ reserved = FALSE
    /\ code = [i \in Iso |-> FALSE]
    /\ logged = [i \in Iso |-> TRUE]
    /\ shadowed = {}
    /\ copy = [i \in Iso |-> NoCopy]
    /\ snap = [i \in Iso |-> NoSnap]
    /\ kept = [i \in Iso |-> NoKept]
    /\ sent = {}
    /\ edits = 0 /\ tampers = 0 /\ marks = 0 /\ deploys = 0 /\ releases = 0
    /\ left = Budget
    /\ appv = [i \in Iso |-> 1] /\ vaultv = 1 /\ moves = 0 /\ mismatched = FALSE

\* A vault call by isolate i that reads or changes the route: with VersionGate,
\* only on the vault's own release; the ghost records one made across two.
Called(i) ==
    /\ VersionGate => appv[i] = vaultv
    /\ mismatched' = (mismatched \/ appv[i] # vaultv)
    /\ UNCHANGED <<appv, vaultv, moves>>

\* A change writes the newest version, its body with it.
Write(d) == /\ defs' = Append(defs, d) /\ row' = [ver |-> Newest + 1, host |-> d.host]

\* A save of `r` through isolate i's page: an Owner's (clearance
\* "sensitive") or another editor's, who may name only a key that is secret
\* now. The page refuses a name its code defines; the vault, with
\* SaveChecksReserved, a name the log reserves.
Edit(i, h, c) ==
    /\ Called(i)
    /\ edits < MaxEdits /\ ~code[i]
    /\ SaveChecksReserved => ~reserved
    /\ c = "secret" => nature = "secret"
    /\ Write([host |-> h, clearance |-> c])
    /\ edits' = edits + 1
    /\ UNCHANGED <<now, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, tampers, marks, deploys, releases, left>>

\* An Owner releases the reserved name, from an isolate whose code lacks it.
Release(i) ==
    /\ Called(i)
    /\ releases < MaxReleases /\ reserved /\ ~code[i]
    /\ reserved' = FALSE /\ releases' = releases + 1
    /\ UNCHANGED <<now, defs, row, nature, code, logged, shadowed, copy, snap, kept, sent, edits, tampers, marks, deploys, left>>

\* K made sensitive (`coffre mark`), a change of its own.
Mark ==
    /\ UNCHANGED gv
    /\ marks < MaxMarks /\ nature = "secret"
    /\ nature' = "sensitive" /\ marks' = marks + 1
    /\ UNCHANGED <<now, defs, row, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, tampers, deploys, releases, left>>

\* A database writer puts back a row the vault once sealed, body and seal.
Tamper(v) ==
    /\ UNCHANGED gv
    /\ tampers < MaxTampers /\ v \in 1..Newest
    /\ row # [ver |-> v, host |-> Body(v)]
    /\ row' = [ver |-> v, host |-> Body(v)] /\ tampers' = tampers + 1
    /\ UNCHANGED <<now, defs, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, marks, deploys, releases, left>>

\* ... or changes the body under the seal it finds: the MAC no longer holds.
Forge(h) ==
    /\ UNCHANGED gv
    /\ tampers < MaxTampers /\ h # row.host
    /\ row' = [row EXCEPT !.host = h] /\ tampers' = tampers + 1
    /\ UNCHANGED <<now, defs, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, marks, deploys, releases, left>>

\* Isolate i restarts on code that defines `r`, or no longer does: no copy,
\* no kept values, its names not yet reserved.
Deploy(i) ==
    /\ UNCHANGED gv
    /\ deploys < MaxDeploys
    /\ code' = [code EXCEPT ![i] = ~code[i]]
    /\ logged' = [logged EXCEPT ![i] = FALSE]
    /\ copy' = [copy EXCEPT ![i] = NoCopy]
    /\ snap' = [snap EXCEPT ![i] = NoSnap]
    /\ kept' = [kept EXCEPT ![i] = NoKept]
    /\ deploys' = deploys + 1
    /\ UNCHANGED <<now, defs, row, nature, reserved, shadowed, sent, edits, tampers, marks, releases, left>>

\* Before its first proxy request, the isolate reserves its code's names: a
\* `proxy.code` change when it adds one, which deletes the UI definition of
\* the name it reserves (a change: the newest version, "none").
LogCode(i) ==
    /\ Called(i)
    /\ ~logged[i]
    /\ logged' = [logged EXCEPT ![i] = TRUE]
    /\ IF code[i] /\ ~reserved
         THEN /\ reserved' = TRUE
              \* The UI version its code hides from now on, deleted or not.
              /\ shadowed' = IF Body(Newest) # None THEN shadowed \cup {Newest} ELSE shadowed
              /\ IF ClearSuperseded /\ Body(Newest) # None
                   THEN Write([host |-> None, clearance |-> None])
                   ELSE UNCHANGED <<defs, row>>
         ELSE UNCHANGED <<reserved, defs, row, shadowed>>
    /\ UNCHANGED <<now, nature, code, copy, snap, kept, sent, edits, tampers, marks, deploys, releases, left>>

Serving(i) == CodeGate => logged[i]

\* A deploy or a rollback, one Worker at a time: the vault, or an app isolate,
\* which restarts on the other release (no copy, no kept values, its names
\* not yet reserved).
MoveVault ==
    /\ moves < MaxMoves
    /\ vaultv' = 3 - vaultv /\ moves' = moves + 1
    /\ UNCHANGED <<appv, mismatched>>
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent,
                   edits, tampers, marks, deploys, releases, left>>

MoveApp(i) ==
    /\ moves < MaxMoves
    /\ appv' = [appv EXCEPT ![i] = 3 - appv[i]] /\ moves' = moves + 1
    /\ logged' = [logged EXCEPT ![i] = FALSE]
    /\ copy' = [copy EXCEPT ![i] = NoCopy]
    /\ snap' = [snap EXCEPT ![i] = NoSnap]
    /\ kept' = [kept EXCEPT ![i] = NoKept]
    /\ UNCHANGED <<vaultv, mismatched>>
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, shadowed, sent, edits, tampers, marks, deploys, releases, left>>

\* A proxy request whose call the vault refuses, its release not the vault's:
\* 503 `deploying`, nothing read, locked, written or logged.
Refused(i) ==
    /\ left > 0 /\ appv[i] # vaultv
    /\ left' = left - 1
    /\ UNCHANGED gv
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent,
                   edits, tampers, marks, deploys, releases>>

\* A proxy request resolves `r`, or the page shows it. Code first: the UI
\* definition, if any, is hidden (shadowed). Else, without CopyFromVault,
\* the isolate may fill its copy from a read of its own, no MAC checked.
Resolve(i) ==
    /\ UNCHANGED gv
    /\ left > 0 /\ Serving(i)
    /\ left' = left - 1
    /\ IF code[i]
         THEN /\ shadowed' = IF Body(Newest) # None THEN shadowed \cup {Newest} ELSE shadowed
              /\ UNCHANGED copy
         ELSE /\ copy' = IF CopyFromVault THEN copy ELSE [copy EXCEPT ![i] = [ver |-> row.ver, host |-> row.host]]
              /\ UNCHANGED shadowed
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, logged, snap, kept, sent, edits, tampers, marks, deploys, releases>>

\* Without FencedRead: the use's reads take their snapshot before the fence.
Read(i) ==
    /\ Called(i)
    /\ ~FencedRead /\ ~code[i] /\ Serving(i) /\ snap[i] = NoSnap
    /\ snap' = [snap EXCEPT ![i] = [ver |-> row.ver, host |-> row.host, newest |-> Newest]]
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, logged, shadowed, copy, kept, sent, edits, tampers, marks, deploys, releases, left>>

\* The vault's call decides on the row it read (in its own snapshot, or the
\* early one without FencedRead): refused if the row's MAC does not hold,
\* or (SealChecked) its seal is not the newest change's, or it holds no
\* definition, or (ClearanceAtUse) K is sensitive and the definition not an
\* Owner's. Allowed, it answers with the body it decided on, unless the
\* isolate's copy carries that version (the item digest), when it omits
\* the body. The app keeps the values with the upstream it will send them
\* to: the answer's (or the copy's, when the body was omitted), or, without SentAsDecided, its copy's whatever it is.
\* The value cache is per caller, the copy per route: a use by another
\* caller (~mine) refreshes the copy and leaves this caller's kept values.
\* A decision on a version code hid is a revival (the ghost, NoRevival);
\* values decided before code hid it serve out their W, as after an edit.
Decide(i, mine) ==
    /\ Called(i)
    /\ left > 0 /\ ~code[i] /\ Serving(i)
    /\ FencedRead \/ snap[i] # NoSnap
    /\ LET r       == IF FencedRead THEN [ver |-> row.ver, host |-> row.host, newest |-> Newest] ELSE snap[i]
           v       == r.ver
           macOK   == r.host = Body(v)
           sealOK  == ~SealChecked \/ v = r.newest
           clearOK == ~ClearanceAtUse \/ nature = "secret" \/ defs[v].clearance = "sensitive"
           allowed == macOK /\ sealOK /\ Body(v) # None /\ clearOK
           answer  == IF copy[i].ver = v THEN copy[i].host ELSE Body(v)
           sendTo  == IF SentAsDecided \/ copy[i] = NoCopy THEN answer ELSE copy[i].host
       IN /\ kept' = IF allowed /\ mine
                       THEN [kept EXCEPT ![i] = [ver |-> v, host |-> sendTo, at |-> now, newest |-> v = Newest, nat |-> nature,
                                                 revived |-> v \in shadowed,
                                                 ver2 |-> IF OneVersion THEN v ELSE 0,
                                                 newest2 |-> OneVersion /\ v = Newest]]
                       ELSE kept
          /\ copy' = IF allowed /\ (SentAsDecided \/ copy[i] = NoCopy)
                       THEN [copy EXCEPT ![i] = [ver |-> v, host |-> answer]]
                       ELSE copy
    /\ snap' = [snap EXCEPT ![i] = NoSnap]
    /\ left' = left - 1
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, logged, shadowed, sent, edits, tampers, marks, deploys, releases>>

\* Without OneVersion: a later round of the same use decides K2, on the row
\* it reads then (fenced, checked as Decide checks). Refused, nothing is sent.
DecideSecond(i) ==
    /\ Called(i)
    /\ ~OneVersion /\ ~code[i] /\ Serving(i)
    /\ kept[i].ver # 0 /\ kept[i].ver2 = 0
    /\ LET v       == row.ver
           allowed == /\ row.host = Body(v)
                      /\ ~SealChecked \/ v = Newest
                      /\ Body(v) # None
                      /\ ~ClearanceAtUse \/ nature = "secret" \/ defs[v].clearance = "sensitive"
       IN kept' = IF allowed THEN [kept EXCEPT ![i].ver2 = v, ![i].newest2 = (v = Newest)]
                             ELSE [kept EXCEPT ![i] = NoKept]
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, logged, shadowed, copy, snap, sent, edits, tampers, marks, deploys, releases, left>>

\* A request goes out with the kept values: to the kept definition's
\* upstream, or, not bound to it, wherever the isolate's copy says now.
Send(i) ==
    /\ UNCHANGED gv
    /\ kept[i].ver # 0 /\ kept[i].ver2 # 0 /\ ~code[i]
    /\ KeptExpires => now < kept[i].at + W
    /\ LET h == IF BoundToDefinition \/ copy[i] = NoCopy THEN kept[i].host ELSE copy[i].host
       IN /\ h # None
          /\ sent' = sent \cup {[host |-> h, ver |-> kept[i].ver, at |-> kept[i].at, sentAt |-> now,
                                 newest |-> kept[i].newest, nat |-> kept[i].nat,
                                 stillNewest |-> kept[i].ver = Newest, revived |-> kept[i].revived,
                                 ver2 |-> kept[i].ver2, newest2 |-> kept[i].newest2]}
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, logged, shadowed, copy, snap, kept, edits, tampers, marks, deploys, releases, left>>

Tick ==
    /\ UNCHANGED gv
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<defs, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, tampers, marks, deploys, releases, left>>

Done == now = MaxTime /\ left = 0 /\ UNCHANGED vars

Next ==
    \/ \E i \in Iso, h \in Hosts, c \in {"secret", "sensitive"} : Edit(i, h, c)
    \/ \E i \in Iso : Release(i) \/ Deploy(i) \/ LogCode(i) \/ Resolve(i) \/ Read(i) \/ DecideSecond(i) \/ Send(i)
    \/ \E i \in Iso : MoveApp(i) \/ Refused(i)
    \/ MoveVault
    \/ \E i \in Iso, mine \in BOOLEAN : Decide(i, mine)
    \/ Mark
    \/ \E v \in 1..Newest : Tamper(v)
    \/ \E h \in Hosts : Forge(h)
    \/ Tick \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 1..MaxTime
    /\ row.ver \in 1..Newest
    /\ nature \in {"secret", "sensitive"}
    /\ \A i \in Iso : copy[i].ver \in 0..Newest /\ kept[i].ver \in 0..Newest /\ kept[i].ver2 \in 0..Newest

(***************************************************************************)
(* Every request that carried K went where a definition the vault decided  *)
(* on says, a definition that was the log's newest when it decided (not    *)
(* one put back or forged, nor one an edit had replaced), and one cleared  *)
(* for K's nature then: a sensitive key only by an Owner's definition. And *)
(* K2, in the same request, likewise, by the version it was decided on.    *)
(***************************************************************************)
EverySendAllowed ==
    \A s \in sent :
        /\ s.newest /\ s.newest2
        /\ s.host = Body(s.ver) /\ s.host = Body(s.ver2)
        /\ s.nat = "sensitive" => defs[s.ver].clearance = "sensitive" /\ defs[s.ver2].clearance = "sensitive"

\* And within W of that decision: an edit stops the old upstream's requests
\* W after it at the latest (a minute by default, a revocation's bound).
WithinWindow == \A s \in sent : s.sentAt < s.at + W

\* No vault call reads or changes the route across two releases: each one
\* made while the isolate's release and the vault's differ is refused.
MismatchInert == ~mismatched

\* A UI definition that code hid is never decided on again: nobody looked
\* at it while it was locked. (Values decided on it before code hid it
\* serve out their W, the window StrictlyCurrent documents.)
NoRevival == \A s \in sent : ~s.revived

(***************************************************************************)
(* The window the design leaves (EXPECTED): no request goes out under a    *)
(* definition an edit has replaced. Values decided before an edit serve    *)
(* out their W, as a revoked handle's do.                                  *)
(***************************************************************************)
StrictlyCurrent == \A s \in sent : s.stillNewest

\* A witness, not a gap (EXPECTED in RoutingCode): code does hide a UI
\* version in the protected runs, so NoRevival is not held vacuously.
NeverShadowed == shadowed = {}

=============================================================================
