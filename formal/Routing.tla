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
(* The newest change's seal is the vault's here: the vault trusts it       *)
(* only once that change's MAC holds (T190, ChangeMacChecked; the writer   *)
(* who writes a put-back row's seal into it is HotPathOneForged's), so     *)
(* no row put back passes as the newest.                                   *)
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
(* Editors: Ada, an Owner covering the place, and Lin, who reads secrets.  *)
(* A save freezes its editor's standing into the version (its clearance);  *)
(* the editor's standing may change after (Restand: Lin made an Owner,     *)
(* Ada demoted to Developer, either removed), a change of the editor's     *)
(* principal object. Each use decides the route's keys for the frozen      *)
(* clearance intersected with the editor's standing now (proxy-ui.md,      *)
(* decision 5(b)): the use's statement reads the editor's principal in the *)
(* same snapshot as the row.                                               *)
(*                                                                         *)
(* The caller and the key (T205): Bo's handle at the place, whose standing *)
(* there an Owner may revoke or give back (Revoke), and the key the route  *)
(* names, which an edit may change (`defs[v].key`, among Keys: K, or M, a  *)
(* key that stays secret). The vault's call, in its one snapshot, decides  *)
(* Bo's standing first and reads the route only for one who stands        *)
(* (StandingFirst); it resolves the key by the name the row it read gives *)
(* (by name, as a code route's named call does); the isolate's map keeps  *)
(* the id an earlier answer resolved (`mapKey[i]`), which only lets the    *)
(* call make the use when it is the name's now (KeyByItem; else `moved`,   *)
(* nothing used, and the vault asks again by the new id). A cold map (none)*)
(* is a miss: two calls, the second by the ids the first read, the same    *)
(* check in its own snapshot, so the model takes them as one step.         *)
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
    MaxRestands,    \* changes of an editor's standing (promoted, demoted, removed)
    MaxRevokes,     \* changes of the caller's standing at the place (revoked, given back)
    Keys,           \* the keys a save may name: {"K"}, or {"K", "M"}
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
    VersionGate,
    \* The use weighs the key's nature now against its editor's standing now,
    \* read in the same snapshot (else only the standing the save froze).
    EditorStillHolds,
    \* The call decides the caller's standing at the place first, from rows
    \* no key decides, and reads the route and its key only for one who
    \* stands (else it reads them for a caller it then refuses).
    StandingFirst,
    \* The call makes the use by the map's id only when it is the key the row
    \* it read names now, resolved by that name in the same snapshot (else
    \* `moved`); else the map's id, an earlier answer's, makes it.
    KeyByItem

None == "none"
Editors == {"ada", "lin"}
\* How much of K a standing may read: a removed editor nothing, a Developer
\* secrets, an Owner covering the place sensitive values too.
Rank(x) == CASE x = "sensitive" -> 2 [] x = "secret" -> 1 [] OTHER -> 0
Reads(st, n) == Rank(st) >= Rank(n)
NoCopy == [ver |-> 0, host |-> None]
NoKept == [ver |-> 0, host |-> None, at |-> 0, newest |-> FALSE, nat |-> None, revived |-> FALSE,
           ver2 |-> 0, newest2 |-> FALSE, held |-> FALSE, held2 |-> FALSE, key |-> None, stood |-> FALSE]
NoSnap == [ver |-> 0, host |-> None, key |-> None, newest |-> 0, standing |-> [e \in Editors |-> None], stands |-> FALSE]

VARIABLES
    now,
    defs,       \* the log: defs[v], what change v left: [host, clearance, editor]
    standing,   \* standing[e]: editor e's standing now: "sensitive", "secret" or "none"
    row,        \* the row: [ver (its seal), host and key (its body)]
    nature,     \* K's nature: "secret" or "sensitive" (M's is "secret")
    stands,     \* the caller's standing at the place: whether Bo may use its keys
    mapKey,     \* mapKey[i]: the key id isolate i's map holds for the route, None when cold
    readUnstood, \* ghost: a call read the route or its key for a caller who did not stand
    reserved,   \* the log's code names include `r`
    code,       \* code[i]: isolate i's code defines `r`
    logged,     \* logged[i]: isolate i's names are reserved (or it found them so)
    shadowed,   \* ghost: UI versions an isolate's code hid
    copy,       \* copy[i]: the isolate's copy of the definition
    snap,       \* snap[i]: without FencedRead, what its use read before the fence
    kept,       \* kept[i]: its value cache: the version decided, the host it sends to, when, ghosts
    sent,       \* ghost: every request that went out with K
    edits, tampers, marks, restands, revokes, deploys, releases, left,
    appv,       \* appv[i]: the release isolate i runs (1 or 2)
    vaultv,     \* the release the vault runs
    moves,
    mismatched  \* ghost: a vault call read or changed state across two releases

gv == <<appv, vaultv, moves, mismatched>>
rv == <<stands, mapKey, readUnstood, revokes>>
vars == <<now, defs, standing, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent,
          edits, tampers, marks, restands, deploys, releases, left, appv, vaultv, moves, mismatched, rv>>

Newest == Len(defs)
Body(v) == defs[v].host
KeyOf(v) == defs[v].key
\* A key's nature now: K's may be marked sensitive; M stays secret.
NatureOf(k) == IF k = "K" THEN nature ELSE "secret"
\* Whether version v's editor, by the standing st gives them, reads key k now;
\* the key the version names, by default.
EditorReadsKey(v, st, k) == Body(v) # None /\ Reads(st[defs[v].editor], NatureOf(k))
EditorReads(v, st) == EditorReadsKey(v, st, KeyOf(v))

Init ==
    /\ now = 1
    /\ defs = <<[host |-> "good", clearance |-> "sensitive", editor |-> "ada", key |-> "K"]>>
    /\ standing = [e \in Editors |-> IF e = "ada" THEN "sensitive" ELSE "secret"]
    /\ row = [ver |-> 1, host |-> "good", key |-> "K"]
    /\ nature = "secret"
    /\ stands = TRUE /\ mapKey = [i \in Iso |-> None] /\ readUnstood = FALSE /\ revokes = 0
    /\ reserved = FALSE
    /\ code = [i \in Iso |-> FALSE]
    /\ logged = [i \in Iso |-> TRUE]
    /\ shadowed = {}
    /\ copy = [i \in Iso |-> NoCopy]
    /\ snap = [i \in Iso |-> NoSnap]
    /\ kept = [i \in Iso |-> NoKept]
    /\ sent = {}
    /\ edits = 0 /\ tampers = 0 /\ marks = 0 /\ restands = 0 /\ deploys = 0 /\ releases = 0
    /\ left = Budget
    /\ appv = [i \in Iso |-> 1] /\ vaultv = 1 /\ moves = 0 /\ mismatched = FALSE

\* A vault call by isolate i that reads or changes the route: with VersionGate,
\* only on the vault's own release; the ghost records one made across two.
Called(i) ==
    /\ VersionGate => appv[i] = vaultv
    /\ mismatched' = (mismatched \/ appv[i] # vaultv)
    /\ UNCHANGED <<appv, vaultv, moves>>

\* A change writes the newest version, its body with it.
Write(d) == /\ defs' = Append(defs, d) /\ row' = [ver |-> Newest + 1, host |-> d.host, key |-> d.key]

\* A save of `r` by editor e through isolate i's page, freezing e's standing
\* now as the version's clearance: an Owner's ("sensitive"), or another
\* editor's ("secret"), who may name only a key that is secret now. A
\* removed editor saves nothing. The page refuses a name its code defines;
\* the vault, with SaveChecksReserved, a name the log reserves. The save
\* names the route's key, k: K, or M (T205), as the editor may read it now.
Edit(i, h, e, k) ==
    /\ Called(i)
    /\ UNCHANGED rv
    /\ edits < MaxEdits /\ ~code[i]
    /\ SaveChecksReserved => ~reserved
    /\ standing[e] # "none"
    /\ Reads(standing[e], NatureOf(k))
    /\ Write([host |-> h, clearance |-> standing[e], editor |-> e, key |-> k])
    /\ edits' = edits + 1
    /\ UNCHANGED <<now, standing, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, tampers, marks, restands, deploys, releases, left>>

\* An Owner releases the reserved name, from an isolate whose code lacks it.
Release(i) ==
    /\ UNCHANGED rv
    /\ Called(i)
    /\ releases < MaxReleases /\ reserved /\ ~code[i]
    /\ reserved' = FALSE /\ releases' = releases + 1
    /\ UNCHANGED <<now, defs, standing, row, nature, code, logged, shadowed, copy, snap, kept, sent, edits, tampers, marks, restands, deploys, left>>

\* K made sensitive (`coffre mark`), a change of its own.
Mark ==
    /\ UNCHANGED rv
    /\ UNCHANGED gv
    /\ marks < MaxMarks /\ nature = "secret"
    /\ nature' = "sensitive" /\ marks' = marks + 1
    /\ UNCHANGED <<now, defs, standing, row, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, tampers, restands, deploys, releases, left>>

\* An editor's standing changes (a role edit, a demotion, a removal from the
\* instance): a change of their principal object, under the fence like any.
Restand(e, st) ==
    /\ UNCHANGED rv
    /\ UNCHANGED gv
    /\ restands < MaxRestands /\ st # standing[e]
    /\ standing' = [standing EXCEPT ![e] = st] /\ restands' = restands + 1
    /\ UNCHANGED <<now, defs, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, tampers, marks, deploys, releases, left>>

\* A database writer puts back a row the vault once sealed, body and seal.
Tamper(v) ==
    /\ UNCHANGED gv /\ UNCHANGED rv
    /\ tampers < MaxTampers /\ v \in 1..Newest
    /\ row # [ver |-> v, host |-> Body(v), key |-> KeyOf(v)]
    /\ row' = [ver |-> v, host |-> Body(v), key |-> KeyOf(v)] /\ tampers' = tampers + 1
    /\ UNCHANGED <<now, defs, standing, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, marks, restands, deploys, releases, left>>

\* ... or changes the body under the seal it finds, its host or the key it
\* names: the MAC no longer holds.
Forge(h, k) ==
    /\ UNCHANGED gv /\ UNCHANGED rv
    /\ tampers < MaxTampers /\ <<h, k>> # <<row.host, row.key>>
    /\ row' = [row EXCEPT !.host = h, !.key = k] /\ tampers' = tampers + 1
    /\ UNCHANGED <<now, defs, standing, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, marks, restands, deploys, releases, left>>

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
    /\ mapKey' = [mapKey EXCEPT ![i] = None]
    /\ UNCHANGED <<stands, readUnstood, revokes>>
    /\ deploys' = deploys + 1
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, shadowed, sent, edits, tampers, marks, restands, releases, left>>

\* Before its first proxy request, the isolate reserves its code's names: a
\* `proxy.code` change when it adds one, which deletes the UI definition of
\* the name it reserves (a change: the newest version, "none").
LogCode(i) ==
    /\ UNCHANGED rv
    /\ Called(i)
    /\ ~logged[i]
    /\ logged' = [logged EXCEPT ![i] = TRUE]
    /\ IF code[i] /\ ~reserved
         THEN /\ reserved' = TRUE
              \* The UI version its code hides from now on, deleted or not.
              /\ shadowed' = IF Body(Newest) # None THEN shadowed \cup {Newest} ELSE shadowed
              /\ IF ClearSuperseded /\ Body(Newest) # None
                   THEN Write([host |-> None, clearance |-> None, editor |-> None, key |-> None])
                   ELSE UNCHANGED <<defs, row>>
         ELSE UNCHANGED <<reserved, defs, row, shadowed>>
    /\ UNCHANGED <<now, standing, nature, code, copy, snap, kept, sent, edits, tampers, marks, restands, deploys, releases, left>>

Serving(i) == CodeGate => logged[i]

\* A deploy or a rollback, one Worker at a time: the vault, or an app isolate,
\* which restarts on the other release (no copy, no kept values, its names
\* not yet reserved).
MoveVault ==
    /\ UNCHANGED rv
    /\ moves < MaxMoves
    /\ vaultv' = 3 - vaultv /\ moves' = moves + 1
    /\ UNCHANGED <<appv, mismatched>>
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent,
                   edits, tampers, marks, restands, deploys, releases, left>>

MoveApp(i) ==
    /\ moves < MaxMoves
    /\ appv' = [appv EXCEPT ![i] = 3 - appv[i]] /\ moves' = moves + 1
    /\ logged' = [logged EXCEPT ![i] = FALSE]
    /\ copy' = [copy EXCEPT ![i] = NoCopy]
    /\ snap' = [snap EXCEPT ![i] = NoSnap]
    /\ kept' = [kept EXCEPT ![i] = NoKept]
    /\ mapKey' = [mapKey EXCEPT ![i] = None]
    /\ UNCHANGED <<stands, readUnstood, revokes>>
    /\ UNCHANGED <<vaultv, mismatched>>
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, shadowed, sent, edits, tampers, marks, restands, deploys, releases, left>>

\* A proxy request whose call the vault refuses, its release not the vault's:
\* 503 `deploying`, nothing read, locked, written or logged.
Refused(i) ==
    /\ UNCHANGED rv
    /\ left > 0 /\ appv[i] # vaultv
    /\ left' = left - 1
    /\ UNCHANGED gv
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent,
                   edits, tampers, marks, restands, deploys, releases>>

\* A proxy request resolves `r`, or the page shows it. Code first: the UI
\* definition, if any, is hidden (shadowed). Else, without CopyFromVault,
\* the isolate may fill its copy from a read of its own, no MAC checked.
Resolve(i) ==
    /\ UNCHANGED rv
    /\ UNCHANGED gv
    /\ left > 0 /\ Serving(i)
    /\ left' = left - 1
    /\ IF code[i]
         THEN /\ shadowed' = IF Body(Newest) # None THEN shadowed \cup {Newest} ELSE shadowed
              /\ UNCHANGED copy
         ELSE /\ copy' = IF CopyFromVault THEN copy ELSE [copy EXCEPT ![i] = [ver |-> row.ver, host |-> row.host]]
              /\ UNCHANGED shadowed
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, logged, snap, kept, sent, edits, tampers, marks, restands, deploys, releases>>

\* Without FencedRead: the use's reads take their snapshot before the fence.
Read(i) ==
    /\ Called(i)
    /\ UNCHANGED rv
    /\ ~FencedRead /\ ~code[i] /\ Serving(i) /\ snap[i] = NoSnap
    /\ snap' = [snap EXCEPT ![i] = [ver |-> row.ver, host |-> row.host, key |-> row.key, newest |-> Newest, standing |-> standing, stands |-> stands]]
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, logged, shadowed, copy, kept, sent, edits, tampers, marks, restands, deploys, releases, left>>

\* The vault's call decides on the row it read (in its own snapshot, or the
\* early one without FencedRead): refused if the row's MAC does not hold,
\* or (SealChecked) its seal is not the newest change's, or it holds no
\* definition, or (ClearanceAtUse) K is sensitive and the definition not an
\* Owner's, or (EditorStillHolds) the definition's editor, as the snapshot
\* reads their principal, no longer reads K. Allowed, it answers with the body it decided on, unless the
\* isolate's copy carries that version (the item digest), when it omits
\* the body. The app keeps the values with the upstream it will send them
\* to: the answer's (or the copy's, when the body was omitted), or, without SentAsDecided, its copy's whatever it is.
\* The value cache is per caller, the copy per route: a use by another
\* caller (~mine) refreshes the copy and leaves this caller's kept values.
\* A decision on a version code hid is a revival (the ghost, NoRevival);
\* values decided before code hid it serve out their W, as after an edit.
Decide(i, mine) ==
    /\ Called(i)
    /\ UNCHANGED <<stands, revokes>>
    /\ left > 0 /\ ~code[i] /\ Serving(i)
    /\ FencedRead \/ snap[i] # NoSnap
    /\ LET r       == IF FencedRead THEN [ver |-> row.ver, host |-> row.host, key |-> row.key, newest |-> Newest, standing |-> standing, stands |-> stands]
                      ELSE snap[i]
           v       == r.ver
           \* The route and its key read (T205): for a caller who stands at the
           \* place, or, without StandingFirst, for anyone.
           routed  == r.stands \/ ~StandingFirst
           \* The key the use is made of: the one the row read names, resolved
           \* by that name; the map's id makes it only when it is that one
           \* (KeyByItem: else `moved`, nothing used). Without KeyByItem, the
           \* map's id makes it whatever the row names. A cold map, a miss: by
           \* the name, in the call that reads it again.
           named   == r.key
           usedKey == IF KeyByItem \/ mapKey[i] = None THEN named ELSE mapKey[i]
           moved   == KeyByItem /\ mapKey[i] \notin {None, named}
           macOK   == r.host = Body(v) /\ r.key = KeyOf(v)
           sealOK  == ~SealChecked \/ v = r.newest
           clearOK == ~ClearanceAtUse \/ NatureOf(usedKey) = "secret" \/ defs[v].clearance = "sensitive"
           heldOK  == ~EditorStillHolds \/ EditorReadsKey(v, r.standing, usedKey)
           allowed == r.stands /\ routed /\ ~moved /\ usedKey # None /\ macOK /\ sealOK /\ Body(v) # None /\ clearOK /\ heldOK
           \* The ghosts: the editor reads the key by their standing when the use
           \* is decided; the caller stands there then.
           held    == EditorReadsKey(v, standing, usedKey)
           answer  == IF copy[i].ver = v THEN copy[i].host ELSE Body(v)
           sendTo  == IF SentAsDecided \/ copy[i] = NoCopy THEN answer ELSE copy[i].host
       IN /\ kept' = IF allowed /\ mine
                       THEN [kept EXCEPT ![i] = [ver |-> v, host |-> sendTo, at |-> now, newest |-> v = Newest, nat |-> NatureOf(usedKey),
                                                 revived |-> v \in shadowed,
                                                 ver2 |-> IF OneVersion THEN v ELSE 0,
                                                 newest2 |-> OneVersion /\ v = Newest,
                                                 held |-> held, held2 |-> OneVersion /\ held,
                                                 key |-> usedKey, stood |-> stands]]
                       ELSE kept
          /\ copy' = IF allowed /\ (SentAsDecided \/ copy[i] = NoCopy)
                       THEN [copy EXCEPT ![i] = [ver |-> v, host |-> answer]]
                       ELSE copy
          \* The map keeps the id the call resolved, whenever it read the route.
          /\ mapKey' = IF routed /\ named # None THEN [mapKey EXCEPT ![i] = named] ELSE mapKey
          /\ readUnstood' = (readUnstood \/ (routed /\ ~r.stands))
    /\ snap' = [snap EXCEPT ![i] = NoSnap]
    /\ left' = left - 1
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, logged, shadowed, sent, edits, tampers, marks, restands, deploys, releases>>

\* Without OneVersion: a later round of the same use decides K2, on the row
\* it reads then (fenced, checked as Decide checks). Refused, nothing is sent.
DecideSecond(i) ==
    /\ UNCHANGED rv
    /\ Called(i)
    /\ ~OneVersion /\ ~code[i] /\ Serving(i)
    /\ kept[i].ver # 0 /\ kept[i].ver2 = 0
    /\ LET v       == row.ver
           allowed == /\ row.host = Body(v)
                      /\ ~SealChecked \/ v = Newest
                      /\ Body(v) # None
                      /\ ~ClearanceAtUse \/ nature = "secret" \/ defs[v].clearance = "sensitive"
                      /\ ~EditorStillHolds \/ EditorReads(v, standing)
       IN kept' = IF allowed THEN [kept EXCEPT ![i].ver2 = v, ![i].newest2 = (v = Newest),
                                               ![i].held2 = EditorReads(v, standing)]
                             ELSE [kept EXCEPT ![i] = NoKept]
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, logged, shadowed, copy, snap, sent, edits, tampers, marks, restands, deploys, releases, left>>

\* A request goes out with the kept values: to the kept definition's
\* upstream, or, not bound to it, wherever the isolate's copy says now.
Send(i) ==
    /\ UNCHANGED gv /\ UNCHANGED rv
    /\ kept[i].ver # 0 /\ kept[i].ver2 # 0 /\ ~code[i]
    /\ KeptExpires => now < kept[i].at + W
    /\ LET h == IF BoundToDefinition \/ copy[i] = NoCopy THEN kept[i].host ELSE copy[i].host
       IN /\ h # None
          /\ sent' = sent \cup {[host |-> h, ver |-> kept[i].ver, at |-> kept[i].at, sentAt |-> now,
                                 newest |-> kept[i].newest, nat |-> kept[i].nat,
                                 stillNewest |-> kept[i].ver = Newest, revived |-> kept[i].revived,
                                 ver2 |-> kept[i].ver2, newest2 |-> kept[i].newest2,
                                 held |-> kept[i].held, held2 |-> kept[i].held2,
                                 key |-> kept[i].key, stood |-> kept[i].stood]}
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, logged, shadowed, copy, snap, kept, edits, tampers, marks, restands, deploys, releases, left>>

\* The caller's standing at the place changes (T205): an Owner revokes Bo's
\* grant, or gives it back, a change under the fence like any.
Revoke ==
    /\ UNCHANGED gv
    /\ revokes < MaxRevokes
    /\ stands' = ~stands /\ revokes' = revokes + 1
    /\ UNCHANGED <<mapKey, readUnstood>>
    /\ UNCHANGED <<now, defs, standing, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, tampers, marks, restands, deploys, releases, left>>

Tick ==
    /\ UNCHANGED rv
    /\ UNCHANGED gv
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<defs, standing, row, nature, reserved, code, logged, shadowed, copy, snap, kept, sent, edits, tampers, marks, restands, deploys, releases, left>>

Done == now = MaxTime /\ left = 0 /\ UNCHANGED vars

Next ==
    \/ \E i \in Iso, h \in Hosts, e \in Editors, k \in Keys : Edit(i, h, e, k)
    \/ \E e \in Editors, st \in {"sensitive", "secret", "none"} : Restand(e, st)
    \/ \E i \in Iso : Release(i) \/ Deploy(i) \/ LogCode(i) \/ Resolve(i) \/ Read(i) \/ DecideSecond(i) \/ Send(i)
    \/ \E i \in Iso : MoveApp(i) \/ Refused(i)
    \/ MoveVault
    \/ \E i \in Iso, mine \in BOOLEAN : Decide(i, mine)
    \/ Mark \/ Revoke
    \/ \E v \in 1..Newest : Tamper(v)
    \/ \E h \in Hosts, k \in Keys : Forge(h, k)
    \/ Tick \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ now \in 1..MaxTime
    /\ row.ver \in 1..Newest
    /\ nature \in {"secret", "sensitive"}
    /\ \A i \in Iso : copy[i].ver \in 0..Newest /\ kept[i].ver \in 0..Newest /\ kept[i].ver2 \in 0..Newest
    /\ \A e \in Editors : standing[e] \in {"sensitive", "secret", "none"}
    /\ \A i \in Iso : mapKey[i] \in Keys \cup {None}

(***************************************************************************)
(* Every request that carried K went where a definition the vault decided  *)
(* on says, a definition that was the log's newest when it decided (not    *)
(* one put back or forged, nor one an edit had replaced), and one cleared  *)
(* for K's nature then: a sensitive key only by an Owner's definition, and *)
(* only while its editor still read K by their standing at that decision   *)
(* (a demoted or removed editor's route stops). And K2, in the same        *)
(* request, likewise, by the version it was decided on. The key it carried *)
(* is the one that version names (T205), and its caller stood at the place *)
(* when the use was decided.                                               *)
(***************************************************************************)
EverySendAllowed ==
    \A s \in sent :
        /\ s.newest /\ s.newest2
        /\ s.host = Body(s.ver) /\ s.host = Body(s.ver2)
        /\ s.nat = "sensitive" => defs[s.ver].clearance = "sensitive" /\ defs[s.ver2].clearance = "sensitive"
        /\ s.held /\ s.held2
        /\ s.key = KeyOf(s.ver) /\ s.stood

\* No call reads the route, or a key it names, for a caller who does not
\* stand at the place (T205): what it would read there hangs on the route
\* and the key, which the caller has no standing to learn of (Probing.tla's
\* NoKeyBeforeStanding, for a route).
NoRouteBeforeStanding == ~readUnstood

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
