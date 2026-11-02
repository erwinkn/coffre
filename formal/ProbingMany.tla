----------------------------- MODULE ProbingMany -----------------------------
(***************************************************************************)
(* What a caller learns of a place's keys by asking for several at once    *)
(* (T165, B2's second PR; D153): Probing.tla's claims, for a request of    *)
(* several keys. Ada asks for two keys by name at a place (`coffre export *)
(* --keys K1,K2`, the proxy's two keys of a credential), or for every key  *)
(* it holds (`coffre export`, a reveal of `market/dev`), to use them or to *)
(* read them, while her grant there, or at the fork's parent, may be       *)
(* revoked, and the fork's chain cut. Two runs go side by side, alike in   *)
(* everything but the keys: in run A someone makes each key, a sealed      *)
(* value, a plain one or a sensitive one, at the place or (a fork, her     *)
(* personal config) at its parent, inherited or removed there, ends its    *)
(* value (a reference whose source is gone) or deletes it; in run B nobody *)
(* ever makes one. So a batch may be mixed: one key held, one never made,  *)
(* one inherited from a parent she does not read, one left out.            *)
(*                                                                         *)
(* Whenever she has no standing at the place for what she asks, both runs *)
(* answer alike (`SameAnswer`): the place's refusal, in one vault call of  *)
(* one statement, no lock waited for; and that statement read nothing of   *)
(* any key, no name listed, no key's row (`NoKeyBeforeStanding`). Once she *)
(* stands there, key names are hers to know (R6) and the answer may say    *)
(* which keys it holds, leaves out or refuses; what holds then is the      *)
(* batch's own discipline: one vault call whatever the keys               *)
(* (`OneVaultCall`); a refused batch waits for no lock and enters nothing  *)
(* in the cap's set (`NoLockForNo`, `RefusedEntersNothing`); a value she   *)
(* may not have never goes back (`OnlyUsable`), nor is a key the read      *)
(* leaves out ever used (`LeftOutUnused`); and the answer is the one the   *)
(* app's own path gives (`AnsweredAsApp`).                                 *)
(*                                                                         *)
(* One step is one request, whole: the vault's admission (`busy`, the same *)
(* for both runs) and, once admitted, her principal's lock held past the   *)
(* deadline by another call (`contended`, the same for both runs too). The *)
(* isolate's map of names to ids (`UseCache.keyIds`) may hold any key's    *)
(* ids or none, chosen anew for each request and each run (`warm`): a key  *)
(* whose ids it holds is used by them in the first statement, when its    *)
(* row of the cap's is fresh, as a lone named use is (Probing.tla). The    *)
(* cap itself, the batch's own keys counted, is Batching.tla's: the later  *)
(* rounds are its batch by ids, unchanged.                                 *)
(*                                                                         *)
(* How the code makes it (`useNamedMany`, migration 0055's                 *)
(* `use_named_batch`):                                                     *)
(*   statement 1: the gate (her standing at the place, from rows no key    *)
(*   decides, `use_credential` with no key); then, for one who stands and *)
(*   a chain not cut, the keys: the request's names, or every key the      *)
(*   place holds, listed through its layers; each key by the ids the map   *)
(*   holds, when they are its name's now and its value sealed (a use by    *)
(*   ids, `use_batch`'s), else its named call by its name alone; the vault *)
(*   decides every key on those rows, a plain value handed back at once;   *)
(*   statements 2 and 3, only once every key is allowed: the batch by ids  *)
(*   of the keys left (Batching.tla's two rounds).                         *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Budget,         \* how many requests Ada makes
    Where,          \* where she asks: "env", "fork", "mine" (her personal config of dev), "fallback" (`dev@me`, none of hers)
    Cuts            \* someone may archive the fork's parent, which cuts its chain

(***************************************************************************)
(* The protections.                                                        *)
(***************************************************************************)
CONSTANTS
    \* T165 (B2, PR 2): a request of several keys by name is the vault's one
    \* call, which reads the place and its keys itself. Off, as 0.15.0 and
    \* PR 1 left it: the app reads the place and its keys first (`app_read`,
    \* or a fork's layers), then decides her standing (`need`), and makes the
    \* uses by ids (`useMany`): a refusal's work hangs on the keys.
    ManyByName,
    \* The batch decides her standing at the place once, first, from rows no
    \* key decides (`use_credential` with no key, W268's gate), and lists or
    \* reads a key only for one who stands. Off, each key's named call is made
    \* and refuses her on its own: the names listed first, each key's index
    \* probed before its gate.
    GateBeforeKeys,
    \* A fork whose chain is cut reads nothing: the gate's statement refuses
    \* it on the place alone (`n_cut`). Off, each key is decided on 0.15.0's
    \* rules, and a key the fork holds itself goes back.
    CutByPlace,
    \* A key the place inherits is decided on her standing where it is held
    \* too (`decideChecked`, R8). Off, on the place's alone.
    ParentInDecision,
    \* A read that leaves keys out (a person's read leaves out every sensitive
    \* value, naming it) makes its first statement by names alone, writing
    \* nothing, and the vault leaves those keys out, unused, on its rows. Off,
    \* the map's ids are passed as for any batch: a sensitive key mapped is
    \* used, logged and refused, and the read with it.
    LeaveFirst,
    \* No key's use takes the principal's lock, or enters the cap's set,
    \* before the vault has decided every key on the first statement's rows
    \* (AllDecidedFirst, DecideBeforeLock). Off, a mapped key with no fresh
    \* row takes the lock in the first statement.
    DecideAllFirst,
    \* The keys go in one vault call. Off, the app makes one named call a key.
    OneCall

Keys == {"k1", "k2"}
\* The request's order: a refused batch answers its first key refused.
Order == <<"k1", "k2">>
Purposes == {"use", "read"}
\* The keys she names, or every key the place holds.
Asks == {"list", "all"}
Runs == {1, 2}
\* A key as the place holds it: none, a sealed value, a plain one, a sensitive one, or one whose value is gone.
States == {"none", "sealed", "plain", "sensitive", "gone"}
Valued == {"sealed", "plain", "sensitive"}
Layers == IF Where \in {"fork", "mine"} THEN {"own", "parent", "removed"} ELSE {"own"}
Statuses == {"busy", "forbidden", "cut", "refused", "values"}
\* What the request made the vault read before it decided: nothing, rows no key decides, or keys.
Works == {"nothing", "caller", "keys"}
Answers == [status : Statuses, calls : 0..2, stmts : 0..3, waited : BOOLEAN, work : Works]
Last == [a : Answers, b : Answers, stands : BOOLEAN, cutStands : BOOLEAN, appA : Statuses, appB : Statuses,
         wroteA : SUBSET Keys, wroteB : SUBSET Keys, enteredA : SUBSET Keys, enteredB : SUBSET Keys,
         leftA : SUBSET Keys, leftB : SUBSET Keys, givenA : SUBSET Keys, givenB : SUBSET Keys,
         usableA : SUBSET Keys, usableB : SUBSET Keys]

VARIABLES
    granted,        \* what her grant lets her do at the place (at dev, for "mine")
    grantedParent,  \* "fork": what it lets her do at the fork's parent
    key,            \* key[k]: run A's key k ("none" in run B, always)
    layer,          \* layer[k]: where run A holds it: "own", "parent" (inherited), "removed" (its parent's, removed here)
    fresh,          \* fresh[k]: run A's row of the cap's for k and Ada is fresh
    cut,            \* "fork": its parent archived, in both runs
    left,
    last

vars == <<granted, grantedParent, key, layer, fresh, cut, left, last>>

None == [k \in Keys |-> "none"]
Own == [k \in Keys |-> "own"]
Stale == [k \in Keys |-> FALSE]
Quiet == [status |-> "busy", calls |-> 0, stmts |-> 0, waited |-> FALSE, work |-> "nothing"]

Init ==
    /\ granted \in {Purposes, {"use"}}
    /\ grantedParent \in IF Where = "fork" THEN {{}, {"use"}, Purposes} ELSE {{}}
    /\ key = None
    /\ layer = Own
    /\ fresh = Stale
    /\ cut = FALSE
    /\ left = Budget
    /\ last = [a |-> Quiet, b |-> Quiet, stands |-> TRUE, cutStands |-> FALSE, appA |-> "busy", appB |-> "busy",
               wroteA |-> {}, wroteB |-> {}, enteredA |-> {}, enteredB |-> {}, leftA |-> {}, leftB |-> {},
               givenA |-> {}, givenB |-> {}, usableA |-> {}, usableB |-> {}]

\* Whether she stands at the place for `p` (the gate): her grant there; at her personal config, her reading or using dev.
Stands(p) == IF Where = "mine" THEN granted /= {} ELSE p \in granted

\* A run's keys and their layers: run A's as they are, run B's never made.
KeyOf(r) == IF r = 1 THEN key ELSE None
LayerOf(r) == IF r = 1 THEN layer ELSE Own
FreshOf(r) == IF r = 1 THEN fresh ELSE Stale

Held(r, k) == KeyOf(r)[k] /= "none" /\ LayerOf(r)[k] /= "removed"
\* The keys the request covers: those she names, or those the place holds (listed only for one who stands).
Asked(r, ask) == IF ask = "list" THEN Keys ELSE {k \in Keys : Held(r, k)}
\* Whether she may act where k is held, for `p`.
HolderStands(r, k, p) ==
    CASE LayerOf(r)[k] = "own"     -> Stands(p)
      [] LayerOf(r)[k] = "parent"  -> IF Where = "fork" THEN p \in grantedParent ELSE p \in granted
      [] LayerOf(r)[k] = "removed" -> FALSE
\* What the read leaves out, naming it, and never uses: a person's read of a sensitive value (`sensitiveTo`).
LeftOut(r, k, p) == p = "read" /\ KeyOf(r)[k] = "sensitive"
\* Whether she may be given k, as the app's own path decides it.
Usable(r, k, p) == Held(r, k) /\ KeyOf(r)[k] \in Valued /\ ~LeftOut(r, k, p) /\ Stands(p) /\ HolderStands(r, k, p) /\ ~cut

\* The app's own path's answer: the place refused; a chain cut; a key held, not left out, she may not have; or values.
AppStatus(r, ask, p) ==
    IF ~Stands(p) THEN "forbidden"
    ELSE IF cut THEN "cut"
    ELSE IF \E k \in Asked(r, ask) : Held(r, k) /\ ~LeftOut(r, k, p) /\ ~Usable(r, k, p) THEN "refused"
    ELSE "values"

\* The vault's decision of one key, as the code makes it (the protections on, `Usable` but what the read leaves out,
\* which the vault refuses: no person is handed a sensitive value).
Decides(r, k, p) ==
    /\ KeyOf(r)[k] \in Valued
    /\ ~(p = "read" /\ KeyOf(r)[k] = "sensitive")
    /\ Stands(p)
    /\ IF LayerOf(r)[k] = "parent" /\ ~ParentInDecision THEN TRUE ELSE HolderStands(r, k, p)
    /\ (~cut \/ (~CutByPlace /\ LayerOf(r)[k] = "own"))

R(status, calls, stmts, waited, work) == [status |-> status, calls |-> calls, stmts |-> stmts, waited |-> waited, work |-> work]
\* An answer, what it wrote (a use's entry), entered in the cap's set, left out and handed back.
Out(answer, wrote, entered, leftOut, given) == [answer |-> answer, wrote |-> wrote, entered |-> entered, left |-> leftOut, given |-> given]

\* 0.15.0's path, before this PR (ManyByName off): the app reads the place and its keys first, then `need` refuses her
\* on her standing, kept or asked; a read it lets through is a batch by ids (Batching.tla), each key decided as the app
\* decided it.
AppPath(r, ask, busy, contended, p) ==
    LET status == AppStatus(r, ask, p)
        given == {k \in Asked(r, ask) : Usable(r, k, p)}
        locking == {k \in given : ~FreshOf(r)[k]}
    IN IF busy THEN Out(Quiet, {}, {}, {}, {})
       ELSE IF status /= "values" THEN Out(R(status, 1, 1, FALSE, "keys"), {}, {}, {}, {})
       ELSE IF locking /= {} /\ contended THEN Out(R("busy", 1, 2, TRUE, "keys"), {}, {}, {}, {})
       ELSE Out(R("values", 1, IF locking = {} THEN 1 ELSE 2, locking /= {}, "keys"), given, locking, {k \in Asked(r, ask) : Held(r, k) /\ LeftOut(r, k, p)}, given)

\* The request as the code makes it: `warm`, the keys whose ids the isolate's map holds.
Named(r, ask, warm, busy, contended, p) ==
    LET held == {k \in Asked(r, ask) : Held(r, k)}
        leftOut == {k \in held : LeftOut(r, k, p)}
        \* What the vault decides key by key: every key held but those the read leaves out, unless it uses those too.
        candidates == IF LeaveFirst THEN held \ leftOut ELSE held
        refused == {k \in candidates : ~Decides(r, k, p)}
        \* The first statement's keys by ids: none for a read that leaves keys out (LeaveFirst), else those mapped.
        byIds == IF LeaveFirst /\ p = "read" THEN {} ELSE warm \cap candidates
        \* Used in the first statement: by ids, its row of the cap's fresh, as a lone named use is.
        once == {k \in byIds : FreshOf(r)[k]}
        \* By ids with no fresh row: without DecideAllFirst, the use takes the lock in the first statement.
        rushed == IF DecideAllFirst THEN {} ELSE {k \in byIds : ~FreshOf(r)[k]}
        \* The keys the batch by ids makes after, and whether it takes the lock for some.
        rest == candidates \ (once \cup rushed)
        locking == {k \in candidates : ~FreshOf(r)[k]}
        stmts == 1 + (IF rest = {} THEN 0 ELSE 1) + (IF {k \in rest : ~FreshOf(r)[k]} = {} THEN 0 ELSE 1)
        calls == IF OneCall THEN 1 ELSE Cardinality(IF ask = "list" THEN Keys ELSE held)
        work == IF calls = 0 THEN "nothing" ELSE "keys"
    IN IF busy THEN Out(Quiet, {}, {}, {}, {})
       \* The gate: no standing, or a chain cut, refused on rows no key decides, in the first statement.
       ELSE IF GateBeforeKeys /\ ~Stands(p) THEN Out(R("forbidden", 1, 1, FALSE, "caller"), {}, {}, {}, {})
       ELSE IF GateBeforeKeys /\ cut /\ CutByPlace THEN Out(R("cut", 1, 1, FALSE, "caller"), {}, {}, {}, {})
       \* Without the gate first, each key's named call refuses her on her standing there, its name read.
       ELSE IF ~Stands(p) THEN Out(R("forbidden", calls, 1, FALSE, work), {}, {}, {}, {})
       ELSE IF cut /\ CutByPlace THEN Out(R("cut", calls, 1, FALSE, work), {}, {}, {}, {})
       \* A key refused: the batch is, after its first statement, having made only what that statement made.
       ELSE IF refused /= {} THEN
            IF rushed /= {} /\ contended THEN Out(R("busy", calls, 1, TRUE, work), once, {}, leftOut, {})
            ELSE Out(R("refused", calls, 1, rushed /= {}, work), once \cup rushed, rushed, leftOut, {})
       \* Every key allowed: the rest by ids, its principal's lock taken for those entering the set.
       ELSE IF locking /= {} /\ contended THEN Out(R("busy", calls, stmts, TRUE, work), once, {}, leftOut, {})
       ELSE Out(R("values", calls, stmts, locking /= {}, work), candidates, locking, IF LeaveFirst THEN leftOut ELSE {}, candidates)

Answer(r, ask, warm, busy, contended, p) ==
    IF ManyByName THEN Named(r, ask, warm, busy, contended, p) ELSE AppPath(r, ask, busy, contended, p)

\* Run A's key k: someone makes it, at the place or, for a fork or her personal config, at its parent, inherited or
\* removed there.
Make(k) ==
    /\ key[k] = "none"
    /\ \E nature \in Valued, where \in Layers : key' = [key EXCEPT ![k] = nature] /\ layer' = [layer EXCEPT ![k] = where]
    /\ UNCHANGED <<granted, grantedParent, fresh, cut, left, last>>

\* Run A's key k: its value goes, the key still held (a reference whose source is deleted, or that ended).
End(k) ==
    /\ key[k] = "sealed"
    /\ key' = [key EXCEPT ![k] = "gone"]
    /\ UNCHANGED <<granted, grantedParent, layer, fresh, cut, left, last>>

\* Run A's key k: deleted. Its row of the cap's stays, to age out.
Delete(k) ==
    /\ key[k] /= "none"
    /\ key' = [key EXCEPT ![k] = "none"]
    /\ layer' = [layer EXCEPT ![k] = "own"]
    /\ UNCHANGED <<granted, grantedParent, fresh, cut, left, last>>

\* Run A: the place removes a key its parent holds, or brings it back.
Dismiss(k) ==
    /\ key[k] /= "none"
    /\ layer[k] \in {"parent", "removed"}
    /\ layer' = [layer EXCEPT ![k] = IF layer[k] = "parent" THEN "removed" ELSE "parent"]
    /\ UNCHANGED <<granted, grantedParent, key, fresh, cut, left, last>>

\* Run A: the window moves on.
Age(k) ==
    /\ fresh[k]
    /\ fresh' = [fresh EXCEPT ![k] = FALSE]
    /\ UNCHANGED <<granted, grantedParent, key, layer, cut, left, last>>

Revoke ==
    /\ granted /= {}
    /\ granted' = {}
    /\ UNCHANGED <<grantedParent, key, layer, fresh, cut, left, last>>

RevokeParent ==
    /\ grantedParent /= {}
    /\ grantedParent' = {}
    /\ UNCHANGED <<granted, key, layer, fresh, cut, left, last>>

Cut ==
    /\ Where = "fork"
    /\ Cuts
    /\ ~cut
    /\ cut' = TRUE
    /\ UNCHANGED <<granted, grantedParent, key, layer, fresh, left, last>>

Request ==
    /\ left > 0
    /\ \E busy, contended \in BOOLEAN, p \in Purposes, ask \in Asks, warmA, warmB \in SUBSET Keys :
         LET a == Answer(1, ask, warmA, busy, contended, p)
             b == Answer(2, ask, warmB, busy, contended, p)
         IN /\ last' = [a |-> a.answer, b |-> b.answer, stands |-> Stands(p), cutStands |-> Stands(p) /\ cut,
                        appA |-> AppStatus(1, ask, p), appB |-> AppStatus(2, ask, p),
                        wroteA |-> a.wrote, wroteB |-> b.wrote, enteredA |-> a.entered, enteredB |-> b.entered,
                        leftA |-> {k \in Asked(1, ask) : Held(1, k) /\ LeftOut(1, k, p)}, leftB |-> {k \in Asked(2, ask) : Held(2, k) /\ LeftOut(2, k, p)},
                        givenA |-> a.given, givenB |-> b.given,
                        usableA |-> {k \in Keys : Usable(1, k, p)}, usableB |-> {k \in Keys : Usable(2, k, p)}]
            \* A use written leaves its key's row fresh, entering the set or moving on in it.
            /\ fresh' = [k \in Keys |-> fresh[k] \/ k \in a.wrote]
    /\ left' = left - 1
    /\ UNCHANGED <<granted, grantedParent, key, layer, cut>>

Done == left = 0 /\ UNCHANGED vars

Next ==
    \/ \E k \in Keys : Make(k) \/ End(k) \/ Delete(k) \/ Dismiss(k) \/ Age(k)
    \/ Revoke \/ RevokeParent \/ Cut \/ Request \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ granted \subseteq Purposes
    /\ grantedParent \subseteq Purposes
    /\ key \in [Keys -> States]
    /\ layer \in [Keys -> Layers \cup {"own"}]
    /\ fresh \in [Keys -> BOOLEAN]
    /\ cut \in BOOLEAN
    /\ last \in Last

\* What a caller sees of an answer: all of it but the work inside the calls.
Seen(answer) == [status |-> answer.status, calls |-> answer.calls, stmts |-> answer.stmts, waited |-> answer.waited]

\* D153 for several keys: with no standing at the place for what she asks, she is answered alike, whatever the keys
\* are or were and whatever each run's map holds: the status, the vault's calls, their statements, and whether one
\* waited for a lock.
SameAnswer == ~last.stands => Seen(last.a) = Seen(last.b)

\* W268's gate for several keys: with no standing, the vault read nothing of any key before deciding, no name listed.
NoKeyBeforeStanding == ~last.stands => last.a.work \in {"nothing", "caller"} /\ last.b.work \in {"nothing", "caller"}

\* A fork whose chain is cut reads nothing, refused on the place alone, before any key.
CutReadsNothing == last.cutStands => last.a.work \in {"nothing", "caller"} /\ last.b.work \in {"nothing", "caller"}

\* One vault call, whatever the keys: never a call a key.
OneVaultCall == last.a.calls <= 1 /\ last.b.calls <= 1

\* No refusal waited for her principal's lock.
NoLockForNo == /\ last.a.status \in {"forbidden", "cut", "refused"} => ~last.a.waited
               /\ last.b.status \in {"forbidden", "cut", "refused"} => ~last.b.waited

\* A batch that hands back nothing entered no key in the cap's set.
RefusedEntersNothing == /\ last.a.status /= "values" => last.enteredA = {}
                        /\ last.b.status /= "values" => last.enteredB = {}

\* A key the read leaves out is never used.
LeftOutUnused == last.wroteA \cap last.leftA = {} /\ last.wroteB \cap last.leftB = {}

\* Only what she may be given goes back.
OnlyUsable == last.givenA \subseteq last.usableA /\ last.givenB \subseteq last.usableB

\* Answered as the app's own path answers, but busy, which decides nothing.
AnsweredAsApp == /\ last.a.status /= "busy" => last.a.status = last.appA
                 /\ last.b.status /= "busy" => last.b.status = last.appB

=============================================================================
