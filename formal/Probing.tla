------------------------------- MODULE Probing -------------------------------
(***************************************************************************)
(* What a caller learns of a place's keys she may not use, by asking for   *)
(* them (T145, PR B; review r2 of #406; T158; D153): nothing, neither from *)
(* what she is answered nor from how long it takes. Ada asks for API_KEY   *)
(* at market/dev through the proxy or the API, while the vault comes and   *)
(* goes from overload, her grant there may be revoked or lapse, and she    *)
(* may hold it for using values and not for reading them. Two runs go side *)
(* by side, alike in everything but the keys: in run A, API_KEY is a key   *)
(* someone makes, a sealed value or a plain one, before the revoke or      *)
(* after, deletes and makes again, or whose value goes while it is held (a *)
(* reference whose source is deleted, or that has ended); in run B nobody  *)
(* ever makes one. Whenever she may use the key in neither run, the        *)
(* answers must be the same (`NoIsFixed`): one answer, `no`, whatever the  *)
(* reason, in as many of the vault's calls, no lock waited for. Once she   *)
(* may use it, the key is hers to know of, and what follows may vary.      *)
(* Stronger, while she has no standing at the place for what she asks     *)
(* (`NoKeyBeforeStanding`): the vault's call reads nothing of the key, no  *)
(* name's index, no row of a key, a reference or its source, so its work   *)
(* inside, not only its answer, is the same whatever the key is or was.    *)
(* docs/formal.md says what this covers and abstracts.                     *)
(*                                                                         *)
(* One step is one request, whole: the vault's calls and their admission   *)
(* (`busy`, the same for both runs: the vault's load does not hang on a    *)
(* key Ada asks for), the floor of `at` passing it, and, once admitted,    *)
(* her principal's lock held by another call past the use's deadline       *)
(* (`contended`, the same for both runs too). A use of a sealed key takes  *)
(* that lock when the key has no fresh row of the bulk cap's for her       *)
(* (`fresh`): one made since has none until a use of hers for it writes    *)
(* it, and the row ages out of the window (`Age`). A key never made, and a *)
(* plain value, never take it.                                             *)
(*                                                                         *)
(* The isolate keeps no decision for a later use to take the lock on      *)
(* (D153); without `DecideEachLock` it would, one per purpose (`stood`),   *)
(* out of date only on a change of the log's. It maps what a request      *)
(* names to ids (`UseCache.names`,                                         *)
(* `keyIds`), which the model takes as anything at all, chosen anew for    *)
(* each request and for each run on its own (D150, D153): nothing yet;     *)
(* her credential's id, or another's; the place the request names now      *)
(* (`here`), another (`there`: the one renamed away from those slugs, or   *)
(* any other, where run A makes and deletes a key of that name too, and   *)
(* she may stand), or one archived or never made; and the key's id, none, *)
(* API_KEY's in `here` now, one no key has, or the key of that name in    *)
(* `there`. So the map is a dimension of every comparison: what a `no`     *)
(* costs may hang on neither the key nor the map.                          *)
(***************************************************************************)
EXTENDS Naturals, TLC

CONSTANTS
    Budget,         \* how many requests Ada makes
    Floors,         \* the checkpointer's floor of `at` may pass a request
    Archives,       \* someone may archive the place
    Providers,      \* the deployment may stop configuring the sign-in provider of her browser session
    Modes,          \* the deployment may move its sign-in to Cloudflare Access
    Expiries        \* her credential may expire while a request of hers is under way

(***************************************************************************)
(* Where the answer about Ada comes from (not a protection: the code's     *)
(* shape). 0.15 before PR B: an answer of the vault's kept from an earlier *)
(* request (`Accesses`), which the vault checks when it opens a value and  *)
(* the app confirms before anything else goes back. PR B: none kept; each  *)
(* request's vault call decides on Ada as she is, sealed.                  *)
(***************************************************************************)
CONSTANTS
    CallerFromUse

(***************************************************************************)
(* The protections.                                                        *)
(***************************************************************************)
CONSTANTS
    \* D153: every refusal of the key she asked for is one answer, `no`: no
    \* standing at the place, none to read there, no such key, a reference
    \* ended or whose source is gone, a row put back. The vault's reason goes
    \* to the audit log only. Off, each reason is its own answer: a key never
    \* made `missing` beside a reference ended `ended`, to someone who may
    \* use neither.
    OneNo,
    \* D153: a named use's first call reads what the request names, by its
    \* names (her credential by her token's hash, the place by its slugs or
    \* a handle's own, the key by its name there), whatever the isolate's map
    \* holds; the ids the map holds only let that call write the use's entry
    \* and take the lock, when they are the ones its names name now. So a
    \* `no` is decided in that one call whatever the map holds; a `yes` the
    \* map has no ids for makes the use in a second call, by the ids read.
    \* Off, as B1 built it: a name the map has not read costs its read first,
    \* a call more, and one out of date is decided on the rows its ids read,
    \* then read again.
    ResolveByName,
    \* PR B: a key the place does not hold is decided by the vault, on Ada's
    \* standing at the place first, in the same call a use makes, under the
    \* same admission. Off, the app answers it itself: not found.
    MissingByStanding,
    \* PR B: a plain value, which no use opens, goes back only once the vault
    \* has decided on Ada's standing at the place, as for a missing key. Off,
    \* the app hands it back on its own read.
    PlainByStanding,
    \* PR B: that call is admitted as a use is, and refused busy as one is.
    \* Off, it is never busy.
    StandingSharesAdmission,
    \* T158, D153: a use that would take her principal's lock (its key's row
    \* of the cap's not fresh) takes it only once its use is decided: the call
    \* takes no lock, writes nothing and answers the rows, the vault decides
    \* the use on them, key and all, refuses her as for any key, and makes the
    \* use, a second call, only if it allows it. Off, the use takes the lock
    \* first, and the vault decides on what it read after.
    DecideBeforeLock,
    \* D153 (review r1 of the design): every such use decides, each time: no
    \* decision is kept for a later use to take the lock on in its first
    \* call. Off, the isolate keeps the use it last allowed her, per purpose
    \* (`stood`), until a change of the log's: a write around it (0.14's,
    \* mid-upgrade, or a version's nature written beside its row), or a
    \* grant's end, which no change records, leaves it standing, and her
    \* refused use waits for the lock where a key never made is refused at
    \* once (T158's `stood`, whose digest missed a version's field).
    DecideEachLock,
    \* T158: a named use refused on its cover (an allowed use's entry that a
    \* repeat rides, while no change came after it) is answered as it is, in
    \* its one call, the app's entry recording it. Off, it is made again as
    \* an entry of its own, a second call, which a key never made never
    \* makes (review d1 of #416).
    CoveredRefusalAnswered,
    \* T158: what no key decides comes first in every form of the statement
    \* (the deadline, the floor of `at`, the clock, the cap's config; then
    \* the place named archived, which ends the request as the app answers
    \* it), before anything of the names or the key. Off, a call whose map is
    \* out of date is decided on its rows first: refused where a current one
    \* is late, or not found (review d3 of #416).
    AdmissionBeforeKey,
    \* D153 (review r2): the route a named request takes, by the vault's
    \* decision or by the credential's own check (the app's path, as ever),
    \* is picked on her credential and her account alone (`routeOf`): a
    \* key's rows not as the isolate's seals say (a reference's source
    \* rewritten around the log) are one more refusal of the key, by name.
    \* Off, as before r2: the use then decides nothing of her (no standing),
    \* and the app asks the vault as ever, `access` and a use by ids, a call
    \* each: a key's rows, and the isolate's seals of them, pick the path.
    RouteByCredential,
    \* Review r4 of D153: a key that reads an archived place (a reference
    \* whose source's environment is archived) is refused by the vault, by
    \* name, as every refusal of the key is. Off, as before r4 (`unnamed`):
    \* the vault, having found her standing, hands it to the app's path,
    \* `access` and the app's own reads, which then refuse it.
    ArchivedByName,
    \* Review r2 of D153: a use by ids, the app's path's, decides before her
    \* principal's lock too, as a named one does. Off, it takes the lock
    \* first, and a refusal on that path waits for it.
    DecideBeforeLockById,
    \* Reviews r6 and r7 of D153: the vault's "authenticated" is the app's.
    \* The named call carries what the app's config accepts of a credential
    \* (coffre's own sign-in; for a browser session, a sign-in provider the
    \* deployment configures), and the vault holds her credential to it
    \* first, before anything of the place or the key: one the app would
    \* refuse is answered as a token no credential has, 401, in that one
    \* call. Off, the vault, which sees only her sealed rows, decides the use
    \* first, her principal's lock taken for a key her grant covers beside a
    \* key never made refused at once, and the app's 401 only after.
    AcceptedFirst,
    \* Review r8 of D153: one clock. The vault decides the credential's end
    \* at the request's `at`; the app's own check of it, after the vault's
    \* call, judges its expiry at that same instant, so a credential live
    \* when its request began is the request's, which the use's deadline
    \* bounds. Off, the app judges it at its own later time: a credential
    \* that expires in between gets the vault's work first, her principal's
    \* lock for a key her grant covers, and the app's 401 after.
    OneClock,
    \* D150 (fallback D), W268: a named call decides her standing at the place,
    \* for what she asks, from rows no key decides (her credential, account,
    \* grants, the roles, the place), before it reads anything of the key's:
    \* no name's index probed, no key's row, reference or source read. Without
    \* standing she is refused on those alone, as for a key the place does not
    \* hold, by the same statement. Off, as before W268: the call reads the
    \* key by its name, and a reference's source, and the vault decides her
    \* standing on what it read, so a refusal's work inside the call hangs on
    \* the key's shape (a reference reads its source's rows), which neither
    \* her answer nor its calls show (W259's buffer counts: 42 to 136). A
    \* credential ended at the request's `at` is one more way to stand nowhere,
    \* which the gate weighs as the vault does; the model's `Lapse` stands for
    \* it (no change of the log's), `expiring` only for an end after `at`.
    StandingFirst,
    \* Before PR B: a refusal on a kept answer the vault has not vouched for,
    \* a busy one (503) included, first asks the vault for its answer now, and
    \* starts over on the fresh one when it differs (`Recalled.confirm`,
    \* #406 r2). Off, a busy use answers 503 as it is.
    ConfirmOnBusy

Statuses == {"value", "no", "forbidden", "missing", "ended", "busy", "notfound", "unauth"}
\* How the app answered: on the vault's named use (`name`), by its own path, the credential's check and `access` first
\* (`app`: a place it does not serve by name, or no standing the use decided), or busy before anything was read.
Routes == {"name", "app", "busy"}
\* What the request made the vault read before it decided (`work`): nothing (no call, or none admitted), only rows no key
\* decides (`caller`: the credential, the account, the roles, the place), or the key's own as it is (the key's state:
\* its name's index, its rows, a reference's source).
Works == {"nothing", "caller", "none", "sealed", "plain", "gone", "around", "away"}
Answers == [status : Statuses, calls : 0..5, waited : BOOLEAN, route : Routes, work : Works]
\* What a request needs of her: to use a value (the proxy), or to read it (a reveal).
Purposes == {"use", "read"}
Runs == {1, 2}
\* A key she may be given: a sealed value or a plain one, held. One whose value is gone she may not.
Valued == {"sealed", "plain"}

VARIABLES
    granted,        \* what Ada's grant lets her do at the place: both, `use` alone (a Contributor's), or nothing
    grantedThere,   \* what it lets her do at the other place, which no step changes
    made,           \* run A: API_KEY as the place holds it ("none", "sealed", "plain", "gone": held, its value gone,
                    \* "around": a reference whose source a writer rewrote around the log, its rows not as sealed, or
                    \* "away": a reference whose source's environment is archived)
    unseen,         \* run A: no change of the log's since that rewrite, so an isolate's seals of its rows may be older
    madeThere,      \* run A: whether the other place holds a key of that name (run B's never does)
    fresh,          \* run A: the cap's row of API_KEY for Ada is fresh
    stood,          \* each run's `stood`, by purpose: kept, and still of the log's newest change and the rows
    cover,          \* run A: the isolate's cover of API_KEY for Ada, by purpose: an allowed use's entry, no change since
    archived,       \* the place is archived (both runs: it is no key's)
    kept,           \* the app keeps an answer about Ada that says she reads here
    browser,        \* her credential is a browser session, which a sign-in provider of the deployment's vouches for
    unconfigured,   \* the deployment no longer configures that provider: the app refuses the session, 401
    behindAccess,   \* the deployment signs in through Cloudflare Access now: the app takes no coffre token, 401
    left,           \* requests still to make
    last            \* the last request's answers, checked in the state they are given in (`Last`): before any, alike

vars == <<granted, grantedThere, made, unseen, madeThere, fresh, stood, cover, archived, kept, browser, unconfigured, behindAccess, left, last>>

None == [p \in Purposes |-> FALSE]
\* Run A's answer and run B's, whether she may use the key in each, whether she stands where she asks for what she
\* asks, and run A's answer with the map as it should be.
Last == [a : Answers, b : Answers, noA : BOOLEAN, noB : BOOLEAN, stands : BOOLEAN, right : Answers]

A(status, calls, waited) == [status |-> status, calls |-> calls, waited |-> waited, route |-> "name", work |-> IF calls = 0 THEN "nothing" ELSE "caller"]
On(answer, route) == [answer EXCEPT !.route = route]
\* An answer whose calls read the key, as `key` is: what they read hangs on it.
Keyed(answer, key) == IF answer.calls = 0 THEN answer ELSE [answer EXCEPT !.work = key]
\* What a caller sees of an answer: all of it but the work inside the calls.
Seen(answer) == [status |-> answer.status, calls |-> answer.calls, waited |-> answer.waited, route |-> answer.route]

Init ==
    /\ granted \in {Purposes, {"use"}}
    /\ grantedThere \in {{}, Purposes}
    /\ made = "none"
    /\ unseen = FALSE
    /\ madeThere = FALSE
    /\ fresh = FALSE
    /\ stood = [r \in Runs |-> None]
    /\ cover = None
    /\ archived = FALSE
    /\ kept = TRUE
    /\ browser \in BOOLEAN
    /\ unconfigured = FALSE
    /\ behindAccess = FALSE
    /\ left = Budget
    /\ last = [a |-> On(A("busy", 0, FALSE), "busy"), b |-> On(A("busy", 0, FALSE), "busy"), noA |-> TRUE, noB |-> TRUE, stands |-> TRUE, right |-> On(A("busy", 0, FALSE), "busy")]

\* Whether she may be given API_KEY, as `key`, for `p`: the vault's whole decision, key and all, but the cap's.
Usable(key, p) == p \in granted /\ key \in Valued
\* Her credential refused by the app on the deployment's config, which the vault cannot see: a session whose provider
\* it no longer configures, or any coffre token once it signs in through Cloudflare Access.
Gone == (browser /\ unconfigured) \/ behindAccess
\* Whether she may be given it: the vault's decision, and her credential the app's to accept.
Allowed(key, p) == Usable(key, p) /\ ~Gone

\* The use by ids the request's names name now: `key` the key as the call reads it, `isFresh` its row of the cap's,
\* `isStood` the isolate's `stood` as the statement finds it, `isCovered` its cover, `busy` whether admission refuses
\* the vault's calls now, `contended` whether the principal's lock, once asked for, is held past the use's deadline,
\* `p` what the request needs. The answer, and whether the use wrote the key's row of the cap's.
AnswerFresh(key, isFresh, isStood, isCovered, busy, contended, p) ==
    LET usable == Usable(key, p)
        \* Its refusal, as she is told it: one, or the vault's reason.
        refusal == IF OneNo THEN "no"
                   ELSE IF p \notin granted THEN "forbidden" ELSE IF key \in {"gone", "around", "away"} THEN "ended" ELSE "missing"
        decided == IF usable THEN "value" ELSE refusal
        \* One call, decided on what it read, no lock: a missing key, a plain value, a sealed key fresh in the set.
        once == IF StandingSharesAdmission /\ busy THEN [answer |-> On(A("busy", 0, FALSE), "busy"), wrote |-> FALSE]
                ELSE [answer |-> A(decided, 1, FALSE), wrote |-> FALSE]
        \* The use, its principal's lock taken, in its `calls`-th call.
        locked(calls) ==
            IF contended THEN [answer |-> A("busy", calls, TRUE), wrote |-> FALSE]
            ELSE [answer |-> A(decided, calls, TRUE), wrote |-> TRUE]
        \* Every call of it reads the key, as it is.
        K(r) == [answer |-> Keyed(r.answer, key), wrote |-> r.wrote]
    IN K(CASE key \in {"sealed", "gone", "around", "away"} ->
              IF busy THEN [answer |-> On(A("busy", 0, FALSE), "busy"), wrote |-> FALSE]
              \* Refused on its cover: answered so, or made again as an entry of its own.
              ELSE IF isFresh /\ isCovered /\ ~usable
                   THEN [answer |-> A(refusal, IF CoveredRefusalAnswered THEN 1 ELSE 2, FALSE), wrote |-> FALSE]
              ELSE IF isFresh THEN [answer |-> A(decided, 1, FALSE), wrote |-> FALSE]
              ELSE IF ~DecideBeforeLock THEN locked(1)
              ELSE IF ~DecideEachLock /\ isStood THEN locked(1)
              \* The first call took no lock and wrote nothing; the vault decides the use on its rows.
              ELSE IF ~usable THEN [answer |-> A(refusal, 1, FALSE), wrote |-> FALSE]
              ELSE locked(2)
         [] key = "plain" -> IF PlainByStanding THEN once ELSE [answer |-> A("value", 0, FALSE), wrote |-> FALSE]
         [] key = "none"  -> IF MissingByStanding THEN once ELSE [answer |-> A(IF OneNo THEN "no" ELSE "missing", 0, FALSE), wrote |-> FALSE])

\* Before PR B: decided on the kept answer while there is one, which says
\* she reads here; otherwise on the vault's answer now (`access`), which is
\* never busy. A refusal on the kept answer confirms it: the vault's answer
\* now differs (revoked), so the request starts over, asking. Its calls and
\* waits are not modelled (0 and FALSE): this path is the one for several
\* keys, which B2 takes off; its claim is the status alone.
AnswerKept(key, isFresh, busy, contended, p) ==
    LET stands == p \in granted
        sealed == key \in {"sealed", "gone", "around", "away"}
        value == IF key \in {"gone", "around", "away"} THEN "ended" ELSE "value"
        late == contended /\ sealed /\ ~isFresh
        asked == IF ~stands THEN "forbidden"
                 ELSE CASE sealed -> IF busy \/ late THEN "busy" ELSE value
                        [] key = "plain"  -> "value"
                        [] key = "none"   -> "missing"
        onKept == CASE sealed -> IF busy \/ late
                                    THEN IF ConfirmOnBusy THEN asked ELSE "busy"
                                    ELSE IF stands THEN value ELSE asked
                    \* A plain value goes back once a read after it finds the policy unchanged (`fenced`):
                    \* her answer is confirmed as for any request no use vouched for.
                    [] key = "plain"  -> asked
                    [] key = "none"   -> asked
    IN [answer |-> [On(A(IF kept THEN onKept ELSE asked, 0, FALSE), "app") EXCEPT !.work = key], wrote |-> sealed /\ ~busy /\ ~late, here |-> TRUE]

\* What the isolate's map holds for a request's names: nothing yet for its place or its key (`Unread`), or
\* <<credential, place, key>> (the module's comment says what each may be).
Unread == <<"unread">>
Maps == {Unread} \cup ({"right", "wrong"} \X {"here", "there", "gone"} \X {"absent", "current", "dead", "there"})
\* The map as a read of the names makes it: what a request with every name read finds.
RightMap(key) == <<"right", "here", IF key = "none" THEN "absent" ELSE "current">>

\* The app's own path, after `n` calls of the vault's: `access`, a call, then its use by ids, which reads the key's
\* rows anew (the isolate's seals of them dropped): refused, as they are not as sealed, in its first call or once its
\* principal's lock is taken (DecideBeforeLockById). Ada's standing decides nothing here: the key's rows refuse it.
ById(n, isFresh, contended, key) ==
    LET refused(calls, waited) == On(A(IF OneNo THEN "no" ELSE "ended", calls, waited), "app")
    IN [answer |-> Keyed(IF isFresh \/ DecideBeforeLockById THEN refused(n + 2, FALSE)
                         ELSE IF contended THEN On(A("busy", n + 2, TRUE), "app")
                         ELSE refused(n + 2, TRUE), key),
        wrote |-> FALSE, here |-> FALSE]

\* A request by name, with the isolate's map as `map` holds it, in a run where API_KEY is `key` in the place named
\* and `there` says whether the other place holds one of that name; `stale`, whether the isolate's seals of the key's
\* rows, which a call by the map's ids reads by, are from before a writer rewrote them around the log. The answer,
\* whether the cap's row was written, and whether the use was made by the ids of the place named (`here`), where a use
\* it allows is kept.
Named(key, there, map, isFresh, isStood, isCovered, busy, contended, p, pastFloor, stale) ==
    LET \* Answered on rows no key decides (`caller`), or, `RK`, on what its call read of the key too.
        R(status, calls) == [answer |-> On(A(status, calls, FALSE), CASE status = "busy" -> "busy" [] status = "notfound" -> "app" [] OTHER -> "name"),
                             wrote |-> FALSE, here |-> FALSE]
        RK(status, calls) == [R(status, calls) EXCEPT !.answer = Keyed(@, key)]
        With(r, n, h) == [answer |-> [r.answer EXCEPT !.calls = IF @ = 0 THEN 0 ELSE @ + n], wrote |-> r.wrote, here |-> h]
        Use(s) == AnswerFresh(key, isFresh, s, isCovered, busy, contended, p)
        refusal == IF OneNo THEN "no"
                   ELSE IF p \notin granted THEN "forbidden" ELSE IF key \in {"gone", "around", "away"} THEN "ended" ELSE "missing"
        \* The place the ids the map holds name: a key's own, while it is held; the place mapped, for a key mapped as
        \* none; none for an id no key has.
        ids == IF map = Unread THEN "none"
               ELSE CASE map[3] = "current" /\ key /= "none" -> "here"
                      [] map[3] = "there" /\ there -> "there"
                      [] map[3] = "absent" -> map[2]
                      [] OTHER -> "none"
        \* The ids are the ones the names name now: her credential's, the place's and the key's, or none for none.
        right == map /= Unread /\ map[1] = "right" /\ ids = "here" /\ ~(map[3] = "absent" /\ key /= "none")
        \* B1's: the names read again, after `n` calls, then the use made by the ids read.
        Read(n) == IF archived THEN RK("notfound", n + 1)
                   ELSE IF pastFloor THEN RK("busy", n + 2)
                   ELSE With(Use(isStood), n + 1, TRUE)
        \* Before r4: her standing found, a key that reads an archived place went to the app's path, `access` a call
        \* more, and the app's own reads refused it.
        Unnamed == [answer |-> Keyed(On(A(refusal, 2, FALSE), "app"), key), wrote |-> FALSE, here |-> FALSE]
    \* Admission refuses a request before anything is read, a key's name included (StandingSharesAdmission: off, only
    \* a sealed key's use is admitted so, and a missing or plain one goes on, decided).
    IN IF busy /\ (StandingSharesAdmission \/ key \in {"sealed", "gone"}) THEN R("busy", 0)
       ELSE IF ResolveByName
       THEN \* What no key decides (AdmissionBeforeKey: before the names are read).
            IF AdmissionBeforeKey /\ pastFloor THEN R("busy", 1)
            ELSE IF AdmissionBeforeKey /\ archived THEN R("notfound", 1)
            \* No standing at the place for what she asks: refused on rows no key decides, before any of the key's is
            \* read, whatever the map holds (StandingFirst).
            ELSE IF StandingFirst /\ p \notin granted THEN R(refusal, 1)
            ELSE IF ~ArchivedByName /\ key = "away" /\ p \in granted /\ ~pastFloor /\ ~archived THEN Unnamed
            \* The ids are the names': the use as by ids, in this call. A standing kept for another place is none here.
            ELSE IF right THEN IF pastFloor THEN RK("busy", 1) ELSE IF archived THEN RK("notfound", 1)
                               \* The key's rows not as the isolate's seals of them say: refused, `stale`, by name; or,
                               \* before r2, no standing decided, and the app's path.
                               ELSE IF stale THEN IF RouteByCredential THEN RK(refusal, 1) ELSE ById(1, isFresh, contended, key)
                               ELSE With(Use(isStood /\ map[2] = "here"), 0, map[2] = "here")
            \* The call wrote and locked nothing; the vault decides on the rows its names read: `no` at once, or the
            \* use made in a second call, by the ids read.
            ELSE IF ~Usable(key, p) THEN RK(refusal, 1)
            ELSE IF pastFloor THEN RK("busy", 1)
            ELSE IF archived THEN RK("notfound", 1)
            ELSE With(Use(isStood), 1, TRUE)
       \* B1's: a map not read is read first; ids out of date are read again; else the use by them.
       ELSE IF map = Unread THEN Read(0)
       ELSE IF pastFloor THEN RK("busy", 1)
       ELSE IF archived THEN RK("notfound", 1)
       ELSE IF ~right THEN Read(1)
       ELSE With(Use(isStood /\ map[2] = "here"), 0, map[2] = "here")

\* The credential's own check refuses her (401) before anything is asked of the vault.
Unauthenticated == [answer |-> On(A("unauth", 0, FALSE), "app"), wrote |-> FALSE, here |-> FALSE]

\* Her credential refused first by the vault's call, on what the app's config accepts (AcceptedFirst), as a token no
\* credential has: one call, admitted as any, the app's 401 after it, nothing of the place or the key read.
AsUnknown(busy) == [answer |-> IF busy THEN On(A("busy", 0, FALSE), "busy") ELSE On(A("unauth", 1, FALSE), "app"), wrote |-> FALSE, here |-> FALSE]

\* What the app makes of the vault's named answer for a session it then refuses: 401, after whatever the vault did,
\* or the vault's busy answer, which came first.
Refused(r) == IF r.answer.status = "busy" THEN r ELSE [r EXCEPT !.answer.status = "unauth", !.here = FALSE]

\* `expiring`: her credential expires after the request's `at` and before the app's own check of it.
Answer(key, there, map, isFresh, isStood, isCovered, busy, contended, p, pastFloor, stale, expiring) ==
    LET \* What the app refuses of her credential that the vault, deciding at `at`, did not: its own later clock's.
        appRefuses == Gone \/ (expiring /\ ~OneClock)
    IN IF ~CallerFromUse THEN IF appRefuses THEN Unauthenticated ELSE AnswerKept(key, isFresh, busy, contended, p)
       ELSE IF Gone /\ AcceptedFirst THEN AsUnknown(busy)
       ELSE LET r == Named(key, there, map, isFresh, isStood, isCovered, busy, contended, p, pastFloor, stale)
            IN IF appRefuses THEN Refused(r) ELSE r

\* A change, in run A, B or both: `stood` of a change before it is out of date, and so is run A's cover.
Changed(inA, inB) ==
    /\ stood' = [r \in Runs |-> IF (r = 1 /\ inA) \/ (r = 2 /\ inB) THEN None ELSE stood[r]]
    /\ cover' = IF inA THEN None ELSE cover
    \* An isolate's seals are as of the log's newest change: one after the rewrite makes every call read them anew.
    /\ unseen' = (unseen /\ ~inA)

Revoke ==
    /\ granted /= {}
    /\ granted' = {}
    /\ Changed(TRUE, TRUE)
    /\ UNCHANGED <<grantedThere, made, madeThere, fresh, archived, kept, browser, unconfigured, behindAccess, left, last>>

\* Ada loses her standing with no change of the log's: her grant's end
\* passes ("ends"), or the 0.14 code revokes her grant or her credential,
\* mid-upgrade ("old"). Her cover stays: no change came after it.
Lapse ==
    /\ granted /= {}
    /\ granted' = {}
    \* No change of the log's: a decision kept stays, its digest blind to it (DecideEachLock off).
    /\ UNCHANGED <<grantedThere, made, unseen, madeThere, fresh, stood, cover, archived, kept, browser, unconfigured, behindAccess, left, last>>

\* Run A only: someone makes API_KEY, before the revoke or after, or makes it again once deleted.
Make ==
    /\ made = "none"
    /\ \E nature \in Valued : made' = nature
    /\ Changed(TRUE, FALSE)
    /\ UNCHANGED <<granted, grantedThere, madeThere, fresh, archived, kept, browser, unconfigured, behindAccess, left, last>>

\* Run A only: its value goes, the key still held: the source of a reference deleted, or the reference ended.
End ==
    /\ made = "sealed"
    /\ made' = "gone"
    /\ Changed(TRUE, FALSE)
    /\ UNCHANGED <<granted, grantedThere, madeThere, fresh, archived, kept, browser, unconfigured, behindAccess, left, last>>

\* Run A only: a writer around the log (0.14's code mid-upgrade, or someone who owns the database) points the
\* reference API_KEY is at another source: no change of the log's, its rows no longer as sealed (review r2 of D153).
Repoint ==
    /\ made = "sealed"
    /\ made' = "around"
    /\ unseen' = TRUE
    /\ UNCHANGED <<granted, grantedThere, madeThere, fresh, stood, cover, archived, kept, browser, unconfigured, behindAccess, left, last>>

\* Run A only: someone archives the environment of the source API_KEY reads through (its holder archived first, then
\* restored), or brings it back: a change each.
Park ==
    /\ made \in {"sealed", "away"}
    /\ made' = IF made = "sealed" THEN "away" ELSE "sealed"
    /\ Changed(TRUE, FALSE)
    /\ UNCHANGED <<granted, grantedThere, madeThere, fresh, archived, kept, browser, unconfigured, behindAccess, left, last>>

\* Run A only: someone deletes it. Its row of the cap's for Ada stays, to age out.
Delete ==
    /\ made /= "none"
    /\ made' = "none"
    /\ Changed(TRUE, FALSE)
    /\ UNCHANGED <<granted, grantedThere, madeThere, fresh, archived, kept, browser, unconfigured, behindAccess, left, last>>

\* Run A only: someone makes a key of that name in the other place, or deletes it.
MakeThere ==
    /\ madeThere' = ~madeThere
    /\ Changed(TRUE, FALSE)
    /\ UNCHANGED <<granted, grantedThere, made, fresh, archived, kept, browser, unconfigured, behindAccess, left, last>>

\* The deployment stops configuring the sign-in provider her browser session came through: no change of the log's,
\* the same in both runs. Her rows, and all the vault sees, stay as they were.
Unconfigure ==
    /\ Providers
    /\ browser
    /\ ~unconfigured
    /\ unconfigured' = TRUE
    /\ UNCHANGED <<granted, grantedThere, made, unseen, madeThere, fresh, stood, cover, archived, kept, browser, behindAccess, left, last>>

\* The deployment moves its sign-in to Cloudflare Access: no change of the log's, the same in both runs. Her tokens'
\* rows stay as they were, sealed, and the vault sees nothing of it.
BehindAccess ==
    /\ Modes
    /\ ~behindAccess
    /\ behindAccess' = TRUE
    /\ UNCHANGED <<granted, grantedThere, made, unseen, madeThere, fresh, stood, cover, archived, kept, browser, unconfigured, left, last>>

\* Someone archives the place, or its project: a change, in both runs. Every request then ends as the app answers it.
Archive ==
    /\ Archives
    /\ ~archived
    /\ archived' = TRUE
    /\ Changed(TRUE, TRUE)
    /\ UNCHANGED <<granted, grantedThere, made, madeThere, fresh, kept, browser, unconfigured, behindAccess, left, last>>

\* The window moves on: the key's row of the cap's for Ada is no longer fresh, and no cover rides it (CoverFresh).
Age ==
    /\ fresh
    /\ fresh' = FALSE
    /\ cover' = None
    /\ UNCHANGED <<granted, grantedThere, made, unseen, madeThere, stood, archived, kept, browser, unconfigured, behindAccess, left, last>>

Request ==
    /\ left > 0
    \* `pastFloor`: the checkpointer's floor of `at` has passed the request's, the same for both runs; `mapA` and
    \* `mapB`, what the isolate's map holds for its names in each run, anything at all, each on its own.
    \* `warm`: run A's isolate holds seals of the key's rows from before their rewrite, if any, which a call by the map's
    \* ids reads by; anything its map holds, it may. Since review r12 of D153 the code's named call passes no seals at
    \* all (`known`), so that its work hangs on no earlier use: `warm` is FALSE there, and the model keeps both, a superset. The next state hangs on `mapA` and `warm` only through run A's
    \* answer, and on `mapB` only through run B's: the step picks among the answers they give, each once, rather than
    \* among the maps (25 a run, most alike): the same next states, each reached a few times rather than hundreds.
    /\ \E busy, contended \in BOOLEAN, pastFloor \in IF Floors THEN BOOLEAN ELSE {FALSE}, p \in Purposes,
         expiring \in IF Expiries THEN BOOLEAN ELSE {FALSE} :
         LET \* `stood` as a request needing p finds it, without DecideEachLock: kept for p.
             stoodFor(r) == stood[r][p]
             stale(warm) == warm /\ unseen /\ made = "around"
             answersA == {Answer(made, madeThere, mapA, fresh, stoodFor(1), cover[p], busy, contended, p, pastFloor, stale(warm), expiring) :
                          mapA \in Maps, warm \in BOOLEAN}
             answersB == {Answer("none", FALSE, mapB, FALSE, stoodFor(2), FALSE, busy, contended, p, pastFloor, FALSE, expiring) :
                          mapB \in Maps}
             \* Run A's, with the map as a read of the names makes it, and the seals read anew.
             right == Answer(made, madeThere, RightMap(made), fresh, stoodFor(1), cover[p], busy, contended, p, pastFloor, FALSE, expiring)
             \* Refused by the app's later clock, she may use the key in neither run.
             late == expiring /\ ~OneClock
             \* A use the vault allowed by the ids of the place keeps it for p, at the log's newest change.
             allowed(r) == CallerFromUse /\ r.here /\ r.answer.status = "value"
             keep(r, w) == IF allowed(w) THEN [stood[r] EXCEPT ![p] = TRUE] ELSE stood[r]
         IN \E a \in answersA, b \in answersB :
            /\ last' = [a |-> a.answer, b |-> b.answer, noA |-> ~Allowed(made, p) \/ late, noB |-> ~Allowed("none", p) \/ late, stands |-> p \in granted /\ ~Gone /\ ~late, right |-> right.answer]
            \* An answer the vault gave now is kept for the next request, as `accessFor` keeps it;
            \* the answer kept from before the revoke goes once a request asks the vault.
            /\ kept' = IF CallerFromUse THEN FALSE ELSE kept /\ p \in granted
            /\ fresh' = (fresh \/ a.wrote)
            /\ stood' = [r \in Runs |-> keep(r, IF r = 1 THEN a ELSE b)]
            \* An allowed use of the sealed key, fresh in the set by its end, is its isolate's cover for p;
            \* a refusal ends it.
            /\ cover' = [cover EXCEPT ![p] = CallerFromUse /\ made = "sealed" /\ a.answer.status = "value" /\ (fresh \/ a.wrote)]
    /\ left' = left - 1
    /\ UNCHANGED <<granted, grantedThere, made, unseen, madeThere, archived, browser, unconfigured, behindAccess>>

Done == left = 0 /\ UNCHANGED vars

Next == Revoke \/ Lapse \/ Make \/ End \/ Repoint \/ Park \/ Delete \/ MakeThere \/ Unconfigure \/ BehindAccess \/ Archive \/ Age \/ Request \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ granted \subseteq Purposes
    /\ grantedThere \subseteq Purposes
    /\ made \in {"none", "gone", "around", "away"} \cup Valued
    /\ unseen \in BOOLEAN
    /\ madeThere \in BOOLEAN
    /\ fresh \in BOOLEAN
    /\ stood \in [Runs -> [Purposes -> BOOLEAN]]
    /\ cover \in [Purposes -> BOOLEAN]
    /\ archived \in BOOLEAN
    /\ kept \in BOOLEAN
    /\ browser \in BOOLEAN
    /\ unconfigured \in BOOLEAN
    /\ behindAccess \in BOOLEAN
    /\ last \in Last

\* D153: whenever she may use the key in neither run, she is answered
\* alike in both, whatever the key is or was, and whatever each run's map
\* holds: its status, how many of the vault's calls it took, and whether one
\* of them waited for a lock. A `no` costs what any `no` does.
NoIsFixed == last.noA /\ last.noB => Seen(last.a) = Seen(last.b)

\* The narrower claim of PR B and T158 before D153: whenever she has no
\* standing for what she asks there (revoked, lapsed, or a Contributor
\* asking to read), she is answered alike for a key held, deleted or never
\* made. ProbingKept, which models 0.15 before PR B, is held to it alone.
SameAnswer == ~last.stands => Seen(last.a) = Seen(last.b)

\* D150 (fallback D), W268: whenever she has no standing for what she asks
\* there (revoked, lapsed, her credential ended, or a Contributor asking to
\* read), the vault read nothing of the key in either run before deciding:
\* no name's index, no row of a key, a reference or a source. What her
\* refusal costs inside its call then hangs on no key, held, gone, a
\* reference whatever its state, or never made, beside what it shows.
NoKeyBeforeStanding == ~last.stands => last.a.work \in {"nothing", "caller"} /\ last.b.work \in {"nothing", "caller"}

\* No `no` waited for her principal's lock.
NoLockForNo == last.noA => ~last.a.waited

\* D153 (review r2): a request takes the same route whatever the key is or was and whatever the isolate holds (its
\* map, its seals): by name in both runs, or by the app's path in both, or busy in both. Her credential and account,
\* which pick it, are the same in both runs.
OneRoute == last.a.route = last.b.route /\ last.a.route = last.right.route

\* Whatever the isolate's map holds, she is answered as the place her request
\* names decides: the map costs calls, never another decision (review d4 of
\* #416). A busy answer decides nothing: the floor may pass a use the map
\* makes at once, and not a read of the names, which finds the place archived.
AnsweredAsNamed == "busy" \notin {last.a.status, last.right.status} => last.a.status = last.right.status

=============================================================================
