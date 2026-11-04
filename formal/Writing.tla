------------------------------- MODULE Writing -------------------------------
(***************************************************************************)
(* A change in two round trips (T179, R42, R57; docs/design/two-trips.md): *)
(* what a key write and a member add become once each is one vault         *)
(* statement and one app statement, or two vault statements, and nothing   *)
(* else on the request path.                                               *)
(*                                                                         *)
(* The read and its hold. One function reads everything the decision       *)
(* weighs (`write_inputs`, `admit_inputs`): every object with its newest   *)
(* change in the log, every name and set as resolved. The decision takes   *)
(* that read and nothing else, and the commit runs the same function again *)
(* and goes ahead only if it answers the same (the digest). Here that      *)
(* function is `Read`, which both callers use, so the hold cannot read     *)
(* less than the decision did.                                             *)
(*                                                                         *)
(*   key write   1. the vault's statement, as a use's (HotPathOne): under  *)
(*                  the fence shared, the read, held to the log            *)
(*                  (StaleFirst: a row put back is refused), and the       *)
(*                  request numbered. Nothing locked after it.             *)
(*               2. the Worker decides on the read (decide.ts), wraps the  *)
(*                  value's key and seals the app's change, the read's     *)
(*                  digest in it; the app checks the caller's rows'        *)
(*                  `auth_mac`, as read, in memory.                        *)
(*               3. the app's statement: 0.14's head, the issue lock and   *)
(*                  the fence, then the hold (`hold_inputs`: the read      *)
(*                  again, its digest against the change's), then the      *)
(*                  rows, the change, the commit. A hold that fails rolls  *)
(*                  it all back, and the write asks again from 1.          *)
(*               4. the seal wait (R51), then the answer.                  *)
(*   member add  1. the vault's read (no lock);                            *)
(*               2. the Worker decides and builds the new row, its MAC     *)
(*                  and its seal, from the read; the app checks the        *)
(*                  caller's rows' `auth_mac`, as read (round 6), in       *)
(*                  memory, and hands the add back;                        *)
(*               3. one statement: the rows, the head, the issue lock, the *)
(*                  fence, the hold, the write; a hold that fails writes   *)
(*                  nothing and the vault reads again;                     *)
(*               4. the seal wait, then the answer.                        *)
(* Each asks again at most MaxTries times in all, then answers 409.        *)
(*                                                                         *)
(* As built, an add's write is one transaction of two statements, sent as  *)
(* one Sync (0.16.0, the contraction: no `member.add` entry, so no head    *)
(* read before a MAC): the members' rows and 0.14's head, a lock with      *)
(* nothing read under it, then the hold (`admit_hold`: the issue lock      *)
(* shared, the fence, the read again), the rows, COMMIT. The head and the  *)
(* rows taken a statement early only add order: a change that takes either *)
(* waits for the add, and one that takes neither (a session's revoke, a    *)
(* database writer) is what the hold, after the fence, weighs. AWrite is   *)
(* the second statement; whether the first's locks can close a cycle is    *)
(* WriteLocks.tla's (AddLocks). TwoTrips is the shape, as for a key write. *)
(* The read holds the adder's session too (`cred`): ended, or not as its   *)
(* log has it, the add answers 401 there and then, as a key write's does.  *)
(* An add the vault leaves to today's path (refused, an object not as its  *)
(* log has it, or a case it does not serve: PR 5 serves only an admin's    *)
(* first add) goes there as a key write does, with the caller the first    *)
(* try authenticated (Auth). Today's add (`admit`, `setAccess`) decides    *)
(* and writes in one transaction under the members' rows and 0.14's head,  *)
(* which every change of what it weighs takes but a session's revoke: one  *)
(* step (AToday), its caller's session not weighed again                   *)
(* (TodayCallerStandsAtDecision, as a key write's).                        *)
(*                                                                         *)
(* A refusal's record (PR 6). A try the decision refuses on its read is    *)
(* answered there: once the app has checked the caller's rows, the vault   *)
(* writes its record, a row of the log's changes of the request's own      *)
(* object, under the fence shared, which moves no object's newest change   *)
(* (Refuse); then the seal wait, then the answer. Before PR 6               *)
(* (RefusalLogged off) a refusal went down today's path.                    *)
(*                                                                         *)
(* Today's path (PR 3: `served: false`). A key write the vault does not    *)
(* serve goes as every write went before: the vault decides on the rows as *)
(* they are, each object's row held to its newest change, and that change  *)
(* to its MAC once T190 is in it (TodayChangeMacChecked), and wraps the    *)
(* key; then the app's transaction, under 0.14's head and the fence,       *)
(* writes on that decision (WToday, then WTodayCommit). A change between   *)
(* the two does not stop it, but for the roles' or the policy's, which the *)
(* commit holds to as the caller was loaded with (TodayPolicyHeld,         *)
(* `policyStill`; review r3 of #469): a grant revoked, a session ended     *)
(* (TodayStandsAtCommit, EXPECTED broken: the window every write has had   *)
(* since 0.14; review r1). A write goes there from its vault step (an      *)
(* object but the caller's credential not as the log has it) or from its   *)
(* decision (refused), on its first try or on a later one, after a try the *)
(* vault served and the app's hold abandoned: that try's request number    *)
(* stays, a gap the checkpointer seals past (0.16.0 writes no `key.wrap`   *)
(* on the two-trip path; today's path writes its own). The caller's own    *)
(* credential, not as its log has it or ended, answers 401 and never goes  *)
(* there: the credential's own check holds its row to its MAC alone, and   *)
(* would take one a database writer put back meanwhile. Nor is it weighed  *)
(* there again (review r2 of #469): today's path goes on with the caller   *)
(* the app authenticated, on the first try's read or by that check (Auth), *)
(* and a session revoked after does not stop the write                     *)
(* (TodayCallerStandsAtDecision, EXPECTED broken, as today's front door to *)
(* its wrap; WritingCaller).                                               *)
(*                                                                         *)
(* Every other change (a revoke, a role or policy change, an archive, a    *)
(* demotion, a rename) is one atomic step here, as each is one statement   *)
(* or one transaction under the head and the fence in the code. One step   *)
(* is one statement, or the part of one between two lock waits (READ      *)
(* COMMITTED: each statement reads afresh, so a hold sent as a statement   *)
(* after the locks reads after them). Locks: 0.14's head (held across      *)
(* steps by the app's statement only when its hold runs before the fence)  *)
(* and the fence; from a hold to its COMMIT, both (`held`), which a        *)
(* database writer ignores. A session's revoke takes the fence, not the    *)
(* head: 0047's `revoke_credential` takes the head too, and keeps it in    *)
(* 0.16.0 while 0.14.5 may serve beside it (Migration015's EntryLessHead;  *)
(* WriteLocks.tla checks its locks), which only adds order: the revoke     *)
(* here is the stronger adversary.                                         *)
(*                                                                         *)
(* Objects have seals: a counter per object, its newest change's number    *)
(* in the log, moved by each change. A row stores its seal too; a database *)
(* writer may put a row back (R64), which its column then cannot tell.     *)
(* Names have none: a rename, a key appearing, a personal config deleted   *)
(* moves only what a name resolves to. The caller's token hash is a name   *)
(* too: the credential's seal does not cover it, and only the app's        *)
(* `auth_mac` binds it to its credential (`tok`: 0 while it resolves to    *)
(* the caller's own credential, as that MAC vouches).                      *)
(*                                                                         *)
(* Who is who:                                                             *)
(*   w1, w2   Ada writes key k at env, each from her session cA;           *)
(*   rev      an admin takes Ada's grant at env away (her member object);  *)
(*   bk       ... and gives it back (the same row, a newer change: ABA);   *)
(*   end      Ada's session cA is revoked (the credential alone);          *)
(*   rol      an Owner redefines the roles (`role.define`): Ada's no       *)
(*            longer writes, an admin's no longer adds;                    *)
(*   pol      an Owner changes the instance policy (its own object);       *)
(*   arc      a maintainer archives env, or protects it (env's object);    *)
(*   par      a maintainer archives env's fork parent;                     *)
(*   rep      the parent's key Ada's regenerate replaces is written;       *)
(*   mrk      the parent's key whose level Ada's override inherits is      *)
(*            marked sensitive;                                            *)
(*   ren      a maintainer renames the key Ada writes (k becomes OLD_K);   *)
(*   phn      the fork's parent gains the key Ada writes, sensitive, where *)
(*            it held none (a dismissal is the same step);                 *)
(*   del      a maintainer deletes the personal config `env@me` names;     *)
(*   dbw      a database writer puts cA's row back, live, after its revoke;*)
(*   fsg      ... and one who puts it back also writes the row's seal     *)
(*            into the log's newest change of it, the revoke (T190): the   *)
(*            row and the log agree again, and only that change's MAC,     *)
(*            which the writer cannot make, says it is not the vault's;    *)
(*            in an add, Bob's row put back after his demotion likewise;   *)
(*   shp      a maintainer makes the key Ada writes a reference: a write    *)
(*            the two-trip path does not serve, down today's path on any   *)
(*            try (its `shape`, a name: no seal moves);                    *)
(*   rfl      a database writer copies a refusal's record, MAC and all, as *)
(*            the newest change of a revoked or demoted object, the row    *)
(*            put back to match (PR 6);                                    *)
(*   sub      a database writer copies a token hash they hold onto a live  *)
(*            Owner's credential row: the token now resolves to the Owner, *)
(*            no seal moves, the row's `auth_mac` no longer matches        *)
(*            (round 6's P1);                                              *)
(*   bob, cy  two admins each add the service account svc (bob, in         *)
(*            SetUp and Protect, no admin, sets it up with a first grant,  *)
(*            on a whole project in Protect);                              *)
(*   dem      an Owner demotes Bob;                                        *)
(*   rmb      an Owner removes Bob, which ends his session (its generation *)
(*            no longer his membership's), then restores him before the    *)
(*            session's row is revoked (review r1 of #474);                *)
(*   cls      an Owner closes the services setting;                        *)
(*   plc      a maintainer archives the place of svc's first grant;        *)
(*   prt      an Owner protects an environment of the grant's project      *)
(*            (`givesService` weighs the protected ones, `protectedWithin`;*)
(*            round 5's P1);                                               *)
(*   nev      a fork of a protected environment is made in the project:    *)
(*            the set of its environments moves;                           *)
(*   slg      the grant's project is renamed and another made under its    *)
(*            old slug;                                                    *)
(*   scp      the role's scope project is renamed likewise;                *)
(*   ck       the checkpointer: each tick seals every committed number.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs,          \* the scenario's processes (MCWriting.tla)
    MaxTries        \* how many tries a write or an add has in all

CONSTANTS
    \* The vault's statement reads and numbers the request in one statement
    \* under the fence shared, as a use does: its read is one snapshot, and
    \* no change is numbered between it and its number.
    RequestUnderFence,
    \* The commit holds the read: the app's statement (a write) or
    \* `admit_write` (an add) reads again and goes ahead only if the read
    \* answers the same.
    ReadHeld,
    \* The parts of the read the hold skips: normally none. Each left out
    \* in turn stands for a `write_inputs` that missed one.
    Unheld,
    \* The decision weighs the read and nothing else. Without, it takes the
    \* roles from its isolate's cache, as they were when the isolate began.
    DecideOnRead,
    \* The write's hold runs once its statement holds the fence. Without, it
    \* runs under 0.14's head, and the statement then waits for the fence.
    HoldAfterFence,
    \* The read takes each object's number from the log's newest change of
    \* it. Without, from the seal its row stores.
    ReadOnLog,
    \* The hold compares numbers as well as values. Without, values alone.
    ReadByNumber,
    \* A change answers only once its number is sealed in a checkpoint (R51).
    WaitForSeal,
    \* The app checks the caller's rows' `auth_mac`, as the vault read them,
    \* before anything commits: a key write's step 4, an add's step 3.
    AuthChecked,
    \* The change's actor is the credential the checked read resolved, by
    \* id under the vault's MAC: neither the hold nor the write resolves the
    \* token again. Without, the write takes the actor from what the token
    \* resolves to at the commit.
    ActorFromRead,
    \* The Worker holds each object's newest change in the read to its MAC
    \* (T190, `changeHolds`) before it holds the object's row to that
    \* change's seal (StaleFirst): a change whose MAC fails is the log
    \* written around, and the request is refused. Without, the seal the
    \* change records is trusted as it reads.
    ChangeMacChecked,
    \* Today's path holds each object's newest change to its MAC too (T190
    \* on that path: `changeHolds` in `prepare` and in the decisions).
    \* Without, a request the two-trip path refused for a forged change
    \* goes down a path that trusts it.
    TodayChangeMacChecked,
    \* A request goes down today's path only from a try that committed
    \* nothing: the vault's refusal, or a hold that failed and rolled back.
    \* Without, one whose seal wait failed after its COMMIT goes down it too.
    FallBackUncommitted,
    \* Today's commit holds to the policy the caller was loaded with: the
    \* newest change of the roles and of the policy, as the front door read
    \* them (`audited`'s `policyStill`, 409 `policy_changed`). Without, a
    \* roles change between today's decision and its commit does not stop it.
    TodayPolicyHeld,
    \* The add's decision holds the caller's session to the generation of
    \* the membership it was issued under (`credentialEnded`): a session of
    \* a membership removed and restored since is ended, 401, before its row
    \* is revoked. Without, the restored member's old session adds.
    GenerationChecked,
    \* A try the decision refuses is answered by the vault's record of the
    \* refusal (PR 6), its second statement, and goes nowhere else. Without,
    \* it goes down today's path, as before PR 6, which refuses and logs it
    \* there, or, the request asked again since, may write.
    RefusalLogged,
    \* The refusal's record ends the request. Without, the request still goes
    \* down today's path after it.
    RefusalEnds,
    \* The vault writes a refusal's record only once the app has checked the
    \* caller's rows its read answered (AuthChecked, as before a change
    \* commits). Without, it writes it at its decision, in its first call.
    RefusalAfterAuth

Writers == {"w1", "w2"}
Adders == {"bob", "cy"}
\* What each change moves: one object, turned against the writer or the adder.
Moves == [rev |-> "member", end |-> "cred", rol |-> "roles", pol |-> "policy",
          arc |-> "env", par |-> "parent", rep |-> "parentKey", mrk |-> "parentKey",
          dem |-> "bob", cls |-> "settings", plc |-> "place", prt |-> "prot"]
\* What each rename moves: a name's resolution, no seal.
Renames == [ren |-> "keyName", phn |-> "chain", del |-> "me",
            slg |-> "slug", nev |-> "envs", scp |-> "scope", shp |-> "shape"]
\* What a token resolves to, by its hash.
Token == "tok"

\* What a key write reads: Ada's session, her member object, the roles, the
\* policy, the environment, its fork parent, the parent's keys weighed, the
\* key itself; and what the key's name, the fork chain and `env@me` resolve
\* to, and whether the key is still a value of its own (`shape`: made a
\* reference, it is one the two-trip path does not write, and the request
\* goes down today's path, on any try).
WriteObjects == {"cred", "member", "roles", "policy", "env", "parent", "parentKey", "key"}
WriteNames == {"keyName", "chain", "me", "shape", Token}
\* What an add reads: the adder's session and object, the roles, the policy,
\* the services setting, the grant's place, the project's other
\* environments, svc's row; and what the grant's slugs, the project's set of
\* environments and the scope's slug resolve to. (The session is the same
\* object as Ada's, `cred`: no scenario has both an adder and a writer but
\* Forge, where one revoke ends either's.)
AddObjects == {"cred", "bob", "roles", "policy", "settings", "place", "prot", "svc"}
AddNames == {"slug", "envs", "scope", Token}
Movable == {"cred", "member", "roles", "policy", "env", "parent", "parentKey",
            "bob", "settings", "place", "prot"}
Objects == Movable \cup {"key", "svc"}
NameParts == WriteNames \cup AddNames
Kind(p) == IF p \in Writers THEN "write" ELSE "add"
ObjectsOf(k) == IF k = "write" THEN WriteObjects ELSE AddObjects
Parts(k) == IF k = "write" THEN WriteObjects \cup WriteNames ELSE AddObjects \cup AddNames
\* The vault's first reads, when its reads are not one statement.
FirstRead == {"cred"}
None == "none"

VARIABLES
    ok,         \* each movable object still as the writer or adder needs it
    names,      \* what each name resolves to: moved by a rename, no seal
    svc,        \* svc is a member
    kver,       \* the key's committed versions
    seal,       \* each object's newest change in the log: moved by every change
    putBack,    \* the rows a database writer put back to their first state
    forged,     \* ... whose newest change's seal they also wrote to match
    gen,        \* Bob's membership's generation: his session's is 0
    next,       \* the log's next number
    sealedTo,   \* the checkpointer has sealed every number below this
    head,       \* who holds 0.14's head across steps, or None
    held,       \* who holds the head and the fence from its hold to its COMMIT
    pc, l, tries,
    trips,      \* round trips each process made on its path
    requests,   \* ghost: each write's request, as decided live and by the replay
    writes,     \* ghost: each committed key change
    admits,     \* ghost: each committed member add
    answered,   \* ghost: each change answered, with its number
    refusals    \* ghost: each refusal's record, as the vault wrote it

vars == <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, held,
          pc, l, tries, trips, requests, writes, admits, answered, refusals>>

\* An object's row as stored: put back to its first state by a database
\* writer, or as its newest change left it.
RowSeal(o) == IF o \in putBack THEN 0 ELSE seal[o]
\* The session's own standing at the vault: as its row says, and of the
\* membership's generation it was issued under (`credentialEnded`).
SessionLive == ok["cred"] /\ gen = 0
Value(o) == CASE o = "key" -> kver
              [] o = "svc" -> svc
              [] o = "cred" /\ GenerationChecked /\ gen # 0 -> FALSE
              [] o \in putBack -> TRUE
              [] OTHER -> ok[o]

\* The read (`write_inputs`, `admit_inputs`), as it answers now: every object
\* with its number and its row's value, every name as resolved. The vault's
\* read and the hold both call it.
Read(k) == [o \in Parts(k) |->
               IF o \in NameParts THEN [name |-> names[o]]
               ELSE [num |-> IF ReadOnLog THEN seal[o] ELSE RowSeal(o), val |-> Value(o)]]
\* A row the log has moved past (StaleFirst refuses it): its seal is not
\* the one its object's newest change records, which is the change's own,
\* or, forged, the row's.
StaleRow(o) == RowSeal(o) # seal[o] /\ o \notin forged
\* A newest change whose MAC fails (`changeHolds`): refused before its seal
\* is weighed at all.
MacFails(o) == ChangeMacChecked /\ o \in forged
Unsound(o) == StaleRow(o) \/ MacFails(o)
Refused(k) == \E o \in ObjectsOf(k) : Unsound(o)

\* What the decision weighs: the read, or (a removal) the read with the
\* roles from the isolate's cache.
Weighed(r) == IF DecideOnRead THEN r ELSE [r EXCEPT !["roles"].val = TRUE]
WriteAllowed(r) == \A o \in WriteObjects \ {"key"} : r[o].val
\* What today's wrap weighs: the same, but for the caller's credential,
\* which the app checked before (Auth), and does not again.
WrapObjects == WriteObjects \ {"key", "cred"}
WrapAllowed(r) == \A o \in WrapObjects : r[o].val
\* Cy is an admin nobody demotes; Bob stands while his object does. Either
\* adds only a principal that is no member yet.
AddAllowed(p, r) == /\ \A o \in AddObjects \ {"bob", "svc"} : r[o].val
                    /\ p = "cy" \/ r["bob"].val
                    /\ ~r["svc"].val
Decide(p, r) == IF Kind(p) = "write" THEN WriteAllowed(Weighed(r)) ELSE AddAllowed(p, Weighed(r))
\* The app's check: the caller's rows, as read, carry its MAC. A row whose
\* token hash was copied from another fails it.
AppChecks(r) == ~AuthChecked \/ r[Token].name = 0

\* The hold: the read again, compared part by part to the one decided on,
\* but for the parts it skips. A part is its number and its value, or (a
\* removal) its value alone; a name, what it resolves to.
Part(r, o) == IF o \in NameParts \/ ReadByNumber THEN r[o] ELSE r[o].val
Holds(p) == ~ReadHeld \/ \A o \in Parts(Kind(p)) \ Unheld : Part(Read(Kind(p)), o) = Part(l[p].read, o)

\* Ghosts, from the truth at the commit, not from any read:
\* the writer or adder stands on what is (the objects as the log has them,
\* not a row put back), and its names still resolve as it decided ...
\* (The token's resolution is not among them: it says who asks, which the
\* change binds by id, CommitsAuthentic.)
NamesAsRead(p) == \A n \in (Parts(Kind(p)) \cap NameParts) \ {Token} : names[n] = l[p].read[n].name
WriteStands(p) == (\A o \in WriteObjects \ {"key"} : ok[o]) /\ NamesAsRead(p)
\* What an add weighs but its caller's session: what today's add decides on.
AddUp(p) == /\ \A o \in AddObjects \ {"cred", "bob", "svc"} : ok[o]
            /\ p = "cy" \/ ok["bob"]
AddStands(p) == AddUp(p) /\ SessionLive /\ NamesAsRead(p)
\* ... and the log, replayed at the commit, finds every object it read at
\* the number its change binds (the read's).
Replays(p) == \A o \in ObjectsOf(Kind(p)) : seal[o] = l[p].seals[o]

Init ==
    /\ ok = [o \in Movable |-> TRUE]
    /\ names = [n \in NameParts |-> 0]
    /\ svc = FALSE /\ kver = 0
    /\ seal = [o \in Objects |-> 0]
    /\ putBack = {} /\ forged = {} /\ gen = 0
    /\ next = 1 /\ sealedTo = 1 /\ head = None /\ held = None
    /\ pc = [p \in Procs |-> CASE p \in Writers -> "w.vault"
                                [] p \in Adders -> "a.read"
                                [] p = "ck" -> "ck"
                                [] p = "dbw" -> "tamper"
                                [] p = "fsg" -> "forge"
                                [] p = "sub" -> "substitute"
                                [] p = "rfl" -> "refile"
                                [] p = "bk" -> "giveback"
                                [] p = "rmb" -> "remove"
                                [] p \in DOMAIN Renames -> "rename"
                                [] OTHER -> "change"]
    /\ l = [p \in Procs |-> [n |-> 0]]
    /\ tries = [p \in Procs |-> 1]
    /\ trips = [p \in Procs |-> 0]
    /\ requests = {} /\ writes = {} /\ admits = {} /\ answered = {} /\ refusals = {}

Goto(p, to) == pc' = [pc EXCEPT ![p] = to]
\* A change commits, numbered, its object's newest change moved.
Numbered(o) == /\ seal' = [seal EXCEPT ![o] = @ + 1]
               /\ next' = next + 1
\* Asked again, or given up (409 `changed`) once out of tries.
Again(p, from) ==
    /\ IF tries[p] < MaxTries THEN Goto(p, from) ELSE Goto(p, "done")
    /\ tries' = [tries EXCEPT ![p] = @ + 1]
\* Who the change is by: the credential the read resolved the token to,
\* which the app's check vouched for (0: the caller's own), bound by id;
\* or (a removal) whom the token resolves to at the commit.
Actor(p) == IF ActorFromRead THEN l[p].read[Token].name ELSE names[Token]
\* A committed change, as the ghosts record it.
Committed(p, o, stands) ==
    [p |-> p, n |-> next, stands |-> stands, replays |-> Replays(p),
     from |-> l[p].seals[o], was |-> seal[o], authentic |-> Actor(p) = 0, today |-> FALSE, decided |-> TRUE, caller |-> TRUE, policy |-> TRUE,
     t |-> tries[p], wrap |-> IF "wrap" \in DOMAIN l[p] THEN l[p].wrap ELSE tries[p]]

-----------------------------------------------------------------------------
(* A key write *)

\* The request, numbered: as the Worker will decide it from what was read,
\* and as the replay will from the log at its number (each change is one
\* step here, so the log at this step is the log at the number).
Truth == [o \in Parts("write") |->
             IF o \in NameParts THEN [name |-> names[o]]
             ELSE [num |-> seal[o], val |-> IF o = "key" THEN kver ELSE ok[o]]]
Request(p, r) == [p |-> p, n |-> next, live |-> Decide(p, r), replay |-> Decide(p, Truth)]

\* Who the request is by, as the app authenticated it: on the first try,
\* from that try's read (the two-trip path's rows, AppChecks) or, the try
\* not served, by the credential's own check just after (at WDecide, for a
\* try the Worker refuses: Fable's review of #469); on a later try, kept: each later try the vault
\* serves is checked to be the same credential (`Written.again`), and
\* today's path, after one, goes on with the caller the first checked
\* (review r2 of #469). Only the token's resolution is kept: the caller's
\* standing is the read's, and no step after rechecks it on today's path.
\* With it, the policy the caller was loaded with: the newest change of the
\* roles and of the policy (`Caller.policySeq`), which today's commit holds
\* to (TodayPolicyHeld).
PolicyObjects == {"roles", "policy"}
Auth(p) == IF tries[p] = 1 THEN [tok |-> names[Token], pol |-> [o \in PolicyObjects |-> seal[o]]]
                           ELSE l[p].auth

\* The vault's statement: the read under the fence shared, the request
\* numbered. One round trip. The caller's own credential not as its log
\* has it (`forged`), or revoked (`ended`): 401, the end. Another object
\* not as its log has it (`stale`, `tampered`): today's path.
WVault(p) ==
    /\ pc[p] = "w.vault"
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Unsound("cred") \/ ~Value("cred")
         THEN /\ Goto(p, "done")
              /\ UNCHANGED <<next, l, requests>>
       ELSE IF \E o \in WriteObjects \ {"cred"} : Unsound(o)
         THEN /\ Goto(p, "w.today")
              /\ l' = [l EXCEPT ![p] = [n |-> 0, auth |-> Auth(p)]]
              /\ UNCHANGED <<next, requests>>
         ELSE /\ l' = [l EXCEPT ![p] = [n |-> 0, read |-> Read("write"), seals |-> seal, wrap |-> 0, auth |-> Auth(p),
                                          asked |-> Request(p, Read("write"))]]
              /\ IF RequestUnderFence
                   THEN /\ next' = next + 1
                        /\ requests' = requests \cup {Request(p, Read("write"))}
                        /\ Goto(p, "w.decide")
                   ELSE /\ UNCHANGED <<next, requests>>
                        /\ Goto(p, "w.rest")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, sealedTo, head, held, tries, writes, admits, answered, refusals>>

\* Without one statement under the fence: the rest of the read, and the
\* request numbered, in a later step. A change between the two tears what
\* was read from what the log holds at the number.
WRest(p) ==
    /\ pc[p] = "w.rest"
    /\ LET r == [o \in Parts("write") |-> IF o \in FirstRead THEN l[p].read[o] ELSE Read("write")[o]]
           seals == [o \in Objects |-> IF o \in FirstRead THEN l[p].seals[o] ELSE seal[o]]
       IN /\ l' = [l EXCEPT ![p].read = r, ![p].seals = seals, ![p].asked = Request(p, r)]
          /\ requests' = requests \cup {Request(p, r)}
    /\ next' = next + 1
    /\ Goto(p, "w.decide")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, sealedTo, head, held, tries, trips, writes, admits, answered, refusals>>

\* A refusal decided on the read, recorded (PR 6): once the app has checked
\* the caller's rows the read answered (RefusalAfterAuth), the vault writes
\* its record (Refuse); rows not the caller's, 401 and no record. Without,
\* the vault writes it at its decision, before the app has seen the rows.
RefuseOrAnswer(p) ==
    /\ IF RefusalAfterAuth /\ ~AppChecks(l[p].read) THEN Goto(p, "done") ELSE Goto(p, "r.refuse")
    /\ UNCHANGED l

\* Today's path, from a try's decision. A first try: `writeAhead` answers
\* nothing, and the credential's own check reads its row now
\* (`authenticateRequest`): ended, 401; else the caller it finds, which
\* today's path takes. A later one: the caller the first checked (Auth).
Today(p, to) ==
    IF tries[p] = 1 /\ ~Value("cred")
      THEN Goto(p, "done") /\ UNCHANGED l
      ELSE /\ Goto(p, to)
           /\ l' = [l EXCEPT ![p].auth = Auth(p)]

\* The Worker decides on the read; allowed, it wraps the key (the try's,
\* `wrap`, which its change names by the request's number; no 0.14
\* `key.wrap` entry since 0.16.0) and seals the change, and the app checks
\* the caller's rows. No round trip. Refused: the refusal's record (PR 6),
\* or, before it, today's path, which refuses and logs it as ever. A key
\* the read found a reference (`shape`), whatever the decision: today's
\* path, on any try (the vault serves no such write). The rows not the
\* caller's: 401.
WDecide(p) ==
    /\ pc[p] = "w.decide"
    /\ LET unserved == l[p].read["shape"].name # 0
           allowed == Decide(p, l[p].read)
       IN \/ /\ ~unserved /\ allowed
             /\ IF ~AppChecks(l[p].read)
                  THEN Goto(p, "done") /\ UNCHANGED l
                  ELSE /\ l' = [l EXCEPT ![p].wrap = tries[p]] /\ Goto(p, "w.app")
          \/ ~unserved /\ ~allowed /\ RefusalLogged /\ RefuseOrAnswer(p)
          \/ (unserved \/ (~allowed /\ ~RefusalLogged)) /\ Today(p, "w.today")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, held, tries, trips, requests, writes, admits, answered, refusals>>

\* The write itself: the key's next version, its change numbered.
Commit(p) ==
    /\ kver' = kver + 1
    /\ Numbered("key")
    /\ l' = [l EXCEPT ![p].n = next]
    /\ writes' = writes \cup {Committed(p, "key", WriteStands(p))}

\* The app's statement, to its hold. One round trip. The code takes the
\* head, then the fence, then holds; from the hold to COMMIT it keeps both,
\* so no change that takes either comes between (`held`). A database writer
\* takes neither, so the write's rows and its COMMIT are a step of their own
\* (WCommit), after the hold, with only such a writer between (round 7).
WApp(p) ==
    /\ pc[p] = "w.app"
    /\ head = None /\ held = None
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Holds(p)
         THEN IF HoldAfterFence
                THEN /\ held' = p /\ Goto(p, "w.commit")
                     /\ UNCHANGED <<head, tries>>
                \* Its hold under 0.14's head, then a wait for the fence.
                ELSE /\ head' = p /\ Goto(p, "w.fence")
                     /\ UNCHANGED <<held, tries>>
         ELSE /\ Again(p, "w.vault")
              /\ UNCHANGED <<head, held>>
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, l, requests, writes, admits, answered, refusals>>

\* The same statement, after its wait for the fence (a removal: the hold
\* ran before it).
WFence(p) ==
    /\ pc[p] = "w.fence"
    /\ held = None
    /\ head' = None /\ held' = p
    /\ Goto(p, "w.commit")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, l, tries, trips, requests, writes, admits, answered, refusals>>

\* The rows, the key's update, the change, COMMIT; the locks let go.
WCommit(p) ==
    /\ pc[p] = "w.commit"
    /\ held' = None
    /\ Commit(p)
    \* (A removal: the seal wait failing after the COMMIT taken for the
    \* vault's `served: false`.)
    /\ \/ Goto(p, "w.seal")
       \/ ~FallBackUncommitted /\ Goto(p, "w.today")
    /\ UNCHANGED <<ok, names, svc, putBack, forged, gen, sealedTo, head, tries, trips, requests, admits, answered, refusals>>

\* Today's path, as it goes: the vault decides on the rows as they are and
\* wraps the key (0.14's `key.wrap`), then the app's transaction, under
\* 0.14's head and the fence, writes on that decision. Two steps (review r1
\* of #469): a change may come between them, which today's commit does not
\* weigh again but for the roles and the policy (TodayPolicyHeld, review
\* r3): a grant revoked, a session ended (TodayStandsAtCommit, a window
\* every write has had since 0.14, which the two-trip path closes for the
\* writes it serves).
\*
\* The decision holds each object but the caller's credential to its newest
\* change (the row's seal), and that change to its MAC once T190 is in it.
\* The caller's credential it does not weigh at all (review r2 of #469):
\* the request comes with the caller the app authenticated (Auth), on the
\* first try's read or by the credential's own check, and the wrap decides
\* for that caller's member and roles, not its session. A session revoked
\* after that check, before the wrap, does not stop the write
\* (TodayCallerStandsAtDecision, EXPECTED broken: today's path between its
\* front door and its wrap, a window every write has had since 0.14; here
\* it spans the tries before, a few round trips).
WToday(p) ==
    /\ pc[p] = "w.today"
    /\ head = None /\ held = None
    /\ LET r == Read("write")
           refuses == \/ \E o \in WriteObjects \ {"cred"} :
                            StaleRow(o) \/ (TodayChangeMacChecked /\ o \in forged)
                      \/ ~WrapAllowed(r)
                      \* The caller as authenticated: a token hash copied onto
                      \* another credential fails its `auth_mac` there (401).
                      \/ AuthChecked /\ l[p].auth.tok # 0
       IN IF refuses
            THEN /\ Goto(p, "done")
                 /\ UNCHANGED l
            \* What it decided on, and whether the caller stood then, by the log.
            ELSE /\ l' = [l EXCEPT ![p] = [n |-> 0, read |-> r, seals |-> seal, wrap |-> 0, auth |-> l[p].auth,
                                          decided |-> \A o \in WrapObjects : ok[o],
                                          caller |-> ok["cred"]]]
                 /\ Goto(p, "w.tcommit")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, held, tries, trips, requests, writes, admits, answered, refusals>>

\* ... and the app's transaction: under 0.14's head and the fence, it finds
\* the policy the caller was loaded with still the newest (`policyStill`,
\* else 409 `policy_changed`, the end; review r3 of #469), the environment
\* still live (`checkEnvironment`) and the key's row where
\* the decision found it (`app_change`, else `ObjectMoved`, asked again);
\* then the key's next version, its change numbered. Its write binds no
\* read, so it replays trivially; its wrap is its own (0).
WTodayCommit(p) ==
    /\ pc[p] = "w.tcommit"
    /\ head = None /\ held = None
    /\ IF \/ TodayPolicyHeld /\ \E o \in PolicyObjects : seal[o] # l[p].auth.pol[o]
          \/ ~ok["env"]
         THEN /\ Goto(p, "done")
              /\ UNCHANGED <<kver, seal, next, l, tries, writes>>
       ELSE IF seal["key"] # l[p].seals["key"]
         THEN /\ Again(p, "w.today")
              /\ UNCHANGED <<kver, seal, next, l, writes>>
         ELSE /\ kver' = kver + 1
              /\ Numbered("key")
              /\ l' = [l EXCEPT ![p].n = next]
              /\ writes' = writes \cup {[p |-> p, n |-> next, today |-> TRUE,
                                           stands |-> \A o \in WriteObjects \ {"key"} : ok[o],
                                           policy |-> \A o \in PolicyObjects : ok[o],
                                           decided |-> l[p].decided, caller |-> l[p].caller,
                                           replays |-> TRUE, from |-> seal["key"], was |-> seal["key"],
                                           authentic |-> IF ActorFromRead THEN l[p].auth.tok = 0 ELSE names[Token] = 0,
                                           t |-> 0, wrap |-> 0]}
              /\ Goto(p, "t.seal")
              /\ UNCHANGED tries
    /\ UNCHANGED <<ok, names, svc, putBack, forged, gen, sealedTo, head, held, trips, requests, admits, answered, refusals>>

-----------------------------------------------------------------------------
(* A member add *)

\* The read. No lock. The adder's own session ended, or not as its log has
\* it: 401, the end, as a key write's (WVault). Another object not as its
\* log has it: today's path, which refuses it as ever.
ARead(p) ==
    /\ pc[p] = "a.read"
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Unsound("cred") \/ ~Value("cred")
         THEN Goto(p, "done") /\ UNCHANGED l
       ELSE IF Refused("add")
         THEN /\ Goto(p, "a.today")
              /\ l' = [l EXCEPT ![p] = [n |-> 0, auth |-> Auth(p)]]
         ELSE /\ l' = [l EXCEPT ![p] = [n |-> 0, read |-> Read("add"), seals |-> seal, auth |-> Auth(p)]]
              /\ Goto(p, "a.decide")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, held, tries, requests, writes, admits, answered, refusals>>

\* The Worker decides on the read: the adder's standing, svc no member yet;
\* then the app checks the adder's rows, between the vault's two calls.
\* (The check reads only what the vault answered, so it is one step with
\* the decision.) No round trip.
\* Refused: the refusal's record (PR 6), as a key write's (WDecide); or,
\* before it, today's path. Allowed but a case the vault leaves to today's
\* path (PR 5 serves an admin's first add: a set-up by someone who runs no
\* instance is PR 5b's), there, as a key write's, the caller the first try
\* authenticated, or on a first try the credential's own check now.
ADecide(p) ==
    /\ pc[p] = "a.decide"
    /\ LET allowed == Decide(p, l[p].read)
       IN \/ /\ allowed
             /\ IF AppChecks(l[p].read) THEN Goto(p, "a.write") ELSE Goto(p, "done")
             /\ UNCHANGED l
          \/ ~allowed /\ RefusalLogged /\ RefuseOrAnswer(p)
          \/ (allowed \/ ~RefusalLogged) /\ Today(p, "a.today")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, held, tries, trips, requests, writes, admits, answered, refusals>>

\* The write: rows, head, fence, the hold. One round trip. As a key
\* write's, the row and its COMMIT are a step of their own (ACommit), with
\* only a database writer between.
AWrite(p) ==
    /\ pc[p] = "a.write"
    /\ head = None /\ held = None
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Holds(p)
         THEN /\ held' = p /\ Goto(p, "a.commit")
              /\ UNCHANGED tries
         ELSE /\ Again(p, "a.read")
              /\ UNCHANGED held
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, l, requests, writes, admits, answered, refusals>>

\* svc's row, its change, COMMIT; the locks let go.
ACommit(p) ==
    /\ pc[p] = "a.commit"
    /\ held' = None
    /\ svc' = TRUE
    /\ Numbered("svc")
    /\ l' = [l EXCEPT ![p].n = next]
    /\ admits' = admits \cup {Committed(p, "svc", AddStands(p))}
    /\ Goto(p, "a.seal")
    /\ UNCHANGED <<ok, names, kver, putBack, forged, gen, sealedTo, head, tries, trips, requests, writes, answered, refusals>>

\* Today's add (`admit`, `setAccess(…, admit)`): one transaction, under the
\* members' rows and 0.14's head, which every change of what it weighs takes
\* but a session's revoke; the fence from its entry to COMMIT. So one step:
\* it decides on the rows as they are, each held to its newest change and
\* that change to its MAC (T190, `#onLog`), and writes. Its caller is the
\* one the app authenticated (Auth), whose session it does not weigh. svc a
\* member already (another add first): nothing to do, nothing written.
TodayAddAllowed(p, r) == /\ \A o \in AddObjects \ {"cred", "bob", "svc"} : r[o].val
                         /\ p = "cy" \/ r["bob"].val
                         /\ ~r["svc"].val
AToday(p) ==
    /\ pc[p] = "a.today"
    /\ head = None /\ held = None
    /\ LET refuses == \/ \E o \in AddObjects \ {"cred"} :
                            StaleRow(o) \/ (TodayChangeMacChecked /\ o \in forged)
                      \/ ~TodayAddAllowed(p, Read("add"))
                      \/ AuthChecked /\ l[p].auth.tok # 0
       IN IF refuses
            THEN /\ Goto(p, "done")
                 /\ UNCHANGED <<svc, seal, next, l, admits>>
            ELSE /\ svc' = TRUE
                 /\ Numbered("svc")
                 /\ l' = [l EXCEPT ![p].n = next]
                 /\ admits' = admits \cup {[p |-> p, n |-> next, today |-> TRUE,
                                             stands |-> AddUp(p) /\ SessionLive,
                                             decided |-> AddUp(p), caller |-> SessionLive,
                                             policy |-> \A o \in PolicyObjects : ok[o],
                                             replays |-> TRUE, from |-> seal["svc"], was |-> seal["svc"],
                                             authentic |-> IF ActorFromRead THEN l[p].auth.tok = 0 ELSE names[Token] = 0,
                                             t |-> 0, wrap |-> 0]}
                 /\ Goto(p, "t.seal")
    /\ UNCHANGED <<ok, names, kver, putBack, forged, gen, sealedTo, head, held, tries, trips, requests, writes, answered, refusals>>

-----------------------------------------------------------------------------
(* A refusal's record (PR 6) *)

\* The vault's second statement (`log_refusal`): the refusal, MAC'd by the
\* Worker, a row of the log's changes numbered under the fence shared, as a
\* use is (it waits for a change's hold to its COMMIT, `held`, and holds up
\* no use), of the request's own object, so no object's newest change moves
\* and no reader that decides takes it (docs/design/two-trips.md, "A
\* refusal's record"). One round trip. It names the request's number (a
\* key write's: an add's read numbers nothing) and the credential the read
\* resolved the token to, which the app's check vouched for first
\* (RefusalAfterAuth). Then the seal wait (R51, D165 kept for refusals),
\* then the answer: today's status and body, and no 0.14 entry.
Refuse(p) ==
    /\ pc[p] = "r.refuse"
    /\ held = None
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ refusals' = refusals \cup {[p |-> p, kind |-> Kind(p), n |-> next, t |-> tries[p],
                                   replay |-> IF Kind(p) = "write" THEN l[p].asked.replay ELSE FALSE,
                                   authentic |-> l[p].read[Token].name = 0]}
    /\ next' = next + 1
    /\ l' = [l EXCEPT ![p].n = next]
    \* (A removal: the request goes on down today's path after its record.)
    /\ IF RefusalEnds THEN Goto(p, "r.seal")
       ELSE Goto(p, IF Kind(p) = "write" THEN "w.today" ELSE "a.today")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, sealedTo, head, held, tries, requests, writes, admits, answered>>

-----------------------------------------------------------------------------
(* The seal wait, the answer, and everything else *)

\* A change answers once its number is sealed (R51).
Answer(p) ==
    /\ pc[p] \in {"w.seal", "a.seal", "x.seal", "t.seal", "r.seal"}
    /\ ~WaitForSeal \/ l[p].n < sealedTo
    /\ answered' = answered \cup {[p |-> p, n |-> l[p].n]}
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, held, l, tries, trips, requests, writes, admits, refusals>>

\* Every other change, one atomic step: 0.14's head and the fence (a
\* session's revoke the fence alone, which the head's holder does not stop).
Change(p) ==
    /\ pc[p] = "change"
    /\ held = None
    /\ p = "end" \/ head = None
    /\ ok' = [ok EXCEPT ![Moves[p]] = FALSE]
    /\ Numbered(Moves[p])
    /\ l' = [l EXCEPT ![p].n = next]
    /\ Goto(p, "x.seal")
    /\ UNCHANGED <<names, svc, kver, putBack, forged, gen, sealedTo, head, held, tries, trips, requests, writes, admits, answered, refusals>>

\* Ada's grant given back once taken: the same row, a newer change.
GiveBack(p) ==
    /\ pc[p] = "giveback"
    /\ head = None /\ held = None
    /\ ~ok["member"]
    /\ ok' = [ok EXCEPT !["member"] = TRUE]
    /\ Numbered("member")
    /\ l' = [l EXCEPT ![p].n = next]
    /\ Goto(p, "x.seal")
    /\ UNCHANGED <<names, svc, kver, putBack, forged, gen, sealedTo, head, held, tries, trips, requests, writes, admits, answered, refusals>>

\* Bob removed, his generation advanced, which ends his session though its
\* row still says live (its revoke follows, by the app's sweep); then
\* restored, as an admin again: the same row, a newer change, the new
\* generation. Each one step under the head and the fence, as Change.
Remove(p) ==
    /\ pc[p] = "remove"
    /\ head = None /\ held = None
    /\ ok' = [ok EXCEPT !["bob"] = FALSE]
    /\ gen' = 1
    /\ Numbered("bob")
    /\ Goto(p, "restore")
    /\ UNCHANGED <<names, svc, kver, putBack, forged, sealedTo, head, held, l, tries, trips, requests, writes, admits, answered, refusals>>
Restore(p) ==
    /\ pc[p] = "restore"
    /\ head = None /\ held = None
    /\ ok' = [ok EXCEPT !["bob"] = TRUE]
    /\ Numbered("bob")
    /\ l' = [l EXCEPT ![p].n = next]
    /\ Goto(p, "x.seal")
    /\ UNCHANGED <<names, svc, kver, putBack, forged, gen, sealedTo, head, held, tries, trips, requests, writes, admits, answered, refusals>>

\* A database writer puts cA's row back as it was, live, once it is revoked.
\* Nothing logged: the log's newest change of cA is still the revoke.
Tamper(p) ==
    /\ pc[p] = "tamper"
    /\ seal["cred"] > 0
    /\ putBack' = putBack \cup {"cred"}
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, forged, gen, next, sealedTo, head, held, l, tries, trips, requests, writes, admits, answered, refusals>>

\* A database writer puts a revoked or demoted row back, live, and writes its
\* seal into the log's newest change of it, the revoke or the demotion: row
\* and log agree, StaleFirst passes, and the change's MAC no longer holds
\* (round T190). Nothing logged, no number moved.
Forge(p) ==
    /\ pc[p] = "forge"
    /\ \E o \in {"cred", "member", "bob"} :
          /\ seal[o] > 0
          /\ putBack' = putBack \cup {o}
          /\ forged' = forged \cup {o}
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, gen, next, sealedTo, head, held, l, tries, trips, requests, writes, admits, answered, refusals>>

\* A database writer copies a token hash onto another credential: around
\* coffre, no lock, nothing logged.
Substitute(p) ==
    /\ pc[p] = "substitute"
    /\ names' = [names EXCEPT ![Token] = 1]
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, held, l, tries, trips, requests, writes, admits, answered, refusals>>

\* A database writer copies a refusal's record (PR 6), its MAC with it, to a
\* number of its own as the newest change of a revoked or demoted object,
\* the row put back and the record's seal column made the row's: row and
\* log agree. The record's MAC is over its own object, the request's, so
\* under another it fails, as a forged seal's does (ChangeMacChecked).
\* (Copied whole, its object its own, it is the same refusal listed twice,
\* which moves nothing anything decides on: not modelled.)
\* With no refusal to copy once everyone else is done, it has nothing to do.
Refile(p) ==
    /\ pc[p] = "refile"
    /\ Goto(p, "done")
    /\ \/ /\ refusals # {}
          /\ \E o \in {"cred", "member", "bob"} :
                /\ seal[o] > 0
                /\ seal' = [seal EXCEPT ![o] = @ + 1]
                /\ putBack' = putBack \cup {o}
                /\ forged' = forged \cup {o}
          /\ next' = next + 1
       \/ /\ refusals = {} /\ \A q \in Procs \ {p, "ck"} : pc[q] = "done"
          /\ UNCHANGED <<seal, putBack, forged, next>>
    /\ UNCHANGED <<ok, names, svc, kver, gen, sealedTo, head, held, l, tries, trips, requests, writes, admits, answered, refusals>>

\* A rename, a key appearing, a config deleted, a project made under an old
\* slug: an app write under 0.14's head, which moves what a name resolves
\* to and no seal.
Rename(p) ==
    /\ pc[p] = "rename"
    /\ head = None /\ held = None
    /\ names' = [names EXCEPT ![Renames[p]] = @ + 1]
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, svc, kver, seal, putBack, forged, gen, next, sealedTo, head, held, l, tries, trips, requests, writes, admits, answered, refusals>>

\* A tick seals every number committed so far.
Tick ==
    /\ "ck" \in Procs
    /\ sealedTo < next
    /\ sealedTo' = next
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, forged, gen, next, head, held, pc, l, tries, trips, requests, writes, admits, answered, refusals>>

Step(p) == WVault(p) \/ WRest(p) \/ WDecide(p) \/ WApp(p) \/ WFence(p) \/ WCommit(p) \/ WToday(p) \/ WTodayCommit(p)
        \/ ARead(p) \/ ADecide(p) \/ AWrite(p) \/ ACommit(p) \/ AToday(p) \/ Answer(p) \/ Change(p)
        \/ GiveBack(p) \/ Remove(p) \/ Restore(p) \/ Tamper(p) \/ Forge(p) \/ Substitute(p) \/ Rename(p)
        \/ Refuse(p) \/ Refile(p)

Terminating ==
    /\ \A p \in Procs \ {"ck"} : pc[p] = "done"
    /\ sealedTo = next
    /\ UNCHANGED vars

Next == (\E p \in Procs : Step(p)) \/ Tick \/ Terminating
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* What must hold *)

TypeOK ==
    /\ ok \in [Movable -> BOOLEAN]
    /\ names \in [NameParts -> Nat]
    /\ seal \in [Objects -> Nat]
    /\ putBack \subseteq {"cred", "member", "bob"}
    /\ gen \in {0, 1}
    /\ forged \subseteq putBack
    /\ head \in Procs \cup {None}
    /\ held \in Procs \cup {None}
    /\ sealedTo <= next
    /\ \A p \in Procs : tries[p] <= MaxTries + 1

\* A key write commits only while everything it read is as the vault
\* decided on it: every object as it needs it, by the log (a row put back
\* around coffre does not count), every name resolving as it did. A
\* revoke, an end, a role or policy change, an archive or a protection,
\* a write of a replaced key, a new level on an inherited one, a rename, a
\* key appearing in the parent, a personal config deleted, committed first,
\* stops every write after it, the one already decided included. A
\* session's expiry changes nothing in the read: it is judged at the
\* vault's clock, at its decision, as today.
WritesStandAtCommit == \A w \in writes : w.today \/ w.stands

\* Today's path decides on the rows as they are, by the log (each object
\* held to its newest change, and that change to its MAC), and writes on
\* that decision: every object the wrap weighs (the caller's member, roles,
\* policy, place, parent) stood when the vault decided; and an add's (the
\* adder's member, the roles, the policy, the setting, the places), which
\* it decides on and writes in one transaction (AToday).
TodayStandsAtDecision == \A w \in writes \cup admits : w.today => w.decided

\* ... but not the caller's session, which the app checked before and the
\* wrap does not weigh again (EXPECTED in scripts/formal.sh, review r2 of
\* #469: revoked after the first try's check, the write still goes).
TodayCallerStandsAtDecision == \A w \in writes \cup admits : w.today => w.caller

\* ... and commits only while the roles and the policy are still as the
\* caller was loaded with (`policyStill`): a roles or policy change after
\* the front door stops it, 409 `policy_changed` (review r3 of #469).
TodayPolicyStandsAtCommit == \A w \in writes \cup admits : w.today => w.policy

\* ... not at its commit: a revoke or a session's end between the vault's
\* wrap and the app's COMMIT does not stop it (EXPECTED in scripts/formal.sh: the window every
\* write has had since 0.14, which the two-trip path closes for the writes
\* it serves; the rest keep it until they take that path, PR 3b and PR 7).
TodayStandsAtCommit == \A w \in writes \cup admits : w.today => w.stands

\* Each key change goes from the object it was made from: two writes from
\* one version never both commit (EachChangeFlips, for the app's change).
KeyChangesFlip == \A w \in writes : w.from = w.was

\* What the vault decided on is the log at the request's number: its reads
\* are one snapshot, numbered in it. (Which ids and numbers a request stands
\* for is bound by the Worker's MAC on its change, or on its outcome when
\* nothing committed; that the replay recomputes the same decision from
\* those inputs is HotPathOne's ReplayAgrees.)
RequestsReplay == \A r \in requests : r.live = r.replay

\* A member is added on the two-trip path only while its adder stands, at
\* the commit, its session included. (Today's add stands at its decision,
\* TodayStandsAtDecision, which is its commit but for the session.)
AddsStandAtCommit == \A a \in admits : a.today \/ a.stands

\* ... from the principal's row as read: two adds never both commit.
AddsFlip == \A a \in admits : a.from = a.was

\* Replayed at a commit, the log finds every object the write or the add
\* read at the number its change binds: nothing changed between the read
\* and the commit, not even and back.
CommitsReplay == \A c \in writes \cup admits : c.replays

\* A write or an add commits only as the caller its token is: the change's
\* actor is the credential the app's `auth_mac` vouched the token for, as
\* read. Not "the token still resolves to it at the commit": a database
\* writer takes no lock, and may move the hash between the hold and the
\* COMMIT (round 7); what they cannot do is make the change name anyone
\* but the checked caller. Without the check, one who copies a token hash
\* they hold onto an Owner's credential writes, or adds an Owner, as the
\* Owner, with every change sealed and MAC'd by the vault's own keys
\* (round 6).
CommitsAuthentic == \A c \in writes \cup admits : c.authentic

\* A request commits one write at most, whichever path it took: one that
\* fell back from a try the vault served writes once, down today's path,
\* and one that committed never falls back.
OneWritePerRequest == \A v, w \in writes : v.p = w.p => v = w

\* A write names the wrap of the try that committed it, never an abandoned
\* try's: a two-trip write's change carries its own request's number (an
\* abandoned try leaves a gap in the numbers), and today's `secret.write`
\* entry names its own path's `key.wrap` (an abandoned one of those stays
\* in 0.14's log as a wrap no change names).
WritesNameTheirWrap == \A w \in writes : w.wrap = w.t

\* Every change answers only once sealed (R51), and every refusal the vault
\* records (PR 6).
AnsweredSealed == \A a \in answered : a.n < sealedTo

\* A key write's refusal is recorded only where the log, replayed at the
\* request's number, refuses it too: the read and the number are one
\* statement under the fence (RequestUnderFence). An add's read numbers
\* nothing: its record binds the read by its digest alone.
RefusalsReplay == \A f \in refusals : f.kind = "write" => ~f.replay

\* A refusal is recorded only as the caller its token is: the app checks the
\* caller's rows before the vault records it (RefusalAfterAuth), so a token
\* hash copied onto an Owner's credential never puts a refusal in the
\* Owner's name (round 6, for the record a refusal now writes).
RefusalsAuthentic == \A f \in refusals : f.authentic

\* A request ends with its refusal's record or with a change, never both:
\* refused, nothing more is tried (RefusalEnds); and one refusal at most.
RefusedOrWritten == /\ \A f \in refusals : \A c \in writes \cup admits : c.p # f.p
                    /\ \A f, g \in refusals : f.p = g.p => f = g

\* A write or an add that committed at its first try made two round trips:
\* the vault's statement and the app's, or the vault's two; and one refused
\* at its first try, the vault's read and the refusal's record (PR 6). It
\* follows from the steps' shape; it says what the steps are, it proves
\* nothing else.
TwoTrips == \A p \in Procs : (pc[p] \in {"w.seal", "a.seal", "r.seal"} /\ tries[p] = 1) => trips[p] = 2

\* Every write and add ends, committed or refused, within its tries: a hold
\* that keeps failing gives up (409), it never loops.
EveryRequestEnds == <>(\A p \in Procs \ {"ck"} : pc[p] = "done")

=============================================================================
