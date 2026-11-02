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
(* Every other change (a revoke, a role or policy change, an archive, a    *)
(* demotion, a rename) is one atomic step here, as each is one statement   *)
(* or one transaction under the head and the fence in the code. One step   *)
(* is one statement, or the part of one between two lock waits (READ      *)
(* COMMITTED: each statement reads afresh, so a hold sent as a statement   *)
(* after the locks reads after them). Locks: 0.14's head (held across      *)
(* steps by the app's statement only when its hold runs before the fence)  *)
(* and the fence. A session's revoke takes the fence and not the head:     *)
(* 0.16's, once 0047's head in `revoke_credential` is contracted away.     *)
(* Today's revoke takes the head too, which only adds order, so this is    *)
(* the stronger adversary.                                                 *)
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
(*   sub      a database writer copies a token hash they hold onto a live  *)
(*            Owner's credential row: the token now resolves to the Owner, *)
(*            no seal moves, the row's `auth_mac` no longer matches        *)
(*            (round 6's P1);                                              *)
(*   bob, cy  two admins each add the service account svc (bob, in         *)
(*            SetUp and Protect, no admin, sets it up with a first grant,  *)
(*            on a whole project in Protect);                              *)
(*   dem      an Owner demotes Bob;                                        *)
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
    AuthChecked

Writers == {"w1", "w2"}
Adders == {"bob", "cy"}
\* What each change moves: one object, turned against the writer or the adder.
Moves == [rev |-> "member", end |-> "cred", rol |-> "roles", pol |-> "policy",
          arc |-> "env", par |-> "parent", rep |-> "parentKey", mrk |-> "parentKey",
          dem |-> "bob", cls |-> "settings", plc |-> "place", prt |-> "prot"]
\* What each rename moves: a name's resolution, no seal.
Renames == [ren |-> "keyName", phn |-> "chain", del |-> "me",
            slg |-> "slug", nev |-> "envs", scp |-> "scope"]
\* What a token resolves to, by its hash.
Token == "tok"

\* What a key write reads: Ada's session, her member object, the roles, the
\* policy, the environment, its fork parent, the parent's keys weighed, the
\* key itself; and what the key's name, the fork chain and `env@me` resolve to.
WriteObjects == {"cred", "member", "roles", "policy", "env", "parent", "parentKey", "key"}
WriteNames == {"keyName", "chain", "me", Token}
\* What an add reads: the adder's object, the roles, the policy, the services
\* setting, the grant's place, the project's other environments, svc's row;
\* and what the grant's slugs, the project's set of environments and the
\* scope's slug resolve to.
AddObjects == {"bob", "roles", "policy", "settings", "place", "prot", "svc"}
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
    next,       \* the log's next number
    sealedTo,   \* the checkpointer has sealed every number below this
    head,       \* who holds 0.14's head across steps, or None
    pc, l, tries,
    trips,      \* round trips each process made on its path
    requests,   \* ghost: each write's request, as decided live and by the replay
    writes,     \* ghost: each committed key change
    admits,     \* ghost: each committed member add
    answered    \* ghost: each change answered, with its number

vars == <<ok, names, svc, kver, seal, putBack, next, sealedTo, head,
          pc, l, tries, trips, requests, writes, admits, answered>>

\* An object's row as stored: put back to its first state by a database
\* writer, or as its newest change left it.
RowSeal(o) == IF o \in putBack THEN 0 ELSE seal[o]
Value(o) == CASE o = "key" -> kver
              [] o = "svc" -> svc
              [] o \in putBack -> TRUE
              [] OTHER -> ok[o]

\* The read (`write_inputs`, `admit_inputs`), as it answers now: every object
\* with its number and its row's value, every name as resolved. The vault's
\* read and the hold both call it.
Read(k) == [o \in Parts(k) |->
               IF o \in NameParts THEN [name |-> names[o]]
               ELSE [num |-> IF ReadOnLog THEN seal[o] ELSE RowSeal(o), val |-> Value(o)]]
\* A row the log has moved past (StaleFirst refuses it).
Stale(k) == \E o \in ObjectsOf(k) : RowSeal(o) # seal[o]

\* What the decision weighs: the read, or (a removal) the read with the
\* roles from the isolate's cache.
Weighed(r) == IF DecideOnRead THEN r ELSE [r EXCEPT !["roles"].val = TRUE]
WriteAllowed(r) == \A o \in WriteObjects \ {"key"} : r[o].val
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
NamesAsRead(p) == \A n \in Parts(Kind(p)) \cap NameParts : names[n] = l[p].read[n].name
WriteStands(p) == (\A o \in WriteObjects \ {"key"} : ok[o]) /\ NamesAsRead(p)
AddStands(p) == /\ \A o \in AddObjects \ {"bob", "svc"} : ok[o]
                /\ p = "cy" \/ ok["bob"]
                /\ NamesAsRead(p)
\* ... and the log, replayed at the commit, finds every object it read at
\* the number its change binds (the read's).
Replays(p) == \A o \in ObjectsOf(Kind(p)) : seal[o] = l[p].seals[o]

Init ==
    /\ ok = [o \in Movable |-> TRUE]
    /\ names = [n \in NameParts |-> 0]
    /\ svc = FALSE /\ kver = 0
    /\ seal = [o \in Objects |-> 0]
    /\ putBack = {}
    /\ next = 1 /\ sealedTo = 1 /\ head = None
    /\ pc = [p \in Procs |-> CASE p \in Writers -> "w.vault"
                                [] p \in Adders -> "a.read"
                                [] p = "ck" -> "ck"
                                [] p = "dbw" -> "tamper"
                                [] p = "sub" -> "substitute"
                                [] p = "bk" -> "giveback"
                                [] p \in DOMAIN Renames -> "rename"
                                [] OTHER -> "change"]
    /\ l = [p \in Procs |-> [n |-> 0]]
    /\ tries = [p \in Procs |-> 1]
    /\ trips = [p \in Procs |-> 0]
    /\ requests = {} /\ writes = {} /\ admits = {} /\ answered = {}

Goto(p, to) == pc' = [pc EXCEPT ![p] = to]
\* A change commits, numbered, its object's newest change moved.
Numbered(o) == /\ seal' = [seal EXCEPT ![o] = @ + 1]
               /\ next' = next + 1
\* Asked again, or given up (409 `changed`) once out of tries.
Again(p, from) ==
    /\ IF tries[p] < MaxTries THEN Goto(p, from) ELSE Goto(p, "done")
    /\ tries' = [tries EXCEPT ![p] = @ + 1]
\* A committed change, as the ghosts record it.
Committed(p, o, stands) ==
    [p |-> p, n |-> next, stands |-> stands, replays |-> Replays(p),
     from |-> l[p].seals[o], was |-> seal[o], authentic |-> names[Token] = 0]

-----------------------------------------------------------------------------
(* A key write *)

\* The request, numbered: as the Worker will decide it from what was read,
\* and as the replay will from the log at its number (each change is one
\* step here, so the log at this step is the log at the number).
Truth == [o \in Parts("write") |->
             IF o \in NameParts THEN [name |-> names[o]]
             ELSE [num |-> seal[o], val |-> IF o = "key" THEN kver ELSE ok[o]]]
Request(p, r) == [p |-> p, n |-> next, live |-> Decide(p, r), replay |-> Decide(p, Truth)]

\* The vault's statement: the read under the fence shared, the request
\* numbered. One round trip. A row put back is refused (`stale`).
WVault(p) ==
    /\ pc[p] = "w.vault"
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Stale("write")
         THEN /\ Goto(p, "done")
              /\ UNCHANGED <<next, l, requests>>
         ELSE /\ l' = [l EXCEPT ![p] = [n |-> 0, read |-> Read("write"), seals |-> seal]]
              /\ IF RequestUnderFence
                   THEN /\ next' = next + 1
                        /\ requests' = requests \cup {Request(p, Read("write"))}
                        /\ Goto(p, "w.decide")
                   ELSE /\ UNCHANGED <<next, requests>>
                        /\ Goto(p, "w.rest")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, sealedTo, head, tries, writes, admits, answered>>

\* Without one statement under the fence: the rest of the read, and the
\* request numbered, in a later step. A change between the two tears what
\* was read from what the log holds at the number.
WRest(p) ==
    /\ pc[p] = "w.rest"
    /\ LET r == [o \in Parts("write") |-> IF o \in FirstRead THEN l[p].read[o] ELSE Read("write")[o]]
           seals == [o \in Objects |-> IF o \in FirstRead THEN l[p].seals[o] ELSE seal[o]]
       IN /\ l' = [l EXCEPT ![p].read = r, ![p].seals = seals]
          /\ requests' = requests \cup {Request(p, r)}
    /\ next' = next + 1
    /\ Goto(p, "w.decide")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, sealedTo, head, tries, trips, writes, admits, answered>>

\* The Worker decides on the read; allowed, it wraps and seals the change,
\* and the app checks the caller's rows. No round trip.
WDecide(p) ==
    /\ pc[p] = "w.decide"
    /\ IF Decide(p, l[p].read) /\ AppChecks(l[p].read) THEN Goto(p, "w.app") ELSE Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* The write itself: the key's next version, its change numbered.
Commit(p) ==
    /\ kver' = kver + 1
    /\ Numbered("key")
    /\ l' = [l EXCEPT ![p].n = next]
    /\ writes' = writes \cup {Committed(p, "key", WriteStands(p))}

\* The app's statement, its hold after the fence: one atomic step. One
\* round trip. (The code takes the head, then the fence, then holds, then
\* writes: one step here, since the head and the fence are held from the
\* hold to COMMIT, and every change of what the read reads takes one of
\* them.)
WApp(p) ==
    /\ pc[p] = "w.app"
    /\ head = None
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Holds(p)
         THEN IF HoldAfterFence
                THEN /\ Commit(p) /\ Goto(p, "w.seal")
                     /\ UNCHANGED <<head, tries>>
                \* Its hold under 0.14's head, then a wait for the fence.
                ELSE /\ head' = p /\ Goto(p, "w.fence")
                     /\ UNCHANGED <<kver, seal, next, l, tries, writes>>
         ELSE /\ Again(p, "w.vault")
              /\ UNCHANGED <<kver, seal, next, l, head, writes>>
    /\ UNCHANGED <<ok, names, svc, putBack, sealedTo, requests, admits, answered>>

\* The same statement, after its wait for the fence.
WFence(p) ==
    /\ pc[p] = "w.fence"
    /\ head' = None
    /\ Commit(p) /\ Goto(p, "w.seal")
    /\ UNCHANGED <<ok, names, svc, putBack, sealedTo, tries, trips, requests, admits, answered>>

-----------------------------------------------------------------------------
(* A member add *)

\* The read. No lock.
ARead(p) ==
    /\ pc[p] = "a.read"
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Stale("add")
         THEN Goto(p, "done") /\ UNCHANGED l
         ELSE /\ l' = [l EXCEPT ![p] = [n |-> 0, read |-> Read("add"), seals |-> seal]]
              /\ Goto(p, "a.decide")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, sealedTo, head, tries, requests, writes, admits, answered>>

\* The Worker decides on the read: the adder's standing, svc no member yet;
\* then the app checks the adder's rows, between the vault's two calls.
\* (The check reads only what the vault answered, so it is one step with
\* the decision.) No round trip.
ADecide(p) ==
    /\ pc[p] = "a.decide"
    /\ IF Decide(p, l[p].read) /\ AppChecks(l[p].read) THEN Goto(p, "a.write") ELSE Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* The write: rows, head, fence, the hold, the row, its change. One round trip.
AWrite(p) ==
    /\ pc[p] = "a.write"
    /\ head = None
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Holds(p)
         THEN /\ svc' = TRUE
              /\ Numbered("svc")
              /\ l' = [l EXCEPT ![p].n = next]
              /\ admits' = admits \cup {Committed(p, "svc", AddStands(p))}
              /\ Goto(p, "a.seal")
              /\ UNCHANGED tries
         ELSE /\ Again(p, "a.read")
              /\ UNCHANGED <<svc, seal, next, l, admits>>
    /\ UNCHANGED <<ok, names, kver, putBack, sealedTo, head, requests, writes, answered>>

-----------------------------------------------------------------------------
(* The seal wait, the answer, and everything else *)

\* A change answers once its number is sealed (R51).
Answer(p) ==
    /\ pc[p] \in {"w.seal", "a.seal", "x.seal"}
    /\ ~WaitForSeal \/ l[p].n < sealedTo
    /\ answered' = answered \cup {[p |-> p, n |-> l[p].n]}
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, sealedTo, head, l, tries, trips, requests, writes, admits>>

\* Every other change, one atomic step: 0.14's head and the fence (a
\* session's revoke the fence alone, which the head's holder does not stop).
Change(p) ==
    /\ pc[p] = "change"
    /\ p = "end" \/ head = None
    /\ ok' = [ok EXCEPT ![Moves[p]] = FALSE]
    /\ Numbered(Moves[p])
    /\ l' = [l EXCEPT ![p].n = next]
    /\ Goto(p, "x.seal")
    /\ UNCHANGED <<names, svc, kver, putBack, sealedTo, head, tries, trips, requests, writes, admits, answered>>

\* Ada's grant given back once taken: the same row, a newer change.
GiveBack(p) ==
    /\ pc[p] = "giveback"
    /\ head = None
    /\ ~ok["member"]
    /\ ok' = [ok EXCEPT !["member"] = TRUE]
    /\ Numbered("member")
    /\ l' = [l EXCEPT ![p].n = next]
    /\ Goto(p, "x.seal")
    /\ UNCHANGED <<names, svc, kver, putBack, sealedTo, head, tries, trips, requests, writes, admits, answered>>

\* A database writer puts cA's row back as it was, live, once it is revoked.
\* Nothing logged: the log's newest change of cA is still the revoke.
Tamper(p) ==
    /\ pc[p] = "tamper"
    /\ seal["cred"] > 0
    /\ putBack' = putBack \cup {"cred"}
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* A database writer copies a token hash onto another credential: around
\* coffre, no lock, nothing logged.
Substitute(p) ==
    /\ pc[p] = "substitute"
    /\ names' = [names EXCEPT ![Token] = 1]
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, svc, kver, seal, putBack, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* A rename, a key appearing, a config deleted, a project made under an old
\* slug: an app write under 0.14's head, which moves what a name resolves
\* to and no seal.
Rename(p) ==
    /\ pc[p] = "rename"
    /\ head = None
    /\ names' = [names EXCEPT ![Renames[p]] = @ + 1]
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, svc, kver, seal, putBack, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* A tick seals every number committed so far.
Tick ==
    /\ "ck" \in Procs
    /\ sealedTo < next
    /\ sealedTo' = next
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, head, pc, l, tries, trips, requests, writes, admits, answered>>

Step(p) == WVault(p) \/ WRest(p) \/ WDecide(p) \/ WApp(p) \/ WFence(p)
        \/ ARead(p) \/ ADecide(p) \/ AWrite(p) \/ Answer(p) \/ Change(p)
        \/ GiveBack(p) \/ Tamper(p) \/ Substitute(p) \/ Rename(p)

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
    /\ putBack \subseteq {"cred"}
    /\ head \in Procs \cup {None}
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
WritesStandAtCommit == \A w \in writes : w.stands

\* Each key change goes from the object it was made from: two writes from
\* one version never both commit (EachChangeFlips, for the app's change).
KeyChangesFlip == \A w \in writes : w.from = w.was

\* What the vault decided on is the log at the request's number: its reads
\* are one snapshot, numbered in it. (Which ids and numbers a request stands
\* for is bound by the Worker's MAC on its change, or on its outcome when
\* nothing committed; that the replay recomputes the same decision from
\* those inputs is HotPathOne's ReplayAgrees.)
RequestsReplay == \A r \in requests : r.live = r.replay

\* A member is added only while its adder stands, at the commit.
AddsStandAtCommit == \A a \in admits : a.stands

\* ... from the principal's row as read: two adds never both commit.
AddsFlip == \A a \in admits : a.from = a.was

\* Replayed at a commit, the log finds every object the write or the add
\* read at the number its change binds: nothing changed between the read
\* and the commit, not even and back.
CommitsReplay == \A c \in writes \cup admits : c.replays

\* A write or an add commits only for the caller its token is: the token's
\* hash still resolves, at the commit, to the credential the app's MAC
\* binds it to. Without it, a database writer who copies a token hash they
\* hold onto an Owner's credential writes, or adds an Owner, as the Owner,
\* with every change sealed and MAC'd by the vault's own keys (round 6).
CommitsAuthentic == \A c \in writes \cup admits : c.authentic

\* Every change answers only once sealed (R51).
AnsweredSealed == \A a \in answered : a.n < sealedTo

\* A write or an add that committed at its first try made two round trips:
\* the vault's statement and the app's, or the vault's two. It follows from
\* the steps' shape; it says what the steps are, it proves nothing else.
TwoTrips == \A p \in Procs : (pc[p] \in {"w.seal", "a.seal"} /\ tries[p] = 1) => trips[p] = 2

\* Every write and add ends, committed or refused, within its tries: a hold
\* that keeps failing gives up (409), it never loops.
EveryRequestEnds == <>(\A p \in Procs \ {"ck"} : pc[p] = "done")

=============================================================================
