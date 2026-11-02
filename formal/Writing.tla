------------------------------- MODULE Writing -------------------------------
(***************************************************************************)
(* A change in two round trips (T179, R42, R57; docs/design/two-trips.md): *)
(* what a key write and a member add become once each is one vault         *)
(* statement and one app statement, or two vault statements, and nothing   *)
(* else on the request path.                                               *)
(*                                                                         *)
(*   key write   1. the vault's statement, as a use's (HotPathOne): under  *)
(*                  the fence shared, every input the decision and the     *)
(*                  app's checks stand on (the credential, the member, the *)
(*                  roles, the policy, the environment and each one of its *)
(*                  fork chain, the parent's keys weighed: the one a       *)
(*                  regenerate replaces, the one whose level an override   *)
(*                  inherits), each with its newest change, held to its    *)
(*                  row (StaleFirst), and the request numbered. Nothing    *)
(*                  locked after it.                                       *)
(*               2. the Worker decides on what the statement read (pure,   *)
(*                  decide.ts), wraps the value's key and seals the app's  *)
(*                  change from the key's object as read.                  *)
(*               3. the app's statement: 0.14's head, the names'           *)
(*                  resolution as the vault read it (`hold_names`: a       *)
(*                  rename, a key appearing or a dismissal moves no seal), *)
(*                  its rows, then                                         *)
(*                  `app_change`'s issue lock and fence exclusive, the     *)
(*                  key's change from the seal it was made from            *)
(*                  (ChangeCAS); then, in statements after it, each input  *)
(*                  has no change numbered after the one the vault read    *)
(*                  (its newest in `log_changes`, not its row's column),   *)
(*                  the keys it writes aside (ChangeCAS holds those); the  *)
(*                  commit. Any guard failing rolls it all back, and the   *)
(*                  write asks again from 1.                               *)
(*               4. the seal wait (R51), then the answer.                  *)
(*   member add  1. the vault reads the actor's standing, the roles, the   *)
(*                  policy, the services setting, the places of the first  *)
(*                  grants and the principal's row, holding nothing        *)
(*                  (Lifecycle's issue, IssuerCAS);                        *)
(*               2. the Worker decides and builds the new row, its MAC     *)
(*                  and its seal, from the row as read;                    *)
(*               3. one statement: the rows, the head, the fence; it goes  *)
(*                  ahead only while everything step 1 decided on is what  *)
(*                  it read; otherwise it writes nothing and the vault     *)
(*                  reads again;                                           *)
(*               4. the seal wait, then the answer.                        *)
(*                                                                         *)
(* Every other change (a revoke, a session's end, a role or policy change, *)
(* an archive, a demotion) is one atomic step here, as each is one statement  *)
(* or one transaction under the head and the fence in the code.            *)
(*                                                                         *)
(* One step is one statement, or the part of one between two lock waits    *)
(* (READ COMMITTED: each statement reads afresh, so the guards, sent as    *)
(* statements after `app_change_strict`'s, read after the fence).          *)
(* Locks: 0.14's head (held across steps by the app's statement when its   *)
(* guards run before the fence) and the fence. A session's revoke takes    *)
(* the fence and not the head: 0.16's, once 0047's head in                 *)
(* `revoke_credential` is contracted away. Today's revoke takes the head   *)
(* too, which only adds order, so this is the stronger adversary.          *)
(* Seals: a counter per object, the seal of its newest change in the log,  *)
(* moved by each change. A row stores its seal too; a database writer may  *)
(* put a row back (R64), which its column then cannot tell. The vault      *)
(* holds each row it reads to its newest change (StaleFirst); a guard      *)
(* compares the log's newest change, never a row's column.                 *)
(*                                                                         *)
(* Who is who:                                                             *)
(*   w1, w2   Ada writes key k at env, each from her session cA;           *)
(*   rev      an admin takes Ada's grant at env away (her member object);  *)
(*   end      Ada's session cA is revoked (the credential alone);          *)
(*   rol      an Owner redefines Ada's role (`role.define`, the roles      *)
(*            object): it no longer writes, nor adds members;              *)
(*   pol      an Owner changes the instance policy (its own object): what  *)
(*            Ada's write or an admin's add needs no longer holds;         *)
(*   arc      a maintainer archives env, or protects it (both move env's   *)
(*            object);                                                     *)
(*   par      a maintainer archives env's fork parent;                     *)
(*   rep      the parent's key that Ada's regenerate replaces is written   *)
(*            meanwhile, so what she listed is no longer what it replaces; *)
(*   mrk      the parent's key whose level Ada's override inherits is      *)
(*            marked sensitive: her write's level was weighed on the old;  *)
(*   ren      a maintainer renames the key Ada writes (k becomes OLD_K):   *)
(*            a rename moves no object, only what k's name resolves to;    *)
(*   phn      the fork's parent gains the key Ada writes, sensitive, where *)
(*            it held none: an object that did not exist at her read, so   *)
(*            none she could hold (a dismissal is the same step);          *)
(*   dbw      a database writer puts cA's row back, live, after its revoke;*)
(*   bob, cy  two admins each add the service account svc;                *)
(*   dem      an Owner demotes Bob;                                        *)
(*   cls      an Owner closes the services setting: Bob, no admin, set up  *)
(*            service accounts under it;                                   *)
(*   plc      a maintainer archives the place of svc's first grant;        *)
(*   ck       the checkpointer: each tick seals every committed number.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs,          \* the scenario's processes (MCWriting.tla)
    MaxTries        \* how many times a write or an add may ask again

CONSTANTS
    \* The vault's statement reads its inputs and numbers the request in one
    \* statement under the fence shared, as a use does (HotPathOne's
    \* "reads are a statement after the lock"): its reads are one snapshot,
    \* and no change is numbered between them and its number.
    RequestUnderFence,
    \* The inputs the app's statement holds to the objects the vault read:
    \* any of Inputs. Normally all; a removal leaves one out (`Held={...}`).
    Held,
    \* ... and checks them once it holds the fence (after `app_change`
    \* took it), so a change that takes the fence and not 0.14's head (a
    \* session's revoke) cannot commit between the check and the write.
    GuardsAfterFence,
    \* ... each by the newest change the log holds of it, not by the seal
    \* its row stores, which a database writer can put back.
    GuardOnLog,
    \* The key's change goes ahead only from the seal it was made from
    \* (`app_change`'s CAS, ChangeCAS): another write meanwhile fails it.
    ChangeCAS,
    \* What a member add's write holds to its read (IssuerCAS): any of
    \* "actor" (the adder's own object), "roles", "policy", "settings" (the
    \* services setting's newest entry) and "place" (each first grant's
    \* environment). Normally all.
    AdmitHeld,
    \* ... and the principal's row is the one it read (none): the change
    \* from its object as read.
    PrincipalCAS,
    \* The app's statement holds the names' resolution to what the vault
    \* read (`hold_names`, right after 0.14's head, which every rename,
    \* key made and dismissal takes first).
    NameHold,
    \* A change answers only once its number is sealed in a checkpoint (R51).
    WaitForSeal

Writers == {"w1", "w2"}
Adders == {"bob", "cy"}
\* Who moves what a write's names resolve to.
Renames == {"ren", "phn"}
\* What each other change moves: one object, turned against the writer or
\* the adder.
Moves == [rev |-> "member", end |-> "cred", rol |-> "roles", pol |-> "policy",
          arc |-> "env", par |-> "parent", rep |-> "parentKey", mrk |-> "parentKey",
          dem |-> "bob", cls |-> "settings", plc |-> "place"]
\* What a key write stands on: Ada's session, her member object, the roles,
\* the policy, the environment, its fork parent, the parent's keys weighed
\* (the one her regenerate replaces, the one whose level she inherits).
Inputs == {"cred", "member", "roles", "policy", "env", "parent", "parentKey"}
\* What an add stands on besides the adder's own object.
AddInputs == {"roles", "policy", "settings", "place"}
Movable == Inputs \cup AddInputs \cup {"bob"}
Objects == Movable \cup {"key", "svc"}
\* The vault's first reads, when its reads are not one statement.
FirstRead == {"cred"}
None == "none"

VARIABLES
    ok,         \* each movable object still as the writer or adder needs it
    names,      \* what the write's names resolve to, moved by a rename or a
                \* key appearing: no seal moves with it
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

\* What Ada's write needs, as decide.ts and the app's checks weigh it: every
\* input as she needs it.
Allowed(s) == \A o \in Inputs : s[o]
Now == [o \in Inputs |-> ok[o]]
\* Whether an adder stands: while the roles and the policy let admins add,
\* the setting lets Bob set up services, svc's first place is live, and Bob
\* while he is an admin. Cy is an admin nobody demotes.
Stands(p) == (\A o \in AddInputs : ok[o]) /\ (p = "cy" \/ ok["bob"])
\* The seal a row stores: its newest change's, or the first, put back.
RowSeal(o) == IF o \in putBack THEN 0 ELSE seal[o]
\* A row the log has moved past (StaleFirst refuses it).
Stale == \E o \in Inputs : RowSeal(o) # seal[o]

Init ==
    /\ ok = [o \in Movable |-> TRUE]
    /\ names = 0
    /\ svc = FALSE /\ kver = 0
    /\ seal = [o \in Objects |-> 0]
    /\ putBack = {}
    /\ next = 1 /\ sealedTo = 1 /\ head = None
    /\ pc = [p \in Procs |-> CASE p \in Writers -> "w.vault"
                                [] p \in Adders -> "a.read"
                                [] p = "ck" -> "ck"
                                [] p = "dbw" -> "tamper"
                                [] p \in Renames -> "rename"
                                [] OTHER -> "change"]
    /\ l = [p \in Procs |-> [n |-> 0]]
    /\ tries = [p \in Procs |-> 1]
    /\ trips = [p \in Procs |-> 0]
    /\ requests = {} /\ writes = {} /\ admits = {} /\ answered = {}

Goto(p, to) == pc' = [pc EXCEPT ![p] = to]
\* A change commits, numbered, its object's newest change moved.
Numbered(o) == /\ seal' = [seal EXCEPT ![o] = @ + 1]
               /\ next' = next + 1
\* Asked again, or given up (the API's 409) once out of tries.
Again(p, from) ==
    /\ IF tries[p] < MaxTries THEN Goto(p, from) ELSE Goto(p, "done")
    /\ tries' = [tries EXCEPT ![p] = @ + 1]

-----------------------------------------------------------------------------
(* A key write *)

\* The request, numbered: as the Worker will decide it from what was read,
\* and as the replay will from the log at its number (each change is one
\* step here, so the log at this step is the log at the number).
Request(p, s) == [p |-> p, n |-> next, live |-> Allowed(s), replay |-> Allowed(Now)]

\* The vault's statement: every input, by name, under the fence shared, the
\* request numbered. One round trip. A row put back is refused (`stale`).
WVault(p) ==
    /\ pc[p] = "w.vault"
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF Stale
         THEN /\ Goto(p, "done")
              /\ UNCHANGED <<next, l, requests>>
         ELSE /\ l' = [l EXCEPT ![p] = [n |-> 0, s |-> Now, seals |-> seal, ver |-> kver, names |-> names]]
              /\ IF RequestUnderFence
                   THEN /\ next' = next + 1
                        /\ requests' = requests \cup {Request(p, l'[p].s)}
                        /\ Goto(p, "w.decide")
                   ELSE /\ UNCHANGED <<next, requests>>
                        /\ Goto(p, "w.rest")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, sealedTo, head, tries, writes, admits, answered>>

\* Without one statement under the fence: the rest of the inputs read, and
\* the request numbered, in a later step. A change between the two tears
\* what was read from what the log holds at the number.
WRest(p) ==
    /\ pc[p] = "w.rest"
    /\ LET s == [o \in Inputs |-> IF o \in FirstRead THEN l[p].s[o] ELSE ok[o]]
           seals == [o \in Objects |-> IF o \in FirstRead THEN l[p].seals[o] ELSE seal[o]]
       IN /\ l' = [l EXCEPT ![p].s = s, ![p].seals = seals, ![p].names = names]
          /\ requests' = requests \cup {Request(p, s)}
    /\ next' = next + 1
    /\ Goto(p, "w.decide")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, sealedTo, head, tries, trips, writes, admits, answered>>

\* The Worker decides on what it read; allowed, it wraps and seals the
\* change from the key's seal as read. No round trip.
WDecide(p) ==
    /\ pc[p] = "w.decide"
    /\ IF Allowed(l[p].s) THEN Goto(p, "w.app") ELSE Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* Each input has no change after the one the vault read: by the log's
\* newest change, or (a removal) by the seal its row stores.
Guarded(p) == \A o \in Held : (IF GuardOnLog THEN seal[o] ELSE RowSeal(o)) = l[p].seals[o]
CasHolds(p) == ~ChangeCAS \/ seal["key"] = l[p].seals["key"]
\* The names resolve as the vault read them.
NameHeld(p) == ~NameHold \/ names = l[p].names

\* The write itself, once the guards pass and the fence is held: the key's
\* next version, its change numbered.
Commit(p) ==
    /\ kver' = kver + 1
    /\ Numbered("key")
    /\ l' = [l EXCEPT ![p].n = next]
    /\ writes' = writes \cup {[p |-> p, n |-> next, stands |-> Allowed(Now) /\ names = l[p].names, from |-> l[p].seals["key"], was |-> seal["key"]]}

\* The app's statement, guards after the fence: one atomic step. One round trip.
WApp(p) ==
    /\ pc[p] = "w.app"
    /\ head = None
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF GuardsAfterFence
         THEN IF NameHeld(p) /\ Guarded(p) /\ CasHolds(p)
                THEN /\ Commit(p) /\ Goto(p, "w.seal")
                     /\ UNCHANGED <<head, tries>>
                ELSE /\ Again(p, "w.vault")
                     /\ UNCHANGED <<kver, seal, next, l, head, writes>>
         ELSE IF NameHeld(p) /\ Guarded(p)
                \* Its guards under 0.14's head, then a wait for the fence.
                THEN /\ head' = p /\ Goto(p, "w.fence")
                     /\ UNCHANGED <<kver, seal, next, l, tries, writes>>
                ELSE /\ Again(p, "w.vault")
                     /\ UNCHANGED <<kver, seal, next, l, head, writes>>
    /\ UNCHANGED <<ok, names, svc, putBack, sealedTo, requests, admits, answered>>

\* The same statement, after its wait for the fence.
WFence(p) ==
    /\ pc[p] = "w.fence"
    /\ head' = None
    /\ IF CasHolds(p)
         THEN /\ Commit(p) /\ Goto(p, "w.seal") /\ UNCHANGED tries
         ELSE /\ Again(p, "w.vault") /\ UNCHANGED <<kver, seal, next, l, writes>>
    /\ UNCHANGED <<ok, names, svc, putBack, sealedTo, trips, requests, admits, answered>>

-----------------------------------------------------------------------------
(* A member add *)

\* The read: the actor's standing, the policy, the principal's row. No lock.
ARead(p) ==
    /\ pc[p] = "a.read"
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ l' = [l EXCEPT ![p] = [n |-> 0, stands |-> Stands(p), there |-> svc, seals |-> seal]]
    /\ Goto(p, "a.decide")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, sealedTo, head, tries, requests, writes, admits, answered>>

\* The Worker decides; the principal already a member is a conflict.
ADecide(p) ==
    /\ pc[p] = "a.decide"
    /\ IF l[p].stands /\ ~l[p].there THEN Goto(p, "a.write") ELSE Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* The objects an adder's standing rests on: its own (Bob's; nobody moves
\* Cy's), and those of AddInputs it holds.
Rests(p) == (IF p = "bob" /\ "actor" \in AdmitHeld THEN {"bob"} ELSE {})
            \cup (AdmitHeld \cap AddInputs)
ActorHeld(p) == \A o \in Rests(p) : seal[o] = l[p].seals[o]
PrincipalHeld(p) == ~PrincipalCAS \/ seal["svc"] = l[p].seals["svc"]

\* The write: rows, head, fence, the CAS, the row, the change. One round trip.
AWrite(p) ==
    /\ pc[p] = "a.write"
    /\ head = None
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF ActorHeld(p) /\ PrincipalHeld(p)
         THEN /\ svc' = TRUE
              /\ Numbered("svc")
              /\ l' = [l EXCEPT ![p].n = next]
              /\ admits' = admits \cup {[p |-> p, stands |-> Stands(p), from |-> l[p].seals["svc"], was |-> seal["svc"]]}
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

\* A database writer puts cA's row back as it was, live, once it is revoked.
\* Nothing logged: the log's newest change of cA is still the revoke.
Tamper(p) ==
    /\ pc[p] = "tamper"
    /\ seal["cred"] > 0
    /\ putBack' = putBack \cup {"cred"}
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, names, svc, kver, seal, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* A rename of the key Ada writes, or the parent gaining it: an app write
\* under 0.14's head, which moves what the names resolve to and no seal.
Rename(p) ==
    /\ pc[p] = "rename"
    /\ head = None
    /\ names' = names + 1
    /\ Goto(p, "done")
    /\ UNCHANGED <<ok, svc, kver, seal, putBack, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* A tick seals every number committed so far.
Tick ==
    /\ "ck" \in Procs
    /\ sealedTo < next
    /\ sealedTo' = next
    /\ UNCHANGED <<ok, names, svc, kver, seal, putBack, next, head, pc, l, tries, trips, requests, writes, admits, answered>>

Step(p) == WVault(p) \/ WRest(p) \/ WDecide(p) \/ WApp(p) \/ WFence(p)
        \/ ARead(p) \/ ADecide(p) \/ AWrite(p) \/ Answer(p) \/ Change(p) \/ Tamper(p) \/ Rename(p)

Terminating ==
    /\ \A p \in Procs \ {"ck"} : pc[p] = "done"
    /\ sealedTo = next
    /\ UNCHANGED vars

Next == (\E p \in Procs : Step(p)) \/ Tick \/ Terminating
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold *)

TypeOK ==
    /\ ok \in [Movable -> BOOLEAN]
    /\ names \in Nat
    /\ seal \in [Objects -> Nat]
    /\ putBack \subseteq Inputs
    /\ head \in Procs \cup {None}
    /\ sealedTo <= next

\* A key write commits only while every input it stands on is as the vault
\* decided on it. A revoke, an end, a role or policy change, an archive or
\* a protection (of env or of its parent), a write of a replaced key, a
\* new level on an inherited one, a rename of the key written or the parent
\* gaining it answered (committed first)
\* stops every write after it, the one already decided included, and a row
\* put back around coffre does not undo that. Changes that move a seal only:
\* a session's expiry moves none, and is judged at the vault's clock, at
\* its decision, as today.
WritesStandAtCommit == \A w \in writes : w.stands

\* Each key change goes from the object it was made from: two writes from
\* one version never both commit (EachChangeFlips, for the app's change).
KeyChangesFlip == \A w \in writes : w.from = w.was

\* What the vault decided on is the log at the request's number: its reads
\* are one snapshot, numbered in it. (Which ids and numbers a request
\* stands for is bound by the Worker's MAC on its change, or on its outcome
\* when nothing committed: the statement's own answer is not; the request
\* here is that bound record.) (That the replay recomputes the same
\* decision from those inputs is HotPathOne's ReplayAgrees.)
RequestsReplay == \A r \in requests : r.live = r.replay

\* A member is added only while its adder stands, at the commit.
AddsStandAtCommit == \A a \in admits : a.stands

\* ... from the principal's row as read: two adds never both commit.
AddsFlip == \A a \in admits : a.from = a.was

\* Every change answers only once sealed (R51).
AnsweredSealed == \A a \in answered : a.n < sealedTo

\* A write or an add that committed at its first try made two round trips:
\* the vault's statement and the app's, or the vault's two. It follows from
\* the steps' shape; it says what the steps are, it proves nothing else.
TwoTrips == \A p \in Procs : (pc[p] \in {"w.seal", "a.seal"} /\ tries[p] = 1) => trips[p] = 2

=============================================================================
