------------------------------- MODULE Writing -------------------------------
(***************************************************************************)
(* A change in two round trips (T179, R42, R57; docs/design/two-trips.md): *)
(* what a key write and a member add become once each is one vault         *)
(* statement and one app statement, or two vault statements, and nothing   *)
(* else on the request path.                                               *)
(*                                                                         *)
(*   key write   1. the vault's statement, as a use's (HotPathOne): under  *)
(*                  the fence shared, the caller's credential by its       *)
(*                  token's hash, their member row, the policy, the place  *)
(*                  and the key, read by name with each one's seal, and    *)
(*                  the request numbered. Nothing locked after it.         *)
(*               2. the Worker decides on what the statement read (pure,   *)
(*                  decide.ts), wraps the value's key and seals the app's  *)
(*                  change from the key's object as read.                  *)
(*               3. the app's statement: 0.14's head, its rows, then       *)
(*                  `app_change`'s issue lock and fence exclusive; under   *)
(*                  the fence, each input the vault decided on is still    *)
(*                  the object it read (its seal), the key's seal is the   *)
(*                  one its change was made from (ChangeCAS), the rows,    *)
(*                  the change, the commit. Any guard failing rolls it all *)
(*                  back, and the write asks again from 1.                 *)
(*               4. the seal wait (R51), then the answer.                  *)
(*   member add  1. the vault reads the actor's standing, the policy and   *)
(*                  the principal's row, holding nothing (Lifecycle's      *)
(*                  issue, IssuerCAS);                                     *)
(*               2. the Worker decides and builds the new row, its MAC     *)
(*                  and its seal, from the row as read;                    *)
(*               3. one statement: the rows, the head, the fence; it goes  *)
(*                  ahead only while the actor's object, the policy and    *)
(*                  the principal's row are what step 1 read; otherwise it *)
(*                  writes nothing and the vault reads again;              *)
(*               4. the seal wait, then the answer.                        *)
(*                                                                         *)
(* Every other change (a revoke, a session's end, a policy change, an      *)
(* archive, a demotion) is one atomic step here, as each is one statement  *)
(* or one transaction under the head and the fence in the code.            *)
(*                                                                         *)
(* One step is one statement, or the part of one between two lock waits    *)
(* (READ COMMITTED; a PL/pgSQL statement after a lock reads afresh).       *)
(* Locks: 0.14's head (held across steps by the app's statement when its   *)
(* guards run before the fence) and the fence, which every change but an   *)
(* app write under the head takes in one step here. Seals: a counter per   *)
(* object, moved by each change; honest code only (no database writer:    *)
(* HotPathOne and SealedObjects hold seals against one).                   *)
(*                                                                         *)
(* Who is who:                                                             *)
(*   w1, w2   Ada writes key k at env, each from her session cA;           *)
(*   rev      an admin takes Ada's grant at env away (her member object);  *)
(*   end      Ada's session cA is revoked (the credential alone: the fence,*)
(*            not 0.14's head, as Lifecycle's revoke);                     *)
(*   pol      an Owner protects env: Ada's role no longer writes there;    *)
(*   arc      a maintainer archives env (the app's transaction);           *)
(*   bob, cy  two admins each add the service account svc;                *)
(*   dem      an Owner demotes Bob;                                        *)
(*   ck       the checkpointer: each tick seals every committed number.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs,          \* the scenario's processes (MCWriting.tla)
    MaxTries        \* how many times a write or an add may ask again

CONSTANTS
    \* The vault's statement reads its inputs and numbers the request in one
    \* statement under the fence shared, as a use does (HotPathOne's
    \* "reads are a statement after the lock"): no change is numbered
    \* between what it read and its number.
    RequestUnderFence,
    \* The inputs the app's statement holds to the objects the vault read,
    \* by their seals: any of "cred", "member", "policy", "env". Normally
    \* all four; a removal leaves one out (`Held={...}`).
    Held,
    \* ... and checks them once it holds the fence (after `app_change`
    \* took it), so a change that takes the fence and not 0.14's head (a
    \* session's revoke) cannot commit between the check and the write.
    GuardsAfterFence,
    \* The key's change goes ahead only from the seal it was made from
    \* (`app_change`'s CAS, ChangeCAS): another write meanwhile fails it.
    ChangeCAS,
    \* A member add's write goes ahead only while the actor's object and
    \* the policy are what its read decided on (IssuerCAS).
    AdmitCAS,
    \* ... and the principal's row is the one it read (none): the change
    \* from its object as read.
    PrincipalCAS,
    \* A change answers only once its number is sealed in a checkpoint (R51).
    WaitForSeal

Writers == {"w1", "w2"}
Adders == {"bob", "cy"}
Objects == {"cred", "member", "policy", "env", "key", "bob", "svc"}
Inputs == {"cred", "member", "policy", "env"}
None == "none"

VARIABLES
    cred,       \* Ada's session cA is live
    grant,      \* Ada's grant lets her write at env
    protected,  \* env is protected: her role does not write there
    archived,   \* env is archived
    bobAdmin,   \* Bob may add members
    svc,        \* svc is a member
    kver,       \* the key's committed versions
    seal,       \* each object's seal: moved by every change to it
    next,       \* the log's next number
    sealedTo,   \* the checkpointer has sealed every number below this
    head,       \* who holds 0.14's head across steps, or None
    pc, l, tries,
    trips,      \* round trips each process made on its path
    requests,   \* ghost: each write's request, as decided live and by the replay
    writes,     \* ghost: each committed key change
    admits,     \* ghost: each committed member add
    answered    \* ghost: each change answered, with its number

vars == <<cred, grant, protected, archived, bobAdmin, svc, kver, seal, next, sealedTo, head,
          pc, l, tries, trips, requests, writes, admits, answered>>
state == <<cred, grant, protected, archived, bobAdmin, svc, kver, seal>>

\* What Ada's write needs, as decide.ts weighs it: a live session, the grant,
\* a place her role writes in, live.
Allowed(s) == s.cred /\ s.grant /\ ~s.protected /\ ~s.archived
Now == [cred |-> cred, grant |-> grant, protected |-> protected, archived |-> archived]
\* Whether an adder stands: Cy always; Bob while he is an admin.
Stands(p) == p = "cy" \/ bobAdmin

Init ==
    /\ cred = TRUE /\ grant = TRUE /\ protected = FALSE /\ archived = FALSE
    /\ bobAdmin = TRUE /\ svc = FALSE /\ kver = 0
    /\ seal = [o \in Objects |-> 0]
    /\ next = 1 /\ sealedTo = 1 /\ head = None
    /\ pc = [p \in Procs |-> CASE p \in Writers -> "w.vault"
                                [] p \in Adders -> "a.read"
                                [] p = "ck" -> "ck"
                                [] OTHER -> "change"]
    /\ l = [p \in Procs |-> [n |-> 0]]
    /\ tries = [p \in Procs |-> 1]
    /\ trips = [p \in Procs |-> 0]
    /\ requests = {} /\ writes = {} /\ admits = {} /\ answered = {}

Goto(p, to) == pc' = [pc EXCEPT ![p] = to]
\* A change commits, numbered, its object's seal moved.
Numbered(o) == /\ seal' = [seal EXCEPT ![o] = @ + 1]
               /\ next' = next + 1
\* Asked again, or given up (the API's 409) once out of tries.
Again(p, from) ==
    /\ IF tries[p] < MaxTries THEN Goto(p, from) ELSE Goto(p, "done")
    /\ tries' = [tries EXCEPT ![p] = @ + 1]

-----------------------------------------------------------------------------
(* A key write *)

ReadInputs(p) ==
    l' = [l EXCEPT ![p] = [n |-> 0, s |-> Now, seals |-> seal, ver |-> kver]]

\* The vault's statement: read by name under the fence shared, the request
\* numbered. One round trip.
WVault(p) ==
    /\ pc[p] = "w.vault"
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF RequestUnderFence
         THEN /\ ReadInputs(p)
              /\ next' = next + 1
              /\ requests' = requests \cup {[p |-> p, n |-> next, live |-> Allowed(Now), replay |-> Allowed(Now)]}
              /\ Goto(p, "w.decide")
         ELSE /\ ReadInputs(p)
              /\ UNCHANGED <<next, requests>>
              /\ Goto(p, "w.number")
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, kver, seal, sealedTo, head, tries, writes, admits, answered>>

\* Without the fence, the number comes in a later step: what was read and
\* what the log holds at the number may differ.
WNumber(p) ==
    /\ pc[p] = "w.number"
    /\ next' = next + 1
    /\ requests' = requests \cup {[p |-> p, n |-> next, live |-> Allowed(l[p].s), replay |-> Allowed(Now)]}
    /\ Goto(p, "w.decide")
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, kver, seal, sealedTo, head, l, tries, trips, writes, admits, answered>>

\* The Worker decides on what it read; allowed, it wraps and seals the
\* change from the key's seal as read. No round trip.
WDecide(p) ==
    /\ pc[p] = "w.decide"
    /\ IF Allowed(l[p].s) THEN Goto(p, "w.app") ELSE Goto(p, "done")
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, kver, seal, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

\* The inputs still the objects the vault read.
Guarded(p) == \A o \in Held : seal[o] = l[p].seals[o]
CasHolds(p) == ~ChangeCAS \/ seal["key"] = l[p].seals["key"]

\* The write itself, once the guards pass and the fence is held: the key's
\* next version, its change numbered.
Commit(p) ==
    /\ kver' = kver + 1
    /\ Numbered("key")
    /\ l' = [l EXCEPT ![p].n = next]
    /\ writes' = writes \cup {[p |-> p, n |-> next, stands |-> Allowed(Now), from |-> l[p].seals["key"], was |-> seal["key"]]}

\* The app's statement, guards after the fence: one atomic step. One round trip.
WApp(p) ==
    /\ pc[p] = "w.app"
    /\ head = None
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ IF GuardsAfterFence
         THEN IF Guarded(p) /\ CasHolds(p)
                THEN /\ Commit(p) /\ Goto(p, "w.seal")
                     /\ UNCHANGED <<head, tries>>
                ELSE /\ Again(p, "w.vault")
                     /\ UNCHANGED <<kver, seal, next, l, head, writes>>
         ELSE IF Guarded(p)
                \* Its guards under 0.14's head, then a wait for the fence.
                THEN /\ head' = p /\ Goto(p, "w.fence")
                     /\ UNCHANGED <<kver, seal, next, l, tries, writes>>
                ELSE /\ Again(p, "w.vault")
                     /\ UNCHANGED <<kver, seal, next, l, head, writes>>
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, sealedTo, requests, admits, answered>>

\* The same statement, after its wait for the fence.
WFence(p) ==
    /\ pc[p] = "w.fence"
    /\ head' = None
    /\ IF CasHolds(p)
         THEN /\ Commit(p) /\ Goto(p, "w.seal") /\ UNCHANGED tries
         ELSE /\ Again(p, "w.vault") /\ UNCHANGED <<kver, seal, next, l, writes>>
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, sealedTo, trips, requests, admits, answered>>

-----------------------------------------------------------------------------
(* A member add *)

\* The read: the actor's standing, the policy, the principal's row. No lock.
ARead(p) ==
    /\ pc[p] = "a.read"
    /\ trips' = [trips EXCEPT ![p] = @ + 1]
    /\ l' = [l EXCEPT ![p] = [n |-> 0, stands |-> Stands(p), there |-> svc, seals |-> seal]]
    /\ Goto(p, "a.decide")
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, kver, seal, next, sealedTo, head, tries, requests, writes, admits, answered>>

\* The Worker decides; the principal already a member is a conflict.
ADecide(p) ==
    /\ pc[p] = "a.decide"
    /\ IF l[p].stands /\ ~l[p].there THEN Goto(p, "a.write") ELSE Goto(p, "done")
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, kver, seal, next, sealedTo, head, l, tries, trips, requests, writes, admits, answered>>

Actor(p) == IF p = "bob" THEN "bob" ELSE None
ActorHeld(p) == ~AdmitCAS \/ ((Actor(p) = None \/ seal[Actor(p)] = l[p].seals[Actor(p)]) /\ seal["policy"] = l[p].seals["policy"])
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
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, kver, sealedTo, head, requests, writes, answered>>

-----------------------------------------------------------------------------
(* The seal wait, the answer, and everything else *)

\* A change answers once its number is sealed (R51).
Answer(p) ==
    /\ pc[p] \in {"w.seal", "a.seal", "x.seal"}
    /\ ~WaitForSeal \/ l[p].n < sealedTo
    /\ answered' = answered \cup {[p |-> p, n |-> l[p].n]}
    /\ Goto(p, "done")
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, kver, seal, next, sealedTo, head, l, tries, trips, requests, writes, admits>>

\* Every other change, one atomic step: 0.14's head and the fence (a
\* session's revoke the fence alone, which the head's holder does not stop).
Change(p) ==
    /\ pc[p] = "change"
    /\ p = "end" \/ head = None
    /\ CASE p = "rev" -> /\ grant' = FALSE /\ Numbered("member")
                         /\ UNCHANGED <<cred, protected, archived, bobAdmin>>
         [] p = "end" -> /\ cred' = FALSE /\ Numbered("cred")
                         /\ UNCHANGED <<grant, protected, archived, bobAdmin>>
         [] p = "pol" -> /\ protected' = TRUE /\ Numbered("policy")
                         /\ UNCHANGED <<cred, grant, archived, bobAdmin>>
         [] p = "arc" -> /\ archived' = TRUE /\ Numbered("env")
                         /\ UNCHANGED <<cred, grant, protected, bobAdmin>>
         [] p = "dem" -> /\ bobAdmin' = FALSE /\ Numbered("bob")
                         /\ UNCHANGED <<cred, grant, protected, archived>>
    /\ l' = [l EXCEPT ![p].n = next]
    /\ Goto(p, "x.seal")
    /\ UNCHANGED <<svc, kver, sealedTo, head, tries, trips, requests, writes, admits, answered>>

\* A tick seals every number committed so far.
Tick ==
    /\ "ck" \in Procs
    /\ sealedTo < next
    /\ sealedTo' = next
    /\ UNCHANGED <<cred, grant, protected, archived, bobAdmin, svc, kver, seal, next, head, pc, l, tries, trips, requests, writes, admits, answered>>

Step(p) == WVault(p) \/ WNumber(p) \/ WDecide(p) \/ WApp(p) \/ WFence(p)
        \/ ARead(p) \/ ADecide(p) \/ AWrite(p) \/ Answer(p) \/ Change(p)

Terminating ==
    /\ \A p \in Procs \ {"ck"} : pc[p] = "done"
    /\ sealedTo = next
    /\ UNCHANGED vars

Next == (\E p \in Procs : Step(p)) \/ Tick \/ Terminating
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What must hold *)

TypeOK ==
    /\ seal \in [Objects -> Nat]
    /\ head \in Procs \cup {None}
    /\ sealedTo <= next

\* A key write commits only while Ada may still write there: her session,
\* her grant, the policy and the place all as the vault decided on them. A
\* revoke, an end, a protection or an archive answered (committed first)
\* stops every write after it, the one already decided included.
WritesStandAtCommit == \A w \in writes : w.stands

\* Each key change goes from the object it was made from: two writes from
\* one version never both commit (EachChangeFlips, for the app's change).
KeyChangesFlip == \A w \in writes : w.from = w.was

\* The replay decides each write's request at its number as the vault did
\* live (HotPathOne's ReplayAgrees, for the request a write logs).
RequestsReplay == \A r \in requests : r.live = r.replay

\* A member is added only while its adder stands, at the commit.
AddsStandAtCommit == \A a \in admits : a.stands

\* ... from the principal's row as read: two adds never both commit.
AddsFlip == \A a \in admits : a.from = a.was

\* Every change answers only once sealed (R51).
AnsweredSealed == \A a \in answered : a.n < sealedTo

\* A write or an add that committed at its first try made two round trips:
\* the vault's statement and the app's, or the vault's two.
TwoTrips == \A p \in Procs : (pc[p] \in {"w.seal", "a.seal"} /\ tries[p] = 1) => trips[p] = 2

=============================================================================
