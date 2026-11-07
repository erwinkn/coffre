----------------------------- MODULE Unbinding -----------------------------
(***************************************************************************)
(* Removing a binding whose sign-ins keep coming (W331, D177). With no     *)
(* count of a binding's sign-ins, its live credentials can outgrow one     *)
(* vault call (Node's 8 MiB message; the fence each revoke holds; a        *)
(* Worker's CPU), and a request makes a bounded number of vault calls (a   *)
(* Worker's 32 invocations). So a binding is removed in steps, each a      *)
(* statement of its own (server api/workloads.ts, #bindingsByVault;        *)
(* migration 0076), by whoever asks (a person's request) and, until it     *)
(* ends, by the scheduled run, which resumes every closed binding:         *)
(*                                                                         *)
(*   read   the binding's live credentials, a batch and one more, no lock; *)
(*   sweep  (more than a batch read) the binding's row FOR UPDATE, which   *)
(*          waits for every sign-in sharing it; the binding closed (its    *)
(*          `closed_at`); a batch of what was read revoked, each still as  *)
(*          read, under the fence; then read again;                        *)
(*   end    (a batch or fewer) the row FOR UPDATE; the binding still live, *)
(*          every live credential of it one named, else `moved` (nothing   *)
(*          written): then the binding is closed and read again; if all    *)
(*          are named, they are revoked and the binding ended, one commit; *)
(*   answer once the end's change is sealed (R51). A sweep's changes wait  *)
(*          for no seal: the checkpointer seals the log a prefix at a      *)
(*          time, so the end's seal covers every sweep's before it.        *)
(*                                                                         *)
(* A sign-in takes the row FOR KEY SHARE only where it is neither ended    *)
(* nor closed (`sign_in`'s WHERE): a row its predicate drops is never      *)
(* locked, so a closed binding's sign-ins wait for nothing and are         *)
(* refused as `unbound`. The person's request may stop between two steps   *)
(* (its invocations or CPU spent, a crash): asked again it goes on, or it  *)
(* is never asked again, and the scheduled run finishes it.                *)
(*                                                                         *)
(* What it shows: the ended binding leaves no credential live, whatever    *)
(* the batches; no sign-in commits once the binding is closed; a closed    *)
(* binding is never opened again; no credential is revoked twice, nor the  *)
(* binding ended twice, however the two removers race; a remover answers   *)
(* only once every credential it ended is revoked and sealed; and the      *)
(* binding ends, however sign-ins keep coming, the person's request        *)
(* stopped or abandoned; and between the close and the end, which on      *)
(* Workers may be scheduled runs apart, no session of the binding is used: *)
(* its statement reads the binding's row before any vault call             *)
(* (`sessionRowsFor`) and refuses it closed. (A bearer credential it        *)
(* exchanged serves until its batch or its own end, five minutes at most:   *)
(* a use by name asks the vault first, which reads no binding.)             *)
(*                                                                         *)
(* A use takes three steps here: the app's check of its binding, at the   *)
(* request's start (a session's, `sessionRowsFor`); the vault's            *)
(* statement, which takes the fence shared and reads its credential's row; *)
(* and its commit, which numbers it and lets the fence go. Every revoke    *)
(* takes the fence exclusive, after the close too: a request whose check   *)
(* passed before the close can reach the vault after it, and an unfenced   *)
(* revoke would number its use after the revoke (`RevokeOrdersUses`, the   *)
(* negatives without CloseFenced or BatchFenced). A vault that also read   *)
(* the binding's `closed_at` in each use statement (VaultChecksClosed)     *)
(* would let the batches after the close go unfenced; it does not today.   *)
(* A replacement makes its new binding in the statement that closes the   *)
(* old one; what is left after is the old one's removal, which its request *)
(* or the scheduled run finishes.                                          *)
(* The binding's stamp of its last use takes no lock a removal waits for   *)
(* here (it skips when locked) and is left out.                            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    SignIns,        \* the sign-in processes, each signing in again and again
    Creds,          \* credential slots: one revoked or expired is free for a new credential
    Batch,          \* the most a sweep revokes
    Crashes,        \* how many times the person's request may stop between two steps and be asked again
    Abandons,       \* whether the person's request may stop for good, never asked again
    Using,          \* whether a request uses one of the binding's credentials (off where only the removers' liveness is checked)
    Replacing       \* whether the person's request replaces the binding (makes another in its place), rather than removes it

CONSTANTS
    \* A sweep closes the binding, and an end refused as `moved` closes it before reading again.
    Closes,
    \* A sign-in is refused on a closed binding: its WHERE drops the row (no lock taken).
    SignInChecksClosed,
    \* The close takes the row FOR UPDATE, waiting for every sign-in that shares it.
    CloseExclusive,
    \* The end holds every live credential to the ones it names, under the row's lock.
    EndComplete,
    \* The end takes the row FOR UPDATE too.
    EndExclusive,
    \* A remover answers once the end's change is sealed, which seals every sweep's before it.
    SealWait,
    \* The scheduled run resumes every closed binding's removal.
    Resumes,
    \* A sweep or an end revokes only credentials still as read, none revoked since (`moved` otherwise).
    RevokeCAS,
    \* An end ends only a binding still live (its row as read, `revoked_at IS NULL`).
    EndChecksLive,
    \* A use refuses a credential whose binding is closed, not only one ended (a session's statement, `sessionRowsFor`).
    UseChecksClosed,
    \* A replacement makes its new binding in the statement that closes the old one, not at the old one's end.
    MakesAtClose,
    \* The statement that closes the binding takes the fence exclusive, waiting for every use holding it shared.
    CloseFenced,
    \* Every other statement that revokes (the sweeps after the close, the end) takes the fence exclusive too.
    BatchFenced,
    \* The vault's use statement, under the fence shared, refuses a credential whose binding is closed.
    VaultChecksClosed

None == "none"
Ub == "ub"          \* the person's request, asked again after a stop
Rs == "rs"          \* the scheduled run's resume
Removers == {Ub, Rs}
U == "u"            \* a request using one of the binding's credentials, again and again
Procs == SignIns \cup Removers \cup {U}

VARIABLES
    bstate,     \* the binding: "open", "closed" (closed_at set) or "ended" (revoked)
    cred,       \* cred[c]: "none", "live", "expired" or "revoked"
    bx,         \* the row's exclusive holder (FOR UPDATE), or None
    bs,         \* its sharers (FOR KEY SHARE)
    pc,         \* each process's step
    read,       \* read[r]: the credentials remover r read, and names
    crashes,    \* the person's request's stops so far
    late,       \* whether a sign-in ever committed on a binding not open
    unsealed,   \* the credentials whose revoke is committed and not yet sealed
    twice,      \* whether a credential was ever revoked twice
    ends,       \* how many times the binding was ended
    served,     \* whether a use ever passed the app's check of the binding once it was not open
    fs,         \* the uses holding the fence shared
    uc,         \* the credential the use presents, or None
    ulive,      \* whether its vault statement found it live
    uhit,       \* whether it was revoked since that read
    early,      \* whether a use allowed was ever numbered after its credential's revoke
    made        \* whether a replacement's new binding is made

uvars == <<fs, uc, ulive, uhit, early>>
vars == <<bstate, cred, bx, bs, pc, read, crashes, late, unsealed, twice, ends, made, served, fs, uc, ulive, uhit, early>>

Live == {c \in Creds : cred[c] = "live"}
\* A credential the end may name: not revoked; an expired one still matches its row (`revoked_at IS NULL`).
Unrevoked == {c \in Creds : cred[c] \in {"live", "expired"}}
Free == {c \in Creds : cred[c] \in {"none", "expired", "revoked"}}

Init ==
    /\ bstate = "open"
    /\ cred = [c \in Creds |-> "none"]
    /\ bx = None
    /\ bs = {}
    /\ pc = [p \in Procs |-> CASE p = Ub -> "read" [] OTHER -> "idle"]
    /\ read = [r \in Removers |-> {}]
    /\ crashes = 0
    /\ late = FALSE
    /\ unsealed = {}
    /\ twice = FALSE
    /\ ends = 0
    /\ served = FALSE
    /\ fs = {}
    /\ uc = None
    /\ ulive = FALSE
    /\ uhit = FALSE
    /\ early = FALSE
    /\ made = FALSE

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

\* Revoke these credentials: each as read, else none (`moved`); without RevokeCAS, every one, revoked or not.
Revoke(some) ==
    IF RevokeCAS /\ ~(some \subseteq Unrevoked)
      THEN UNCHANGED <<cred, unsealed, twice, uhit>>
      ELSE /\ cred' = [c \in Creds |-> IF c \in some THEN "revoked" ELSE cred[c]]
           /\ unsealed' = unsealed \cup some
           /\ twice' = (twice \/ \E c \in some : cred[c] = "revoked")
           \* A use that read its credential live and has not committed: its credential revoked since.
           /\ uhit' = (uhit \/ (pc[U] = "vcommit" /\ uc \in some))

\* A statement that revokes takes the fence exclusive, if it does, only once no use holds it shared: the one that closes
\* the binding, or ends it at once (CloseFenced), or any after it (BatchFenced).
FenceFor(closing) == (IF closing THEN CloseFenced ELSE BatchFenced) => fs = {}

-----------------------------------------------------------------------------
(* A sign-in: the row FOR KEY SHARE where its WHERE holds, then the        *)
(* credential written and the commit. *)

SignInStart(s) ==
    /\ pc[s] = "idle"
    /\ Goto(s, "rows")
    /\ UNCHANGED <<bstate, cred, bx, bs, read, crashes, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

\* Waits for the close's or the end's FOR UPDATE; then the row as it is now.
SignInRows(s) ==
    /\ pc[s] = "rows"
    /\ bx = None
    /\ IF bstate = "ended" \/ (SignInChecksClosed /\ bstate = "closed")
         THEN /\ Goto(s, "idle") /\ UNCHANGED bs
         ELSE /\ bs' = bs \cup {s} /\ Goto(s, "body")
    /\ UNCHANGED <<bstate, cred, bx, read, crashes, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

SignInBody(s) ==
    /\ pc[s] = "body"
    /\ \/ \E c \in Free :
            /\ cred' = [cred EXCEPT ![c] = "live"]
            /\ late' = (late \/ bstate # "open")
       \/ Free = {} /\ UNCHANGED <<cred, late>>
    /\ bs' = bs \ {s}
    /\ Goto(s, "idle")
    /\ UNCHANGED <<bstate, bx, read, crashes, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

\* A credential's five minutes pass.
Expire ==
    /\ \E c \in Live : cred' = [cred EXCEPT ![c] = "expired"]
    /\ UNCHANGED <<bstate, bx, bs, pc, read, crashes, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

\* The checkpointer seals every change committed so far (a prefix of the log).
Checkpoint ==
    /\ unsealed # {}
    /\ unsealed' = {}
    /\ UNCHANGED <<bstate, cred, bx, bs, pc, read, crashes, late, twice, ends, made, served>>
    /\ UNCHANGED uvars

-----------------------------------------------------------------------------
(* A removal's steps, the person's request's and the scheduled run's alike. *)

\* The scheduled run, at a beat, resumes a closed binding's removal.
RsStart ==
    /\ Resumes
    /\ pc[Rs] = "idle"
    /\ bstate = "closed"
    /\ Goto(Rs, "read")
    /\ UNCHANGED <<bstate, cred, bx, bs, read, crashes, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

Read(r) ==
    /\ pc[r] = "read"
    /\ read' = [read EXCEPT ![r] = Live]
    /\ Goto(r, IF bstate = "ended" THEN "answer" ELSE IF Cardinality(Live) > Batch THEN "sweep" ELSE "end")
    /\ UNCHANGED <<bstate, cred, bx, bs, crashes, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

\* The row's lock, for a sweep (closing) or the end: FOR UPDATE waits for every sharer; without it, one already sharing goes on.
TakeRow(r, exclusive) ==
    /\ bx = None
    /\ exclusive => bs = {}
    /\ bx' = r

\* A sweep: the binding closed, and up to a batch of what was read revoked, each only if still as read (else `moved`: none).
Sweep(r) ==
    /\ pc[r] = "sweep"
    /\ TakeRow(r, CloseExclusive)
    /\ Goto(r, "sweeping")
    /\ UNCHANGED <<bstate, cred, bs, read, crashes, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

Sweeping(r) ==
    /\ pc[r] = "sweeping"
    /\ FenceFor(bstate = "open")
    /\ IF bstate = "ended"
         THEN /\ Goto(r, "answer") /\ UNCHANGED <<bstate, cred, unsealed, twice, uhit, made>>
         ELSE /\ bstate' = IF Closes THEN "closed" ELSE bstate
              \* The replacement's sweep makes the new binding as it closes the old (the scheduled run makes none).
              /\ made' = (made \/ (Replacing /\ r = Ub /\ MakesAtClose))
              /\ \E some \in SUBSET read[r] :
                   /\ Cardinality(some) = IF Cardinality(read[r]) < Batch THEN Cardinality(read[r]) ELSE Batch
                   /\ Revoke(some)
              \* No seal waited for: the next step at once.
              /\ Goto(r, "read")
    /\ bx' = None
    /\ UNCHANGED <<bs, read, crashes, late, ends, served, fs, uc, ulive, early>>

End(r) ==
    /\ pc[r] = "end"
    /\ TakeRow(r, EndExclusive)
    /\ Goto(r, "ending")
    /\ UNCHANGED <<bstate, cred, bs, read, crashes, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

\* The binding still live, every live credential named, those named not revoked since: all revoked and the binding
\* ended. Else `moved`, nothing written: closed first (a sweep of none), then read again. Ended by the other remover:
\* nothing to do but answer.
Ending(r) ==
    /\ pc[r] = "ending"
    /\ FenceFor(bstate = "open")
    /\ IF bstate = "ended" /\ EndChecksLive
         THEN /\ Goto(r, "answer") /\ UNCHANGED <<bstate, cred, read, unsealed, twice, ends, made, uhit>>
         ELSE IF (RevokeCAS => read[r] \subseteq Unrevoked) /\ (EndComplete => Live \subseteq read[r])
         THEN /\ Revoke(read[r])
              /\ bstate' = "ended"
              /\ ends' = ends + 1
              /\ made' = (made \/ (Replacing /\ r = Ub))
              /\ Goto(r, "answer")
              /\ UNCHANGED read
         ELSE /\ read' = [read EXCEPT ![r] = {}]
              /\ Goto(r, IF Closes THEN "sweep" ELSE "read")
              /\ UNCHANGED <<bstate, cred, unsealed, twice, ends, made, uhit>>
    /\ bx' = None
    /\ UNCHANGED <<bs, crashes, late, served, fs, uc, ulive, early>>

\* The answer, once the end's change is sealed: the seal is of the log's prefix, so every sweep's revoke is sealed too.
\* Without SealWait, at once. The scheduled run is then idle again.
Answer(r) ==
    /\ pc[r] = "answer"
    /\ SealWait => unsealed = {}
    /\ Goto(r, IF r = Rs THEN "idle" ELSE "done")
    /\ UNCHANGED <<bstate, cred, bx, bs, read, crashes, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

\* The person's request stops between two steps, holding no lock (a statement's own work rolls back with it): asked
\* again, it goes on from its read; or, with Abandons, never asked again.
UbStop ==
    /\ pc[Ub] \in {"read", "sweep", "end"}
    /\ \/ /\ crashes < Crashes
          /\ crashes' = crashes + 1
          /\ read' = [read EXCEPT ![Ub] = {}]
          /\ Goto(Ub, "read")
       \/ /\ Abandons
          /\ Goto(Ub, "gone")
          /\ UNCHANGED <<crashes, read>>
    /\ UNCHANGED <<bstate, cred, bx, bs, late, unsealed, twice, ends, made, served>>
    /\ UNCHANGED uvars

-----------------------------------------------------------------------------
(* A use of one of the binding's credentials, in its three steps: the      *)
(* app's check of its binding (`bindingStands`), at the request's start;   *)
(* the vault's statement, which takes the fence shared and reads the       *)
(* credential's row (and, with VaultChecksClosed, its binding's); and its  *)
(* commit, which numbers the use and lets the fence go.                    *)

Old == <<bstate, cred, bx, bs, read, crashes, late, unsealed, twice, ends, made>>

UseApp ==
    /\ Using
    /\ pc[U] = "idle"
    /\ \E c \in Live :
         IF UseChecksClosed /\ bstate # "open"
           THEN UNCHANGED <<pc, served, uc>>
           ELSE /\ served' = (served \/ bstate # "open")
                /\ uc' = c
                /\ Goto(U, "vread")
    /\ UNCHANGED <<fs, ulive, uhit, early>>
    /\ UNCHANGED Old

UseRead ==
    /\ pc[U] = "vread"
    /\ fs' = {U}
    /\ ulive' = (cred[uc] = "live" /\ (VaultChecksClosed => bstate = "open"))
    /\ uhit' = FALSE
    /\ Goto(U, "vcommit")
    /\ UNCHANGED <<uc, early, served>>
    /\ UNCHANGED Old

UseCommit ==
    /\ pc[U] = "vcommit"
    /\ early' = (early \/ (ulive /\ uhit))
    /\ fs' = {}
    /\ uc' = None
    /\ Goto(U, "idle")
    /\ UNCHANGED <<ulive, uhit, served>>
    /\ UNCHANGED Old

RemoverStep(r) == Read(r) \/ Sweep(r) \/ End(r) \/ Answer(r)

Next ==
    \/ \E s \in SignIns : SignInStart(s) \/ SignInRows(s) \/ SignInBody(s)
    \/ Expire \/ Checkpoint \/ RsStart \/ UbStop
    \/ \E r \in Removers : RemoverStep(r) \/ Sweeping(r) \/ Ending(r)
    \/ UseApp \/ UseRead \/ UseCommit
    \/ (pc[Ub] \in {"done", "gone"} /\ pc[Rs] = "idle" /\ \A s \in SignIns : pc[s] = "idle") /\ UNCHANGED vars

\* A statement under way goes on (WF); a remover's lock, free again and again, it eventually takes (SF): sign-ins may
\* take the row whenever it is free, but not forever before it, as an unbind's FOR UPDATE was measured to get the row
\* within 2 ms at 5,000 sign-ins a second on one binding. The scheduled run comes round (WF on its start: a beat every
\* five minutes); the person's request may stop for good. Sign-ins may stop, or never stop; credentials may expire, or not.
Fairness ==
    /\ \A r \in Removers : SF_vars(Sweep(r)) /\ SF_vars(End(r)) /\ WF_vars(Read(r) \/ Answer(r))
    \* A fenced statement waits for the use's commit, which frees the fence again and again (SF): uses come and go.
    /\ \A r \in Removers : SF_vars(Sweeping(r)) /\ SF_vars(Ending(r))
    /\ WF_vars(UseRead) /\ WF_vars(UseCommit)
    /\ WF_vars(RsStart)
    /\ WF_vars(Checkpoint)
    /\ \A s \in SignIns : WF_vars(SignInBody(s))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------

TypeOK ==
    /\ bstate \in {"open", "closed", "ended"}
    /\ cred \in [Creds -> {"none", "live", "expired", "revoked"}]
    /\ bx \in {None} \cup Removers
    /\ bs \subseteq SignIns
    /\ read \in [Removers -> SUBSET Creds]
    /\ crashes \in 0..Crashes

\* Ended, the binding leaves no credential live: a use, which decides on a credential's row, serves none after.
EndedBindingEndsCredentials == bstate = "ended" => Live = {}

\* Closed, the binding serves no use, though its credentials are not all revoked yet: the window a removal under way
\* leaves, for minutes on Workers, is closed at once.
ClosedServesNone == ~served

\* A revoke orders its credential's uses: none allowed is numbered after it (Lifecycle.tla's RevokeOrdersUses), a use
\* whose app check passed before the close included.
RevokeOrdersUses == ~early

\* No sign-in commits on a binding closed or ended: the set a removal revokes stops growing once it closed it.
NoSignInAfterClose == ~late

\* However the person's request and the scheduled run race: no credential revoked twice, the binding ended once.
NoDoubleRevoke == ~twice
EndsOnce == ends <= 1

\* The person's request answers only once every credential the binding issued is revoked, and sealed (R51), whichever
\* remover ended it. (The scheduled run answers nobody.)
AnsweredWhenSealed == pc[Ub] = "done" => bstate = "ended" /\ Live = {} /\ unsealed = {}

\* A closed binding is never opened again: a stop leaves it closed, for a rerun or the schedule to end.
ClosedStaysClosed == [][bstate # "open" => bstate' # "open"]_vars

\* A removal asked, and never abandoned, ends the binding, however sign-ins keep coming and its request stops.
UnbindFinishes == <>(bstate = "ended")

\* A removal that got as far as closing the binding ends it, however sign-ins keep coming, its request abandoned: the
\* scheduled run finishes it. (One abandoned before its first sweep left nothing behind to finish.)
RemovalEnds == bstate = "closed" ~> bstate = "ended"

\* A replacement leaves no moment with the old binding closed and the new one not made: stopped after its first statement,
\* what is left is the old one's removal, which the scheduled run finishes (reviews r8, r9).
NoGapInTrust == (Replacing /\ bstate # "open") => made

=============================================================================
