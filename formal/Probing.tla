------------------------------- MODULE Probing -------------------------------
(***************************************************************************)
(* What a caller with no access learns of a place's keys by asking for     *)
(* them (T145, PR B; review r2 of #406): nothing. Ada's grant on           *)
(* market/dev is revoked; she keeps asking for API_KEY through the proxy   *)
(* or the API, while the vault comes and goes from overload. Two runs go   *)
(* side by side, alike in everything but one: in run A someone makes      *)
(* API_KEY after the revoke, a sealed value or a plain one; in run B       *)
(* nobody does. Every answer Ada gets must be the same in both            *)
(* (`SameAnswer`): what tells them apart is a key she may not know of.     *)
(* docs/formal.md says what this covers and abstracts.                     *)
(*                                                                         *)
(* One step is one request, whole: the app's read of the key's rows, its   *)
(* answer about Ada (the vault's now, or one kept from before the revoke), *)
(* the vault's calls and their admission (`busy`, the same for both runs:  *)
(* the vault's load does not hang on a key Ada asks for), and, once        *)
(* admitted, her principal's lock held by another call past the use's      *)
(* deadline (`contended`, the same for both runs too). A use of a sealed   *)
(* key waits for that lock when the key has no fresh row of the bulk cap's *)
(* for her (`fresh`): one made since has none until a request of hers for  *)
(* it, a refused one too, writes it. A key never made, and a plain value,  *)
(* never wait: so what she asked before, which she chooses, says which of  *)
(* her requests wait (review r2 of #412).                                  *)
(***************************************************************************)
EXTENDS Naturals, Sequences, TLC

CONSTANTS
    Budget          \* how many requests Ada makes

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
    \* PR B: a key the place does not hold is decided by the vault, on Ada's
    \* standing at the place first (`missing` only if she may act there), in
    \* the same call a use makes, under the same admission. Off, the app
    \* answers it itself: not found.
    MissingByStanding,
    \* PR B: a plain value, which no use opens, goes back only once the vault
    \* has decided on Ada's standing at the place, as for a missing key. Off,
    \* the app hands it back on its own read.
    PlainByStanding,
    \* PR B: that call is admitted as a use is, and refused busy as one is.
    \* Off, it is never busy.
    StandingSharesAdmission,
    \* PR B: a use late after it was admitted (it waited for her principal's
    \* lock) first asks the vault for Ada's standing at the place, in a call
    \* that waits for no lock and reads no key, and is refused as any key is
    \* if she may not act there; otherwise it answers busy. Off, it answers
    \* busy as it is.
    ConfirmStandingOnLate,
    \* PR B: that call runs within the place in admission the late use held,
    \* once the use's own call has let it go. Off, it asks admission anew, and
    \* is refused busy when none is free (`full`): the late use's own call,
    \* still running, may hold the last (review r3 of #412).
    ConfirmReserved,
    \* Before PR B: a refusal on a kept answer the vault has not vouched for,
    \* a busy one (503) included, first asks the vault for its answer now, and
    \* starts over on the fresh one when it differs (`Recalled.confirm`,
    \* #406 r2). Off, a busy use answers 503 as it is.
    ConfirmOnBusy

Answers == {"value", "forbidden", "missing", "busy"}

VARIABLES
    granted,        \* Ada's grant stands
    made,           \* run A: API_KEY made since the revoke ("none", "sealed", "plain")
    fresh,          \* run A: the cap's row of API_KEY for Ada, which a request of hers for it writes
    kept,           \* the app keeps an answer about Ada that says she reads here
    left,           \* requests still to make
    answers         \* <<run A's answer, run B's>> to each request so far

vars == <<granted, made, fresh, kept, left, answers>>

Init ==
    /\ granted = TRUE
    /\ made = "none"
    /\ fresh = FALSE
    /\ kept = TRUE
    /\ left = Budget
    /\ answers = <<>>

\* The answer to one request, `key` the key as the app's read finds it
\* ("none", "sealed" or "plain"), `busy` whether the vault's admission
\* refuses its calls now, `late` whether its use waits for the principal's
\* lock past its deadline: a sealed key's with no fresh row of the cap's.
AnswerFresh(key, busy, late, full) ==
    \* PR B: the vault decides each request on Ada as she is.
    LET decided(standing) == IF ~granted THEN "forbidden" ELSE standing
        confirmed == ConfirmStandingOnLate /\ (ConfirmReserved \/ ~full)
        vault(standing) ==
            IF busy THEN "busy"
            ELSE IF late THEN (IF confirmed /\ ~granted THEN "forbidden" ELSE "busy")
            ELSE decided(standing)
    IN CASE key = "sealed" -> vault("value")
         [] key = "plain"  -> IF PlainByStanding
                                THEN IF StandingSharesAdmission THEN vault("value") ELSE decided("value")
                                ELSE "value"
         [] key = "none"   -> IF MissingByStanding
                                THEN IF StandingSharesAdmission THEN vault("missing") ELSE decided("missing")
                                ELSE "missing"

AnswerKept(key, busy, late) ==
    \* Before PR B: decided on the kept answer while there is one, which says
    \* she reads here; otherwise on the vault's answer now (`access`), which
    \* is never busy. A refusal on the kept answer confirms it: the vault's
    \* answer now differs (revoked), so the request starts over, asking.
    LET asked == IF ~granted THEN "forbidden"
                 ELSE CASE key = "sealed" -> IF busy \/ late THEN "busy" ELSE "value"
                        [] key = "plain"  -> "value"
                        [] key = "none"   -> "missing"
        onKept == CASE key = "sealed" -> IF busy \/ late
                                            THEN IF ConfirmOnBusy THEN asked ELSE "busy"
                                            ELSE IF granted THEN "value" ELSE asked
                    \* A plain value goes back once a read after it finds the policy unchanged (`fenced`):
                    \* her answer is confirmed as for any request no use vouched for.
                    [] key = "plain"  -> asked
                    [] key = "none"   -> asked
    IN IF kept THEN onKept ELSE asked

Answer(key, busy, late, full) == IF CallerFromUse THEN AnswerFresh(key, busy, late, full) ELSE AnswerKept(key, busy, late)

Revoke ==
    /\ granted
    /\ granted' = FALSE
    /\ UNCHANGED <<made, fresh, kept, left, answers>>

\* Run A only: someone makes API_KEY, after the revoke.
Make ==
    /\ ~granted
    /\ made = "none"
    /\ \E nature \in {"sealed", "plain"} : made' = nature
    /\ UNCHANGED <<granted, fresh, kept, left, answers>>

Request ==
    /\ left > 0
    /\ \E busy, contended, full \in BOOLEAN :
         \* Run A's key waits for the lock if sealed with no fresh row; run B's, never made, never does.
         \* `full`: no place free in admission once a use is late, but one its own call may hold.
         LET late == contended /\ made = "sealed" /\ ~fresh
             a == Answer(made, busy, late, full)
             b == Answer("none", busy, FALSE, full)
         IN /\ answers' = Append(answers, <<a, b>>)
            \* An answer the vault gave now is kept for the next request, as `accessFor` keeps it;
            \* the answer kept from before the revoke goes once a request asks the vault.
            /\ kept' = IF CallerFromUse THEN FALSE ELSE kept /\ granted
            \* A request for the sealed key admitted and not late writes its row of the cap's, refused or not.
            /\ fresh' = (fresh \/ (made = "sealed" /\ ~busy /\ ~late))
    /\ left' = left - 1
    /\ UNCHANGED <<granted, made>>

Done == left = 0 /\ UNCHANGED vars

Next == Revoke \/ Make \/ Request \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ granted \in BOOLEAN
    /\ made \in {"none", "sealed", "plain"}
    /\ fresh \in BOOLEAN
    /\ kept \in BOOLEAN
    /\ \A i \in 1..Len(answers) : answers[i][1] \in Answers /\ answers[i][2] \in Answers

\* Once her grant is revoked, what Ada is answered never tells a key made
\* since from one never made.
SameAnswer == \A i \in 1..Len(answers) : answers[i][1] = answers[i][2]

=============================================================================
