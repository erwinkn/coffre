----------------------------- MODULE MCUnbinding -----------------------------
(***************************************************************************)
(* The scenarios TLC checks of Unbinding.tla.                              *)
(***************************************************************************)
EXTENDS Unbinding

\* One run signing in again and again, two credentials live at most, a batch of one: the removal sweeps, and ends.
OneRun == {"s1"}
TwoCreds == {"c1", "c2"}

\* Two runs signing in at once, sharing the row, while it closes: safety alone (two runs that always overlap could hold
\* the row's lock from the removal forever; one run leaves it free between its sign-ins).
TwoRuns == {"s1", "s2"}
=============================================================================
