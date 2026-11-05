---------------------------- MODULE ShardsCredentials ----------------------------
(* Credentials through the shards (formal/Shards.md). A sign-in issues a
   credential: it writes the row to Postgres, without a fence and without
   raising the revision, then answers. A shard keeps a principal's standing,
   the credentials included, read at a revision; a use presents a
   credential the standing does not know (authentic: its MAC holds, so it
   was issued since), and the shard reads the standing again. Revoking a
   credential is a fenced change (Shards.tla): fence every shard, commit
   the revocation and the revision, answer. Fences are delayed, not lost:
   Shards.tla has the rest.

   Protections, each turned off by a constant to show TLC finds the race:
     CredentialRevokeFenced   a revocation is a fenced change (off: an
                              UPDATE that answers at once)
     UnknownCredentialRereads a shard reads the standing again for a
                              credential it does not know (off: refused) *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Shards, Creds, Revocable, Uses, MaxChanges
CONSTANTS CredentialRevokeFenced, UnknownCredentialRereads

VARIABLES
  cred,       \* Postgres: each credential, "none", "live" or "revoked"
  revision,   \* Postgres: the committed revision
  ch,         \* the changer: [st, c, rev, acks, n]
  pending,    \* the shards its fences have not reached yet
  floor,      \* each shard's floor
  standing,   \* each shard's kept standing: [has, cred, rev]
  issued,     \* the credentials whose sign-in answered: what clients hold
  revoked,    \* ghost: the credentials whose revocation answered
  use         \* each use: [st, c, s, after, rc, rr, allow]

vars == <<cred, revision, ch, pending, floor, standing, issued, revoked, use>>

Max(a, b) == IF a > b THEN a ELSE b
First == CHOOSE c \in Creds : TRUE
NoStanding == [has |-> FALSE, cred |-> [c \in Creds |-> "none"], rev |-> 0]
Blank == [st |-> "idle", c |-> First, s |-> CHOOSE s \in Shards : TRUE, after |-> {},
          rc |-> [c \in Creds |-> "none"], rr |-> 0, allow |-> FALSE]

Init ==
  /\ cred = [c \in Creds |-> IF c = First THEN "live" ELSE "none"]
  /\ revision = 0
  /\ ch = [st |-> "idle", c |-> First, rev |-> 0, n |-> 0]
  /\ pending = {}
  /\ floor = [s \in Shards |-> 0]
  /\ standing = [s \in Shards |-> NoStanding]
  /\ issued = {First}
  /\ revoked = {}
  /\ use = [u \in Uses |-> Blank]

\* A sign-in: the credential's row, then the answer. No fence.
Issue(c) ==
  /\ cred[c] = "none"
  /\ cred' = [cred EXCEPT ![c] = "live"]
  /\ issued' = issued \cup {c}
  /\ UNCHANGED <<revision, ch, pending, floor, standing, revoked, use>>

\* A revocation begins: the revision's row taken, every shard to fence.
\* Without CredentialRevokeFenced, an UPDATE that answers at once.
Begin(c) ==
  /\ ch.st = "idle" /\ ch.n < MaxChanges /\ c \in Revocable /\ cred[c] = "live"
  /\ IF CredentialRevokeFenced
     THEN /\ ch' = [st |-> "fencing", c |-> c, rev |-> revision + 1, n |-> ch.n + 1]
          /\ pending' = Shards
          /\ UNCHANGED <<cred, revoked>>
     ELSE /\ ch' = [ch EXCEPT !.n = @ + 1]
          /\ cred' = [cred EXCEPT ![c] = "revoked"]
          /\ revoked' = revoked \cup {c}
          /\ UNCHANGED pending
  /\ UNCHANGED <<revision, floor, standing, issued, use>>

Fence(s) ==
  /\ s \in pending
  /\ floor' = [floor EXCEPT ![s] = Max(@, ch.rev)]
  /\ pending' = pending \ {s}
  /\ UNCHANGED <<cred, revision, ch, standing, issued, revoked, use>>

\* Every shard fenced: the revocation and the revision commit, then it answers.
Commit ==
  /\ ch.st = "fencing" /\ pending = {}
  /\ cred' = [cred EXCEPT ![ch.c] = "revoked"]
  /\ revision' = ch.rev
  /\ ch' = [ch EXCEPT !.st = "committed"]
  /\ UNCHANGED <<pending, floor, standing, issued, revoked, use>>

Answer ==
  /\ ch.st = "committed"
  /\ ch' = [ch EXCEPT !.st = "idle"]
  /\ revoked' = revoked \cup {ch.c}
  /\ UNCHANGED <<cred, revision, pending, floor, standing, issued, use>>

\* A client presents a credential it holds, at any shard.
Invoke(u, c, s) ==
  /\ use[u].st = "idle" /\ c \in issued
  /\ use' = [use EXCEPT ![u] = [Blank EXCEPT !.st = "new", !.c = c, !.s = s, !.after = revoked]]
  /\ UNCHANGED <<cred, revision, ch, pending, floor, standing, issued, revoked>>

Reply(u, allow) == [use[u] EXCEPT !.st = "replied", !.allow = allow]

\* From the standing kept, read at the floor or later: the credential live,
\* allowed; revoked, refused; unknown, read again (UnknownCredentialRereads)
\* or refused. Else read again.
Serve(u) ==
  LET s == use[u].s
      sd == standing[s]
      known == sd.cred[use[u].c]
  IN
  /\ use[u].st = "new"
  /\ IF sd.has /\ sd.rev >= floor[s] /\ (known # "none" \/ ~UnknownCredentialRereads)
     THEN use' = [use EXCEPT ![u] = Reply(u, known = "live")]
     ELSE use' = [use EXCEPT ![u] = [@ EXCEPT !.st = "loaded", !.rc = cred, !.rr = revision]]
  /\ UNCHANGED <<cred, revision, ch, pending, floor, standing, issued, revoked>>

\* The read is back: at the floor or later, kept and decided on; else 503.
Check(u) ==
  LET s == use[u].s IN
  /\ use[u].st = "loaded"
  /\ IF use[u].rr >= floor[s]
     THEN /\ standing' = [standing EXCEPT ![s] = [has |-> TRUE, cred |-> use[u].rc, rev |-> use[u].rr]]
          /\ use' = [use EXCEPT ![u] = Reply(u, use[u].rc[use[u].c] = "live")]
     ELSE /\ use' = [use EXCEPT ![u].st = "new"]
          /\ UNCHANGED standing
  /\ UNCHANGED <<cred, revision, ch, pending, floor, issued, revoked>>

UseStep(u) == Serve(u) \/ Check(u)

Next ==
  \/ \E c \in Creds : Issue(c) \/ Begin(c)
  \/ \E s \in Shards : Fence(s)
  \/ Commit \/ Answer
  \/ \E u \in Uses, c \in Creds, s \in Shards : Invoke(u, c, s)
  \/ \E u \in Uses : UseStep(u)

Spec == Init /\ [][Next]_vars

LiveSpec ==
  /\ Spec
  /\ \A u \in Uses : WF_vars(UseStep(u))
  /\ \A s \in Shards : WF_vars(Fence(s))
  /\ WF_vars(Commit \/ Answer)

-----------------------------------------------------------------------------

\* No use with a credential whose revocation was answered before it arrived
\* is allowed.
NoUseAfterCredentialRevoked ==
  \A u \in Uses : use[u].st = "replied" /\ use[u].allow => use[u].c \notin use[u].after

\* A credential just issued, and never revoked, is usable at any shard: its
\* use is allowed.
IssuedUsable ==
  \A u \in Uses : (use[u].st = "new" /\ use[u].c \notin Revocable) ~> (use[u].st = "replied" /\ use[u].allow)
=============================================================================
