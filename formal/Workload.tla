------------------------------- MODULE Workload -------------------------------
(***************************************************************************)
(* Workload sessions (docs/design/workload-access.md, sections 5 and 8):   *)
(* every request signed by the session's key with a DPoP proof, single use *)
(* through the workload's gate, checked live by one statement, and the     *)
(* children `narrow` makes. docs/formal.md says what this covers, what it  *)
(* abstracts and what it does not prove.                                   *)
(*                                                                         *)
(* Coffre decides a request in one step: the statement of 5.3 (the row,   *)
(* its member's generation, its binding, its ancestors and the freezes),   *)
(* the proof and the gate's admit, which is one call to one object.        *)
(* Nothing that ends a session waits for a request, so a request decided   *)
(* before an end commits is one decided before it: what the invariants     *)
(* hold is the decision.                                                   *)
(*                                                                         *)
(* Two workloads, "A" and "B", each a service account with one binding and *)
(* one session, "sA" and "sB", bound to its key, "kA" or "kB". "c" is the  *)
(* child `narrow` makes of "sA", bound to the key "kC" its recipient made. *)
(* The attacker, "eve", learns every token and every request that crosses  *)
(* a channel, and holds a key of its own, "x", but no workload's.          *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Procs,          \* concurrent clients and operators, each one a process
    Ops,            \* Ops[p]: the operations process p may run
    Budget,         \* Budget[p]: how many it runs, one after another
    MaxTime,        \* how far the clock runs
    HardEnd,        \* the roots' `not_after`
    Life,           \* how far a renewal moves `expires_at`, and a child's life
    CacheTicks,     \* how long the proxy keeps a session's vault decision
    Recheck         \* how long an open tunnel runs on its last good check

(***************************************************************************)
(* The protections the design has, each a switch, as in Coffre.tla.        *)
(***************************************************************************)
CONSTANTS
    \* The proof's key is the row's: thumbprint(jwk) = row.jkt (verifyProof,
    \* step 5). Off, any valid signature over the token passes.
    KeyCheckedAgainstRow,
    \* `req` is recomputed from what arrived (5.1): method, path, query,
    \* the headers `hdr` names and the body.
    RequestDigestChecked,
    \* Only the headers `hdr` names are forwarded upstream; one added on the
    \* way is dropped.
    OnlySignedHeadersForwarded,
    \* The gate's nonces are epochs (5.2): a proof must carry the current or
    \* the previous one, and its `jti` is remembered under it. Off, the gate
    \* remembers `jti`s alone, in memory a restart loses.
    NonceEpochs,
    \* Every request runs the statement before the proxy's value cache is
    \* consulted (5.3). Off, a session with a warm cache is not asked again.
    LiveCheckBeforeCache,
    \* A tunnel's recheck runs the same statement, freezes included (8.2).
    TunnelRecheckSeesFreezes,
    \* The statement compares the row's generation with its member's in
    \* vault_members, so a removal counts before the app's sweep revokes.
    GenerationInStatement,
    \* The statement checks each ancestor as it checks the row (8.4).
    AncestorsChecked,
    \* A child's paths are matched on the resolved upstream URL, after dot
    \* segments, never the path as received (`constraintsAllow`, 8.4).
    TargetResolvedBeforeConstraints,
    \* A child's request is refused if its path holds an encoded `.`, `/` or
    \* `\`, a `%25` or a `;`, so the upstream cannot read a segment
    \* otherwise (8.4). With the resolved match, each covers for the other
    \* on an encoded dot segment; only this one on `..;`.
    EncodedSegmentsRefused,
    \* A child reaches only `/use`, narrow and logout: no read, no renewal
    \* (WORKLOAD_ROUTES, 6.1).
    ChildOpsRefused,
    \* A renewal never moves `expires_at` past `not_after` (5.4).
    RenewCappedAtNotAfter

None == "none"
Workloads == {"A", "B"}
Sessions == {"sA", "sB", "c"}
\* The upstream paths a request may name, as sent. "dotdot" is
\* /v1/refunds/%2e%2e/charges, which starts with the refunds prefix as
\* received, and which the WHATWG parser resolves to /v1/charges. "semi" is
\* /v1/refunds/..;/charges, which the parser leaves under /v1/refunds, and
\* an upstream such as Tomcat reads as /v1/charges.
Targets == {"refunds", "charges"}
Paths == {"refunds", "charges", "dotdot", "semi"}
Bodies == {"b1", "b2"}

\* The path as Coffre resolves it, and as the upstream acts on it.
Resolved(path) == CASE path = "dotdot" -> "charges" [] path = "semi" -> "refunds" [] OTHER -> path
Upstream(path) == IF path \in {"dotdot", "semi"} THEN "charges" ELSE path
Encoded(path) == path \in {"dotdot", "semi"}
\* constraintsAllow on the path as received, by its prefix.
AsReceived(path, allowed) == path \in allowed \/ (Encoded(path) /\ "refunds" \in allowed)
PathAllowed(path, allowed) ==
    /\ ~(EncodedSegmentsRefused /\ Encoded(path))
    /\ IF TargetResolvedBeforeConstraints THEN Resolved(path) \in allowed ELSE AsReceived(path, allowed)

Min(a, b) == IF a < b THEN a ELSE b

VARIABLES
    now,            \* the database's clock
    sessions,       \* sessions[s]: the credentials row
    status,         \* status[w]: the member's status in vault_members
    gen,            \* gen[w]: its generation
    unbound,        \* unbound[w]: its binding is untrusted
    log,            \* the audit log, in seq order: its ends and freezes
    gate,           \* gate[w]: [cur, prev, seen], the workload's gate
    epochs,         \* the next epoch a gate draws
    seen,           \* every request that crossed a channel, which eve holds
    cache,          \* cache[s]: until when the proxy holds s's vault decision
    tunnel,         \* the open tunnel: [open, s, ok], its last good check
    pc, op, l, left,
    accepted        \* history: a record per request Coffre accepted, and per tunnel byte

rows == <<sessions, status, gen, unbound>>
procs == <<pc, op, l, left>>
vars == <<now, rows, log, gate, epochs, seen, cache, tunnel, procs, accepted>>

-----------------------------------------------------------------------------
(* Sessions and what is true of them *)

\* The ancestors a row names (`ancestors`): here a child's root.
Ancestors(s) == IF sessions[s].parent = None THEN {} ELSE {sessions[s].parent}
Line(s) == {s} \cup Ancestors(s)

\* The freeze targets a use under s falls under (`freezeTarget`): the
\* instance, the service, its one binding, the session, and the one
\* upstream credential, which a read and a renewal do not use.
FreezeTargets(s, kind) ==
    {"instance", "token:" \o sessions[s].principal, "binding:" \o sessions[s].principal, "session:" \o s}
      \cup (IF kind = "use" THEN {"credential"} ELSE {})

\* A target is frozen when its newest `workload.freeze` or
\* `workload.unfreeze` entry is a freeze (8.2): that entry's index, or 0.
Newest(t) == LET is == {i \in 1..Len(log) : log[i].kind \in {"workload.freeze", "workload.unfreeze"} /\ log[i].target = t}
             IN IF is = {} THEN 0 ELSE CHOOSE i \in is : \A j \in is : j <= i
Frozen(targets) == \E t \in targets : Newest(t) > 0 /\ log[Newest(t)].kind = "workload.freeze"

\* Whether entry e ends session s: its `token.revoke`, its binding's
\* `token.unbind`, or a removal past its generation.
Ends(e, s) ==
    \/ e.kind = "token.revoke" /\ e.s = s
    \/ e.kind = "token.unbind" /\ e.w = sessions[s].principal
    \/ e.kind = "member.remove" /\ e.w = sessions[s].principal /\ e.gen > sessions[s].gen

\* Ended, or frozen, by an entry at least `by` ticks old.
EndedBy(s, by) == \E i \in 1..Len(log) : Ends(log[i], s) /\ log[i].time + by <= now
FrozenBy(targets, by) ==
    \E t \in targets : Newest(t) > 0 /\ log[Newest(t)].kind = "workload.freeze" /\ log[Newest(t)].time + by <= now

\* What the statement finds of one row, freezes aside (5.3).
RowStands(s) ==
    LET r == sessions[s] IN
    /\ r.made /\ ~r.revoked
    /\ r.expires > now /\ r.notAfter > now
    /\ ~unbound[r.principal]
    /\ GenerationInStatement => status[r.principal] = "active" /\ gen[r.principal] = r.gen

\* The statement: the row, its ancestors, and the freezes over all of them
\* (`freezes` FALSE for a renewal, which uses nothing; docs/formal.md).
Checked(s) == IF AncestorsChecked THEN Line(s) ELSE {s}
Admits(s, kind, freezes) ==
    /\ \A x \in Checked(s) : RowStands(x)
    /\ freezes => ~Frozen(UNION {FreezeTargets(x, kind) : x \in Checked(s)})

\* What is true of s at this state, for the invariants: its line unended by
\* any entry, unexpired, and for a use unfrozen.
TrulyLive(s) == \A x \in Line(s) : sessions[x].expires > now /\ sessions[x].notAfter > now /\ ~EndedBy(x, 0)

Renewed(r) == IF RenewCappedAtNotAfter THEN Min(now + Life, r.notAfter) ELSE now + Life

-----------------------------------------------------------------------------
(* Processes *)

NoOp == [kind |-> "none", s |-> None, key |-> None, path |-> None, body |-> None, target |-> None]
NoMsg == [id |-> <<None, 0>>, token |-> None, kind |-> None, path |-> None, body |-> None, extra |-> FALSE,
          proof |-> [key |-> None, token |-> None, jti |-> <<None, 0>>, nonce |-> 0, kind |-> None, path |-> None, body |-> None]]
L0 == [id |-> <<None, 0>>, msg |-> NoMsg]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

FirstLabel(kind) ==
    CASE kind \in {"use", "read", "renew"} -> "req.sign"
      [] kind \in {"replay", "tamper", "forge", "swap"} -> "eve.send"
      [] kind = "narrow"   -> "narrow"
      [] kind = "open"     -> "tunnel.open"
      [] kind = "byte"     -> "tunnel.byte"
      [] kind = "recheck"  -> "tunnel.recheck"
      [] kind = "freeze"   -> "freeze"
      [] kind = "unfreeze" -> "unfreeze"
      [] kind = "revoke"   -> "revoke"
      [] kind = "unbind"   -> "unbind"
      [] kind = "remove"   -> "remove.vault"
      [] kind = "restart"  -> "gate.restart"
      [] kind = "rotate"   -> "gate.rotate"

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ l' = [l EXCEPT ![p] = [L0 EXCEPT !.id = <<p, left[p]>>]]
         /\ Goto(p, FirstLabel(o.kind))
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<now, rows, log, gate, epochs, seen, cache, tunnel, accepted>>

Done(p) ==
    /\ Goto(p, "idle")
    /\ UNCHANGED <<op, l, left>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* A request: the client signs it with the gate's newest nonce and sends   *)
(* it, then Coffre decides it. Whoever sees the channel holds a copy.      *)
(***************************************************************************)

ReqSign(p) ==
    /\ pc[p] = "req.sign"
    /\ LET o == op[p]
           proof == [key |-> o.key, token |-> o.s, jti |-> l[p].id, nonce |-> gate[sessions[o.s].principal].cur,
                     kind |-> o.kind, path |-> o.path, body |-> o.body]
           m == [id |-> l[p].id, token |-> o.s, kind |-> o.kind, path |-> o.path, body |-> o.body,
                 extra |-> FALSE, proof |-> proof]
       IN /\ seen' = seen \cup {m}
          /\ l' = [l EXCEPT ![p].msg = m]
    /\ Goto(p, "req.serve")
    /\ UNCHANGED <<now, rows, log, gate, epochs, cache, tunnel, op, left, accepted>>

\* Coffre decides request m (5.1, 5.3, 5.2): the statement, unless the
\* cache answers first; the proof's token, key and digest; a child's
\* constraints; then the gate. Accepted, a renewal moves the row's expiry.
Serve(m) ==
    LET s == m.token
        r == sessions[s]
        w == r.principal
        g == gate[w]
        cached == ~LiveCheckBeforeCache /\ m.kind = "use" /\ cache[s] > now
        live == cached \/ Admits(s, m.kind, m.kind # "renew")
        keyOk == m.proof.token = s /\ (KeyCheckedAgainstRow => m.proof.key = r.key)
        signed == [kind |-> m.proof.kind, path |-> m.proof.path, body |-> m.proof.body, extra |-> FALSE]
        sent == [kind |-> m.kind, path |-> m.path, body |-> m.body, extra |-> m.extra]
        forwarded == [sent EXCEPT !.extra = m.extra /\ ~OnlySignedHeadersForwarded]
        digestOk == RequestDigestChecked => sent.kind = signed.kind /\ sent.path = signed.path /\ sent.body = signed.body
        rightOk == r.parent # None =>
                     ((ChildOpsRefused => m.kind = "use") /\ (m.kind = "use" => PathAllowed(m.path, r.constraints)))
        fresh == IF NonceEpochs
                   THEN m.proof.nonce \in {g.cur, g.prev} /\ <<m.proof.nonce, m.proof.jti>> \notin g.seen
                   ELSE \A e \in g.seen : e[2] # m.proof.jti
        record == [id |-> m.id, s |-> s, kind |-> m.kind, signer |-> m.proof.key, jti |-> m.proof.jti,
                   holder |-> m.proof.key = r.key,
                   faithful |-> forwarded = signed,
                   frozen |-> m.kind # "renew" /\ Frozen(UNION {FreezeTargets(x, m.kind) : x \in Line(s)}),
                   ended |-> ~TrulyLive(s),
                   subset |-> r.parent = None \/
                                (/\ m.kind = "use"
                                 /\ Upstream(m.path) \in r.constraints
                                 /\ \A a \in Ancestors(s) : Upstream(m.path) \in sessions[a].constraints /\ TrulyLive(a)
                                 /\ ~Frozen(UNION {FreezeTargets(a, "use") : a \in Ancestors(s)})),
                   late |-> now >= r.notAfter]
    IN IF r.made /\ live /\ keyOk /\ digestOk /\ rightOk /\ fresh
         THEN /\ gate' = [gate EXCEPT ![w].seen = @ \cup {<<m.proof.nonce, m.proof.jti>>}]
              /\ accepted' = accepted \cup {record}
              /\ cache' = IF m.kind = "use" THEN [cache EXCEPT ![s] = now + CacheTicks] ELSE cache
              /\ sessions' = IF m.kind = "renew" THEN [sessions EXCEPT ![s].expires = Renewed(r)] ELSE sessions
         ELSE UNCHANGED <<gate, accepted, cache, sessions>>

ReqServe(p) ==
    /\ pc[p] = "req.serve"
    /\ Serve(l[p].msg)
    /\ Done(p)
    /\ UNCHANGED <<now, status, gen, unbound, log, epochs, seen, tunnel>>

\* Eve sends what it holds: a copy as it was, one with another body or a
\* header added on the way, a proof of its own key over a token it read,
\* or a proof under another session's token. Coffre decides it at once;
\* the original may still be on its way.
EveSend(p) ==
    /\ pc[p] = "eve.send"
    /\ \E m \in seen, t \in Sessions, b \in Bodies, x \in BOOLEAN :
         LET copy == [m EXCEPT !.id = l[p].id]
             own == [id |-> l[p].id, token |-> t, kind |-> "use", path |-> "charges", body |-> b, extra |-> FALSE,
                     proof |-> [key |-> "x", token |-> t, jti |-> l[p].id, nonce |-> gate[sessions[t].principal].cur,
                                kind |-> "use", path |-> "charges", body |-> b]]
             sent == CASE op[p].kind = "replay" -> copy
                       [] op[p].kind = "tamper" -> [copy EXCEPT !.body = b, !.extra = x]
                       [] op[p].kind = "forge"  -> own
                       [] op[p].kind = "swap"   -> [copy EXCEPT !.token = t]
         IN /\ op[p].kind = "tamper" => (b # m.body \/ x)
            /\ op[p].kind = "swap" => t # m.token
            /\ op[p].kind = "forge" => sessions[t].made
            /\ Serve(sent)
    /\ Done(p)
    /\ UNCHANGED <<now, status, gen, unbound, log, epochs, seen, tunnel>>

\* Or it holds back.
EveHold(p) ==
    /\ pc[p] = "eve.send"
    /\ Done(p)
    /\ UNCHANGED <<now, rows, log, gate, epochs, seen, cache, tunnel, accepted>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* The gate (5.2): a restart, or an eviction, draws a new epoch and        *)
(* forgets every `jti`; a rotation keeps the previous epoch's.             *)
(***************************************************************************)

GateRestart(p) ==
    /\ pc[p] = "gate.restart"
    /\ gate' = [gate EXCEPT ![op[p].target] = [cur |-> epochs, prev |-> 0, seen |-> {}]]
    /\ epochs' = epochs + 1
    /\ Done(p)
    /\ UNCHANGED <<now, rows, log, seen, cache, tunnel, accepted>>

GateRotate(p) ==
    /\ pc[p] = "gate.rotate"
    /\ LET g == gate[op[p].target] IN
       gate' = [gate EXCEPT ![op[p].target] =
                  [cur |-> epochs, prev |-> g.cur,
                   seen |-> IF NonceEpochs THEN {e \in g.seen : e[1] = g.cur} ELSE g.seen]]
    /\ epochs' = epochs + 1
    /\ Done(p)
    /\ UNCHANGED <<now, rows, log, seen, cache, tunnel, accepted>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* narrow (8.4): under the parent's own statement, a child row bound to    *)
(* the recipient's key, its constraints the intersection with the          *)
(* parent's, its `not_after` at most the parent's.                         *)
(***************************************************************************)

Narrow(p) ==
    /\ pc[p] = "narrow"
    /\ LET parent == sessions[op[p].s] IN
       IF ~sessions["c"].made /\ Admits(op[p].s, "narrow", TRUE)
         THEN sessions' = [sessions EXCEPT !["c"] =
                [made |-> TRUE, principal |-> parent.principal, key |-> "kC", parent |-> op[p].s,
                 constraints |-> {op[p].path} \cap parent.constraints,
                 notAfter |-> Min(now + Life, parent.notAfter), expires |-> Min(now + Life, parent.notAfter),
                 revoked |-> FALSE, gen |-> parent.gen]]
         ELSE UNCHANGED sessions
    /\ Done(p)
    /\ UNCHANGED <<now, status, gen, unbound, log, gate, epochs, seen, cache, tunnel, accepted>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* The Postgres tunnel (7.1): opened under the statement, it carries bytes *)
(* while its last good check is under `Recheck` old (the deadline counts   *)
(* as no, as #296's Tunnel.tla has it), and rechecks run the statement     *)
(* without the proof.                                                      *)
(***************************************************************************)

TunnelOpen(p) ==
    /\ pc[p] = "tunnel.open"
    /\ tunnel' = IF ~tunnel.open /\ Admits(op[p].s, "use", TRUE)
                   THEN [open |-> TRUE, s |-> op[p].s, ok |-> now] ELSE tunnel
    /\ Done(p)
    /\ UNCHANGED <<now, rows, log, gate, epochs, seen, cache, accepted>>

TunnelByte(p) ==
    /\ pc[p] = "tunnel.byte"
    /\ LET s == tunnel.s IN
       IF tunnel.open /\ now < tunnel.ok + Recheck
         THEN accepted' = accepted \cup
                {[id |-> l[p].id, s |-> s, kind |-> "byte", signer |-> None, jti |-> l[p].id,
                  holder |-> TRUE, faithful |-> TRUE,
                  frozen |-> FrozenBy(UNION {FreezeTargets(x, "use") : x \in Line(s)}, Recheck),
                  ended |-> \E x \in Line(s) : EndedBy(x, Recheck),
                  subset |-> TRUE, late |-> now >= sessions[s].notAfter + Recheck]}
         ELSE UNCHANGED accepted
    /\ Done(p)
    /\ UNCHANGED <<now, rows, log, gate, epochs, seen, cache, tunnel>>

TunnelRecheck(p) ==
    /\ pc[p] = "tunnel.recheck"
    /\ tunnel' = IF ~tunnel.open THEN tunnel
                 ELSE IF Admits(tunnel.s, "use", TunnelRecheckSeesFreezes)
                   THEN [tunnel EXCEPT !.ok = now]
                   ELSE [tunnel EXCEPT !.open = FALSE]
    /\ Done(p)
    /\ UNCHANGED <<now, rows, log, gate, epochs, seen, cache, accepted>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* What ends a session or stops its uses, each one transaction under the   *)
(* head, which commits its entry with its rows.                            *)
(***************************************************************************)

Entry(kind, p) == [kind |-> kind, id |-> l[p].id, target |-> None, s |-> None, w |-> None, gen |-> 0, time |-> now]

\* A freeze (8.2): the `workload.freeze` entry is the state.
Freeze(p) ==
    /\ pc[p] = "freeze"
    /\ log' = Append(log, [Entry("workload.freeze", p) EXCEPT !.target = op[p].target])
    /\ Done(p)
    /\ UNCHANGED <<now, rows, gate, epochs, seen, cache, tunnel, accepted>>

\* Lifting one: `workload.unfreeze`.
Unfreeze(p) ==
    /\ pc[p] = "unfreeze"
    /\ log' = Append(log, [Entry("workload.unfreeze", p) EXCEPT !.target = op[p].target])
    /\ Done(p)
    /\ UNCHANGED <<now, rows, gate, epochs, seen, cache, tunnel, accepted>>

\* Revoking a session, as logout or `token.revoke` does.
Revoke(p) ==
    /\ pc[p] = "revoke"
    /\ sessions' = [sessions EXCEPT ![op[p].s].revoked = TRUE]
    /\ log' = Append(log, [Entry("token.revoke", p) EXCEPT !.s = op[p].s])
    /\ Done(p)
    /\ UNCHANGED <<now, status, gen, unbound, gate, epochs, seen, cache, tunnel, accepted>>

\* Untrusting the workload's binding revokes what it issued (#revoke).
Unbind(p) ==
    /\ pc[p] = "unbind"
    /\ unbound' = [unbound EXCEPT ![op[p].target] = TRUE]
    /\ sessions' = [s \in Sessions |-> IF sessions[s].principal = op[p].target
                                        THEN [sessions[s] EXCEPT !.revoked = TRUE] ELSE sessions[s]]
    /\ log' = Append(log, [Entry("token.unbind", p) EXCEPT !.w = op[p].target])
    /\ Done(p)
    /\ UNCHANGED <<now, status, gen, gate, epochs, seen, cache, tunnel, accepted>>

\* Removing the member: the vault moves its generation on and logs
\* `member.remove`; then the app, in a transaction of its own, revokes its
\* rows below that generation (removeMember), as Credentials.tla has it.
RemoveVault(p) ==
    /\ pc[p] = "remove.vault"
    /\ LET w == op[p].target IN
       /\ status' = [status EXCEPT ![w] = "removed"]
       /\ gen' = [gen EXCEPT ![w] = @ + 1]
       /\ log' = Append(log, [Entry("member.remove", p) EXCEPT !.w = w, !.gen = gen[w] + 1])
    /\ Goto(p, "remove.sweep")
    /\ UNCHANGED <<now, sessions, unbound, gate, epochs, seen, cache, tunnel, op, l, left, accepted>>

RemoveSweep(p) ==
    /\ pc[p] = "remove.sweep"
    /\ sessions' = [s \in Sessions |-> IF sessions[s].principal = op[p].target /\ sessions[s].gen < gen[op[p].target]
                                        THEN [sessions[s] EXCEPT !.revoked = TRUE] ELSE sessions[s]]
    /\ Done(p)
    /\ UNCHANGED <<now, status, gen, unbound, log, gate, epochs, seen, cache, tunnel, accepted>>

-----------------------------------------------------------------------------

\* The clock runs, whatever the processes do.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<rows, log, gate, epochs, seen, cache, tunnel, procs, accepted>>

Root(w, key) == [made |-> TRUE, principal |-> w, key |-> key, parent |-> None, constraints |-> Targets,
                 notAfter |-> HardEnd, expires |-> Min(Life, HardEnd), revoked |-> FALSE, gen |-> 0]

Init ==
    /\ now = 0
    /\ sessions = [s \in Sessions |->
                     CASE s = "sA" -> Root("A", "kA")
                       [] s = "sB" -> Root("B", "kB")
                       [] s = "c"  -> [Root("A", "kC") EXCEPT !.made = FALSE, !.parent = "sA"]]
    /\ status = [w \in Workloads |-> "active"]
    /\ gen = [w \in Workloads |-> 0]
    /\ unbound = [w \in Workloads |-> FALSE]
    /\ log = <<>>
    /\ gate = [w \in Workloads |-> [cur |-> IF w = "A" THEN 1 ELSE 2, prev |-> 0, seen |-> {}]]
    /\ epochs = 3
    /\ seen = {}
    /\ cache = [s \in Sessions |-> 0]
    /\ tunnel = [open |-> FALSE, s |-> "sA", ok |-> 0]
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> L0]
    /\ left = Budget
    /\ accepted = {}

Step(p) ==
    \/ Begin(p)
    \/ ReqSign(p) \/ ReqServe(p) \/ EveSend(p) \/ EveHold(p)
    \/ GateRestart(p) \/ GateRotate(p)
    \/ Narrow(p)
    \/ TunnelOpen(p) \/ TunnelByte(p) \/ TunnelRecheck(p)
    \/ Freeze(p) \/ Unfreeze(p) \/ Revoke(p) \/ Unbind(p) \/ RemoveVault(p) \/ RemoveSweep(p)

Finished == \A p \in Procs : pc[p] = "idle" /\ left[p] = 0

Next == (\E p \in Procs : Step(p)) \/ Tick \/ (Finished /\ now = MaxTime /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* What must hold in every state (section 12.1).                           *)
(***************************************************************************)

TypeOK ==
    /\ now \in 0..MaxTime
    /\ \A w \in Workloads : status[w] \in {"active", "removed"}
    /\ tunnel.open \in BOOLEAN

\* Every accepted request was signed by the holder of its session's key.
CopyIsUseless == \A a \in accepted : a.holder

\* What Coffre forwards upstream (method, URL, query, headers, body) is
\* what the key signed.
ForwardedIsSigned == \A a \in accepted : a.faithful

\* No (jkt, jti) is accepted twice, across gate restarts.
ProofOnce ==
    \A a, b \in accepted : a.id # b.id => <<a.signer, a.jti>> # <<b.signer, b.jti>>

\* No use is accepted once a freeze of its target has committed, and no
\* tunnel byte flows `Recheck` after it.
FreezeBound == \A a \in accepted : a.kind # "renew" => ~a.frozen

\* The same for revoking a session or an ancestor, untrusting its binding
\* and removing its member; a renewal included.
RevokeBound == \A a \in accepted : ~a.ended

\* A child's accepted requests are uses its constraints and every
\* ancestor's allow, on the path sent upstream, while every ancestor lives.
NarrowSubset == \A a \in accepted : a.subset

\* No session is usable, or renewed, past `not_after`.
NotAfter ==
    /\ \A a \in accepted : ~a.late
    /\ \A s \in Sessions : sessions[s].made => sessions[s].expires <= sessions[s].notAfter

=============================================================================
