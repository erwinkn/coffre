------------------------------ MODULE MCWorkload ------------------------------
(***************************************************************************)
(* The scenarios TLC checks of Workload.tla, as MC.tla's of Coffre.tla.    *)
(***************************************************************************)
EXTENDS Workload

Req(kind, s, key, path) == [NoOp EXCEPT !.kind = kind, !.s = s, !.key = key, !.path = path, !.body = "b1"]
Act(kind, target) == [NoOp EXCEPT !.kind = kind, !.target = target, !.s = target]

-----------------------------------------------------------------------------
(* Replay: A sends two requests and B one, while eve replays, tampers with,
   forges and swaps what it reads, and A's gate restarts or rotates. *)

ReplayProcs == {"a", "b", "eve", "gate"}
ReplayOps == [p \in ReplayProcs |->
    CASE p = "a"    -> {Req("use", "sA", "kA", "charges")}
      [] p = "b"    -> {Req("use", "sB", "kB", "charges")}
      [] p = "eve"  -> {Act(k, None) : k \in {"replay", "tamper", "forge", "swap"}}
      [] p = "gate" -> {Act("restart", "A"), Act("rotate", "A")}]
ReplayBudget == [p \in ReplayProcs |-> IF p = "b" THEN 1 ELSE 2]

-----------------------------------------------------------------------------
(* Ending: A uses its session and renews it, and holds a tunnel open, while
   Omar freezes any target over it, revokes it, untrusts its binding or
   removes the service, and the clock runs to its not_after. *)

EndingProcs == {"a", "tun", "omar"}
EndingOps == [p \in EndingProcs |->
    CASE p = "a"    -> {Req("use", "sA", "kA", "charges"), Req("renew", "sA", "kA", None)}
      [] p = "tun"  -> {Act("open", "sA"), Act("byte", None), Act("recheck", None)}
      [] p = "omar" -> {Act("freeze", t) : t \in {"instance", "token:A", "binding:A", "session:sA", "credential"}}
                         \cup {Act("revoke", "sA"), Act("unbind", "A"), Act("remove", "A")}]
EndingBudget == [p \in EndingProcs |-> CASE p = "a" -> 2 [] p = "tun" -> 3 [] p = "omar" -> 1]

-----------------------------------------------------------------------------
(* Freezing: A uses its session and reads through it, while Omar freezes
   it, its instance or its credential and Olga lifts either, in any order. *)

FreezingProcs == {"a", "omar", "olga"}
FreezingTargets == {"instance", "session:sA", "credential"}
FreezingOps == [p \in FreezingProcs |->
    CASE p = "a"    -> {Req("use", "sA", "kA", "charges"), Req("read", "sA", "kA", None)}
      [] p = "omar" -> {Act("freeze", t) : t \in FreezingTargets}
      [] p = "olga" -> {Act("unfreeze", t) : t \in FreezingTargets}]
FreezingBudget == [p \in FreezingProcs |-> IF p = "a" THEN 3 ELSE 1]

-----------------------------------------------------------------------------
(* Narrowing: A narrows its session to refunds for an agent, which uses
   every path, reads and renews, while Omar revokes or freezes the parent. *)

NarrowProcs == {"a", "agent", "omar"}
NarrowOps == [p \in NarrowProcs |->
    CASE p = "a"     -> {[Act("narrow", "sA") EXCEPT !.path = "refunds"]}
      [] p = "agent" -> {Req("use", "c", "kC", path) : path \in Paths} \cup {Req("read", "c", "kC", None), Req("renew", "c", "kC", None)}
      [] p = "omar"  -> {Act("revoke", "sA"), Act("freeze", "session:sA")}]
NarrowBudget == [p \in NarrowProcs |-> IF p = "agent" THEN 2 ELSE 1]

=============================================================================
