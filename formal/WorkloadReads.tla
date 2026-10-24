---------------------------- MODULE WorkloadReads ----------------------------
(***************************************************************************)
(* What a workload session reads (docs/design/workload-access.md, 6.1): a  *)
(* value only if its binding's `reads` lists the key, by ID, at the place  *)
(* where the value is held, whatever the workload or anyone renames,       *)
(* references or copies. docs/formal.md says what this covers, what it     *)
(* abstracts and what it does not prove.                                   *)
(*                                                                         *)
(* No step here races another: each is one vault decision, which reads its *)
(* rows under its locks (Coffre.tla). What TLC explores is every sequence  *)
(* of renames, references, copies, deletions and reads.                    *)
(*                                                                         *)
(* `market/prod` holds STRIPE_SECRET_KEY, "S", the key "k1", and           *)
(* STRIPE_WEBHOOK_SECRET, "W", "k2". `market/dev` is a fork of it and      *)
(* inherits "S". The binding's `reads` lists "k2" in prod, and "*" in dev. *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Procs,          \* the workload and the people, each one a process
    Ops,            \* Ops[p]: the operations process p may run
    Budget          \* Budget[p]: how many it runs, one after another

CONSTANTS
    \* The vault checks `reads` at the place where the value is held: a
    \* reference's source, a fork's parent for an inherited key. Off, at the
    \* place the request names.
    CheckWhereHeld,
    \* `reads` holds environment and key IDs. Off, key names.
    ReadsByID,
    \* A workload may not make a reference or a copy whose source it may not
    \* read (6.1, no laundering).
    RefusesUnreadableSources

None == "none"
Envs == {"prod", "dev"}
Ids == {"k1", "k2", "k3", "k4", "k5"}
Names == {"S", "W", "X"}

\* The binding's `reads`: by ID, as stored, and by name, as shown; `all`
\* is "*".
Reads == [e \in Envs |-> IF e = "dev" THEN [all |-> TRUE, keys |-> {}] ELSE [all |-> FALSE, keys |-> {"k2"}]]
ReadsByName == [e \in Envs |-> IF e = "dev" THEN [all |-> TRUE, keys |-> {}] ELSE [all |-> FALSE, keys |-> {"W"}]]

VARIABLES
    keys,           \* keys[id]: [made, gone, env, name, ref, laundered]; a gone ID is never reused
    pc, op, l, left,  \* l is unused, kept for scripts/formal-trace.mjs
    read            \* history: what each read the vault allowed handed back

procs == <<pc, op, l, left>>
vars == <<keys, procs, read>>

-----------------------------------------------------------------------------

Live(id) == keys[id].made /\ ~keys[id].gone
Unused == {id \in Ids : ~keys[id].made}
Named(e, n) == {id \in Ids : Live(id) /\ keys[id].env = e /\ keys[id].name = n}
\* The value a row stands for: its own, or its reference's source.
Held(id) == IF keys[id].ref = None THEN id ELSE keys[id].ref

\* What is true: the binding lists the key, by ID, where it is held.
Listed(id) == Reads[keys[id].env].all \/ id \in Reads[keys[id].env].keys

\* What the vault decides (6.1): `reads` at the place it checks, by ID or
\* by name.
Allowed(id) ==
    LET at == IF CheckWhereHeld THEN Held(id) ELSE id
        e == keys[at].env
    IN IF ReadsByID THEN Reads[e].all \/ at \in Reads[e].keys
                    ELSE ReadsByName[e].all \/ keys[at].name \in ReadsByName[e].keys

NoOp == [kind |-> "none", env |-> None, name |-> None, to |-> None]

Goto(p, label) == pc' = [pc EXCEPT ![p] = label]

Begin(p) ==
    /\ pc[p] = "idle"
    /\ left[p] > 0
    /\ \E o \in Ops[p] :
         /\ op' = [op EXCEPT ![p] = o]
         /\ Goto(p, o.kind)
    /\ left' = [left EXCEPT ![p] = @ - 1]
    /\ UNCHANGED <<keys, l, read>>

Done(p) == Goto(p, "idle") /\ UNCHANGED <<op, l, left>>

\* The workload reads env/name: `reveal`, the plan or `workload.read`.
Read(p) ==
    /\ pc[p] = "read"
    /\ \/ /\ Named(op[p].env, op[p].name) = {}
          /\ UNCHANGED read
       \/ \E id \in Named(op[p].env, op[p].name) :
            read' = IF Live(Held(id)) /\ Allowed(id)
                      THEN read \cup {[key |-> Held(id), listed |-> Listed(Held(id)), laundered |-> keys[Held(id)].laundered]}
                      ELSE read
    /\ Done(p)
    /\ UNCHANGED keys

\* A reference or a copy into dev of prod's env/name, by the workload or by
\* a person. A workload's is refused unless it may read the source; a copy
\* the workload made of a value it could not read is laundered, a person's
\* never is: a person who may read it chose to.
Into(p, copy) ==
    /\ pc[p] = IF copy THEN "copy" ELSE "reference"
    /\ LET srcs == Named(op[p].env, op[p].name)
           free == Unused
           workload == p = "wl"
       IN IF srcs = {} \/ free = {} \/ Named("dev", op[p].to) # {}
            THEN UNCHANGED keys
            ELSE LET src == CHOOSE id \in srcs : TRUE
                     new == CHOOSE id \in free : TRUE
                 IN IF workload /\ RefusesUnreadableSources /\ ~Allowed(src)
                      THEN UNCHANGED keys
                      ELSE keys' = [keys EXCEPT ![new] =
                             [made |-> TRUE, env |-> "dev", name |-> op[p].to,
                              gone |-> FALSE, ref |-> IF copy THEN None ELSE Held(src),
                              laundered |-> copy /\ (keys[Held(src)].laundered \/ (workload /\ ~Listed(Held(src))))]]
    /\ Done(p)
    /\ UNCHANGED read

Copy(p) == Into(p, TRUE)
Reference(p) == Into(p, FALSE)

\* Renaming a key in place: its ID stays.
Rename(p) ==
    /\ pc[p] = "rename"
    /\ keys' = IF Named(op[p].env, op[p].name) = {} \/ Named(op[p].env, op[p].to) # {}
                 THEN keys
                 ELSE LET id == CHOOSE id \in Named(op[p].env, op[p].name) : TRUE
                      IN [keys EXCEPT ![id].name = op[p].to]
    /\ Done(p)
    /\ UNCHANGED read

\* Deleting a key and making one of the same name: a new ID.
Recreate(p) ==
    /\ pc[p] = "recreate"
    /\ keys' = IF Named(op[p].env, op[p].name) = {} \/ Unused = {}
                 THEN keys
                 ELSE LET old == CHOOSE id \in Named(op[p].env, op[p].name) : TRUE
                          new == CHOOSE id \in Unused : TRUE
                      IN [keys EXCEPT ![old].gone = TRUE,
                                      ![new] = [made |-> TRUE, gone |-> FALSE, env |-> op[p].env, name |-> op[p].name,
                                                ref |-> None, laundered |-> FALSE]]
    /\ Done(p)
    /\ UNCHANGED read

Init ==
    /\ keys = [id \in Ids |->
                 CASE id = "k1" -> [made |-> TRUE, gone |-> FALSE, env |-> "prod", name |-> "S", ref |-> None, laundered |-> FALSE]
                   [] id = "k2" -> [made |-> TRUE, gone |-> FALSE, env |-> "prod", name |-> "W", ref |-> None, laundered |-> FALSE]
                   [] id = "k3" -> [made |-> TRUE, gone |-> FALSE, env |-> "dev", name |-> "S", ref |-> "k1", laundered |-> FALSE]
                   [] OTHER     -> [made |-> FALSE, gone |-> FALSE, env |-> "prod", name |-> "X", ref |-> None, laundered |-> FALSE]]
    /\ pc = [p \in Procs |-> "idle"]
    /\ op = [p \in Procs |-> NoOp]
    /\ l = [p \in Procs |-> [id |-> <<None, 0>>]]
    /\ left = Budget
    /\ read = {}

Step(p) ==
    Begin(p) \/ Read(p) \/ Copy(p) \/ Reference(p) \/ Rename(p) \/ Recreate(p)

Finished == \A p \in Procs : pc[p] = "idle" /\ left[p] = 0

Next == (\E p \in Procs : Step(p)) \/ (Finished /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK == \A id \in Ids : keys[id].env \in Envs /\ keys[id].name \in Names

\* A workload reads a value only if `reads` lists the key, by ID, where the
\* value is held, and the value did not reach that key through a copy the
\* workload could not have read.
NoLaundering == \A a \in read : a.listed /\ ~a.laundered

=============================================================================
