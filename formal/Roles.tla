------------------------------- MODULE Roles -------------------------------
(***************************************************************************)
(* The roles split out of `log_config` (T178 PR 2, 0.16): one row and one  *)
(* seal per role, while 0.15.0's code still runs on the new schema.        *)
(*                                                                         *)
(* Until 0.16, the roles are one sealed object, `roles`/`instance`: the    *)
(* Owner's edits of every role, one row of `log_config`, its seal the one  *)
(* its newest change left. 0.16 makes each role an object of its own,      *)
(* `role`/`<scope>/<name>`: a row of the `roles` table, which `grants`'    *)
(* role names (a foreign key), its seal its own newest change's.           *)
(*                                                                         *)
(* Between `coffre migrate` and the deploy, 0.15.0's vault serves on the   *)
(* new schema (AGENTS.md, "expand, then contract"); after a rollback, it   *)
(* does again. Its TypeScript knows only the whole object; its SQL is the  *)
(* migration's, `change_input` included, which every change of either      *)
(* release calls to write the rows it changes. So:                         *)
(*                                                                         *)
(*   old    0.15.0's change of one role: under the head and the fence,     *)
(*          its whole object checked current, a change of `roles`/         *)
(*          `instance`, and `change_input`, which writes `log_config` and  *)
(*          (NullOnOld) the role's own row, as the edit leaves it, with no *)
(*          seal: 0.15.0 makes none for it. Or its grant of a role.        *)
(*   new    0.16's change of one role: the role's row checked current, a   *)
(*          change of the role's object, sealing its row, and (DualWrite)  *)
(*          one of the whole object, sealing `log_config`, in the one      *)
(*          transaction, so that 0.15.0's code reads every edit 0.16 made. *)
(*   rec    0.16's vault, at its start and whenever a use finds a role's   *)
(*          row unsealed: it reads `log_config`, checked current, then,    *)
(*          under the head and the fence, (ReconcileRechecks) holds it to  *)
(*          what it read, and writes a change of each role whose row is    *)
(*          not sealed and current, (ReconcileFromConfig) to what the      *)
(*          whole object says, never to what the unsealed row says.        *)
(*   use    a use's one statement, which reads the roles it decides on:    *)
(*          0.16's, each role's row and its object's newest change, served *)
(*          only while the seal is the vault's and (NewestChecked) the     *)
(*          newest; 0.15.0's, the whole object and its newest change.      *)
(*   evil   someone who writes the database (R64): writes a role's row     *)
(*          with any definition and no seal, puts back an earlier sealed   *)
(*          one, or deletes it. They make no seal of the vault's.          *)
(*                                                                         *)
(* Changes take the head and the fence exclusive, and a use's statement    *)
(* reads one snapshot under the fence shared: each is one step here. The   *)
(* reconcile's read before it takes them is its own.                       *)
(*                                                                         *)
(* What must hold: every use decides on what the newest change of the      *)
(* role, of either object, says (NoStaleDecision), and 0.15.0's grant of a *)
(* role it defined finds the row the foreign key asks for (OldGrantWorks). *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Roles,          \* the roles: some the release ships, the others an Owner makes
    Custom,         \* the roles an Owner makes, which 0.15.0 had not made yet
    Defs,           \* the definitions a role may have, Shipped (no edit) among them
    Shipped,        \* no edit: the definition the running release ships
    Gone,           \* no such role: a custom role never made, or deleted
    Edited,         \* the definition 0.15.0 left each shipped role with
    MaxChanges,     \* how many changes the log takes
    MaxTampers,     \* how many rows the database's writer writes
    MaxOld,         \* how many changes 0.15.0's code makes
    MaxReconciles   \* how many times 0.16's vault reconciles

CONSTANTS
    \* `change_input`, as the migration makes it, writes the role's row as
    \* a 0.15.0 change leaves it, with no seal, or deletes it.
    NullOnOld,
    \* A 0.16 change of a role writes a change of the whole object too.
    DualWrite,
    \* The reconcile holds `log_config`, under the head, to what it read.
    ReconcileRechecks,
    \* The reconcile seals what the sealed whole object says, not the row.
    ReconcileFromConfig,
    \* The reconcile seals every role whose row is not what the whole object
    \* says, sealed and current or not: a row put back is current on its
    \* own object, which 0.15.0 never writes.
    ReconcileEveryRole,
    \* A 0.16 use, and a 0.16 change, reads a role's row only while the whole
    \* object's newest change is 0.16's (`by`), written beside a role's change
    \* or by the reconcile: after 0.15.0's, until the reconcile, none. The use
    \* reads that change anyway, as 0.15.0's does.
    OldFenced,
    \* A 0.16 use serves a role's row only while its seal is its newest change's.
    NewestChecked

\* No seal: changes are numbered from 1.
None == 0
Defined == Defs \cup {Gone}
Whole == "whole"

ASSUME Shipped \in Defs /\ Gone \notin Defs /\ Edited \in Defs /\ Custom \subseteq Roles

\* Each role's definition as 0.15.0 left it: the shipped ones edited, no custom one made.
Initial == [r \in Roles |-> IF r \in Custom THEN Gone ELSE Edited]

\* What a change may make a role: a shipped one is edited or reset, never
\* deleted; a custom one is made, edited or deleted, and ships no definition.
Allowed(r) == IF r \in Custom THEN (Defs \ {Shipped}) \cup {Gone} ELSE Defs

VARIABLES
    log,        \* the changes, oldest first: [obj: Whole or a role, val, seal, by: the release's]
    cfg,        \* `log_config`'s roles row: [val: Roles -> Defined, seal]
    rows,       \* `roles`: rows[r] = [def, seal], def Gone for no row
    recRead,    \* what the reconcile read of `log_config`, while it holds a read (`held`)
    olds,       \* how many changes 0.15.0's code made
    recs,       \* how many reconciles began
    tampers,    \* how many rows the writer wrote
    wrong,      \* a use decided on what no newest change says
    refused     \* 0.15.0's grant of a role it defined met no row

vars == <<log, cfg, rows, recRead, olds, recs, tampers, wrong, refused>>

\* A change's seal: its place in the log, the vault's alone. A deletion's is
\* none, as a deleted object's newest change leaves no seal.
SealOf(i, val) == IF val = Gone THEN None ELSE i

\* The newest change of a role, of its own object: its index, or 0.
NewestOwn(r) ==
    LET is == {i \in 1..Len(log) : log[i].obj = r}
    IN IF is = {} THEN 0 ELSE CHOOSE i \in is : \A j \in is : j <= i
NewestWhole ==
    LET is == {i \in 1..Len(log) : log[i].obj = Whole}
    IN CHOOSE i \in is : \A j \in is : j <= i

\* What the newest change of either object says of the role.
Truth(r) ==
    LET is == {i \in 1..Len(log) : log[i].obj = r \/ log[i].obj = Whole}
        n == CHOOSE i \in is : \A j \in is : j <= i
    IN IF log[n].obj = Whole THEN log[n].val[r] ELSE log[n].val

\* A role's row, as `checkSeals` weighs it: valid, a seal of the vault's
\* over this object and this definition (no row: no seal); current, the
\* seal its object's newest change left (no row: that change left none).
Valid(r) ==
    IF rows[r].def = Gone THEN rows[r].seal = None
    ELSE \E i \in 1..Len(log) : log[i].obj = r /\ log[i].seal = rows[r].seal /\ log[i].val = rows[r].def
Current(r) ==
    LET n == NewestOwn(r)
    IN IF n = 0 THEN rows[r].def = Gone
       ELSE IF rows[r].def = Gone THEN log[n].seal = None
       ELSE rows[r].seal # None /\ rows[r].seal = log[n].seal
Sealed(r) == Valid(r) /\ Current(r)

\* `log_config`'s row: 0.15.0's check, valid and its whole object's newest.
CfgCurrent == cfg.seal = log[NewestWhole].seal /\ cfg.val = log[NewestWhole].val

Init ==
    \* 0.15.0's log: its roles as one object. The migration made a row of
    \* each role it defines, its definition copied from `log_config`, unsealed.
    /\ log = << [obj |-> Whole, val |-> Initial, seal |-> 1, by |-> "old"] >>
    /\ cfg = [val |-> Initial, seal |-> 1]
    /\ rows = [r \in Roles |-> [def |-> Initial[r], seal |-> None]]
    /\ recRead = [held |-> FALSE, val |-> Initial, seal |-> None]
    /\ olds = 0 /\ recs = 0 /\ tampers = 0
    /\ wrong = FALSE /\ refused = FALSE

Room == Len(log) < MaxChanges

\* No change of 0.15.0's since 0.16's last of the whole object.
Fenced == OldFenced => log[NewestWhole].by = "new"

\* 0.15.0 changes one role: its whole object, then `change_input`.
OldEdit(r, d) ==
    /\ Room /\ olds < MaxOld /\ CfgCurrent
    /\ d \in Allowed(r) /\ cfg.val[r] # d
    /\ LET val == [cfg.val EXCEPT ![r] = d]
           i == Len(log) + 1
       IN /\ log' = Append(log, [obj |-> Whole, val |-> val, seal |-> i, by |-> "old"])
          /\ cfg' = [val |-> val, seal |-> i]
          /\ rows' = IF NullOnOld THEN [rows EXCEPT ![r] = [def |-> d, seal |-> None]] ELSE rows
    /\ olds' = olds + 1
    /\ UNCHANGED <<recRead, recs, tampers, wrong, refused>>

\* 0.15.0 grants a role its whole object defines: the row of `grants`,
\* which the foreign key holds to a row of `roles`.
OldGrant(r) ==
    /\ CfgCurrent /\ cfg.val[r] \notin {Gone}
    /\ refused' = (refused \/ rows[r].def = Gone)
    /\ UNCHANGED <<log, cfg, rows, recRead, olds, recs, tampers, wrong>>

\* 0.16 changes one role: its row checked as a use checks it, then a change
\* of its object, and with DualWrite one of the whole object, `log_config`
\* checked current first.
NewEdit(r, d) ==
    /\ Room /\ d \in Allowed(r) /\ Sealed(r) /\ Fenced /\ rows[r].def # d
    /\ DualWrite => (CfgCurrent /\ Len(log) + 1 < MaxChanges)
    /\ LET i == Len(log) + 1
           own == [obj |-> r, val |-> d, seal |-> SealOf(i, d), by |-> "new"]
           val == [cfg.val EXCEPT ![r] = d]
       IN /\ log' = IF DualWrite THEN log \o << own, [obj |-> Whole, val |-> val, seal |-> i + 1, by |-> "new"] >> ELSE Append(log, own)
          /\ cfg' = IF DualWrite THEN [val |-> val, seal |-> i + 1] ELSE cfg
          /\ rows' = [rows EXCEPT ![r] = [def |-> d, seal |-> SealOf(i, d)]]
    /\ UNCHANGED <<recRead, olds, recs, tampers, wrong, refused>>

\* The reconcile reads `log_config`, before it takes any lock.
RecRead ==
    /\ ~recRead.held /\ recs < MaxReconciles /\ CfgCurrent
    /\ recRead' = [held |-> TRUE, val |-> cfg.val, seal |-> cfg.seal]
    /\ recs' = recs + 1
    /\ UNCHANGED <<log, cfg, rows, olds, tampers, wrong, refused>>

\* Under the head and the fence, in one transaction: a change of each role
\* whose row is not sealed and current (ReconcileEveryRole: or not what the
\* whole object says), then one of the whole object, as it is, 0.16's, which
\* lifts the fence. With ReconcileRechecks, only while `log_config` is what
\* it read; else it reads again.
RecWrite ==
    /\ recRead.held
    /\ IF ReconcileRechecks /\ cfg.seal # recRead.seal
       THEN /\ recRead' = [recRead EXCEPT !.held = FALSE]
            /\ UNCHANGED <<log, cfg, rows>>
       ELSE LET todo == {r \in Roles : ~Sealed(r) \/ (ReconcileEveryRole /\ rows[r].def # recRead.val[r])}
                order == CHOOSE f \in [1..Cardinality(todo) -> todo] : \A a, b \in DOMAIN f : a < b => f[a] # f[b]
                base == Len(log)
                def(r) == IF ReconcileFromConfig THEN recRead.val[r] ELSE rows[r].def
                at(r) == base + CHOOSE k \in DOMAIN order : order[k] = r
                mark == base + Cardinality(todo) + 1
            IN /\ mark <= MaxChanges
               /\ log' = log \o [k \in 1..Cardinality(todo) |-> [obj |-> order[k], val |-> def(order[k]), seal |-> SealOf(base + k, def(order[k])), by |-> "new"]]
                             \o << [obj |-> Whole, val |-> cfg.val, seal |-> mark, by |-> "new"] >>
               /\ rows' = [r \in Roles |-> IF r \in todo THEN [def |-> def(r), seal |-> SealOf(at(r), def(r))] ELSE rows[r]]
               /\ cfg' = [cfg EXCEPT !.seal = mark]
               /\ recRead' = [recRead EXCEPT !.held = FALSE]
    /\ UNCHANGED <<olds, recs, tampers, wrong, refused>>

\* What a use decides on a role's row: a shipped role with none, as the
\* release ships it (`readerOf` merges the rows over the shipped roles).
\* No check of its own refuses that: the fence holds every use until the
\* reconcile has sealed each shipped role, and no change deletes one, so its
\* object's newest change always leaves a seal, which no row is not current
\* to (`checkSeals`).
Read(r) == IF rows[r].def = Gone /\ r \notin Custom THEN Shipped ELSE rows[r].def

\* A use that finds no row of a custom role the writer deleted reads it as
\* no such role: a grant of it reaches nothing. Closed, as R64 asks.
Denial(r, d) == d = Gone /\ r \in Custom /\ tampers > 0

\* A 0.16 use of role r: served on its row, refused (and reconciled) when
\* the row is not the vault's or not the newest.
NewUse(r) ==
    /\ Valid(r) /\ (NewestChecked => Current(r))
    /\ Fenced
    /\ wrong' = (wrong \/ (Read(r) # Truth(r) /\ ~Denial(r, Read(r))))
    /\ UNCHANGED <<log, cfg, rows, recRead, olds, recs, tampers, refused>>

\* A 0.15.0 use of role r: served on the whole object while it is current.
OldUse(r) ==
    /\ CfgCurrent
    /\ wrong' = (wrong \/ cfg.val[r] # Truth(r))
    /\ UNCHANGED <<log, cfg, rows, recRead, olds, recs, tampers, refused>>

\* The database's writer: a row with any definition and no seal, an
\* earlier sealed row of the same role put back, or the row deleted.
Tamper(r) ==
    /\ tampers < MaxTampers
    /\ \/ \E d \in Defined : rows' = [rows EXCEPT ![r] = [def |-> d, seal |-> None]]
       \/ \E i \in 1..Len(log) : log[i].obj = r /\ rows' = [rows EXCEPT ![r] = [def |-> log[i].val, seal |-> log[i].seal]]
    /\ tampers' = tampers + 1
    /\ UNCHANGED <<log, cfg, recRead, olds, recs, wrong, refused>>

Next ==
    \/ \E r \in Roles, d \in Defined : OldEdit(r, d) \/ NewEdit(r, d)
    \/ \E r \in Roles : OldGrant(r) \/ NewUse(r) \/ OldUse(r) \/ Tamper(r)
    \/ RecRead \/ RecWrite

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ \A i \in 1..Len(log) : log[i].obj \in Roles \cup {Whole}
    /\ cfg.val \in [Roles -> Defined]
    /\ \A r \in Roles : rows[r].def \in Defined
    /\ wrong \in BOOLEAN /\ refused \in BOOLEAN

NoStaleDecision == ~wrong
\* A row the database's writer deleted refuses the grant: closed, as R64 asks.
OldGrantWorks == tampers = 0 => ~refused

\* The model bounds how much happens; nothing else stops it.
Bounded == Len(log) <= MaxChanges
=============================================================================
