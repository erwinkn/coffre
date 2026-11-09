------------------------------- MODULE Roles -------------------------------
(***************************************************************************)
(* The roles split out of `log_config` (T178 PR 2): one row and one seal   *)
(* per role, written beside the whole object in 0.16, read in 0.17.        *)
(*                                                                         *)
(* Until 0.16, the roles are one sealed object, `roles`/`instance`: the    *)
(* Owner's edits of every role, one row of `log_config`, its seal the one  *)
(* its newest change left. 0.16 adds `role`/`<scope>/<name>`, one object   *)
(* per role: a row of the `roles` table, sealed by its own newest change.  *)
(* Three releases:                                                         *)
(*                                                                         *)
(*   0.16   uses and changes decide on the whole object, as 0.15.0's do;   *)
(*          each change of a role writes its row too, and the vault        *)
(*          reseals the rows from the whole object at its start.           *)
(*   0.17   uses read the rows, never the whole object; `grants` names a   *)
(*          row through a foreign key, which 0.16 cannot add: 0.14.5,      *)
(*          which may serve on its schema (a one-step upgrade), grants     *)
(*          roles it never writes a row of.                                *)
(*   0.18   drops `log_config`.                                            *)
(*                                                                         *)
(* Between `coffre migrate` and the deploy, and again after a rollback,    *)
(* 0.15.0's vault serves on 0.16's schema (AGENTS.md, "expand, then        *)
(* contract"). Its TypeScript knows only the whole object; its SQL is the  *)
(* migration's, `change_input` included, which every change calls to       *)
(* write the rows it changes. That is Postgres: on SQLite the change is    *)
(* the release's own TypeScript, so 0.15.0's writes no row, and a SQLite   *)
(* deployment (dev and tests only) does not roll back across 0.16. So:     *)
(*                                                                         *)
(*   old    0.15.0's change of one role: under the head and the fence,     *)
(*          its whole object checked current, a change of it, and          *)
(*          `change_input`, which writes `log_config` and (NullOnOld)      *)
(*          the role's row, as the edit leaves it, with no seal (0.15.0    *)
(*          makes none for it), unless the row already says that.          *)
(*   new    0.16's change of one role, under the head and the fence, the   *)
(*          whole object checked current: (EditSyncs) a change of each     *)
(*          role whose row is not what the whole object says, as the sync  *)
(*          below; a change of the role's own object; and (DualWrite) one  *)
(*          of the whole object, in one transaction.                       *)
(*   sync   0.16's vault at its start, under the head and the fence, the   *)
(*          whole object checked current: a change of each role whose row  *)
(*          is not sealed and current, or (SyncEveryRole) not what the     *)
(*          whole object says, (SyncFromConfig) to what the whole object   *)
(*          says, never to what the row says.                              *)
(*   use    a use of 0.15.0 or 0.16, one statement: the whole object,      *)
(*          served while its seal is its newest change's.                  *)
(*   up     0.17's deploy, after which no 0.15.0 code runs: (NeverSkip)    *)
(*          only once 0.16's vault has synced since 0.15.0's last change.  *)
(*   read   a use of 0.17: a role's row, served (ReadChecksSeal) only      *)
(*          while it is sealed and its object's newest; else refused. No   *)
(*          row is no role: a grant of it reaches nothing.                 *)
(*   evil   someone who writes the database (R64): writes a role's row     *)
(*          with any definition and no seal, puts back an earlier sealed   *)
(*          one, or deletes it. They make no seal of the vault's.          *)
(*                                                                         *)
(* Changes take the head and the fence exclusive, and a use's statement    *)
(* reads one snapshot under the fence shared: each is one step here.       *)
(*                                                                         *)
(* What must hold: every use decides on what the newest change of the      *)
(* role, of either object, says, or refuses (NoStaleDecision); after any   *)
(* step of 0.16's, every row is sealed, current, and what the whole        *)
(* object says (RowsFaithful), which is what 0.17 reads; and, but for the  *)
(* database's writer, a row sealed and current says what the newest change *)
(* says, whichever release wrote last (SealedRowsTrue): a 0.17 deployed    *)
(* over a skipped 0.16 refuses what 0.15.0 changed, never serves it stale. *)
(*                                                                         *)
(* One abstraction: a role an Owner made and 0.15.0 deleted before 0.16    *)
(* ever wrote its row is Gone here, so the sync changes nothing. In code   *)
(* NullOnOld left its row, no definition and no seal, so the next start    *)
(* logs one change of an object the log never had, to no role with no     *)
(* seal, and deletes the row: the same end, one change more, which the     *)
(* replay takes (no value, no seal).                                       *)
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
    MaxOld          \* how many changes 0.15.0's code makes

CONSTANTS
    \* `change_input`, as the migration makes it, writes the role's row as
    \* a 0.15.0 change leaves it, with no seal, unless the row says that already.
    NullOnOld,
    \* A 0.16 change of a role writes a change of the whole object too.
    DualWrite,
    \* A 0.16 change of a role first syncs every other role's row.
    EditSyncs,
    \* The sync seals what the sealed whole object says, not what the row says.
    SyncFromConfig,
    \* The sync rewrites every row that is not what the whole object says,
    \* sealed and current or not: a row put back is current on its own
    \* object, which 0.15.0 never writes.
    SyncEveryRole,
    \* 0.17 deploys only once 0.16's vault has synced since 0.15.0's last change.
    NeverSkip,
    \* 0.17 serves a role's row only while it is sealed and its object's newest.
    ReadChecksSeal

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
    log,        \* the changes, oldest first: [obj: Whole or a role, val, seal]
    cfg,        \* `log_config`'s roles row: [val: Roles -> Defined, seal]
    rows,       \* `roles`: rows[r] = [def, seal], def Gone for no row
    last,       \* who wrote last: "old" (0.15.0), "new" (0.16) or "evil"
    phase,      \* "16" while 0.15.0's code may still run, "17" after 0.17's deploy
    olds,       \* how many changes 0.15.0's code made
    tampers,    \* how many rows the writer wrote
    wrong       \* a use decided on what no newest change says

vars == <<log, cfg, rows, last, phase, olds, tampers, wrong>>

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

\* `log_config`'s row, as both releases check it: its whole object's newest.
CfgCurrent == cfg.seal = log[NewestWhole].seal /\ cfg.val = log[NewestWhole].val

Init ==
    \* 0.15.0's log: its roles as one object. The migration makes the table, no row.
    /\ log = << [obj |-> Whole, val |-> Initial, seal |-> 1] >>
    /\ cfg = [val |-> Initial, seal |-> 1]
    /\ rows = [r \in Roles |-> [def |-> Gone, seal |-> None]]
    /\ last = "old" /\ phase = "16"
    /\ olds = 0 /\ tampers = 0
    /\ wrong = FALSE

\* The roles a sync rewrites, and to what.
Todo == {r \in Roles : ~Sealed(r) \/ (SyncEveryRole /\ rows[r].def # cfg.val[r])}
SyncDef(r) == IF SyncFromConfig THEN cfg.val[r] ELSE rows[r].def

\* A change of each role in `todo`, appended to the log, and the rows it leaves.
SyncLog(todo) ==
    LET order == CHOOSE f \in [1..Cardinality(todo) -> todo] : \A a, b \in DOMAIN f : a < b => f[a] # f[b]
    IN log \o [k \in 1..Cardinality(todo) |-> [obj |-> order[k], val |-> SyncDef(order[k]), seal |-> SealOf(Len(log) + k, SyncDef(order[k]))]]
SyncRows(todo, synced) ==
    [r \in Roles |-> IF r \in todo
                     THEN LET i == CHOOSE i \in 1..Len(synced) : synced[i].obj = r /\ \A j \in 1..Len(synced) : synced[j].obj = r => j <= i
                          IN [def |-> SyncDef(r), seal |-> synced[i].seal]
                     ELSE rows[r]]

\* 0.15.0 changes one role: its whole object, then `change_input`.
OldEdit(r, d) ==
    /\ phase = "16" /\ Len(log) < MaxChanges /\ olds < MaxOld /\ CfgCurrent
    /\ d \in Allowed(r) /\ cfg.val[r] # d
    /\ LET val == [cfg.val EXCEPT ![r] = d]
           i == Len(log) + 1
       IN /\ log' = Append(log, [obj |-> Whole, val |-> val, seal |-> i])
          /\ cfg' = [val |-> val, seal |-> i]
          /\ rows' = IF NullOnOld /\ rows[r].def # d THEN [rows EXCEPT ![r] = [def |-> d, seal |-> None]] ELSE rows
    /\ olds' = olds + 1 /\ last' = "old"
    /\ UNCHANGED <<phase, tampers, wrong>>

\* 0.16 changes one role, in one transaction: the sync (with EditSyncs),
\* a change of its own object, and (with DualWrite) one of the whole object.
NewEdit(r, d) ==
    /\ CfgCurrent /\ d \in Allowed(r) /\ cfg.val[r] # d
    /\ LET todo == IF EditSyncs THEN Todo \ {r} ELSE {}
           synced == SyncLog(todo)
           i == Len(synced) + 1
           own == [obj |-> r, val |-> d, seal |-> SealOf(i, d)]
           val == [cfg.val EXCEPT ![r] = d]
       IN /\ Len(synced) + (IF DualWrite THEN 2 ELSE 1) <= MaxChanges
          /\ log' = IF DualWrite THEN synced \o << own, [obj |-> Whole, val |-> val, seal |-> i + 1] >> ELSE Append(synced, own)
          /\ cfg' = IF DualWrite THEN [val |-> val, seal |-> i + 1] ELSE cfg
          /\ rows' = [SyncRows(todo, synced) EXCEPT ![r] = [def |-> d, seal |-> SealOf(i, d)]]
    /\ last' = "new"
    /\ UNCHANGED <<phase, olds, tampers, wrong>>

\* 0.16's vault at its start: the sync alone.
Sync ==
    /\ CfgCurrent
    /\ Len(log) + Cardinality(Todo) <= MaxChanges
    /\ log' = SyncLog(Todo)
    /\ rows' = SyncRows(Todo, SyncLog(Todo))
    /\ last' = "new"
    /\ UNCHANGED <<cfg, phase, olds, tampers, wrong>>

\* A use of 0.15.0 or 0.16 on role r: the whole object, while it is current.
Use(r) ==
    /\ CfgCurrent
    /\ wrong' = (wrong \/ cfg.val[r] # Truth(r))
    /\ UNCHANGED <<log, cfg, rows, last, phase, olds, tampers>>

\* 0.17's deploy: no 0.15.0 code runs after it.
Upgrade ==
    /\ phase = "16" /\ (NeverSkip => last = "new")
    /\ phase' = "17"
    /\ UNCHANGED <<log, cfg, rows, last, olds, tampers, wrong>>

\* A use of 0.17 on role r: its row, refused unless sealed and current.
Read(r) ==
    /\ phase = "17"
    /\ ReadChecksSeal => Sealed(r)
    \* No row is no role, shipped or not: a grant of it reaches nothing, closed.
    /\ wrong' = (wrong \/ (rows[r].def # Truth(r) /\ rows[r].def # Gone))
    /\ UNCHANGED <<log, cfg, rows, last, phase, olds, tampers>>

\* The database's writer: a row with any definition and no seal, an
\* earlier sealed row of the same role put back, or the row deleted.
Tamper(r) ==
    /\ tampers < MaxTampers
    /\ \/ \E d \in Defined : rows' = [rows EXCEPT ![r] = [def |-> d, seal |-> None]]
       \/ \E i \in 1..Len(log) : log[i].obj = r /\ rows' = [rows EXCEPT ![r] = [def |-> log[i].val, seal |-> log[i].seal]]
    /\ tampers' = tampers + 1 /\ last' = "evil"
    /\ UNCHANGED <<log, cfg, phase, olds, wrong>>

Next ==
    \/ \E r \in Roles, d \in Defined : OldEdit(r, d) \/ NewEdit(r, d)
    \/ \E r \in Roles : Use(r) \/ Read(r) \/ Tamper(r)
    \/ Sync \/ Upgrade

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ \A i \in 1..Len(log) : log[i].obj \in Roles \cup {Whole}
    /\ cfg.val \in [Roles -> Defined]
    /\ \A r \in Roles : rows[r].def \in Defined
    /\ last \in {"old", "new", "evil"} /\ phase \in {"16", "17"}
    /\ wrong \in BOOLEAN

NoStaleDecision == ~wrong
\* But for the writer, a row sealed and current says what the newest change does,
\* whichever release wrote last: what a 0.17 deployed too soon would read.
SealedRowsTrue == tampers = 0 => \A r \in Roles : Sealed(r) /\ rows[r].def # Gone => rows[r].def = Truth(r)
\* After 0.16's last step, every row is what 0.17 may read.
RowsFaithful == last = "new" => \A r \in Roles : Sealed(r) /\ rows[r].def = cfg.val[r]

\* The model bounds how much happens; nothing else stops it.
Bounded == Len(log) <= MaxChanges
=============================================================================
