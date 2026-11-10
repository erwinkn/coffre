-------------------------------- MODULE Reads --------------------------------
(***************************************************************************)
(* T166: the projection of 0.15's uses for the audit pages (`log_reads`).  *)
(* Written before the code (R45).                                          *)
(*                                                                         *)
(* A use is a slim row of `log_uses`: (number, credential, key, mac), its  *)
(* MAC under the vault's key over every column but the number. A change    *)
(* writes one object (a credential's account, a key's place and version, a *)
(* reference's place and source) and is numbered from the same sequence.   *)
(* An object's state at a use is its newest change numbered below the use  *)
(* (R50): the replay. The signer (Seal.tla, abstracted to `sealed` and the *)
(* entries it sealed) moves `sealed` over what the tables hold; a change   *)
(* answers once sealed (R51).                                              *)
(*                                                                         *)
(* The projector writes, for each sealed use, a row (number, account, the  *)
(* key's place, the source if the key was a reference then, the version    *)
(* read) with a MAC under the vault's key, and keeps its cursor ("reads    *)
(* projected through"). One run: read the cursor, take the next chunk of   *)
(* at most Chunk numbers, derive each use's row, insert the rows, move the *)
(* cursor. It may crash between any two steps; two instances may race      *)
(* (Workers retries). The audit page lists the rows at or below the cursor *)
(* whose MAC holds and says "reads sealed through <cursor>" when the       *)
(* cursor is below `sealed`. The full verify (explicit, never per page)    *)
(* holds the listed numbers to the sealed uses at or below the cursor.     *)
(*                                                                         *)
(* An attacker with write access to the database and no key may delete or *)
(* swap rows of `log_uses`, delete rows of `log_changes`, edit the live    *)
(* rows (a credential's account, a key's place, a reference's source),     *)
(* delete, copy or make up rows of `log_reads`, and set the cursor. It     *)
(* forges no MAC and no signature. The sealed entries (`tu`, `tc`) are     *)
(* what the signed pairs hold: no attacker step changes them. Writers are  *)
(* honest, and the vault decides each use on the state the honest changes  *)
(* give (HotPathOne's ReplayAgrees): `dec`, a ghost the use's row carries. *)
(*                                                                         *)
(* The protections, each a constant (scripts/formal.sh shows each          *)
(* necessary):                                                             *)
(*   DeriveFromSealed  a use's state comes from the changes below it, each *)
(*                     row found held to the tree at its number, never     *)
(*                     from the live rows;                                 *)
(*   InputsInUseMac    the use's MAC covers what it decided on (its        *)
(*                     inputs' seals), and the projector holds what it     *)
(*                     derives to it. A probe of `log_changes` by object   *)
(*                     finds a sealed change, but cannot show it is the    *)
(*                     newest: a writer who deletes the newest makes it    *)
(*                     find the one before. Not in the brief (TLC's        *)
(*                     finding); without it the probe is only as good as   *)
(*                     Seal's verifier (ReadsProbe);                       *)
(*   ProjectSealedOnly the projector takes only numbers at or below        *)
(*                     `sealed`;                                           *)
(*   WindowChecked     ... and holds its window's use rows whole to the    *)
(*                     sealed uses of that window (a range, which the      *)
(*                     signed pair proves complete);                       *)
(*   NumberInMac       the projection row's MAC covers its number;         *)
(*   IdempotentByNumber the rows are unique on the number, and the cursor *)
(*                     moves only forward (a compare-and-set);             *)
(*   ReplaceOnConflict ... and the insert replaces a row its number has    *)
(*                     (an upsert), never skips it: the derived row is the *)
(*                     same bytes whoever derives it, and a row made up    *)
(*                     ahead of the projector is overwritten. Insert-if-   *)
(*                     absent (the brief's) skips it; the writer deletes   *)
(*                     it once the cursor is past, a silent gap (TLC);     *)
(*   CursorAfterRows   the cursor moves only once the chunk's rows are     *)
(*                     committed;                                          *)
(*   CursorMac         the cursor carries a MAC under the vault's key,     *)
(*                     which the projector and the page check: a writer    *)
(*                     can only put back a cursor the vault wrote, never   *)
(*                     one ahead of it. Not in the brief;                  *)
(*   CountChecked      the full verify flags a sealed use at or below the  *)
(*                     cursor with no row, not only a row with no use;     *)
(*   ProjectorApart    the projector runs apart from the signer's tick,    *)
(*                     which never waits for it;                           *)
(*   FromChecked       a chunk's rows are written only while the cursor    *)
(*                     still stands where the chunk started: a projector   *)
(*                     another overtook writes nothing. Retention drops    *)
(*                     the uses and rows at or below a cut the cursor has  *)
(*                     passed; without it, the overtaken projector writes  *)
(*                     retired rows back, below the cut, where nothing     *)
(*                     looks for them again (review r11 of #434).          *)
(*                                                                         *)
(* T252: an offboarding report names, for a member, each key and version   *)
(* they read and when last. It reads `log_read_newest`, one entry for each *)
(* (account, key, version) with the time of the newest read of it, never   *)
(* each day the member read (R48). A use's time is its own (`At`), which   *)
(* need not rise with its number: clocks of isolates apart. The attacker   *)
(* may delete an entry or set its time ("newest"). Its protections:        *)
(*   NewestWithRows    the entries are written with the rows (a trigger on *)
(*                     `log_reads`), so before the cursor passes them;     *)
(*                     written after the cursor moved (a pass of its own), *)
(*                     a crash between leaves a read the page lists and    *)
(*                     the report never names;                             *)
(*   GreatestAt        an entry's time moves only up (the upsert keeps the *)
(*                     greater): set to the time of the chunk's own read,  *)
(*                     a read of a later number from a clock behind leaves *)
(*                     the newest uncovered;                               *)
(*   NewestChecked     the full verify holds each listed read to an entry  *)
(*                     of its account, key and version at its time or      *)
(*                     later, as it holds it to its member's day;          *)
(*   NewestRetired     retention drops the entries of the reads it drops,  *)
(*                     those whose time is at or below the cut's: the      *)
(*                     report names no read retention dropped.             *)
(*   PruneLocked       each call of `drop_reads_day` also sweeps the       *)
(*                     entries older than the oldest day of reads left (a  *)
(*                     day an earlier call dropped and left entries of),   *)
(*                     under the projector's lock, so as one step between  *)
(*                     its calls: apart, it reads the floor, a projector's *)
(*                     call writes a read below it (its day made then, or  *)
(*                     no day left at all), and the sweep drops its entry. *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Creds,       \* the credentials
    Keys,        \* the plain keys
    Ref,         \* the reference, whose source is one of Keys
    Accounts, Places,   \* two each: an attacker's edit flips one
    Start,       \* each object's state before the first change: [acct, pl, v, src], "-" or 0 where unused
    Script,      \* the appends, in number order: [k |-> "c", obj, val] or [k |-> "u", cred, key]
    Chunk,       \* the numbers a projector run takes at most
    Projectors,  \* the projector instances
    MaxCrashes,  \* projector crashes in a behaviour
    MaxAttacks,  \* attacker steps in a behaviour
    Attacks,     \* the attacker's steps in play: "uses", "changes", "live", "reads", "cursor"
    Retention,   \* whether retention drops what is below a cut
    At,          \* each number's time: a use's own clock, which retention's days are of
    DeriveFromSealed, InputsInUseMac, ProjectSealedOnly, WindowChecked, NumberInMac, IdempotentByNumber, CursorAfterRows,
    ReplaceOnConflict, CursorMac, CountChecked, ProjectorApart, FromChecked,
    NewestWithRows, GreatestAt, NewestChecked, NewestRetired, PruneLocked

Objs == Creds \cup Keys \cup {Ref}
N == Len(Script)
Nums == 1..N
Other(x, S) == CHOOSE y \in S : y # x
Max(x, y) == IF x >= y THEN x ELSE y
Min(x, y) == IF x <= y THEN x ELSE y

\* A use's projection under the objects' states S: the account, the key's place, the reference's source, the version read.
\* The key read is the source through the reference (`coalesce(source, secret)`), the key itself otherwise.
Proj(S, cred, key) ==
    [a   |-> S[cred].acct,
     pl  |-> S[key].pl,
     src |-> IF key = Ref THEN S[Ref].src ELSE "-",
     k   |-> IF key = Ref THEN S[Ref].src ELSE key,
     v   |-> IF key = Ref THEN S[S[Ref].src].v ELSE S[key].v]
Junk == [a |-> "-", pl |-> "-", src |-> "-", k |-> "-", v |-> 0]

\* What an entry of `log_read_newest` is of: a row's account, key and version.
Of(r) == <<r.p.a, r.p.k, r.p.v>>
Times == {At[n] : n \in Nums}
\* The time at or below which retention's cut at k drops: the newest of the numbers it drops (its days, as built).
\* Every time is past 0, which no cut drops.
CutAt(k) == IF k = 0 THEN 0 ELSE CHOOSE t \in {At[n] : n \in 1..k} : \A n \in 1..k : At[n] <= t

\* The objects' states below number n, from the changes cs: each object's newest change numbered below n (R50).
Newest(cs, o, n) ==
    LET m == {c \in cs : c.obj = o /\ c.n < n} IN
    IF m = {} THEN Start[o] ELSE (CHOOSE c \in m : \A d \in m : d.n <= c.n).val
StateAt(cs, n) == [o \in Objs |-> Newest(cs, o, n)]

VARIABLES
    seq,       \* the sequence's last value: the appends numbered
    done,      \* the appends committed: one at a time is in flight, numbered and not yet committed
    usesT,     \* `log_uses`: [n, cred, key, dec], dec (a ghost) what the vault decided on
    changesT,  \* `log_changes`: [n, obj, val]
    st,        \* ghost: each object's state as the honest changes left it
    live,      \* the live rows: each object's state as the database holds it
    sealed,    \* the newest signed pair's upto
    tu, tc,    \* the uses and changes the signed pairs hold (the trees' leaves)
    reads,     \* `log_reads`: [n, p, ok, by]: its projection, whether its MAC holds, who wrote it (a ghost, to tell rows apart)
    cur,       \* the cursor
    curOk,     \* the cursor's MAC holds
    maced,     \* the cursors the vault wrote, each with its MAC: what a writer can put back
    pr,        \* each projector: pc, the chunk (from, to], the rows it derived
    attacks, crashes,
    gone,      \* ghost: the numbers whose projector-written row the attacker deleted
    cut,       \* retention's cut: the uses and rows at or below it dropped
    newest,    \* `log_read_newest`: [of, at], one an account, key and version, its newest read's time
    touched,   \* ghost: what the attacker deleted or set an entry of `log_read_newest` of
    fl         \* retention's sweep below the oldest day of reads: the floor it read, not yet swept by (0: none)

vars == <<seq, done, usesT, changesT, st, live, sealed, tu, tc, reads, cur, curOk, maced, pr, attacks, crashes, gone, cut, newest, touched, fl>>
writes == <<seq, done, usesT, changesT, st, live>>
seals == <<sealed, tu, tc>>
proj == <<reads, cur, curOk, maced, pr, newest>>

Init ==
    /\ seq = 0 /\ done = 0 /\ usesT = {} /\ changesT = {} /\ st = Start /\ live = Start
    /\ sealed = 0 /\ tu = {} /\ tc = {}
    /\ reads = {} /\ cur = 0 /\ curOk = TRUE /\ maced = {0}
    /\ pr = [p \in Projectors |-> [pc |-> "idle", from |-> 0, to |-> 0, rows |-> {}]]
    /\ attacks = 0 /\ crashes = 0 /\ gone = {} /\ cut = 0
    /\ newest = {} /\ touched = {} /\ fl = 0

-----------------------------------------------------------------------------
(* The writers: the next append of the script, numbered, then committed (Seal.tla checks the numbering, gaps and
   commits out of order; here one append is in flight at a time). *)

Number ==
    /\ seq = done /\ seq < N
    /\ seq' = seq + 1
    /\ UNCHANGED <<done, usesT, changesT, st, live>> /\ UNCHANGED seals /\ UNCHANGED proj /\ UNCHANGED <<attacks, crashes, gone, cut, touched, fl>>

Commit ==
    /\ done < seq
    /\ LET n == seq
           e == Script[n]
       IN IF e.k = "c"
          THEN /\ changesT' = changesT \cup {[n |-> n, obj |-> e.obj, val |-> e.val]}
               /\ st' = [st EXCEPT ![e.obj] = e.val]
               /\ live' = [live EXCEPT ![e.obj] = e.val]
               /\ UNCHANGED usesT
          ELSE /\ usesT' = usesT \cup {[n |-> n, cred |-> e.cred, key |-> e.key, dec |-> Proj(st, e.cred, e.key)]}
               /\ UNCHANGED <<changesT, st, live>>
    /\ done' = seq
    /\ UNCHANGED seq /\ UNCHANGED seals /\ UNCHANGED proj /\ UNCHANGED <<attacks, crashes, gone, cut, touched, fl>>

-----------------------------------------------------------------------------
(* The signer: seals what the tables hold up to any number below which every append has committed (Seal.tla's
   barrier). Without ProjectorApart the tick
   projects the window it sealed before it seals the next: it waits for the cursor. *)

SignTo(k) ==
    /\ sealed < k /\ k <= done
    /\ ProjectorApart \/ cur >= sealed
    /\ sealed' = k
    /\ tu' = tu \cup {u \in usesT : sealed < u.n /\ u.n <= k}
    /\ tc' = tc \cup {c \in changesT : sealed < c.n /\ c.n <= k}
    /\ UNCHANGED writes /\ UNCHANGED proj /\ UNCHANGED <<attacks, crashes, gone, cut, touched, fl>>

Sign == \E k \in Nums : SignTo(k)

-----------------------------------------------------------------------------
(* The projector. *)

\* A use's row as the projector derives it: from the changes below it that the tree holds, or from the live rows.
Derive(u) ==
    IF DeriveFromSealed
    THEN Proj(StateAt(changesT \cap tc, u.n), u.cred, u.key)
    ELSE Proj(live, u.cred, u.key)

\* `log_read_newest` once the rows `rows` are written: each of what they are of at their newest time, or the time it
\* had if greater (GreatestAt).
Upsert(ns, rows) ==
    LET ofs == {Of(r) : r \in rows}
        top(o) == CHOOSE t \in {r.at : r \in {x \in rows : Of(x) = o}} : \A x \in rows : Of(x) = o => x.at <= t
        had(o) == {e \in ns : e.of = o}
        at(o) == IF GreatestAt /\ had(o) # {} THEN Max(top(o), (CHOOSE e \in had(o) : TRUE).at) ELSE top(o)
    IN {e \in ns : e.of \notin ofs} \cup {[of |-> o, at |-> at(o)] : o \in ofs}

\* Reads the cursor and its chunk, and derives the chunk's rows: only if its window's rows are the sealed uses
\* (WindowChecked) and each derivation is what the use's MAC covers (InputsInUseMac); otherwise it cannot go on.
PRead(p) ==
    /\ pr[p].pc = "idle"
    /\ CursorMac => curOk
    /\ LET from == cur
           to == Min(from + Chunk, IF ProjectSealedOnly THEN sealed ELSE seq)
           w == {u \in usesT : from < u.n /\ u.n <= to}
       IN /\ from < to
          /\ WindowChecked => w = {u \in tu : from < u.n /\ u.n <= to}
          /\ InputsInUseMac => \A u \in w : Derive(u) = u.dec
          /\ pr' = [pr EXCEPT ![p] = [pc |-> IF CursorAfterRows THEN "rows" ELSE "cursor", from |-> from, to |-> to,
                                      rows |-> {[n |-> u.n, p |-> Derive(u), at |-> At[u.n], ok |-> TRUE, by |-> p] : u \in w}]]
    /\ UNCHANGED writes /\ UNCHANGED seals /\ UNCHANGED <<reads, cur, curOk, maced, attacks, crashes, gone, cut, newest, touched, fl>>

\* The chunk's rows, one statement: each replacing the rows at its number (ReplaceOnConflict) or skipped where it has
\* one (IdempotentByNumber alone), or inserted as is.
\* Overtaken (FromChecked): the cursor no longer where the chunk started, nothing is written and the run ends.
\* The rows written, inserted or replacing, write their entries of `log_read_newest` in the same statement
\* (NewestWithRows: the trigger), or the run writes them once its cursor has moved.
\* The run's end: idle, or, the entries written apart, those.
Ended(p) == IF NewestWithRows THEN [pr[p] EXCEPT !.pc = "idle"] ELSE [pr[p] EXCEPT !.pc = "newest"]
PRows(p) ==
    /\ pr[p].pc = "rows"
    /\ IF FromChecked /\ cur # (IF CursorAfterRows THEN pr[p].from ELSE pr[p].to)
       THEN /\ pr' = [pr EXCEPT ![p] = [pc |-> "idle", from |-> 0, to |-> 0, rows |-> {}]]
            /\ UNCHANGED <<reads, newest>>
       ELSE /\ LET rows == pr[p].rows
                   nums == {r.n : r \in rows}
                   written == CASE IdempotentByNumber /\ ReplaceOnConflict -> rows
                                [] IdempotentByNumber -> {r \in rows : ~\E x \in reads : x.n = r.n}
                                [] OTHER -> rows
               IN /\ reads' = CASE IdempotentByNumber /\ ReplaceOnConflict -> {x \in reads : x.n \notin nums} \cup rows
                                [] OTHER -> reads \cup written
                  /\ newest' = IF NewestWithRows THEN Upsert(newest, written) ELSE newest
                  \* Written apart, the run keeps what it wrote for its entries.
                  /\ LET kept == IF NewestWithRows THEN rows ELSE written
                     IN pr' = [pr EXCEPT ![p] = IF CursorAfterRows THEN [pr[p] EXCEPT !.pc = "cursor", !.rows = kept] ELSE [Ended(p) EXCEPT !.rows = kept]]
    /\ UNCHANGED writes /\ UNCHANGED seals /\ UNCHANGED <<cur, curOk, maced, attacks, crashes, gone, cut, touched, fl>>

\* The cursor moved to the chunk's end, with its MAC: only forward (IdempotentByNumber), or wherever this run read.
PCursor(p) ==
    /\ pr[p].pc = "cursor"
    /\ LET to == pr[p].to IN
       IF IdempotentByNumber /\ to <= cur
       THEN UNCHANGED <<cur, curOk>>
       ELSE cur' = to /\ curOk' = TRUE
    /\ maced' = maced \cup {pr[p].to}
    /\ pr' = [pr EXCEPT ![p] = IF CursorAfterRows THEN Ended(p) ELSE [pr[p] EXCEPT !.pc = "rows"]]
    /\ UNCHANGED writes /\ UNCHANGED seals /\ UNCHANGED <<reads, attacks, crashes, gone, cut, newest, touched, fl>>

\* NewestWithRows off: the entries of the rows the run wrote, once it has moved the cursor.
PNewest(p) ==
    /\ pr[p].pc = "newest"
    /\ newest' = Upsert(newest, pr[p].rows)
    /\ pr' = [pr EXCEPT ![p] = [pc |-> "idle", from |-> 0, to |-> 0, rows |-> {}]]
    /\ UNCHANGED writes /\ UNCHANGED seals /\ UNCHANGED <<reads, cur, curOk, maced, attacks, crashes, gone, cut, touched, fl>>

\* A projector dies mid-run and loses what it derived; the next run starts from the cursor.
PCrash(p) ==
    /\ pr[p].pc # "idle"
    /\ crashes < MaxCrashes
    /\ crashes' = crashes + 1
    /\ pr' = [pr EXCEPT ![p] = [pc |-> "idle", from |-> 0, to |-> 0, rows |-> {}]]
    /\ UNCHANGED writes /\ UNCHANGED seals /\ UNCHANGED <<reads, cur, curOk, maced, attacks, gone, cut, newest, touched, fl>>

PStep(p) == PRead(p) \/ PRows(p) \/ PCursor(p) \/ PNewest(p)

-----------------------------------------------------------------------------
(* Retention: a cut at or below the newest pair and the cursor it holds (retention.ts, behindReads), the uses and the
   rows at or below it dropped with their days, and (NewestRetired) the entries of `log_read_newest` at or below the
   time of the newest it drops: a day's go with it, `drop_reads_day`. The uses and rows go by number here and the
   entries by time, where the code drops all three by day: the same cut only while clocks run in number order, as
   `ReadsAt` does, so a scenario that turns `Retention` on keeps it (ReadsRetain.cfg; review r5 of #560). *)

RetainTo(k) ==
    /\ Retention /\ cut < k /\ k <= sealed /\ k <= cur
    /\ CursorMac => curOk
    /\ cut' = k
    /\ usesT' = {u \in usesT : u.n > k}
    /\ reads' = {r \in reads : r.n > k}
    /\ newest' = IF NewestRetired THEN {e \in newest : e.at > CutAt(k)} ELSE newest
    /\ UNCHANGED <<seq, done, changesT, st, live>> /\ UNCHANGED seals /\ UNCHANGED <<cur, curOk, maced, pr, attacks, crashes, gone, touched, fl>>

Retain == \E k \in Nums : RetainTo(k)

\* The sweep's floor: the oldest time of a read left (each read lies in its day's partition, which is at or below it),
\* or, none left, past every time: all go.
Floor == IF reads = {} THEN (CHOOSE t \in Times : \A x \in Times : x <= t) + 1
         ELSE CHOOSE t \in {r.at : r \in reads} : \A r \in reads : t <= r.at
\* Each call's sweep (retention's calls, `kept` included): under the projector's lock (PruneLocked), the floor read and
\* the entries below it dropped at once, never inside a projector's call (its rows written, its cursor not yet moved);
\* apart, the floor read now and swept by later.
Prune ==
    /\ Retention /\ fl = 0
    /\ IF PruneLocked
       THEN /\ \A p \in Projectors : pr[p].pc # "cursor"
            /\ newest' = {e \in newest : e.at >= Floor}
            /\ UNCHANGED fl
       ELSE /\ fl' = Floor
            /\ UNCHANGED newest
    /\ UNCHANGED writes /\ UNCHANGED seals /\ UNCHANGED <<reads, cur, curOk, maced, pr, attacks, crashes, gone, cut, touched>>
Swept ==
    /\ fl # 0
    /\ newest' = {e \in newest : e.at >= fl}
    /\ fl' = 0
    /\ UNCHANGED writes /\ UNCHANGED seals /\ UNCHANGED <<reads, cur, curOk, maced, pr, attacks, crashes, gone, cut, touched>>

-----------------------------------------------------------------------------
(* The attacker: write access to the database, no key. *)

Attack(kind) ==
    /\ kind \in Attacks
    /\ attacks < MaxAttacks
    /\ attacks' = attacks + 1
    /\ UNCHANGED seals /\ UNCHANGED <<seq, done, st, pr, crashes, cut, fl>>

\* A use deleted, or two uses' numbers swapped (both MACs hold: they do not cover the number), sealed or not.
DeleteUse == Attack("uses") /\ \E u \in usesT : usesT' = usesT \ {u}
               /\ UNCHANGED <<changesT, live, reads, cur, curOk, maced, gone, cut, newest, touched, fl>>
SwapUses == Attack("uses") /\ \E u1, u2 \in usesT : u1.n < u2.n
               /\ usesT' = (usesT \ {u1, u2}) \cup {[u1 EXCEPT !.n = u2.n], [u2 EXCEPT !.n = u1.n]}
               /\ UNCHANGED <<changesT, live, reads, cur, curOk, maced, gone, cut, newest, touched, fl>>
\* A change's row deleted, sealed or not.
DeleteChange == Attack("changes") /\ \E c \in changesT : changesT' = changesT \ {c}
               /\ UNCHANGED <<usesT, live, reads, cur, curOk, maced, gone, cut, newest, touched, fl>>
\* A live row edited: a credential's account, a key's place, the reference's source.
Flip(o, s) ==
    IF o \in Creds THEN [s EXCEPT !.acct = Other(s.acct, Accounts)]
    ELSE IF o \in Keys THEN [s EXCEPT !.pl = Other(s.pl, Places)]
    ELSE [s EXCEPT !.src = Other(s.src, Keys)]
EditLive == Attack("live") /\ \E o \in Objs : live' = [live EXCEPT ![o] = Flip(o, live[o])]
               /\ UNCHANGED <<usesT, changesT, reads, cur, curOk, maced, gone, cut, newest, touched, fl>>
\* A projection row deleted; copied under another number (its MAC holds unless it covers the number); or made up.
DeleteRead == Attack("reads") /\ \E r \in reads :
               /\ reads' = reads \ {r}
               /\ gone' = IF r.by \in Projectors THEN gone \cup {r.n} ELSE gone
               /\ UNCHANGED <<usesT, changesT, live, cur, curOk, maced, newest, touched, fl>>
CopyRead == Attack("reads") /\ \E r \in reads, n \in Nums : n # r.n
               /\ reads' = reads \cup {[r EXCEPT !.n = n, !.ok = r.ok /\ ~NumberInMac, !.by = "attacker"]}
               /\ UNCHANGED <<usesT, changesT, live, cur, curOk, maced, gone, cut, newest, touched, fl>>
ForgeRead == Attack("reads") /\ \E n \in Nums :
               /\ reads' = reads \cup {[n |-> n, p |-> Junk, at |-> At[n], ok |-> FALSE, by |-> "attacker"]}
               /\ UNCHANGED <<usesT, changesT, live, cur, curOk, maced, gone, cut, newest, touched, fl>>
\* The cursor set to any number: its MAC holds only for one the vault wrote.
SetCursor == Attack("cursor") /\ \E v \in 0..N : v # cur
               /\ cur' = v /\ curOk' = (v \in maced)
               /\ UNCHANGED <<usesT, changesT, live, reads, maced, gone, cut, newest, touched, fl>>

\* An entry of `log_read_newest` deleted, or its time set to another (it carries no MAC: what the full verify holds it to
\* is the rows').
DeleteNewest == Attack("newest") /\ \E e \in newest :
               /\ newest' = newest \ {e} /\ touched' = touched \cup {e.of}
               /\ UNCHANGED <<usesT, changesT, live, reads, cur, curOk, maced, gone>>
SetNewest == Attack("newest") /\ \E e \in newest, t \in Times : t # e.at
               /\ newest' = (newest \ {e}) \cup {[e EXCEPT !.at = t]} /\ touched' = touched \cup {e.of}
               /\ UNCHANGED <<usesT, changesT, live, reads, cur, curOk, maced, gone>>

-----------------------------------------------------------------------------

Next ==
    \/ Number \/ Commit \/ Sign \/ Retain \/ Prune \/ Swept
    \/ \E p \in Projectors : PStep(p) \/ PCrash(p)
    \/ DeleteUse \/ SwapUses \/ DeleteChange \/ EditLive \/ DeleteRead \/ CopyRead \/ ForgeRead \/ SetCursor
    \/ DeleteNewest \/ SetNewest

Spec == Init /\ [][Next]_vars
\* The signer alone is fair: the projector may stop for good.
SignerFairSpec == Spec /\ WF_vars(Sign)
\* The signer and every projector fair.
FairSpec == Spec /\ WF_vars(Sign) /\ \A p \in Projectors : WF_vars(PStep(p))

-----------------------------------------------------------------------------
(* The page and the full verify. *)

SealedUses == {u.n : u \in tu}
\* The replay's projection of the sealed use u: the sealed changes below its number.
Replay(u) == Proj(StateAt(tc, u.n), u.cred, u.key)

\* The page shows anything only under a cursor it accepts; it lists the rows at or below it whose MAC holds.
PageShown == CursorMac => curOk
Listed == {r \in reads : r.ok /\ r.n <= cur}
\* What it claims: every sealed use at or below the cursor, above retention's cut, has its row.
Missing == {n \in SealedUses : cut < n /\ n <= cur /\ ~\E r \in Listed : r.n = n}

\* A row an entry of `log_read_newest` names, at its time or later: what the report says of it.
Covered(r) == \E e \in newest : e.of = Of(r) /\ e.at >= r.at
\* The sealed uses' rows the page lists, above the cut, that the report would not name.
Unnamed == {r \in Listed : r.n \in SealedUses /\ cut < r.n /\ ~Covered(r)}

\* The full verify: a listed row that is no sealed use's, or (CountChecked) a sealed use with no row, or a cursor
\* whose MAC fails; or (NewestChecked) a sealed use's row no entry of `log_read_newest` covers.
FullFlags ==
    \/ CursorMac /\ ~curOk
    \/ \E r \in Listed : r.n \notin SealedUses
    \/ CountChecked /\ Missing # {}
    \/ NewestChecked /\ Unnamed # {}

\* Seal's verifier (Seal.tla's SealedDeletionDetected): a sealed entry gone from its table, or moved.
SealFlags == (\E c \in tc : c \notin changesT) \/ (\E u \in tu : u \notin usesT)

-----------------------------------------------------------------------------
(* Invariants. *)

\* Every row the page lists states what the replay gives for that number, a sealed use's.
ProjectionMatchesReplay ==
    PageShown => \A r \in Listed : \E u \in tu : u.n = r.n /\ r.p = Replay(u)

\* ... or Seal's verifier sees a sealed entry gone (InputsInUseMac off: ReadsProbe).
ProjectionMatchesReplayOrFlagged ==
    ProjectionMatchesReplay \/ SealFlags

\* No listed row above `sealed`, nor at a number that is no sealed use's.
OnlySealedProjected ==
    PageShown => \A r \in Listed : r.n <= sealed /\ r.n \in SealedUses

\* What the page says is so: reads sealed through a cursor at or below `sealed` (below it, it says so), every sealed
\* use at or below it listed but those whose row the attacker deleted (DeletionDetected's).
LagShown ==
    PageShown => cur <= sealed /\ Missing \subseteq gone

\* Two projectors never leave two rows for one number.
NoDuplicate ==
    \A r1, r2 \in reads : r1 # r2 /\ r1.by \in Projectors /\ r2.by \in Projectors => r1.n # r2.n

\* A projection row the attacker deleted, at or below the cursor and not written again, is flagged by the full verify.
DeletionDetected ==
    (Missing \cap gone # {}) => FullFlags

\* Nothing retention dropped is written back: no projector's row at or below the cut.
RetiredStayGone ==
    \A r \in reads : r.by \in Projectors => r.n > cut

\* The offboarding report names every read the page lists of a projector's: its account, key and version, at its
\* time or later; but for what the attacker deleted or set an entry of.
ReportNamesListed ==
    PageShown => \A r \in Listed : r.by \in Projectors /\ Of(r) \notin touched => Covered(r)

\* A listed read the report would not name is flagged by the full verify, whoever made it so.
UnnamedDetected ==
    PageShown => (Unnamed # {} => FullFlags)

\* The report names nothing retention dropped: no entry of `log_read_newest` at or below the cut's time, but one the
\* attacker set.
RetiredUnnamed ==
    \A e \in newest : e.of \notin touched => e.at > CutAt(cut)

\* The signer can always seal what is committed, whatever the projector does.
SealNeverWaitsOnProjection ==
    sealed < done => ENABLED Sign

\* EXPECTED TO FAIL, with every protection: the page does not see a row deleted below its cursor (the full verify does).
ListedComplete ==
    PageShown => Missing = {}

-----------------------------------------------------------------------------
(* Liveness. *)

\* Every committed change is eventually answered: sealed (R51), with the signer alone fair.
ChangeAnswered ==
    \A i \in Nums : Script[i].k = "c" => ((done >= i) ~> (sealed >= i))

\* Every sealed use is eventually projected, and the cursor reaches `sealed`, with the projector fair.
EveryUseProjected ==
    \A i \in Nums : (i \in SealedUses) ~> (\E r \in reads : r.ok /\ r.n = i)
CursorReachesSeal ==
    \A k \in Nums : (sealed >= k) ~> (cur >= k)

=============================================================================
