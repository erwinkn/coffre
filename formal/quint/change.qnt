// 0.16, changes and uses. A change reads rows, decides in TypeScript, then
// writes in one statement under the change lock, only if what it read is as
// it read it: the same rows, each with the MAC it had. A change of a role
// reads the caller, the target and every Owner, since it counts them, as the
// code does (packages/vault/src/change.ts). A use reads a row or answers from
// the vault's short memory. A row's MAC is a function of its content, here
// (role, gen): gen counts removals, as a principal's generation does. So a row
// that went from Owner to Member and back carries the MAC it had, and a change
// that read it before still lands: its decision holds for a row with that
// content, whenever it was read.
module change {
  type Role = Out | Member | Owner
  type Op = Promote | Demote | Remove
  type Row = (Role, int)
  type Change = { decided: bool, op: Op, target: str, deps: Set[str], seen: str -> Row, owned: Set[str], left: int }
  type Use = { reading: bool, ok: bool, at: int }
  type Memory = { ok: bool, at: int }

  const People: Set[str]
  const Users: Set[str]
  const TTL: int
  const MaxClock: int
  const MaxChanges: int
  const CompareReads: bool   // false: the write compares only the row it writes
  const StampAtRead: bool    // false: the memory is dated when the use answers

  var role: str -> Role
  var gen: str -> int
  var chg: str -> Change
  var use: str -> Use
  var cache: str -> Memory
  var clock: int
  var gone: str -> int
  var bad: bool
  var late: bool

  val owners = People.filter(p => role.get(p) == Owner)
  val rows = People.mapBy(p => (role.get(p), gen.get(p)))
  pure def after(op: Op): Role = match op { | Promote => Owner | Demote => Member | Remove => Out }
  pure def idle(p: str, left: int): Change =
    { decided: false, op: Promote, target: p, deps: Set(), seen: People.mapBy(_ => (Out, 0)), owned: Set(), left: left }
  def may(p: str, op: Op, t: str): bool = and {
    role.get(p) == Owner,
    after(op) != role.get(t),
    op == Demote implies role.get(t) == Owner,
    (op != Promote and role.get(t) == Owner) implies owners.size() > 1,
  }

  action init = all {
    role' = People.mapBy(_ => Owner),
    gen' = People.mapBy(_ => 0),
    chg' = People.mapBy(p => idle(p, MaxChanges)),
    use' = People.mapBy(_ => { reading: false, ok: false, at: 0 }),
    cache' = People.mapBy(_ => { ok: false, at: 0 }),
    clock' = 0,
    gone' = People.mapBy(_ => 0),
    bad' = false,
    late' = false,
  }

  // One read: the caller's row, the target's, and the Owners. A refusal is a
  // step that changes nothing, so a replayed trace holds the code to refusing
  // too.
  action read(p: str, op: Op, t: str): bool = all {
    not(chg.get(p).decided), chg.get(p).left > 0,
    chg' = if (not(may(p, op, t))) chg else chg.set(p, {
      decided: true, op: op, target: t, seen: rows, left: chg.get(p).left - 1,
      deps: Set(p, t).union(owners), owned: owners,
    }),
    role' = role, gen' = gen, use' = use, cache' = cache, clock' = clock, gone' = gone, bad' = bad, late' = late,
  }

  // One write, under the change lock: nothing happens if a row it read moved,
  // or if the Owners are no longer the ones it read, one more included.
  action write(p: str): bool = {
    val c = chg.get(p)
    val held = if (CompareReads) c.deps else Set(c.target)
    val still = held.forall(q => rows.get(q) == c.seen.get(q)) and (not(CompareReads) or owners == c.owned)
    all {
      c.decided,
      chg' = chg.set(p, idle(p, c.left)),
      role' = if (still) role.set(c.target, after(c.op)) else role,
      gen' = if (still and c.op == Remove) gen.setBy(c.target, n => n + 1) else gen,
      gone' = if (still and c.op == Remove) gone.set(c.target, clock) else gone,
      bad' = (bad or (still and role.get(p) != Owner)),
      use' = use, cache' = cache, clock' = clock, late' = late,
    }
  }

  // A use: from memory while it is fresh, else one read of the row.
  action useStart(p: str): bool = {
    val hit = cache.get(p).ok and clock < cache.get(p).at + TTL
    all {
      not(use.get(p).reading),
      late' = (late or (hit and role.get(p) == Out and clock >= gone.get(p) + TTL)),
      use' = if (hit) use else use.set(p, { reading: true, ok: role.get(p) != Out, at: clock }),
      role' = role, gen' = gen, chg' = chg, cache' = cache, clock' = clock, gone' = gone, bad' = bad,
    }
  }

  action useAnswer(p: str): bool = {
    val u = use.get(p)
    all {
      u.reading,
      use' = use.set(p, { reading: false, ok: false, at: 0 }),
      cache' = cache.set(p, { ok: u.ok, at: if (not(u.ok)) 0 else if (StampAtRead) u.at else clock }),
      role' = role, gen' = gen, chg' = chg, clock' = clock, gone' = gone, bad' = bad, late' = late,
    }
  }

  action tick = all {
    clock < MaxClock, clock' = clock + 1,
    role' = role, gen' = gen, chg' = chg, use' = use, cache' = cache, gone' = gone, bad' = bad, late' = late,
  }

  action step = any {
    nondet p = People.oneOf()
    nondet t = People.oneOf()
    nondet op = Set(Promote, Demote, Remove).oneOf()
    read(p, op, t),
    nondet p = People.oneOf()
    write(p),
    nondet p = Users.oneOf()
    any { useStart(p), useAnswer(p) },
    tick,
  }

  val alwaysAnOwner = owners.size() > 0
  val onlyOwnersChange = not(bad)
  val revokedWithinTTL = not(late)
  val safe = alwaysAnOwner and onlyOwnersChange and revokedWithinTTL
}

module sound {
  import change(People = Set("a", "b", "c"), Users = Set("c"), TTL = 2, MaxClock = 3, MaxChanges = 2, CompareReads = true, StampAtRead = true).*
}
module noReadSet {
  import change(People = Set("a", "b", "c"), Users = Set("c"), TTL = 2, MaxClock = 3, MaxChanges = 2, CompareReads = false, StampAtRead = true).*
}
module stampLate {
  import change(People = Set("a", "b", "c"), Users = Set("c"), TTL = 2, MaxClock = 3, MaxChanges = 2, CompareReads = true, StampAtRead = false).*
}
