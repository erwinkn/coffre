// 0.16, changes and uses. A change reads rows, decides in TypeScript, then
// writes in one statement under the change lock, only if the rows it read
// still carry the MACs it read. A use reads a row or answers from the vault's
// short memory. mac(p) stands for the MAC of p's row: it moves on each write.
module change {
  type Role = Out | Member | Owner
  type Op = Promote | Demote | Remove
  type Change = { decided: bool, op: Op, target: str, deps: Set[str], seen: str -> int, left: int }
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
  var mac: str -> int
  var chg: str -> Change
  var use: str -> Use
  var cache: str -> Memory
  var clock: int
  var gone: str -> int
  var bad: bool
  var late: bool

  val owners = People.filter(p => role.get(p) == Owner)
  pure def after(op: Op): Role = match op { | Promote => Owner | Demote => Member | Remove => Out }
  pure def idle(p: str, left: int): Change =
    { decided: false, op: Promote, target: p, deps: Set(), seen: People.mapBy(_ => 0), left: left }
  def may(p: str, op: Op, t: str): bool = and {
    role.get(p) == Owner,
    after(op) != role.get(t),
    op == Demote implies role.get(t) == Owner,
    (op != Promote and role.get(t) == Owner) implies owners.size() > 1,
  }

  action init = all {
    role' = People.mapBy(_ => Owner),
    mac' = People.mapBy(_ => 0),
    chg' = People.mapBy(p => idle(p, MaxChanges)),
    use' = People.mapBy(_ => { reading: false, ok: false, at: 0 }),
    cache' = People.mapBy(_ => { ok: false, at: 0 }),
    clock' = 0,
    gone' = People.mapBy(_ => 0),
    bad' = false,
    late' = false,
  }

  // One read: the caller's row, the target's, and the Owners when it removes one.
  // A refusal is a step that changes nothing, so a replayed trace holds the
  // code to refusing too.
  action read(p: str, op: Op, t: str): bool = all {
    not(chg.get(p).decided), chg.get(p).left > 0,
    chg' = if (not(may(p, op, t))) chg else chg.set(p, {
      decided: true, op: op, target: t, seen: mac, left: chg.get(p).left - 1,
      deps: Set(p, t).union(if (op != Promote and role.get(t) == Owner) owners else Set()),
    }),
    role' = role, mac' = mac, use' = use, cache' = cache, clock' = clock, gone' = gone, bad' = bad, late' = late,
  }

  // One write, under the change lock: nothing happens if a row it read moved.
  action write(p: str): bool = {
    val c = chg.get(p)
    val held = if (CompareReads) c.deps else Set(c.target)
    val still = held.forall(q => mac.get(q) == c.seen.get(q))
    all {
      c.decided,
      chg' = chg.set(p, idle(p, c.left)),
      role' = if (still) role.set(c.target, after(c.op)) else role,
      mac' = if (still) mac.setBy(c.target, m => m + 1) else mac,
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
      role' = role, mac' = mac, chg' = chg, cache' = cache, clock' = clock, gone' = gone, bad' = bad,
    }
  }

  action useAnswer(p: str): bool = {
    val u = use.get(p)
    all {
      u.reading,
      use' = use.set(p, { reading: false, ok: false, at: 0 }),
      cache' = cache.set(p, { ok: u.ok, at: if (not(u.ok)) 0 else if (StampAtRead) u.at else clock }),
      role' = role, mac' = mac, chg' = chg, clock' = clock, gone' = gone, bad' = bad, late' = late,
    }
  }

  action tick = all {
    clock < MaxClock, clock' = clock + 1,
    role' = role, mac' = mac, chg' = chg, use' = use, cache' = cache, gone' = gone, bad' = bad, late' = late,
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
