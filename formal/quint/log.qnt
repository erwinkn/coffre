// 0.16, the log against someone who can write the database but holds no key.
//
// A change or a use commits its row and its log entry together; the entry
// waits in `pending`. The vault then tells the signer the entry exists (the
// wake-up). The signer runs outside the database and keeps its own copy of
// every access row's MAC, the mirror. It reads what waits, holds each change
// to the mirror (the MAC the entry replaced must be the mirror's), and signs
// it into the log; once a minute the same read also takes the rows, which
// must equal the mirror.
//
// A row's MAC is a number, 0 for no row. The writer can put back any MAC the
// vault once made, delete or put back any waiting entry, and delete any entry
// of the log; it cannot make a MAC. Of the log, the check holds only that it
// ends with the entry signed last: one step whatever its size. An entry
// deleted further back, or the last one once another has been signed after
// it, is the re-check of old entries' to find (D222), and not modelled.
// `quiet`: without tampering, and with the signer on time, nothing alerts.
// `caught`: no full check passes over a row that differs from what the
// entries say, a change that wrote or found such a row, a missing entry the
// signer heard of, or a shortened log. The one exception is a row with an entry
// whose wake-up never arrived.
module log {
  type Entry = { row: str, was: int, now: int, read: str, saw: int, at: int }
  type Snap = { on: bool, full: bool, at: int, pending: Set[int], expected: Set[int], rows: str -> int, ends: bool, wrong: bool }
  type Db = { rows: str -> int, pending: Set[int], log: Set[int] }
  type Vault = { made: List[Entry], calls: Set[int], lost: Set[int] }
  type Signer = { expected: Set[int], root: Set[int], mirror: str -> int, moving: Set[int], order: List[int], snap: Snap, drained: int, alert: bool }
  type World = { clock: int, attacks: int, slow: bool, tainted: Set[int], missed: bool }

  const Rows: Set[str]
  const MaxVal: int
  const MaxEntries: int
  const MaxClock: int
  const Fresh: int          // how long before its last read the signer still takes an entry's date
  const Attacks: int        // how many times the writer acts
  // The protections: each run again with one off must fail.
  const Wake: bool          // the vault tells the signer of each entry
  const Dedupe: bool        // a wake-up for an entry already signed is dropped
  const Once: bool          // an entry the signer remembers signing is refused
  const FreshOnly: bool     // an entry dated before the window is refused
  const CaptureFirst: bool  // what is expected is noted before the read, not after
  const OneSnapshot: bool   // the rows and the waiting entries come from one read
  const KeepIntent: bool    // what was signed is kept until it is moved
  const SizeCheck: bool     // the log must end with the entry signed last
  const Chain: bool         // a change must replace the MAC the mirror holds
  const Reads: bool         // and must have decided on the MAC the mirror holds, of a row it read, found, and did not write

  var db: Db          // what the writer can change
  var vault: Vault    // made: every entry it MAC'd, by number; lost: wake-ups that never left
  var signer: Signer  // outside the database
  var world: World

  val made = vault.made
  val idle: Snap = { on: false, full: false, at: 0, pending: Set(), expected: Set(), rows: Rows.mapBy(_ => 0), ends: true, wrong: false }

  // The window opens `Fresh` before the signer's last read and slides with the
  // signer, not the clock: a signer that was away takes what waited for it. It
  // remembers what it signed for as long as it would still take it.
  def fresh(n: int): bool = made[n].at + Fresh >= signer.drained
  val remembered = signer.root.filter(n => fresh(n))
  def taken(ns: Set[int]): Set[int] = ns.filter(n => and {
    not(FreshOnly) or fresh(n),
    not(Once) or not(remembered.contains(n)),
  })

  // What a full check must not pass over. An entry is unheard while its wake-up
  // has not reached the signer; unheard and gone, nobody outside the database
  // knows it was written, and its row is no longer vouched for.
  // The log ends with the entry signed last: the newest one signed is in it.
  val ends = signer.order.length() == 0 or db.log.contains(signer.order[signer.order.length() - 1])
  def unheard(n: int): bool = vault.lost.union(vault.calls).contains(n)
  def gone(n: int): bool = not(signer.root.contains(n)) and not(db.pending.contains(n))
  val due = range(0, made.length()).foldl(Rows.mapBy(_ => 0), (r, n) =>
    if (made[n].was == made[n].now) r else r.set(made[n].row, made[n].now))
  def excused(row: str): bool = made.indices().exists(n => made[n].row == row and unheard(n) and gone(n))
  // A change decided on a row that was not what the entries say: its own, or the one it read and found.
  def decidedOn(n: int): bool = not(excused(made[n].row)) and not(excused(made[n].read))
  def offBook(row: str): bool = db.rows.get(row) != due.get(row) and not(excused(row))
  val wrong = or {
    world.tainted.exists(n => decidedOn(n)),
    Rows.exists(row => offBook(row)),
    made.indices().exists(n => not(unheard(n)) and gone(n)),
    not(ends),
  }
  // A wake-up still on its way when its entry leaves the window: only then does an honest run alert.
  def late(read: int): bool = vault.calls.exists(n => made[n].at + Fresh < read)

  action init = all {
    db' = { rows: Rows.mapBy(_ => 0), pending: Set(), log: Set() },
    vault' = { made: [], calls: Set(), lost: Set() },
    signer' = { expected: Set(), root: Set(), mirror: Rows.mapBy(_ => 0), moving: Set(), order: [], snap: idle, drained: 0, alert: false },
    world' = { clock: 0, attacks: Attacks, slow: false, tainted: Set(), missed: false },
  }

  // A change (v is a new MAC) or a use (v is the row's own): one statement
  // writes the row and the entry. A change is decided on a row it reads, its
  // own or another: the caller's, say, for a change to someone else's. Its
  // entry names the row it found. One it looked for and did not find it cannot
  // name, so a row taken away for the decision and put back after is not
  // caught: a decision must take nothing from a missing row. `sent` false: the
  // vault dies before the wake-up.
  action commit(row: str, v: int, read: str, sent: bool): bool = {
    val n = made.length()
    all {
      n < MaxEntries,
      db' = { ...db, rows: db.rows.set(row, v), pending: db.pending.union(Set(n)) },
      vault' = {
        made: made.append({ row: row, was: db.rows.get(row), now: v, read: read, saw: db.rows.get(read), at: world.clock }),
        calls: if (sent) vault.calls.union(Set(n)) else vault.calls,
        lost: if (sent) vault.lost else vault.lost.union(Set(n)),
      },
      signer' = signer,
      world' = if (v != db.rows.get(row) and (offBook(row) or (db.rows.get(read) != 0 and offBook(read)))) { ...world, tainted: world.tainted.union(Set(n)) } else world,
    }
  }

  action deliver(n: int): bool = all {
    vault.calls.contains(n),
    vault' = { ...vault, calls: vault.calls.exclude(Set(n)) },
    signer' = if (not(Wake) or (Dedupe and remembered.contains(n))) signer
      else { ...signer, expected: signer.expected.union(Set(n)) },
    db' = db, world' = world,
  }

  // The signer's run, in three steps. One read: what waits and, on a full run, the rows.
  action runRead(full: bool): bool = all {
    not(signer.snap.on), signer.moving == Set(),
    signer' = { ...signer, snap: {
      on: true, full: full, at: world.clock, pending: db.pending, expected: signer.expected,
      rows: if (full) db.rows else idle.rows, ends: not(full) or ends, wrong: full and wrong,
    } },
    db' = db, vault' = vault, world' = world,
  }

  // Outside the database: sign what it takes, and say what it found.
  action runSign: bool = {
    val s = signer.snap
    val good = taken(s.pending)
    // In the order they were written: each change moves the mirror from the MAC it replaced.
    val held = range(0, made.length()).foldl({ rows: signer.mirror, ok: true }, (m, n) =>
      if (not(good.contains(n)) or made[n].was == made[n].now) m
      else {
        rows: m.rows.set(made[n].row, made[n].now),
        ok: m.ok and (not(Chain) or m.rows.get(made[n].row) == made[n].was) and (not(Reads) or made[n].read == made[n].row or made[n].saw == 0 or m.rows.get(made[n].read) == made[n].saw),
      })
    val found = or {
      good != s.pending,
      not((if (CaptureFirst) s.expected else signer.expected).subseteq(s.pending)),
      not(held.ok),
      s.full and held.rows != (if (OneSnapshot) s.rows else db.rows),
      s.full and SizeCheck and not(s.ends),
    }
    all {
      s.on,
      signer' = {
        expected: signer.expected.exclude(good), root: signer.root.union(good), mirror: held.rows,
        moving: good, order: signer.order.concat(range(0, made.length()).select(n => good.contains(n))),
        snap: idle, drained: s.at, alert: signer.alert or found,
      },
      world' = { ...world, slow: world.slow or late(s.at), missed: world.missed or (s.wrong and not(signer.alert or found)) },
      db' = db, vault' = vault,
    }
  }

  // In the database: move what was signed into the log. A run that died here is finished by the next.
  action runMove: bool = all {
    signer.moving != Set(),
    db' = { ...db, log: db.log.union(signer.moving.intersect(db.pending)), pending: db.pending.exclude(signer.moving) },
    signer' = { ...signer, moving: Set() },
    vault' = vault, world' = world,
  }

  action forget: bool = all {
    not(KeepIntent), signer.moving != Set(),
    signer' = { ...signer, moving: Set() },
    db' = db, vault' = vault, world' = world,
  }

  action tick: bool = all {
    world.clock < MaxClock,
    world' = { ...world, clock: world.clock + 1 },
    db' = db, vault' = vault, signer' = signer,
  }

  // The writer: a MAC the vault once gave the row or no row, a waiting entry out
  // or back in, an entry out of the log.
  action attack: bool = all {
    world.attacks > 0,
    world' = { ...world, attacks: world.attacks - 1 },
    vault' = vault, signer' = signer,
    any {
      nondet row = Rows.oneOf()
      nondet v = 0.to(MaxVal).oneOf()
      all {
        db.rows.get(row) != v,
        v == 0 or made.indices().exists(n => made[n].row == row and made[n].now == v),
        db' = { ...db, rows: db.rows.set(row, v) },
      },
      nondet n = made.indices().oneOf()
      any {
        all { db.pending.contains(n), db' = { ...db, pending: db.pending.exclude(Set(n)) } },
        all { not(db.pending.contains(n)), db' = { ...db, pending: db.pending.union(Set(n)) } },
        all { db.log.contains(n), db' = { ...db, log: db.log.exclude(Set(n)) } },
      },
    },
  }

  action step = any {
    nondet row = Rows.oneOf()
    nondet v = 0.to(MaxVal).oneOf()
    nondet read = Rows.oneOf()
    nondet sent = Set(true, false).oneOf()
    commit(row, v, read, sent),
    nondet n = 0.to(MaxEntries - 1).oneOf()
    deliver(n),
    nondet full = Set(true, false).oneOf()
    runRead(full),
    runSign, runMove, forget, tick,
    all { made.length() > 0, attack },
  }

  val quiet = signer.alert implies (world.attacks < Attacks or world.slow)
  val caught = not(world.missed)
  val safe = quiet and caught
}

module logSound {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = true, Reads = true).*
}
module noWake {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = false, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = true, Reads = true).*
}
module noDedupe {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = false, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = true, Reads = true).*
}
module twice {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = false, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = true, Reads = true).*
}
module stale {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = false, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = true, Reads = true).*
}
module captureLate {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = false, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = true, Reads = true).*
}
module twoReads {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = false, KeepIntent = true, SizeCheck = true, Chain = true, Reads = true).*
}
module forgetful {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = false, SizeCheck = true, Chain = true, Reads = true).*
}
module noSize {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = false, Chain = true, Reads = true).*
}
module noChain {
  import log(Rows = Set("g"), MaxVal = 2, MaxEntries = 3, MaxClock = 2, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = false, Reads = true).*
}

// Two rows, each there or not: a change to one decided on the other.
module logTwo {
  import log(Rows = Set("g", "h"), MaxVal = 1, MaxEntries = 3, MaxClock = 1, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = true, Reads = true).*
}
module noReads {
  import log(Rows = Set("g", "h"), MaxVal = 1, MaxEntries = 3, MaxClock = 1, Fresh = 1, Attacks = 2,
    Wake = true, Dedupe = true, Once = true, FreshOnly = true, CaptureFirst = true, OneSnapshot = true, KeepIntent = true, SizeCheck = true, Chain = true, Reads = false).*
}
