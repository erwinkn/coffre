// 0.16, rotating the vault's key. Key 1 is replaced by key 2. The signer does
// it: one write re-MACs the policy row and logs key.rotate (the fence), a
// sweep re-MACs the other rows, and once nothing is left under key 1 it
// retires that key. Two vaults run through it: "old", a deployment not yet
// replaced, holds key 1 only; "new" holds both. A database writer who holds
// key 1, which is why it is being replaced, forges after the fence.
module rotate {
  type Mac = { key: int, n: int, forged: bool }
  type Entry = { change: bool, key: int, row: str, was: Mac, now: Mac }
  type Snap = { ok: bool, policy: Mac, grant: Mac, at: int }
  type Signer = { current: int, fencedAt: int, retired: bool, mirror: str -> Mac, alert: bool }

  const Mem: int               // how long a vault answers from memory
  const Wait: int              // how long after the fence key 1 is retired
  const MaxClock: int
  const Ops: int               // changes and uses per vault
  const Attacks: int
  const ComparePolicy: bool    // false: a change does not compare the policy row it read
  const UnderPolicy: bool      // false: a vault writes under its configuration's newest key
  const Drain: bool            // false: the fence leaves waiting changes unsigned
  const CurrentOnly: bool      // false: the signer takes a change under any key not retired

  var db: str -> Mac
  var pending: List[Entry]
  var snap: str -> Snap
  var left: str -> int
  var signer: Signer
  var clock: int
  var fresh: int
  var tampered: bool
  var attacks: int

  pure val Vaults = Set("old", "new")
  pure val first: Mac = { key: 1, n: 0, forged: false }
  pure val none: Snap = { ok: false, policy: first, grant: first, at: 0 }
  pure def holds(v: str): Set[int] = if (v == "old") Set(1) else Set(1, 2)
  pure def newest(v: str): int = if (v == "old") 1 else 2

  action init = all {
    db' = Set("policy", "grant").mapBy(_ => first),
    pending' = List(),
    snap' = Vaults.mapBy(_ => none),
    left' = Vaults.mapBy(_ => Ops),
    signer' = { current: 1, fencedAt: 0, retired: false, mirror: Set("policy", "grant").mapBy(_ => first), alert: false },
    clock' = 0, fresh' = 1, tampered' = false, attacks' = Attacks,
  }

  // One read. A vault that meets a row under a key it does not hold answers nothing.
  action read(v: str): bool = all {
    left.get(v) > 0,
    holds(v).contains(db.get("policy").key), holds(v).contains(db.get("grant").key),
    snap' = snap.set(v, { ok: true, policy: db.get("policy"), grant: db.get("grant"), at: clock }),
    db' = db, pending' = pending, left' = left, signer' = signer, clock' = clock, fresh' = fresh, tampered' = tampered, attacks' = attacks,
  }

  // One write, under the change lock: nothing happens if a row it read moved.
  action change(v: str): bool = {
    val s = snap.get(v)
    val still = (not(ComparePolicy) or db.get("policy") == s.policy) and db.get("grant") == s.grant
    val key = if (UnderPolicy) s.policy.key else newest(v)
    val mac = { key: key, n: fresh, forged: false }
    all {
      s.ok, left.get(v) > 0,
      snap' = snap.set(v, none),
      left' = left.setBy(v, n => n - 1),
      db' = if (still) db.set("grant", mac) else db,
      pending' = if (still) pending.append({ change: true, key: key, row: "grant", was: s.grant, now: mac }) else pending,
      fresh' = fresh + 1,
      signer' = signer, clock' = clock, tampered' = tampered, attacks' = attacks,
    }
  }

  // A use, from a read or from memory while it is fresh. It logs under the key it read.
  action use(v: str): bool = {
    val s = snap.get(v)
    all {
      s.ok, left.get(v) > 0, clock <= s.at + Mem,
      left' = left.setBy(v, n => n - 1),
      pending' = pending.append({ change: false, key: if (UnderPolicy) s.policy.key else newest(v), row: "grant", was: s.grant, now: s.grant }),
      db' = db, snap' = snap, signer' = signer, clock' = clock, fresh' = fresh, tampered' = tampered, attacks' = attacks,
    }
  }

  // The signer takes the oldest waiting entry.
  action sign = {
    val e = pending.head()
    val keyOk = if (not(e.change)) e.key == signer.current or not(signer.retired)
      else if (CurrentOnly) e.key == signer.current
      else e.key == signer.current or not(signer.retired)
    val fits = not(e.change) or e.was == signer.mirror.get(e.row)
    all {
      pending.length() > 0,
      pending' = pending.tail(),
      signer' = if (not(keyOk) or not(fits)) { ...signer, alert: true }
        else if (e.change) { ...signer, mirror: signer.mirror.set(e.row, e.now) }
        else signer,
      db' = db, snap' = snap, left' = left, clock' = clock, fresh' = fresh, tampered' = tampered, attacks' = attacks,
    }
  }

  // The fence: the signer signs what waits, then re-MACs the policy row and
  // logs key.rotate, all under the change lock.
  action fence = {
    val mac = { key: 2, n: fresh, forged: false }
    all {
      signer.current == 1, db.get("policy") == signer.mirror.get("policy"),
      Drain implies pending.select(e => e.change).length() == 0,
      db' = db.set("policy", mac),
      pending' = pending.append({ change: true, key: 2, row: "policy", was: db.get("policy"), now: mac }),
      signer' = { ...signer, current: 2, fencedAt: clock },
      fresh' = fresh + 1,
      snap' = snap, left' = left, clock' = clock, tampered' = tampered, attacks' = attacks,
    }
  }

  // The sweep: a row still under key 1 is re-MACed as an ordinary change.
  action sweep = {
    val was = db.get("grant")
    val mac = { key: 2, n: fresh, forged: was.forged }
    all {
      signer.current == 2, was.key == 1,
      db' = db.set("grant", mac),
      pending' = pending.append({ change: true, key: 2, row: "grant", was: was, now: mac }),
      fresh' = fresh + 1,
      snap' = snap, left' = left, signer' = signer, clock' = clock, tampered' = tampered, attacks' = attacks,
    }
  }

  // Key 1 is retired once nothing is under it, nothing under it waits, and
  // every memory read before the fence has lapsed.
  action retire = all {
    signer.current == 2, not(signer.retired),
    db.get("policy").key == 2, db.get("grant").key == 2,
    pending.select(e => e.key == 1).length() == 0,
    clock >= signer.fencedAt + Wait,
    signer' = { ...signer, retired: true },
    db' = db, pending' = pending, snap' = snap, left' = left, clock' = clock, fresh' = fresh, tampered' = tampered, attacks' = attacks,
  }

  // The minute's check: the rows against the mirror, with nothing waiting.
  action check = all {
    pending.length() == 0,
    signer' = { ...signer, alert: signer.alert or db != signer.mirror },
    db' = db, pending' = pending, snap' = snap, left' = left, clock' = clock, fresh' = fresh, tampered' = tampered, attacks' = attacks,
  }

  // The writer holds key 1 and writes the database: a row of their own under
  // key 1, with or without an entry that fits the mirror; or the policy row
  // as it was before the fence. Before the fence key 1 is the vault's key,
  // and whoever holds it is the vault.
  action forge(entry: bool): bool = {
    val mac = { key: 1, n: fresh, forged: true }
    all {
      attacks > 0, signer.current == 2,
      db' = db.set("grant", mac),
      pending' = if (entry) pending.append({ change: true, key: 1, row: "grant", was: signer.mirror.get("grant"), now: mac }) else pending,
      fresh' = fresh + 1, tampered' = true, attacks' = attacks - 1,
      snap' = snap, left' = left, signer' = signer, clock' = clock,
    }
  }
  action putBack = all {
    attacks > 0, signer.current == 2,
    db' = db.set("policy", first),
    tampered' = true, attacks' = attacks - 1,
    pending' = pending, snap' = snap, left' = left, signer' = signer, clock' = clock, fresh' = fresh,
  }

  action tick = all {
    clock < MaxClock, clock' = clock + 1,
    db' = db, pending' = pending, snap' = snap, left' = left, signer' = signer, fresh' = fresh, tampered' = tampered, attacks' = attacks,
  }

  action step = any {
    nondet v = Vaults.oneOf()
    any { read(v), change(v), use(v) },
    sign, fence, sweep, retire, check, tick,
    nondet entry = Set(true, false).oneOf()
    forge(entry),
    putBack,
  }

  // With nobody writing behind the vault, a rotation raises no alert.
  val quiet = tampered or not(signer.alert)
  // The signer never vouches for a row the writer made.
  val clean = not(signer.mirror.get("grant").forged)
  // With nothing waiting and nobody writing behind the vault, the rows are what the mirror holds.
  val inStep = (pending.length() == 0 and db != signer.mirror) implies (tampered or signer.alert)
  val safe = quiet and clean and inStep
}

module rotateSound {
  import rotate(Mem = 1, Wait = 2, MaxClock = 4, Ops = 2, Attacks = 1, ComparePolicy = true, UnderPolicy = true, Drain = true, CurrentOnly = true).*
}
// A change that does not compare the policy row lands under key 1 after the fence.
module noFence {
  import rotate(Mem = 1, Wait = 2, MaxClock = 4, Ops = 2, Attacks = 0, ComparePolicy = false, UnderPolicy = true, Drain = true, CurrentOnly = true).*
}
// A new vault that writes under key 2 before the fence is refused by a signer still on key 1.
module underConfig {
  import rotate(Mem = 1, Wait = 2, MaxClock = 4, Ops = 2, Attacks = 0, ComparePolicy = true, UnderPolicy = false, Drain = true, CurrentOnly = true).*
}
// A change waiting at the fence is refused after it.
module noDrain {
  import rotate(Mem = 1, Wait = 2, MaxClock = 4, Ops = 2, Attacks = 0, ComparePolicy = true, UnderPolicy = true, Drain = false, CurrentOnly = true).*
}
// Retired at once, key 1 still has a use from memory to log.
module retireAtOnce {
  import rotate(Mem = 1, Wait = 0, MaxClock = 4, Ops = 2, Attacks = 0, ComparePolicy = true, UnderPolicy = true, Drain = true, CurrentOnly = true).*
}
// A signer that takes changes under key 1 after the fence vouches for a forged row.
module anyKey {
  import rotate(Mem = 1, Wait = 2, MaxClock = 4, Ops = 2, Attacks = 1, ComparePolicy = true, UnderPolicy = true, Drain = true, CurrentOnly = false).*
}
