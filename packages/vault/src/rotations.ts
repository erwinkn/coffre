import type { LogEntry } from '@coffre/core/merkle';

/** A key the rotations are weighed against: its log's origin, and whether an entry's MAC holds under it. */
export type RotationKey = { origin: string; authentic: (entry: LogEntry) => boolean };

/** A rotation that counts: the number it is at, and the keys it moves the log between, by origin. */
export type Rotation = { number: bigint; from: string; to: string };

/** Past every number: the bound of the current key, and of a key the rotation under way has yet to retire. */
export const UNBOUNDED = (1n << 63n) - 1n;

/**
 * The rotations of 0.15's log that count, and the number below which each
 * replaced key vouches (formal/Rotation.tla's and Keyring.tla's
 * ChainRule; docs/design/audit-tree.md, "A rotation"). A rotation is an
 * entry like any other: it counts only where the key whose MAC it carries,
 * the key it moves the log to, vouches at its number. So the bounds are a
 * chain from the current key back: a rotation into the current key counts
 * at any number, and bounds the key it moves from; a rotation into a key it
 * replaced counts only below that key's own bound. A key no rotation that
 * counts moved on from vouches for everything while the newest pair is
 * under it (`under`: the rotation under way), and for nothing otherwise (its
 * rotation's row gone: it fails closed).
 *
 * Without the chain, a rotation would count on its MAC alone: someone who
 * holds two replaced keys A and B, and writes the database, deletes A→B and
 * plants A→B under B's MAC past B's own rotation into C, and A vouches up
 * to it. With it, she moves a bound only where
 * a key she holds vouches anyway.
 *
 * Bounds are found a round at a time, as Keyring.tla's `Bounds`: each round
 * bounds every key not yet bounded, at the first rotation from it into a key
 * bounded already, below that key's bound. A key bounded keeps its bound. A
 * rotation from the current key, or from a key the vault does not hold,
 * bounds nothing. `rotationOf` is the entry's decoding (`log-entry.ts`):
 * null for any entry not a rotation, or one moved off its number.
 */
export function chainOf(
  keys: { current: RotationKey; previous: readonly RotationKey[] },
  entries: readonly LogEntry[],
  rotationOf: (entry: LogEntry) => { from: string; to: string } | null,
  under: string | null,
): { rotations: Rotation[]; until: (origin: string) => bigint } {
  const held = new Map([keys.current, ...keys.previous].map((key) => [key.origin, key]));
  const decoded = entries.flatMap((entry) => {
    const r = rotationOf(entry);
    return r === null ? [] : [{ entry, number: entry.number, from: r.from, to: r.to }];
  });
  const bound = new Map<string, bigint>([[keys.current.origin, UNBOUNDED]]);
  const counts = (r: (typeof decoded)[number]) => {
    const to = bound.get(r.to);
    return to !== undefined && r.number < to && held.get(r.to)!.authentic(r.entry);
  };
  let pending = under !== null && held.has(under);
  for (;;) {
    const round = new Map<string, bigint>();
    for (const r of decoded) {
      if (!held.has(r.from) || bound.has(r.from) || !counts(r)) continue;
      const first = round.get(r.from);
      if (first === undefined || r.number < first) round.set(r.from, r.number);
    }
    if (round.size > 0) {
      for (const [origin, number] of round) bound.set(origin, number);
      continue;
    }
    // The chain from the current key is done: a key the newest pair is under, and no rotation that counts retired,
    // is the one the log is moving on from, and vouches on; the rotations into it count then too.
    if (pending && !bound.has(under!)) {
      bound.set(under!, UNBOUNDED);
      pending = false;
      continue;
    }
    break;
  }
  return {
    rotations: decoded.filter(counts).map(({ number, from, to }) => ({ number, from, to })).sort((a, b) => (a.number < b.number ? -1 : 1)),
    until: (origin) => bound.get(origin) ?? -1n,
  };
}
