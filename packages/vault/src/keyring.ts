import { openPair, splitNote, type LogEntry, type Pair, type PairNotes, type PairVerifiers } from '@coffre/core/merkle';

import { logKeys } from './log-checkpointer.ts';
import { authentic, rotationOf, type LogMacKey } from './log-entry.ts';

/**
 * The vault's keys of 0.15's log held to its rotations (T168;
 * formal/Rotation.tla's BoundaryChecked; docs/design/audit-tree.md, "A
 * rotation"): R41's rule, one for every reader that takes a key's word for
 * something the log holds. The checkpointer and the verifier hold to it
 * (each with checks of its own around it), and so do the reads' projector,
 * `coffre verify log`'s check of the reads and the vault's `vouch`, through
 * this. The current key vouches for anything. A key it replaced vouches only
 * for what is numbered below its rotation: a pair whose `upto`, an entry or
 * a read whose number, a cursor whose `through` is below it. A replaced key
 * no rotation retired yet vouches while the newest pair is under it (the
 * rotation under way: the checkpointer writes it at its first start under
 * the new key), and for nothing once it is not: a rotation's row deleted
 * leaves its key vouching for nothing, never for everything (fail closed).
 */

/** One key's part of a check: its log's origin, its trees' public keys, its entries' MAC key. */
export type KeyCheck = { origin: string; verifiers: PairVerifiers; mac: LogMacKey };

/** The keys a check needs, from each of the vault's signing keys: the one it signs with, then those it replaced. */
export type VerifierKeys = { current: KeyCheck; previous: KeyCheck[] };

/** The verifier's keys from the vault's signing keys, as the checkpointer has them (log-checkpointer.ts). */
export async function verifierKeys(seeds: readonly Uint8Array[]): Promise<VerifierKeys> {
  const { current, previous } = await logKeys(seeds);
  const check = ({ origin, verifiers, mac }: KeyCheck): KeyCheck => ({ origin, verifiers, mac });
  return { current: check(current), previous: previous.map(check) };
}

/** Each key with the number below which it vouches: none for the current key, which vouches for anything. */
export type Keyring = { current: KeyCheck; previous: readonly { key: KeyCheck; until: bigint }[] };

/** What a keyring is read from: the log's rotations and its newest pair. */
export type KeyringStore = {
  rotations(): Promise<LogEntry[]>;
  newest(): Promise<{ upto: bigint; notes: PairNotes } | null>;
};

/** Past every number: a key the rotation under way has yet to retire. */
const UNBOUNDED = (1n << 63n) - 1n;

/** A keyring with no key replaced: the current key alone. */
export const alone = (keys: VerifierKeys): Keyring => ({ current: keys.current, previous: [] });

/**
 * The keyring the log's rotations give: each rotation authentic under the
 * key it moves the log to, which the vault holds, the first from each key.
 * Reads nothing when the vault holds no replaced key.
 */
export async function keyringOf(keys: VerifierKeys, store: KeyringStore): Promise<Keyring> {
  if (keys.previous.length === 0) return alone(keys);
  const all = [keys.current, ...keys.previous];
  const until = new Map<string, bigint>();
  for (const entry of [...(await store.rotations())].sort((a, b) => (a.number < b.number ? -1 : 1))) {
    const r = rotationOf(entry);
    const to = r === null ? undefined : all.find((key) => key.origin === r.to);
    if (r !== null && to !== undefined && authentic(to.mac)(entry) && !until.has(r.from)) until.set(r.from, entry.number);
  }
  const newest = keys.previous.some((key) => !until.has(key.origin)) ? await store.newest() : null;
  const under = newest === null ? null : signerOf(newest.notes, all);
  return {
    current: keys.current,
    previous: keys.previous.map((key) => ({ key, until: until.get(key.origin) ?? (under === key ? UNBOUNDED : -1n) })),
  };
}

/** Whether every replaced key's bound comes from its rotation: the ring stays as it is, whatever is written next. */
export const settledRing = (ring: Keyring) => ring.previous.every((p) => p.until !== UNBOUNDED);

/** The keys that vouch at `number`: the current one first. */
export function keysAt(ring: Keyring, number: bigint): KeyCheck[] {
  return [ring.current, ...ring.previous.filter((p) => number < p.until).map((p) => p.key)];
}

/** The pair two notes make under a key that vouches at its place, and that key; null if none does. */
export async function openUnder(ring: Keyring, notes: PairNotes): Promise<{ pair: Pair; key: KeyCheck } | null> {
  for (const key of [ring.current, ...ring.previous.map((p) => p.key)]) {
    const pair = await openPair(notes, key.verifiers);
    if (pair !== null) return keysAt(ring, pair.upto).includes(key) ? { pair, key } : null;
  }
  return null;
}

/**
 * Whether an entry's MAC holds under a key that vouches at its number; or,
 * if it holds only under a replaced key past its rotation, `past`.
 */
export function entryVouched(ring: Keyring, entry: LogEntry): 'held' | 'past' | 'none' {
  if (authentic(ring.current.mac)(entry)) return 'held';
  const under = ring.previous.find((p) => authentic(p.key.mac)(entry));
  return under === undefined ? 'none' : entry.number < under.until ? 'held' : 'past';
}

/** The key that signed a pair, by the name its changes note is signed under (each key's own, `<origin>/changes`): not verified, which opening it does. */
export function signerOf(notes: PairNotes, keys: readonly KeyCheck[]): KeyCheck | null {
  let names: string[];
  try {
    names = splitNote(notes.changes).signatures.map((s) => s.name);
  } catch {
    return null;
  }
  return keys.find((key) => names.includes(key.verifiers.changes.name)) ?? null;
}
