import { openPair, type LogEntry, type Pair, type PairNotes, type PairVerifiers } from '@coffre/core/merkle';

import { logKeys } from './log-checkpointer.ts';
import { authentic, rotationOf, type LogMacKey } from './log-entry.ts';
import { chainOf } from './rotations.ts';

/**
 * The vault's keys of 0.15's log held to its rotations (T168;
 * formal/Rotation.tla's BoundaryChecked; docs/design/audit-tree.md, "A
 * rotation"): R41's rule, one for every reader that takes a key's word for
 * something the log holds. The checkpointer and the verifier hold to it
 * (each with checks of its own around it), and so do the reads' projector,
 * `coffre verify log`'s check of the reads and the vault's `vouch`, through
 * this. The current key vouches for anything. A key it replaced vouches only
 * for what is numbered below its rotation: a pair whose `upto`, an entry or
 * a read whose number is below it, and a cursor whose `through` is, with its
 * `pair` at or below its `through` (`cursorVouched`: a cursor's `pair` past
 * the rotation would skip every use between them). A replaced key
 * no rotation retired yet vouches while the newest pair is under it (the
 * rotation under way: the checkpointer writes it at its first start under
 * the new key), and for nothing once it is not: a rotation's row deleted
 * leaves its key vouching for nothing, never for everything (fail closed).
 * Each is Rotation.tla's: a rotation counts at the number its payload names
 * (NumberInRotation, `rotationOf`), and only where the key it moves the log
 * to vouches at that number (ChainRule, `chainOf`; Keyring.tla's, with a
 * third key); the newest pair is under the key its
 * signatures hold under, never a name it carries (SignerVerified); a
 * replaced key's bound is its own rotation's, whatever key the newest pair
 * is under (KeyringBound: a tick seals its window in parts, so a pair under
 * the new key can lie below the rotation); and the rotations and the newest
 * pair are read in one statement (SnapshotRead). A keyring is read for one
 * call and kept by none: a bound kept would go stale across a restore,
 * whose rotation comes back at another number.
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

/** What a keyring is read from: the log's rotations and its newest pair, in one statement (`logStore`'s). */
export type KeyringStore = {
  keyringRows(): Promise<{ rotations: LogEntry[]; newest: { upto: bigint; notes: PairNotes } | null }>;
};

/** A keyring with no key replaced: the current key alone. */
export const alone = (keys: VerifierKeys): Keyring => ({ current: keys.current, previous: [] });

/**
 * The keyring the log's rotations give: those that count by the chain rule
 * (`chainOf`, rotations.ts), each where the key it moves the log to vouches
 * at its number. Reads nothing when the vault holds no replaced key.
 */
export async function keyringOf(keys: VerifierKeys, store: KeyringStore): Promise<Keyring> {
  if (keys.previous.length === 0) return alone(keys);
  const { rotations, newest } = await store.keyringRows();
  return ringOf(keys, rotations, newest === null ? null : await signedUnder(newest.notes, [keys.current, ...keys.previous]));
}

/** The keyring the rotations give, `under` the key the newest pair's signatures hold under (null: none, or no pair). */
export function ringOf(keys: VerifierKeys, rotations: readonly LogEntry[], under: KeyCheck | null): Keyring {
  const weighed = (key: KeyCheck) => ({ origin: key.origin, authentic: authentic(key.mac) });
  const { until } = chainOf({ current: weighed(keys.current), previous: keys.previous.map(weighed) }, rotations, rotationOf, under?.origin ?? null);
  return { current: keys.current, previous: keys.previous.map((key) => ({ key, until: until(key.origin) })) };
}

/** The key a pair's signatures hold under, the current one first: never a name its notes carry (SignerVerified). */
export async function signedUnder(notes: PairNotes, keys: readonly KeyCheck[]): Promise<KeyCheck | null> {
  for (const key of keys) if ((await openPair(notes, key.verifiers)) !== null) return key;
  return null;
}

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
