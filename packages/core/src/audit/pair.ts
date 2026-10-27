import { hkdfSync } from 'node:crypto';

import { checkpointBody, noteSigner, noteVerifier, openCheckpoint, signNote, type Checkpoint, type NoteSigner, type NoteVerifier } from './note.ts';
import type { Hash } from './tree.ts';

/**
 * 0.15's log is two growing trees, one per retention class (W212, by numbers):
 * `changes`, kept for good, and `uses`, dropped by day. Each is a standard log
 * with its own origin and key, so any C2SP witness or Go's tlog reads either
 * one alone. They stay one log by moving as one pair:
 *
 * - one tick signs both, with the same `upto`, `at` and `floor`;
 * - the signer remembers both in one record, before the database has either;
 * - one statement writes both;
 * - opening, each tick and witnesses check both, as one value.
 *
 * So no state anywhere holds one head without the other, and a fork of either
 * tree is a fork of the pair.
 */
export const TREES = ['changes', 'uses'] as const;
export type TreeName = (typeof TREES)[number];

export type Pair = { upto: bigint; at: number; floor: number; prev: number; changes: Checkpoint; uses: Checkpoint };

/** The pair as it is stored, remembered and published: each tree's signed note. */
export type PairNotes = { changes: string; uses: string };

export type PairSigners = Record<TreeName, NoteSigner>;
export type PairVerifiers = Record<TreeName, NoteVerifier>;

/** A tree's origin: the log's own, then the tree's name. */
export const treeOrigin = (origin: string, tree: TreeName) => `${origin}/${tree}`;

/** The two trees' keys, derived from one 32-byte signing seed, each under its own origin. */
export async function pairSigners(origin: string, seed: Uint8Array): Promise<PairSigners> {
  if (seed.length < 32) throw new Error('a signing seed is at least 32 bytes');
  const derive = (tree: TreeName) => new Uint8Array(hkdfSync('sha256', seed, new Uint8Array(0), `coffre.audit.tree.v1.${tree}`, 32));
  const [changes, uses] = await Promise.all(TREES.map((tree) => noteSigner(treeOrigin(origin, tree), derive(tree))));
  return { changes: changes!, uses: uses! };
}

export async function pairVerifiers(keys: Record<TreeName, string>): Promise<PairVerifiers> {
  const [changes, uses] = await Promise.all(TREES.map((tree) => noteVerifier(keys[tree])));
  return { changes: changes!, uses: uses! };
}

export type Heads = Record<TreeName, { size: number; root: Hash }>;

/**
 * One tick's signatures: both heads, at one `upto`, `at`, `floor` (the floor of `at` its barrier set; 0 at genesis) and
 * `prev` (the floor of the pair signed before it; 0 at genesis).
 */
export async function signPair(signers: PairSigners, upto: bigint, at: number, heads: Heads, floor = 0, prev = 0): Promise<{ pair: Pair; notes: PairNotes }> {
  const checkpoint = (tree: TreeName): Checkpoint => ({ origin: signers[tree].name, size: heads[tree].size, root: heads[tree].root, upto, at, floor, prev });
  const pair: Pair = { upto, at, floor, prev, changes: checkpoint('changes'), uses: checkpoint('uses') };
  const [changes, uses] = await Promise.all(TREES.map((tree) => signNote(checkpointBody(pair[tree]), [signers[tree]])));
  return { pair, notes: { changes: changes!, uses: uses! } };
}

/** The pair two notes make, if each is signed by its tree's key and both name the same `upto`, `at`, `floor` and `prev`; else null. */
export async function openPair(notes: PairNotes, verifiers: PairVerifiers): Promise<Pair | null> {
  const [changes, uses] = await Promise.all(TREES.map((tree) => openCheckpoint(notes[tree], verifiers[tree])));
  if (!changes || !uses || changes.upto !== uses.upto || changes.at !== uses.at || changes.floor !== uses.floor || changes.prev !== uses.prev) return null;
  return { upto: changes.upto, at: changes.at, floor: changes.floor, prev: changes.prev, changes, uses };
}

/** Whether two pairs are the same heads: same place, same sizes and roots in both trees. Not `at`: callers that need one signing compare it too. */
export const samePair = (a: Pair, b: Pair) =>
  a.upto === b.upto && TREES.every((tree) => a[tree].size === b[tree].size && a[tree].root.equals(b[tree].root));

/** The one record the signer remembers, holding both notes. */
export function encodePair(notes: PairNotes): string {
  return JSON.stringify({ changes: notes.changes, uses: notes.uses });
}

export function decodePair(record: string): PairNotes | null {
  try {
    const value = JSON.parse(record) as unknown;
    if (typeof value !== 'object' || value === null) return null;
    const { changes, uses, ...rest } = value as Record<string, unknown>;
    if (typeof changes !== 'string' || typeof uses !== 'string' || Object.keys(rest).length > 0) return null;
    return { changes, uses };
  } catch {
    return null;
  }
}
