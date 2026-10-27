import { cosignNote, type NoteSigner } from './note.ts';
import { openPair, samePair, TREES, type Pair, type PairNotes, type PairVerifiers, type TreeName } from './pair.ts';
import { verifyConsistency, type Hash } from './tree.ts';

/**
 * A witness of the pair, as transparency-dev's and Sigsum's witnesses work on
 * one log: it holds the newest pair it has seen, and cosigns a new one only if
 * both trees prove they extend what it holds. So the log cannot show two
 * parties two histories (a split view) and get both witnessed, in either tree.
 * The witness's Durable Object runs this, and so do the tests.
 *
 * It takes both notes in one request and answers for both: a pair whose
 * changes head extends the one held while its uses head forks is refused
 * whole. (A standard C2SP witness takes one origin; given each tree's note,
 * it checks that tree alone, which is all it needs to.)
 */
export type WitnessState = { pair: Pair; notes: PairNotes } | null;

export type WitnessAnswer = { ok: true; cosigned: PairNotes } | { ok: false; reason: string };

/** Consistency proofs from the sizes the witness holds to the new pair's, one per tree. */
export type PairProofs = Record<TreeName, readonly Hash[]>;

export async function witnessPair(
  state: WitnessState,
  notes: PairNotes,
  proofs: PairProofs,
  log: PairVerifiers,
  self: NoteSigner,
): Promise<{ state: WitnessState; answer: WitnessAnswer }> {
  const pair = await openPair(notes, log);
  if (pair === null) return { state, answer: { ok: false, reason: 'not a pair signed by the log' } };
  if (state !== null) {
    const held = state.pair;
    if (pair.upto < held.upto) return { state, answer: { ok: false, reason: `older than the pair held (up to ${held.upto})` } };
    // One place, one pair: the same `upto` with other heads is a second history, however consistent.
    if (pair.upto === held.upto && !samePair(pair, held)) return { state, answer: { ok: false, reason: `split view: a second pair up to ${pair.upto}` } };
    for (const tree of TREES) {
      const [from, to] = [held[tree], pair[tree]];
      if (!verifyConsistency(from.size, to.size, from.root, to.root, proofs[tree])) {
        return { state, answer: { ok: false, reason: `split view: ${tree} at ${to.size} leaves up to ${pair.upto} does not extend ${from.size} up to ${held.upto}` } };
      }
    }
  }
  const [changes, uses] = await Promise.all(TREES.map((tree) => cosignNote(notes[tree], self)));
  return { state: { pair, notes }, answer: { ok: true, cosigned: { changes: changes!, uses: uses! } } };
}
