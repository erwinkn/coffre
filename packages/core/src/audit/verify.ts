import { entryLeaf, type LeafValue } from './leaf.ts';
import { MAX_NUMBER } from './note.ts';
import { openPair, samePair, TREES, type Pair, type PairNotes, type PairVerifiers, type TreeName } from './pair.ts';
import { Edge, edgeOf, nodesFrom, tileMap, tilesFor, type Tile, type TileKey } from './tiles.ts';
import { consistencyProof, EMPTY_ROOT, verifyConsistency } from './tree.ts';

/**
 * The two trees, verified from what the database holds and the pairs held
 * outside it (the signer's, a witness's, an archive's). It walks the entries
 * in number order from a start it trusts, never one the database picks: the
 * genesis pair, or a pair the caller verified before (`from`). On the way it
 * rebuilds both trees and requires every stored pair and every pair held
 * outside, both heads each: so every sealed entry is there, unchanged, at its
 * place and in its tree, nothing was added, and the database shows the one
 * history the outside pairs saw. A database that ends before an outside pair
 * lost entries or checkpoints.
 *
 * It needs the trees' public keys alone. What an entry's columns mean (its
 * MAC, its request ID) is the caller's to check, through `check`. The cost is
 * the entries since the start: a caller that keeps the `head` it verified
 * walks only what came after (R25).
 */
export type LogEntry = { tree: TreeName; number: bigint; at: number; columns: readonly LeafValue[] };

/** A checkpoint row: one pair's two notes, at the `upto` the row says. */
export type StoredPair = { upto: bigint; notes: PairNotes };

export type LogReader = {
  /** The rows above `after`, by `upto`, at most `limit`. */
  pairs(after: bigint, limit: number): Promise<StoredPair[]>;
  /** The row at exactly `upto`, if any. */
  pair(upto: bigint): Promise<StoredPair | null>;
  /** The entries numbered in (after, upto], by number, both trees. */
  entries(after: bigint, upto: bigint): Promise<LogEntry[]>;
  tiles(tree: TreeName, keys: readonly TileKey[]): Promise<Tile[]>;
};

export type Verdict = {
  ok: boolean;
  problems: string[];
  /** Rows walked, entries sealed under them, entries above the newest. */
  checkpoints: number;
  sealed: number;
  unsealed: number;
  /** The newest pair walked, when the walk found nothing wrong: the `from` of the next one. */
  head: PairNotes | null;
};

type Stop = { pair: Pair; notes: PairNotes; row: boolean };

const PAGE = 100;

export async function verifyLog(
  reader: LogReader,
  opts: { verifiers: PairVerifiers; from?: PairNotes; anchors?: readonly PairNotes[]; check?: (entry: LogEntry) => string | null },
): Promise<Verdict> {
  const problems: string[] = [];
  const verdict = { checkpoints: 0, sealed: 0, unsealed: 0 };
  const done = (head: PairNotes | null): Verdict => ({ ok: problems.length === 0, problems, ...verdict, head: problems.length === 0 ? head : null });
  // What the database holds is the adversary's to shape: anything the walk cannot read is a problem, never a crash.
  try {
    return await walk(reader, opts, problems, verdict, done);
  } catch (error) {
    problems.push(`verification stopped on what the database holds: ${(error as Error).message}`);
    return done(null);
  }
}

async function walk(
  reader: LogReader,
  opts: { verifiers: PairVerifiers; from?: PairNotes; anchors?: readonly PairNotes[]; check?: (entry: LogEntry) => string | null },
  problems: string[],
  verdict: { checkpoints: number; sealed: number; unsealed: number },
  done: (head: PairNotes | null) => Verdict,
): Promise<Verdict> {
  const open = async (row: StoredPair): Promise<Pair | null> => {
    const pair = await openPair(row.notes, opts.verifiers);
    if (pair === null) problems.push(`checkpoint ${row.upto}: not a pair signed by the log`);
    else if (pair.upto !== row.upto) problems.push(`checkpoint ${row.upto}: its row does not match its notes (up to ${pair.upto})`);
    else return pair;
    return null;
  };

  // The start: a pair the caller trusts, which must be the row at its place, or the genesis row.
  let start: Stop;
  if (opts.from !== undefined) {
    const trusted = await openPair(opts.from, opts.verifiers);
    if (trusted === null) return (problems.push('the pair to start from is not signed by the log'), done(null));
    const row = await reader.pair(trusted.upto);
    const pair = row === null ? null : await open(row);
    if (pair === null || !samePair(pair, trusted)) return (problems.push(`no checkpoint at ${trusted.upto} with the pair to start from: checkpoints were deleted or replaced`), done(null));
    start = { pair, notes: row!.notes, row: true };
  } else {
    const [row] = await reader.pairs(-1n, 1);
    const pair = row === undefined ? null : await open(row);
    const genesis = pair !== null && pair.upto === 0n && TREES.every((tree) => pair[tree].size === 0 && pair[tree].root.equals(EMPTY_ROOT));
    if (!genesis) return (problems.push('no genesis checkpoint to start from: checkpoints were deleted or replaced'), done(null));
    start = { pair: pair!, notes: row!.notes, row: true };
  }
  let edges = await loadEdges(reader, start.pair);

  // Pairs held outside. Those at or below the start are not walked (verified before), but each must still be the row
  // at its place, if there is one, and, whether or not there is, a prefix of the start, by a consistency proof from the
  // tiles, in both trees.
  const above: Stop[] = [];
  for (const notes of opts.anchors ?? []) {
    const anchor = await openPair(notes, opts.verifiers);
    if (anchor === null) {
      problems.push('a pair held outside is not signed by the log');
    } else if (anchor.upto > start.pair.upto) {
      above.push({ pair: anchor, notes, row: false });
    } else {
      const row = await reader.pair(anchor.upto);
      const pair = row === null ? null : await open(row);
      if (pair !== null && !samePair(pair, anchor)) problems.push(`checkpoint ${anchor.upto}: not the pair held outside for that place: a second history`);
      // A row that agrees proves nothing by itself: a fork can be both the row and the pair held outside.
      for (const tree of TREES) {
        const [from, to] = [anchor[tree], start.pair[tree]];
        const proof = from.size > to.size ? null : await proveConsistency(reader, tree, from.size, to.size).catch(() => null);
        if (proof === null || !verifyConsistency(from.size, to.size, from.root, to.root, proof)) {
          problems.push(`the pair held outside up to ${anchor.upto}: its ${tree} head is not a prefix of the start's: a second history, or tiles deleted`);
        }
      }
    }
  }
  above.sort((a, b) => (a.pair.upto < b.pair.upto ? -1 : 1));

  // The walk: a page of rows at a time, with the outside pairs that fall among them, entries read once per page.
  let last = start;
  let previous = start.pair.upto;
  const walkEntries = (entries: readonly LogEntry[]) => {
    for (const e of entries) {
      if (e.number <= previous) problems.push(`${e.number}: numbered at or below the entry before (${previous}): two entries with one number, or out of order`);
      if (!TREES.includes(e.tree)) problems.push(`${e.number}: in no tree (${String(e.tree)})`);
      const problem = opts.check?.(e) ?? null;
      if (problem !== null) problems.push(`${e.number}: ${problem}`);
      previous = e.number > previous ? e.number : previous;
    }
  };
  for (let rows = await reader.pairs(start.pair.upto, PAGE); ; rows = await reader.pairs(rows.at(-1)!.upto, PAGE)) {
    const stops: Stop[] = [];
    for (const row of rows) {
      const pair = await open(row);
      if (pair !== null) stops.push({ pair, notes: row.notes, row: true });
    }
    const final = rows.length < PAGE;
    const newest = (stops.at(-1) ?? last).pair.upto;
    while (above.length > 0 && (final || above[0]!.pair.upto <= rows.at(-1)!.upto)) {
      const anchor = above.shift()!;
      const row = stops.find((s) => s.pair.upto === anchor.pair.upto);
      if (row !== undefined) {
        if (!samePair(row.pair, anchor.pair)) problems.push(`checkpoint ${anchor.pair.upto}: not the pair held outside for that place: a second history`);
      } else if (final && anchor.pair.upto > newest) {
        problems.push(`the database ends up to ${newest}; a pair held outside seals up to ${anchor.pair.upto}: entries or checkpoints were deleted`);
      } else {
        stops.push(anchor);
      }
    }
    stops.sort((a, b) => (a.pair.upto < b.pair.upto ? -1 : 1));
    if (stops.length > 0) {
      const entries = await reader.entries(last.pair.upto, stops.at(-1)!.pair.upto);
      let at = 0;
      for (const stop of stops) {
        const window: LogEntry[] = [];
        while (at < entries.length && entries[at]!.number <= stop.pair.upto) window.push(entries[at++]!);
        walkEntries(window);
        for (const tree of TREES) edges[tree].append(window.filter((e) => e.tree === tree).map((e) => entryLeaf(tree, e.number, e.columns)));
        verdict.sealed += window.length;
        const wrong = TREES.filter((tree) => edges[tree].size !== stop.pair[tree].size || !edges[tree].root().equals(stop.pair[tree].root));
        if (wrong.length > 0) {
          problems.push(`${stop.row ? 'checkpoint' : 'the pair held outside up to'} ${stop.pair.upto}: the ${wrong.join(' and ')} head${wrong.length > 1 ? 's' : ''} differ from the entries: entries deleted, added, changed or moved, or a second history`);
          // Carry on from the signed row, so one problem is reported once.
          if (stop.row) edges = await loadEdges(reader, stop.pair);
        }
        if (stop.row) {
          verdict.checkpoints += 1;
          last = stop;
        }
      }
    }
    if (final) break;
  }
  const unsealed = await reader.entries(last.pair.upto, MAX_NUMBER);
  walkEntries(unsealed);
  verdict.unsealed = unsealed.length;
  return done(last.notes);
}

/** Both trees' edges at a pair, from their tiles; throws unless each gives its signed head. */
export async function loadEdges(reader: Pick<LogReader, 'tiles'>, pair: Pair): Promise<Record<TreeName, Edge>> {
  const edges = {} as Record<TreeName, Edge>;
  for (const tree of TREES) {
    const { size, root } = pair[tree];
    edges[tree] = Edge.load(size, tileMap(await reader.tiles(tree, edgeOf(size).filter((e) => e.width > 0))));
    if (!edges[tree].root().equals(root)) throw new Error(`checkpoint ${pair.upto}: the ${tree} tiles at its edge do not give its signed head`);
  }
  return edges;
}

/** A consistency proof between two sizes of one tree, from its tiles. */
export async function proveConsistency(reader: Pick<LogReader, 'tiles'>, tree: TreeName, from: number, to: number) {
  const nodes = nodesFrom(tileMap(await reader.tiles(tree, tilesFor((n) => consistencyProof(n, from, to)))));
  return consistencyProof(nodes, from, to);
}
