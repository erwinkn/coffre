import { entryLeaf, leafData, type LeafValue } from './leaf.ts';
import { MAX_NUMBER } from './note.ts';
import { openPair, samePair, TREES, type Pair, type PairNotes, type PairVerifiers, type TreeName } from './pair.ts';
import { Edge, edgeOf, nodesFrom, tileMap, tilesFor, type Tile, type TileKey } from './tiles.ts';
import { consistencyProof, EMPTY_ROOT, inclusionProof, verifyConsistency, verifyInclusion, type Hash } from './tree.ts';

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
 * MAC, its request ID) is the caller's to check, through `check`, which sees
 * every entry walked, in number order. The cost is the entries since the
 * start: a caller that keeps the `head` it verified walks only what came
 * after (R25). With `limit`, a walk stops at the first stored pair at or
 * past that many entries, before the entries above the newest (`done`
 * false): a caller bounded in time says so rather than walk on.
 *
 * Retention (plan PR 7, formal/Seal.tla) drops days of uses, and the uses
 * tree's tiles, below a cut that a retention change names; changes are kept
 * for good. With `cut`, which says whether a change is one and its cut, the
 * walk takes the newest retention change (the reader's `retention`), requires
 * it sealed in the changes tree, never merely held (CutSealed), and walks the
 * changes tree from the start but the uses tree from that cut: from the cut's
 * uses head, which the kept tiles at its edge must give, through the
 * checkpoint at the cut, which must hold that head. A use at or below the cut
 * is not walked: a straggler (one of the next day's, numbered below it) can go
 * unseen until its own day does.
 */
export type LogEntry = { tree: TreeName; number: bigint; at: number; columns: readonly LeafValue[] };

/** A checkpoint row: one pair's two notes, at the `upto` the row says. */
export type StoredPair = { upto: bigint; notes: PairNotes };

export type LogReader = {
  /** The rows above `after`, by `upto`, at most `limit`. */
  pairs(after: bigint, limit: number): Promise<StoredPair[]>;
  /** The row at exactly `upto`, if any. */
  pair(upto: bigint): Promise<StoredPair | null>;
  /**
   * The entries numbered in (after, upto], by number, both trees; at most
   * `limit`. Uses are read from `floor`, the floor of `at` signed in the
   * pair at `after`, when the caller gives it: a reader that takes it from
   * its rows lets a writer hide what lies above (FloorChecked).
   */
  entries(after: bigint, upto: bigint, options?: { floor?: number; limit?: number }): Promise<LogEntry[]>;
  tiles(tree: TreeName, keys: readonly TileKey[]): Promise<Tile[]>;
  /** The newest retention change, if any, and its leaf index in the changes tree (plan PR 7). */
  retention?(): Promise<{ entry: LogEntry; index: number } | null>;
};

/** Where retention cut the uses tree: the pair at `upto`, signed at `at`, whose uses head every later one extends. */
export type Cut = { upto: bigint; at: number; uses: { size: number; root: Hash } };

export type Verdict = {
  ok: boolean;
  problems: string[];
  /** Rows walked, entries sealed under them, entries above the newest. */
  checkpoints: number;
  sealed: number;
  unsealed: number;
  /** The newest pair walked, when the walk found nothing wrong: the `from` of the next one. */
  head: PairNotes | null;
  /** Whether the walk reached the log's end, the entries above the newest pair included; false for a walk cut at `limit`. */
  done: boolean;
  /**
   * Whether the database ends before a pair held outside: deleted entries or
   * checkpoints, or the signer's own write a moment away (it remembers a pair
   * before the database holds it), which a caller may tell apart by asking
   * again a tick later.
   */
  behind: boolean;
};

type Stop = { pair: Pair; notes: PairNotes; row: boolean };

export type VerifyOptions = {
  verifiers: PairVerifiers;
  from?: PairNotes;
  anchors?: readonly PairNotes[];
  check?: (entry: LogEntry) => string | null;
  /** Whether a change is a retention change, and the cut it names; null for any other entry. */
  cut?: (entry: LogEntry) => Cut | null;
  limit?: number;
};

const PAGE = 100;

export async function verifyLog(reader: LogReader, opts: VerifyOptions): Promise<Verdict> {
  const problems: string[] = [];
  const verdict = { checkpoints: 0, sealed: 0, unsealed: 0, done: true, behind: false };
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
  opts: VerifyOptions,
  problems: string[],
  verdict: { checkpoints: number; sealed: number; unsealed: number; done: boolean; behind: boolean },
  done: (head: PairNotes | null) => Verdict,
): Promise<Verdict> {
  // The start's pair and those held outside, each opened once: a page's check starts at the pair the signer holds, which
  // is also its row, and four signature checks of one pair were a third of its cost. Rows past them are opened as read.
  const held = new Map<string, Promise<Pair | null>>();
  const noted = (notes: PairNotes) => `${notes.changes}\0${notes.uses}`;
  const openHeld = (notes: PairNotes) => {
    const key = noted(notes);
    if (!held.has(key)) held.set(key, openPair(notes, opts.verifiers));
    return held.get(key)!;
  };
  const open = async (row: StoredPair): Promise<Pair | null> => {
    const pair = await (held.get(noted(row.notes)) ?? openPair(row.notes, opts.verifiers));
    if (pair === null) problems.push(`checkpoint ${row.upto}: not a pair signed by the log`);
    else if (pair.upto !== row.upto) problems.push(`checkpoint ${row.upto}: its row does not match its notes (up to ${pair.upto})`);
    else return pair;
    return null;
  };

  // The start: a pair the caller trusts, which must be the row at its place, or the genesis row.
  let start: Stop;
  if (opts.from !== undefined) {
    const trusted = await openHeld(opts.from);
    if (trusted === null) return (problems.push('the pair to start from is not signed by the log'), done(null));
    const row = await reader.pair(trusted.upto);
    const pair = row === null ? null : await open(row);
    if (pair === null || !sameNotes(pair, trusted)) return (problems.push(`no checkpoint at ${trusted.upto} with the pair to start from: checkpoints were deleted or replaced`), done(null));
    start = { pair, notes: row!.notes, row: true };
  } else {
    const [row] = await reader.pairs(-1n, 1);
    const pair = row === undefined ? null : await open(row);
    const genesis = pair !== null && pair.upto === 0n && TREES.every((tree) => pair[tree].size === 0 && pair[tree].root.equals(EMPTY_ROOT));
    if (!genesis) return (problems.push('no genesis checkpoint to start from: checkpoints were deleted or replaced'), done(null));
    start = { pair: pair!, notes: row!.notes, row: true };
  }
  // The newest retention change: sealed in the changes tree, below the start by a proof from its tiles, above it on the
  // walk (Seal.tla's CutSealed); its cut names where the uses tree is walked from, when that is past the start.
  const retained = opts.cut === undefined || reader.retention === undefined ? null : await reader.retention();
  const cut = retained === null ? null : opts.cut!(retained.entry);
  if (retained !== null) {
    const { entry, index } = retained;
    if (cut === null) return (problems.push(`${entry.number}: the newest retention change names no cut`), done(null));
    if (cut.upto >= entry.number) return (problems.push(`${entry.number}: a retention change at or below its own cut (${cut.upto})`), done(null));
    if (entry.number <= start.pair.upto) {
      const size = start.pair.changes.size;
      const proof = Number.isSafeInteger(index) && index >= 0 && index < size
        ? inclusionProof(nodesFrom(tileMap(await reader.tiles('changes', tilesFor((n) => inclusionProof(n, index, size))))), index, size)
        : null;
      if (proof === null || !verifyInclusion(entryLeaf('changes', entry.number, entry.columns), index, size, proof, start.pair.changes.root)) {
        return (problems.push(`${entry.number}: the retention change cutting the uses at ${cut.upto} is not in the changes tree the walk starts from`), done(null));
      }
    }
  }
  // Past the start, the uses tree starts at the cut: its edge from the kept tiles, held to the cut's head.
  const ahead = cut !== null && cut.upto > start.pair.upto ? cut : null;
  const dropped = (e: { tree: TreeName; number: bigint }) => ahead !== null && e.tree === 'uses' && e.number <= ahead.upto;
  // Tiles that do not give their signed head are a problem to report, and the walk goes on where it can.
  const load = async (pair: Pair) => {
    const edges = {} as Record<TreeName, Edge>;
    for (const tree of TREES) {
      const head = tree === 'uses' && ahead !== null && pair.upto < ahead.upto ? ahead.uses : pair[tree];
      edges[tree] = await loadEdge(reader, tree, head.size, head.root, pair.upto);
    }
    return edges;
  };
  const reload = (pair: Pair) => load(pair).catch((error: Error) => (problems.push(error.message), null));

  // Pairs held outside below the start, in order, then the start: their times and floors never come down.
  const below = (await Promise.all((opts.anchors ?? []).map(openHeld)))
    .filter((a): a is Pair => a !== null && a.upto <= start.pair.upto)
    .sort((a, b) => (a.upto < b.upto ? -1 : 1));
  for (const [i, a] of below.entries()) {
    const next = below[i + 1] ?? start.pair;
    if (next.at < a.at || next.floor < a.floor) problems.push(`the pair held outside up to ${a.upto}: its time or floor is past the next pair's (up to ${next.upto}): time runs back`);
    // Two pairs held for one place must be one signing.
    if (next.upto === a.upto && (next.at !== a.at || next.floor !== a.floor || next.prev !== a.prev)) problems.push(`two pairs held outside up to ${a.upto}, signed at two times, floors or prevs`);
  }

  // Pairs held outside. Those at or below the start are not walked (verified before), but each must still be the row
  // at its place, if there is one, and, whether or not there is, a prefix of the start, by a consistency proof from the
  // tiles, in both trees.
  const above: Stop[] = [];
  for (const notes of opts.anchors ?? []) {
    const anchor = await openHeld(notes);
    if (anchor === null) {
      problems.push('a pair held outside is not signed by the log');
    } else if (anchor.upto > start.pair.upto) {
      above.push({ pair: anchor, notes, row: false });
    } else if (sameNotes(anchor, start.pair)) {
      // The start itself, as a page's check starts at the pair the signer holds: its row is the start's, and a head is
      // a prefix of itself.
    } else {
      const row = await reader.pair(anchor.upto);
      const pair = row === null ? null : await open(row);
      if (pair !== null && !sameNotes(pair, anchor)) problems.push(`checkpoint ${anchor.upto}: not the pair held outside for that place: ${samePair(pair, anchor) ? 'the same heads signed at another time or floor' : 'a second history'}`);
      // A row that agrees proves nothing by itself: a fork can be both the row and the pair held outside. Below a cut, the
      // uses tree's tiles are gone: its consistency is proved from the cut on only.
      for (const tree of TREES) {
        if (tree === 'uses' && cut !== null && anchor.uses.size < cut.uses.size) continue;
        const [from, to] = [anchor[tree], start.pair[tree]];
        const proof = from.size > to.size ? null : await proveConsistency(reader, tree, from.size, to.size).catch(() => null);
        if (proof === null || !verifyConsistency(from.size, to.size, from.root, to.root, proof)) {
          problems.push(`the pair held outside up to ${anchor.upto}: its ${tree} head is not a prefix of the start's: a second history, or tiles deleted`);
        }
      }
    }
  }
  above.sort((a, b) => (a.pair.upto < b.pair.upto ? -1 : 1));
  const loaded = await reload(start.pair);
  if (loaded === null) return done(null);
  let edges = loaded;

  // The walk: a page of rows at a time, with the outside pairs that fall among them, entries read once per page.
  // `last` is the newest row walked, `cursor` how far entries have gone into the trees (an outside pair can be past it).
  let last = start;
  let cursor = start.pair.upto;
  let previous = start.pair.upto;
  let time = start.pair.at;
  let floor = start.pair.floor;
  // Whether the walk met the retention change it starts the uses tree from, and the checkpoint at its cut.
  let retainedMet = retained === null || retained.entry.number <= start.pair.upto;
  let cutMet = ahead === null;
  const walkEntries = (entries: readonly LogEntry[]) => {
    for (const e of entries) {
      // The retention change the walk starts the uses tree from, met on the way. A newer one is not looked for: it can be
      // appended, or sealed, while the walk runs, and an older cut only makes the walk cover more uses. (A day dropped
      // below a newer cut while the walk still reads those uses shows as uses gone: walk again.)
      if (e.tree === 'changes' && retained !== null && e.number === retained.entry.number) {
        if (!sameEntry(e, retained.entry)) problems.push(`${e.number}: not the retention change the database names at its number`);
        else retainedMet = true;
      }
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
        if (!sameNotes(row.pair, anchor.pair)) problems.push(`checkpoint ${anchor.pair.upto}: not the pair held outside for that place: ${samePair(row.pair, anchor.pair) ? 'the same heads signed at another time or floor' : 'a second history'}`);
      } else if (final && anchor.pair.upto > newest) {
        verdict.behind = true;
        problems.push(`the database ends up to ${newest}; a pair held outside seals up to ${anchor.pair.upto}: entries or checkpoints were deleted`);
      } else {
        stops.push(anchor);
      }
    }
    stops.sort((a, b) => (a.pair.upto < b.pair.upto ? -1 : 1));
    if (stops.length > 0) {
      // From the floor the pair at `cursor` signed, never its row's (review r9).
      const entries = (await reader.entries(cursor, stops.at(-1)!.pair.upto, { floor })).filter((e) => !dropped(e));
      let at = 0;
      for (const stop of stops) {
        const window: LogEntry[] = [];
        while (at < entries.length && entries[at]!.number <= stop.pair.upto) window.push(entries[at++]!);
        walkEntries(window);
        for (const tree of TREES) edges[tree].append(window.filter((e) => e.tree === tree).map((e) => entryLeaf(tree, e.number, e.columns)));
        verdict.sealed += window.length;
        // Time never runs back along one history: retention's freshness step rests on it. Equal is honest (a window of
        // gaps keeps the time).
        if (stop.pair.at < time) problems.push(`${stop.row ? 'checkpoint' : 'the pair held outside up to'} ${stop.pair.upto}: signed at ${stop.pair.at}, before the pair before it (${time}): time runs back`);
        if (stop.pair.floor < floor) problems.push(`${stop.row ? 'checkpoint' : 'the pair held outside up to'} ${stop.pair.upto}: its floor of at (${stop.pair.floor}) is below the one before it (${floor})`);
        time = Math.max(time, stop.pair.at);
        floor = Math.max(floor, stop.pair.floor);
        cursor = stop.pair.upto;
        // Below the cut the uses tree is not walked; the checkpoint at the cut must hold the cut's uses head itself.
        const walked = TREES.filter((tree) => tree === 'changes' || ahead === null || stop.pair.upto >= ahead.upto);
        if (ahead !== null && stop.pair.upto === ahead.upto) {
          if (stop.pair.uses.size !== ahead.uses.size || !stop.pair.uses.root.equals(ahead.uses.root)) {
            problems.push(`${stop.row ? 'checkpoint' : 'the pair held outside up to'} ${stop.pair.upto}: not the uses head the retention change cuts at`);
          } else if (stop.row) cutMet = true;
        }
        if (ahead !== null && stop.pair.upto > ahead.upto && !cutMet) {
          problems.push(`no checkpoint at the retention cut (${ahead.upto}): checkpoints were deleted or replaced`);
          cutMet = true;
        }
        const wrong = walked.filter((tree) => edges[tree].size !== stop.pair[tree].size || !edges[tree].root().equals(stop.pair[tree].root));
        if (wrong.length > 0) {
          problems.push(`${stop.row ? 'checkpoint' : 'the pair held outside up to'} ${stop.pair.upto}: the ${wrong.join(' and ')} head${wrong.length > 1 ? 's' : ''} differ from the entries: entries deleted, added, changed or moved, or a second history`);
          // Carry on from the signed row, so one problem is reported once.
          if (stop.row) edges = (await reload(stop.pair)) ?? edges;
        }
        if (stop.row) {
          verdict.checkpoints += 1;
          last = stop;
          // A walk bounded by `limit` ends at a stored pair, short of the present: its caller says it stopped there.
          if (opts.limit !== undefined && verdict.sealed >= opts.limit) {
            verdict.done = false;
            return done(last.notes);
          }
        }
      }
    }
    if (final) break;
  }
  // Above the newest pair, no tree to hold the entries to: the signed floor is all that bounds the read (review r9).
  // Under `limit`, the entries left in it, and one more to tell a walk that would pass it.
  const left = opts.limit === undefined || !Number.isFinite(opts.limit) ? undefined : Math.max(opts.limit - verdict.sealed, 0);
  const unsealed = (await reader.entries(cursor, MAX_NUMBER, { floor, ...(left === undefined ? {} : { limit: left + 1 }) })).filter((e) => !dropped(e));
  if (left !== undefined && unsealed.length > left) {
    verdict.done = false;
    return done(last.notes);
  }
  walkEntries(unsealed);
  verdict.unsealed = unsealed.length;
  if (!cutMet) problems.push(`no checkpoint at the retention cut (${ahead!.upto}): checkpoints were deleted or replaced`);
  // Above the start, the retention change must be on the walk and sealed: in a window a checkpoint verified.
  if (!retainedMet || (retained !== null && retained.entry.number > last.pair.upto)) {
    problems.push(`${retained!.entry.number}: the retention change cutting the uses at ${cut!.upto} is not sealed in the changes tree`);
  }
  return done(last.notes);
}

/**
 * Whether a pair held outside is the row at its place: the same heads, and
 * the same time and floor. Two notes for one place signed at two times take the
 * signer's key twice; honest pairs held outside are copies of rows.
 */
const sameNotes = (a: Pair, b: Pair) => samePair(a, b) && a.at === b.at && a.floor === b.floor && a.prev === b.prev;

/** Both trees' edges at a pair, from their tiles; throws unless each gives its signed head. */
export async function loadEdges(reader: Pick<LogReader, 'tiles'>, pair: Pair): Promise<Record<TreeName, Edge>> {
  const edges = {} as Record<TreeName, Edge>;
  for (const tree of TREES) edges[tree] = await loadEdge(reader, tree, pair[tree].size, pair[tree].root, pair.upto);
  return edges;
}

/** One tree's edge at `size`, from its tiles; throws unless it gives `root`, the head signed up to `upto`. */
async function loadEdge(reader: Pick<LogReader, 'tiles'>, tree: TreeName, size: number, root: Hash, upto: bigint): Promise<Edge> {
  const edge = Edge.load(size, tileMap(await reader.tiles(tree, edgeOf(size).filter((e) => e.width > 0))));
  if (!edge.root().equals(root)) throw new Error(`checkpoint ${upto}: the ${tree} tiles at its edge do not give its signed head`);
  return edge;
}

/** Whether two entries are one, whole: the same leaf. */
const sameEntry = (a: LogEntry, b: LogEntry) => leafData(a.tree, a.number, a.columns).equals(leafData(b.tree, b.number, b.columns));

/** A consistency proof between two sizes of one tree, from its tiles. */
export async function proveConsistency(reader: Pick<LogReader, 'tiles'>, tree: TreeName, from: number, to: number) {
  const nodes = nodesFrom(tileMap(await reader.tiles(tree, tilesFor((n) => consistencyProof(n, from, to)))));
  return consistencyProof(nodes, from, to);
}
