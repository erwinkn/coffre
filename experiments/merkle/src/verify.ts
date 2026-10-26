import { entryMac, leafOf, readTiles, type Db, type Entry } from './log.ts';
import { entriesBetween, retentions } from './retention.ts';
import { referenceHash } from './tree.ts';
import { openNote, parseCheckpoint, verifierFrom, type Checkpoint } from './note.ts';
import { Edge, edgeOf, tileMap } from './tiles.ts';

/**
 * The log, verified from the database and the heads held outside it. It walks
 * the entries above a starting checkpoint (the first, the retention horizon,
 * or the last one verified) in number order, rebuilds the tree from them, and
 * requires every signed checkpoint's head on the way: so every entry sealed
 * since is there, unchanged, at its place, and nothing was added. Then the
 * heads held outside (a witness's, an archive's newest) must be heads of this
 * same tree: a database that lost its newest checkpoints, or shows a second
 * history, fails here. The cost is the entries since the start, never the
 * whole log (R25).
 *
 * It needs the log's public key only. With the MAC key it also checks the
 * entries not sealed yet.
 */
/** `warnings`: what may be an attack and may be a clock (an entry's `at` running back against its number). */
export type Verdict = { ok: boolean; problems: string[]; warnings: string[]; checkpoints: number; sealed: number; unsealed: number; ms: number };

/** How far apart two Workers' clocks may be before an entry's `at` running back against its number is worth a look. */
const SKEW_MS = 5000;

export async function verifyLog(
  db: Db,
  opts: { verifierKey: string; macKey?: Buffer; anchors?: string[]; fromUpto?: string },
): Promise<Verdict> {
  const started = performance.now();
  const verifier = await verifierFrom(opts.verifierKey);
  const problems: string[] = [];
  // Numbers and request IDs must be unique: nothing in the database enforces it across partitions, and a copy of an
  // entry under a fresh number (a replay, before it is sealed) is otherwise a valid entry.
  const warnings: string[] = [];
  let latest = 0;
  const numbers = new Set<string>();
  const requests = new Set<string>();
  const unique = (e: Entry) => {
    if (numbers.has(e.number)) problems.push(`${e.number}: two entries with this number`);
    if (requests.has(e.requestId)) problems.push(`${e.number}: request ${e.requestId} logged twice`);
    numbers.add(e.number);
    requests.add(e.requestId);
    // Numbers swapped before sealing (the MAC does not cover them) show as an `at` running back; so does a skewed clock.
    if (e.at < latest - SKEW_MS) warnings.push(`${e.number}: at ${e.at}, ${latest - e.at} ms before an entry numbered earlier`);
    latest = Math.max(latest, e.at);
  };
  // Retention: what stays below each cut must be exactly what its retention entry says; the walk starts at the last cut.
  let fromUpto = opts.fromUpto ?? '0';
  for (const r of await retentions(db)) {
    const kept = await entriesBetween(db, r.prevCutUpto, r.cutUpto);
    kept.forEach(unique);
    if (kept.length !== r.kept || referenceHash(kept.map(leafOf)).toString('base64') !== r.keptRoot) {
      problems.push(`retention of day ${r.day}: ${kept.length} entries stay below its cut at ${r.cutUpto}, it kept ${r.kept}${kept.length === r.kept ? ' with another head' : ''}`);
    }
    if (BigInt(r.cutUpto) > BigInt(fromUpto)) fromUpto = r.cutUpto;
  }
  const { rows } = await db.query('SELECT c.upto::text, c.size::text, c.note FROM checkpoints c WHERE c.upto >= $1 ORDER BY c.upto', [fromUpto]);
  const heads: Checkpoint[] = [];
  for (const r of rows) {
    const text = await openNote(r.note, verifier);
    if (text === null) {
      problems.push(`checkpoint ${r.upto}: not signed by the log`);
      continue;
    }
    const c = parseCheckpoint(text);
    if (c.upto !== r.upto || String(c.size) !== r.size) problems.push(`checkpoint ${r.upto}: its row does not match its note`);
    heads.push(c);
  }
  if (heads.length === 0) return { ok: false, problems: [...problems, 'no checkpoint'], warnings, checkpoints: 0, sealed: 0, unsealed: 0, ms: performance.now() - started };

  // The start: its head from the tiles at its edge, which must give its signed head.
  const start = heads[0]!;
  const edgeKeys = edgeOf(start.size).filter((e) => e.width > 0);
  let edge = Edge.load(start.size, tileMap(await readTiles(db, edgeKeys)));
  if (!edge.root().equals(start.root)) problems.push(`checkpoint ${start.upto}: the tiles at its edge do not give its head`);

  // Every head held outside, by the place it seals: each must be met on the walk.
  const anchors = new Map<string, Checkpoint>();
  for (const note of opts.anchors ?? []) {
    const text = await openNote(note, verifier);
    if (text === null) problems.push('an anchored head is not signed by the log');
    // Heads below the start (the last retention cut) speak of leaves that are gone: not checked here.
    else if (BigInt(parseCheckpoint(text).upto) >= BigInt(start.upto)) anchors.set(parseCheckpoint(text).upto, parseCheckpoint(text));
  }
  const last = heads.at(-1)!;
  for (const a of anchors.values()) {
    if (BigInt(a.upto) > BigInt(last.upto)) problems.push(`the database ends at ${last.upto} (${last.size} leaves); a head held outside seals up to ${a.upto} (${a.size} leaves): entries or checkpoints were deleted`);
  }

  let sealed = 0;
  let unsealed = 0;
  let cursor = start.upto;
  const check = (e: Entry) => {
    unique(e);
    if (opts.macKey !== undefined && !entryMac(opts.macKey, e).equals(e.mac)) problems.push(`${e.number}: mac`);
  };
  // Walk in chunks of whole checkpoints, a bounded read each.
  const pending = heads.slice(1);
  for (let i = 0; i < pending.length;) {
    const chunk: Checkpoint[] = [];
    let leaves = 0;
    while (i < pending.length && (chunk.length === 0 || leaves < 50_000)) {
      leaves += pending[i]!.size - (chunk.at(-1) ?? (i === 0 ? start : pending[i - 1]!)).size;
      chunk.push(pending[i]!);
      i += 1;
    }
    const entries = await entriesBetween(db, cursor, chunk.at(-1)!.upto);
    let at = 0;
    for (const c of chunk) {
      const before = edge.size;
      const window: Entry[] = [];
      while (at < entries.length && BigInt(entries[at]!.number) <= BigInt(c.upto)) window.push(entries[at++]!);
      window.forEach(check);
      edge.append(window.map(leafOf));
      sealed += window.length;
      if (edge.size !== c.size || !edge.root().equals(c.root)) {
        problems.push(`checkpoint ${c.upto}: ${window.length} entries since the one before, signed ${c.size - before}; the head ${edge.size === c.size ? 'differs' : 'cannot match'}: entries deleted, added or changed`);
        // Carry on from the signed head, so one problem is reported once.
        edge = Edge.load(c.size, tileMap(await readTiles(db, edgeOf(c.size).filter((e) => e.width > 0))));
      }
      const a = anchors.get(c.upto);
      if (a !== undefined && !(a.size === c.size && a.root.equals(c.root))) problems.push(`checkpoint ${c.upto}: not the head held outside for that place: a second history`);
      anchors.delete(c.upto);
      cursor = c.upto;
    }
  }
  for (const a of anchors.values()) {
    if (BigInt(a.upto) <= BigInt(last.upto)) problems.push(`no checkpoint in the database at ${a.upto}, where a head held outside is: a second history`);
  }
  for (const e of await entriesBetween(db, last.upto, '9223372036854775807')) {
    check(e);
    unsealed += 1;
  }
  return { ok: problems.length === 0, problems, warnings, checkpoints: heads.length, sealed, unsealed, ms: performance.now() - started };
}

