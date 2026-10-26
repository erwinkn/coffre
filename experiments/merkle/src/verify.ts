import { entryMac, leafOf, readTiles, type Db, type Entry } from './log.ts';
import { entriesBetween, retentions } from './retention.ts';
import { referenceHash } from './tree.ts';
import { openCheckpoint, verifierFrom, type Checkpoint } from './note.ts';
import { Edge, edgeOf, tileMap } from './tiles.ts';

/**
 * The log, verified from the database and the heads held outside it. It walks
 * the entries from a start it trusts, never one the database picks: the
 * genesis head, the cut named by the newest sealed retention entry, or a head
 * the caller verified before (`from`). In number order it rebuilds the tree
 * and requires, on the way, every signed checkpoint row and every head held
 * outside (a witness's, an archive's): so every sealed entry is there,
 * unchanged, at its place, nothing was added, and the database shows the one
 * history the outside heads saw. A database that ends before an outside head
 * lost entries or checkpoints. The cost is the entries since the start, and a
 * caller that keeps its last verified head walks only what came after (R25).
 *
 * It needs the log's public key only. With the MAC key it also checks every
 * entry's MAC, those not sealed yet included.
 */
/** `warnings`: what may be an attack and may be a clock (an entry's `at` running back against its number). */
export type Verdict = { ok: boolean; problems: string[]; warnings: string[]; checkpoints: number; sealed: number; unsealed: number; ms: number };

/** How far apart two Workers' clocks may be before an entry's `at` running back against its number is worth a look. */
const SKEW_MS = 5000;

const GENESIS_UPTO = '0';

export async function verifyLog(
  db: Db,
  opts: { verifierKey: string; macKey?: Buffer; anchors?: string[]; from?: string },
): Promise<Verdict> {
  const started = performance.now();
  const verifier = await verifierFrom(opts.verifierKey);
  const problems: string[] = [];
  const warnings: string[] = [];
  const done = (checkpoints = 0, sealed = 0, unsealed = 0): Verdict =>
    ({ ok: problems.length === 0, problems, warnings, checkpoints, sealed, unsealed, ms: performance.now() - started });
  // Numbers and request IDs must be unique: nothing in the database enforces it across partitions, and a copy of an
  // entry under a fresh number (a replay, before it is sealed) is otherwise a valid entry.
  let latest = 0;
  const numbers = new Set<string>();
  const requests = new Set<string>();
  const check = (e: Entry) => {
    if (numbers.has(e.number)) problems.push(`${e.number}: two entries with this number`);
    if (requests.has(e.requestId)) problems.push(`${e.number}: request ${e.requestId} logged twice`);
    numbers.add(e.number);
    requests.add(e.requestId);
    if (opts.macKey !== undefined && !entryMac(opts.macKey, e).equals(e.mac)) problems.push(`${e.number}: mac`);
    // Numbers swapped before sealing (the MAC does not cover them) show as an `at` running back; so does a skewed clock.
    if (e.at < latest - SKEW_MS) warnings.push(`${e.number}: at ${e.at}, ${latest - e.at} ms before an entry numbered earlier`);
    latest = Math.max(latest, e.at);
  };

  // Every signed checkpoint row.
  const { rows } = await db.query('SELECT c.upto::text, c.size::text, c.note FROM checkpoints c ORDER BY c.upto');
  const heads = new Map<string, Checkpoint>();
  for (const r of rows) {
    const c = await openCheckpoint(r.note, verifier);
    if (c === null) {
      problems.push(`checkpoint ${r.upto}: not signed by the log`);
      continue;
    }
    if (c.upto !== r.upto || String(c.size) !== r.size) problems.push(`checkpoint ${r.upto}: its row does not match its note`);
    else heads.set(c.upto, c);
  }
  const last = [...heads.values()].at(-1);
  if (last === undefined) return { ...done(), ok: false, problems: [...problems, 'no checkpoint'] };

  // Retention: the cuts must chain from genesis, each entry was appended after its cut and is sealed, and what stays
  // below each cut is exactly what it says. The newest cut's entry is then on the walk (it lies above the cut), and
  // each earlier one either is too or lies below a later cut, covered by that cut's head of what stayed.
  const cuts = await retentions(db);
  let prevCut = GENESIS_UPTO;
  for (const r of cuts) {
    if (r.prevCutUpto !== prevCut || BigInt(r.cutUpto) <= BigInt(prevCut)) problems.push(`retention of day ${r.day}: its cut does not follow the one before (${prevCut})`);
    if (BigInt(r.number) <= BigInt(r.cutUpto)) problems.push(`retention of day ${r.day}: written below its own cut`);
    if (BigInt(r.number) > BigInt(last.upto)) problems.push(`retention of day ${r.day}: not sealed yet`);
    const kept = await entriesBetween(db, r.prevCutUpto, r.cutUpto);
    kept.forEach(check);
    if (kept.length !== r.kept || referenceHash(kept.map(leafOf)).toString('base64') !== r.keptRoot) {
      problems.push(`retention of day ${r.day}: ${kept.length} entries stay below its cut at ${r.cutUpto}, it kept ${r.kept}${kept.length === r.kept ? ' with another head' : ''}`);
    }
    prevCut = r.cutUpto;
  }

  // The start: a head the caller trusts, else the newest cut (its size from the retention entry), else genesis.
  let expected: { upto: string; size: number; root?: Buffer };
  const trusted = opts.from === undefined ? null : await openCheckpoint(opts.from, verifier);
  if (opts.from !== undefined && trusted === null) return { ...done(), ok: false, problems: [...problems, 'the head to start from is not signed by the log'] };
  const cut = cuts.at(-1);
  if (trusted !== null) {
    const t = trusted;
    if (cut !== undefined && BigInt(t.upto) < BigInt(cut.cutUpto)) problems.push(`the head to start from (${t.upto}) is below the retention cut (${cut.cutUpto})`);
    expected = { upto: t.upto, size: t.size, root: t.root };
  } else if (cut !== undefined) {
    expected = { upto: cut.cutUpto, size: cut.cutSize };
  } else {
    expected = { upto: GENESIS_UPTO, size: 0 };
  }
  const start = heads.get(expected.upto);
  if (start === undefined || start.size !== expected.size || (expected.root !== undefined && !start.root.equals(expected.root))) {
    return { ...done(heads.size), ok: false, problems: [...problems, `no checkpoint at ${expected.upto} with ${expected.size} leaves, where the walk must start: checkpoints were deleted or replaced`] };
  }
  let edge = Edge.load(start.size, tileMap(await readTiles(db, edgeOf(start.size).filter((e) => e.width > 0))));
  if (!edge.root().equals(start.root)) problems.push(`checkpoint ${start.upto}: the tiles at its edge do not give its head`);

  // The stops on the walk: every checkpoint row above the start, and every head held outside, by the place it seals.
  type Stop = { head: Checkpoint; row: boolean; outside: boolean };
  const stops = new Map<string, Stop>();
  for (const h of heads.values()) if (BigInt(h.upto) > BigInt(start.upto)) stops.set(h.upto, { head: h, row: true, outside: false });
  for (const note of opts.anchors ?? []) {
    const a = await openCheckpoint(note, verifier);
    if (a === null) {
      problems.push('a head held outside is not signed by the log');
      continue;
    }
    // Heads below the start speak of leaves the walk does not rebuild (dropped by retention, or verified before).
    if (BigInt(a.upto) <= BigInt(start.upto)) {
      if (a.upto === start.upto && !(a.size === start.size && a.root.equals(start.root))) problems.push(`checkpoint ${a.upto}: not the head held outside for that place: a second history`);
      continue;
    }
    const row = stops.get(a.upto);
    if (row !== undefined && !(row.head.size === a.size && row.head.root.equals(a.root))) problems.push(`checkpoint ${a.upto}: not the head held outside for that place: a second history`);
    if (BigInt(a.upto) > BigInt(last.upto)) problems.push(`the database ends at ${last.upto} (${last.size} leaves); a head held outside seals up to ${a.upto} (${a.size} leaves): entries or checkpoints were deleted`);
    else if (row === undefined) stops.set(a.upto, { head: a, row: false, outside: true });
    else row.outside = true;
  }
  const ordered = [...stops.values()].sort((x, y) => (BigInt(x.head.upto) < BigInt(y.head.upto) ? -1 : 1));

  let sealed = 0;
  let cursor = start.upto;
  // Walk in chunks of whole windows, a bounded read each.
  for (let i = 0; i < ordered.length;) {
    const chunk: Stop[] = [];
    while (i < ordered.length && (chunk.length === 0 || ordered[i]!.head.size - edge.size < 50_000)) chunk.push(ordered[i++]!);
    const entries = await entriesBetween(db, cursor, chunk.at(-1)!.head.upto);
    let at = 0;
    for (const { head: c, row } of chunk) {
      const before = edge.size;
      const window: Entry[] = [];
      while (at < entries.length && BigInt(entries[at]!.number) <= BigInt(c.upto)) window.push(entries[at++]!);
      window.forEach(check);
      edge.append(window.map(leafOf));
      sealed += window.length;
      if (edge.size !== c.size || !edge.root().equals(c.root)) {
        problems.push(`${row ? 'checkpoint' : 'the head held outside at'} ${c.upto}: ${window.length} entries since the stop before, signed ${c.size - before}; the head ${edge.size === c.size ? 'differs' : 'cannot match'}: entries deleted, added or changed, or a second history`);
        // Carry on from the signed head, so one problem is reported once.
        if (row) edge = Edge.load(c.size, tileMap(await readTiles(db, edgeOf(c.size).filter((e) => e.width > 0))));
      }
      cursor = c.upto;
    }
  }
  const above = await entriesBetween(db, last.upto, '9223372036854775807');
  above.forEach(check);
  return done(heads.size, sealed, above.length);
}
