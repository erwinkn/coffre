import { append, leafOf, type Db, type DayRecord, type Entry, type Keys } from './log.ts';
import { referenceHash } from './tree.ts';

/**
 * Retention: drop a day of uses once it is sealed, and say so in the log.
 *
 * Changes are kept forever and share the tree with uses, so a dropped day is
 * not a clean prefix of the tree: changes (and, with `at` days, a few uses of
 * the next day that took smaller numbers near midnight) stay among the leaves
 * below the cut. The retention entry, a change itself, names the cut (a
 * checkpoint at or above every dropped number) and commits to exactly what
 * stays below it since the last cut: how many entries, and the RFC 9162 head
 * of their leaves. The verifier then checks what stays against that head and
 * walks the tree from the cut as before; a kept change deleted later, or the
 * retention entry itself, fails one of the two. The tree's tiles below the cut
 * go with the day, except the higher levels (one hash per 256 leaves), which
 * proofs of what comes after still read.
 */
export type Retention = { action: 'audit.retention'; day: number; mode: 'number' | 'at'; prevCutUpto: string; cutUpto: string; cutSize: number; kept: number; keptRoot: string };

export async function retainDay(db: Db, keys: Keys, day: number): Promise<{ retention: Retention; dropped: number; tilesDropped: number; ms: number }> {
  const started = performance.now();
  const { rows: [layout] } = await db.query('SELECT mode FROM audit_layout');
  const mode = layout.mode as 'number' | 'at';
  const partition = `audit_uses_d${day}`;
  const { rows: [part] } = await db.query(`SELECT count(*)::int AS n, max(number)::text AS max FROM ${partition}`);
  // The cut: the first checkpoint at or above every number the day holds. Number days: the day's signed entry names
  // its last number (an unsigned column would let a writer move the cut).
  let highest: string = part.max ?? '0';
  if (mode === 'number') {
    const { rows: [d] } = await db.query(`SELECT a.payload FROM audit_changes a WHERE a.payload LIKE '{"action":"audit.day","day":' || $1 || ',%'`, [day]);
    if (d === undefined) throw new Error(`day ${day} has not closed`);
    highest = (JSON.parse(d.payload) as DayRecord).last;
  }
  const { rows: [cut] } = await db.query('SELECT c.upto::text, c.size::int FROM checkpoints c WHERE c.upto >= $1 ORDER BY c.upto LIMIT 1', [highest]);
  if (cut === undefined) throw new Error(`day ${day} is not sealed yet`);
  const previous = await latestRetention(db);
  const prevCutUpto = previous?.cutUpto ?? '0';
  await db.query(`DROP TABLE ${partition}`);
  const kept = await entriesBetween(db, prevCutUpto, cut.upto);
  const retention: Retention = {
    action: 'audit.retention', day, mode, prevCutUpto, cutUpto: cut.upto, cutSize: cut.size,
    kept: kept.length, keptRoot: referenceHash(kept.map(leafOf)).toString('base64'),
  };
  await append(db, keys, { at: Date.now(), principal: 'vault', credential: null, kind: 'change', requestId: `retention-${day}`, payload: JSON.stringify(retention) });
  const { rows: [t] } = await db.query('WITH d AS (DELETE FROM audit_tiles WHERE level = 0 AND idx < $1 RETURNING 1) SELECT count(*)::int AS n FROM d', [Math.floor(cut.size / 256)]);
  return { retention, dropped: part.n, tilesDropped: t.n, ms: performance.now() - started };
}

/** Every retention entry, oldest first. */
export async function retentions(db: Db): Promise<(Retention & { number: string })[]> {
  const { rows } = await db.query(
    `SELECT a.number::text, a.payload FROM audit_changes a WHERE a.payload LIKE '{"action":"audit.retention"%' ORDER BY a.number`,
  );
  return rows.map((r) => ({ ...(JSON.parse(r.payload) as Retention), number: r.number }));
}

async function latestRetention(db: Db): Promise<Retention | null> {
  return (await retentions(db)).at(-1) ?? null;
}

export async function entriesBetween(db: Db, from: string, upto: string): Promise<Entry[]> {
  const { rows } = await db.query(
    'SELECT a.number::text, a.at::text, a.principal, a.credential, a.kind, a.request_id, a.payload, a.seal, a.mac FROM audit a WHERE a.number > $1 AND a.number <= $2 ORDER BY a.number',
    [from, upto],
  );
  return rows.map((r) => ({ number: r.number, at: Number(r.at), principal: r.principal, credential: r.credential, kind: r.kind, requestId: r.request_id, payload: r.payload, seal: r.seal, mac: r.mac }));
}
