import { randomUUID } from 'node:crypto';

import { append, entryMac, leafOf, type Checkpointer, type Db, type DayRecord, type Entry, type Keys } from './log.ts';
import { openCheckpoint, verifierFrom } from './note.ts';
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

export async function retainDay(db: Db, keys: Keys, day: number, checkpointer: Checkpointer): Promise<{ retention: Retention; dropped: number; tilesDropped: number; ms: number }> {
  const started = performance.now();
  const { rows: [layout] } = await db.query('SELECT mode FROM audit_layout');
  const mode = layout.mode as 'number' | 'at';
  const partition = `audit_uses_d${day}`;
  const { rows: [part] } = await db.query(`SELECT count(*)::int AS n, max(number)::text AS max FROM ${partition}`);
  // The cut: the first checkpoint at or above every number the day holds. Number days: the day's signed entry names
  // its last number (an unsigned column would let a writer move the cut).
  let highest: string = part.max ?? '0';
  if (mode === 'number') {
    // Exactly one, sealed, with its MAC: the day's extent is read from the log, never from what a writer can edit.
    const records = (await entriesBetween(db, '0', '9223372036854775807', `a.kind = 'change' AND a.payload LIKE '{"action":"audit.day","day":${Number(day)},%'`));
    if (records.length !== 1) throw new Error(`day ${day}: ${records.length} day entries, not one`);
    const d = records[0]!;
    const { rows: [top] } = await db.query('SELECT max(upto)::text AS upto FROM checkpoints');
    if (BigInt(d.number) > BigInt(top.upto)) throw new Error(`day ${day}: its entry is not sealed yet`);
    if (!entryMac(keys.mac, d).equals(d.mac)) throw new Error(`day ${day}: its entry fails its MAC`);
    highest = (JSON.parse(d.payload) as DayRecord).last;
  }
  const { rows: [cut] } = await db.query('SELECT c.upto::text, c.size::int, c.note FROM checkpoints c WHERE c.upto >= $1 ORDER BY c.upto LIMIT 1', [highest]);
  if (cut === undefined) throw new Error(`day ${day} is not sealed yet`);
  // Before anything is dropped, a head signed well after the cut: the signer then refuses to seal any entry stamped
  // before it, less its freshness bound, and every dropped entry was stamped before the cut was signed. So a copy of
  // a dropped use, which no lookup can match once its original is gone, is refused whenever it is slipped in, even
  // into the tick that seals the retention entry, on a log quiet since the day closed (review r5).
  if (!checkpointer.remembers) throw new Error('retention needs a checkpointer that remembers its head outside the database');
  const cutHead = await openCheckpoint(cut.note, await verifierFrom(keys.signer.verifierKey));
  // The note must be the row's own: a row's columns are the writer's, the note's place and size are signed.
  if (cutHead === null || cutHead.upto !== cut.upto || cutHead.size !== cut.size) throw new Error(`day ${day}: the checkpoint at its cut is not the one this log signed there`);
  // A request ID of its own per attempt: an attempt refused below may be tried again later.
  const begin = await append(db, keys, {
    at: Date.now(), principal: 'vault', credential: null, kind: 'change', requestId: `retention-begin-${day}-${randomUUID()}`, payload: JSON.stringify({ action: 'audit.retention.begin', day }),
  });
  const { head } = await checkpointer.sealThrough(begin);
  const notBefore = cutHead.at + 2 * checkpointer.freshMs;
  if (head.at < notBefore) throw new Error(`day ${day} closed too recently to drop: not before ${new Date(notBefore).toISOString()}`);
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

export async function entriesBetween(db: Db, from: string, upto: string, where = 'true'): Promise<Entry[]> {
  const { rows } = await db.query(
    `SELECT a.number::text, a.at::text, a.principal, a.credential, a.kind, a.request_id, a.payload, a.seal, a.mac FROM audit a WHERE a.number > $1 AND a.number <= $2 AND ${where} ORDER BY a.number`,
    [from, upto],
  );
  return rows.map((r) => ({ number: r.number, at: Number(r.at), principal: r.principal, credential: r.credential, kind: r.kind, requestId: r.request_id, payload: r.payload, seal: r.seal, mac: r.mac }));
}
