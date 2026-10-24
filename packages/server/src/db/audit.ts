import { deriveLogKey, GENESIS_HASH, verifyEntries, type LogKey } from '@coffre/core/audit';
import type { Queryable, Transaction } from '@coffre/db';
import { appendEntries, type Appended } from '@coffre/db/log';

import { auditHashAt, auditRange, newestHeartbeats } from './queries.ts';

export type AuditEntry = {
  actorType: 'user' | 'service' | 'system';
  actorId: string;
  action: string;
  decision: 'allow' | 'deny';
  projectId?: string | null;
  environmentId?: string | null;
  secretId?: string | null;
  /** One id for everything one action did, shared with the vault's entries for it. */
  operationId?: string | null;
  requestId?: string | null;
  sourceIp?: string | null;
  /** The vault's entry this one follows from: a write's `key.wrap`, a restore's `key.rewrap`. */
  relatedSeq?: number | null;
  metadata?: Record<string, unknown>;
};

/**
 * Append the app's entries to the audit log, inside the caller's transaction.
 *
 * This is deliberately NOT a queue, NOT a background write, and NOT
 * best-effort. Infisical's audit queue returned early and dropped every entry
 * silently; that failure mode is the reason this project exists. If the append
 * throws, the caller's transaction rolls back and the read that would have
 * been unlogged does not happen either.
 *
 * The append itself, which locks the log's head, dates, MACs and chains the
 * entries, is @coffre/db's: the vault appends to the same log the same way,
 * under its own key.
 */
export async function appendAudit(tx: Transaction, chainKey: Buffer, entries: readonly AuditEntry[]): Promise<Appended> {
  return appendEntries(
    tx,
    appLogKey(chainKey),
    entries.map((entry) => ({
      actor: actorOf(entry.actorType, entry.actorId),
      action: entry.action,
      decision: entry.decision,
      projectId: entry.projectId,
      environmentId: entry.environmentId,
      secretId: entry.secretId,
      operationId: entry.operationId,
      requestId: entry.requestId,
      sourceIp: entry.sourceIp,
      relatedSeq: entry.relatedSeq === undefined || entry.relatedSeq === null ? null : BigInt(entry.relatedSeq),
      metadata: JSON.stringify(entry.metadata ?? {}),
    })),
  );
}

const logKeys = new WeakMap<Buffer, LogKey>();

/**
 * The key the app's entries are MACed with, derived from `auditChainKey`.
 * One object per configured key, so the append's memory of the heads it
 * found lasts as long as the configuration does.
 */
export function appLogKey(chainKey: Buffer): LogKey {
  let key = logKeys.get(chainKey);
  if (key === undefined) logKeys.set(chainKey, (key = deriveLogKey('app', chainKey)));
  return key;
}

const ACTOR_PREFIX = { user: 'user', service: 'token', system: 'system' } as const;

/** An entry's actor as the log stores it: `user:<email>`, `token:<id>` or `system:<name>`. */
export function actorOf(type: AuditEntry['actorType'], id: string): string {
  return `${ACTOR_PREFIX[type]}:${id}`;
}

/** An actor as the API shows it, a type and an id: `actorOf` undone. */
export function actorParts(actor: string): { actorType: AuditEntry['actorType']; actorId: string } {
  const colon = actor.indexOf(':');
  const [prefix, rest] = [actor.slice(0, colon), actor.slice(colon + 1)];
  if (prefix === 'user') return { actorType: 'user', actorId: rest };
  if (prefix === 'token') return { actorType: 'service', actorId: rest };
  return { actorType: 'system', actorId: rest };
}

/** Where a check of the chain stands: the last entry it covered, -1 before the first, and that entry's hash. */
export type ChainPoint = { seq: bigint; hash: Buffer };

/** Before the first entry. */
export const CHAIN_START: ChainPoint = { seq: -1n, hash: GENESIS_HASH };

/**
 * Entries one walk of the chain covers, at most, on the app's side: about
 * 200 ms of a Worker's CPU. A walk cut short goes on from there next time.
 */
export const CHAIN_WALK = 10_000;

/** Entries read at once, at most, and no more than `BATCH_BYTES` of what they say (`auditRange`): within a Worker's memory, and few round trips. */
const BATCH = 5_000;

export type ChainWalk =
  | { ok: true; at: ChainPoint; done: boolean }
  | { ok: false; failedAtSeq: bigint; reason: string; through: bigint };

/**
 * The chain walked on from `from`, through `to` or the log's last entry,
 * and no more than `limit` entries: the numbers, the links, the hashes and
 * the app's MACs, each batch carrying on from the one before. The vault's
 * entries only by their place: the vault checks their MACs over the same
 * stretch, and its key never leaves it. `from` must still be where it was,
 * its entry's hash unchanged: a rewrite chained again from before it
 * changes that. Where it got to, and whether that is as far as it was to
 * go; on a fault, the entry before the faulty one, `through`.
 */
export async function walkChain(
  db: Queryable,
  chainKey: Buffer,
  from: ChainPoint,
  { to, limit = CHAIN_WALK }: { to?: bigint; limit?: number } = {},
): Promise<ChainWalk> {
  if (from.seq >= 0n) {
    if ((await auditHashAt(db, from.seq)) !== from.hash.toString('hex')) {
      return { ok: false, failedAtSeq: from.seq, reason: 'changed since the app last verified the log through it', through: from.seq - 1n };
    }
  }
  let at = from;
  for (let left = limit; ; ) {
    if (to !== undefined && at.seq >= to) return { ok: true, at, done: true };
    // Out of entries to walk, it is done if there are none left to: a walk that ends at its budget's last read one more.
    if (left <= 0) return { ok: true, at, done: !(await auditRange(db, at.seq + 1n, 1)).some((row) => to === undefined || row.seq <= to) };
    let batch = await auditRange(db, at.seq + 1n, Math.min(BATCH, left));
    if (to !== undefined) batch = batch.filter((row) => row.seq <= to);
    if (batch.length === 0) return { ok: true, at, done: to === undefined };
    const result = verifyEntries(batch, { startSeq: at.seq + 1n, startPrevHash: at.hash, keys: [appLogKey(chainKey)], chainOnly: ['vault'] });
    if (!result.ok) {
      // Verified through the entry read before the faulty one: with a gap, not the seq before it.
      const failed = batch.findIndex((row) => row.seq === result.failedAtSeq);
      return { ok: false, failedAtSeq: result.failedAtSeq, reason: result.reason, through: failed > 0 ? batch[failed - 1]!.seq : at.seq };
    }
    at = { seq: result.nextSeq - 1n, hash: result.head };
    left -= batch.length;
  }
}

/** Heartbeats looked back over for the newest the app wrote, by its MAC: an hour of them. */
const ATTESTATIONS_BACK = 12;

/** Heartbeats read past where a walk would resume, at most: far more than ever commit while one walks. */
const BEATS_SINCE = 1000;

/**
 * Where the next walk of the chain resumes: what the newest heartbeat the
 * app wrote says it verified (`verified`), a walk's end, or, if it found
 * the chain broken, where it began; and no further than where the walk of
 * any broken one after that point began, until a later walk clears it.
 * Read in the snapshot the walk runs in (`writeAuditHeartbeat`,
 * `auditReadiness`), so that every beat row past it is one the walk reads:
 * one hidden, forged or deleted there is an entry it finds changed
 * (formal/Audit.tla, `OneSnapshot`).
 *
 * A beat counts only by its MAC, and only for a point before its own row,
 * which its MAC covers: anyone who writes rows can change one, never make
 * one (`CursorByMac`). A broken one past that point found the chain
 * broken in a walk the newest one's did not see: two beats at once, the one
 * that walked first committing last. Its finding stands (`NoResumePastFinding`)
 * until a clean beat cleared it: one that walked over the entry it found,
 * from before it, in a snapshot that held the finder (`head`), so after the
 * finder found it, and found it whole (`Clears`, `ClearsOverFault`).
 * Without that, a finder whose row lies more than a walk past where its
 * walk began would bring every walk back there once the entry is put
 * back, and none would reach past it. One past the point that its MAC
 * does not vouch for is read by the walk, and found changed. Before the
 * first beat that walked, or past the hour of them, the first entry; past
 * `BEATS_SINCE` since, the first entry too, and `closed`.
 */
export async function resumePoint(db: Queryable, chainKey: Buffer): Promise<ChainPoint> {
  return (await resume(db, chainKey)).from;
}

/**
 * `resumePoint`, with what a beat records of it: `seen`, the newest beat
 * its MAC vouches for, whose row the snapshot holds, and so every row
 * before it; and `closed`, whether it fell back to the first entry for too
 * many beats past the point, which readiness answers red without walking.
 */
export async function resume(db: Queryable, chainKey: Buffer): Promise<{ from: ChainPoint; seen: bigint; closed: boolean }> {
  const key = appLogKey(chainKey);
  let seen = -1n;
  let base: Said | undefined;
  for (const beat of await newestHeartbeats(db, ATTESTATIONS_BACK)) {
    base = said(beat, key);
    if (base !== undefined) break;
  }
  if (base === undefined) return { from: CHAIN_START, seen, closed: false };
  seen = base.seq;
  let from = base.point;
  if (from.seq < 0n) return { from, seen, closed: false };
  const since = await newestHeartbeats(db, BEATS_SINCE, from.seq);
  if (since.length === BEATS_SINCE) return { from: CHAIN_START, seen, closed: true };
  const beats = since.map((beat) => said(beat, key)).filter((beat) => beat !== undefined);
  for (const finder of beats) {
    if (finder.broken === null || finder.point.seq >= from.seq) continue;
    if (!beats.some((beat) => clears(beat, finder))) from = finder.point;
  }
  return { from, seen, closed: false };
}

/** What a beat the app wrote says, by its MAC; undefined for one it did not write, or that ran no walk. */
type Said = {
  seq: bigint;
  /** Where the next walk goes on from: where this one ended, or, if it found the chain broken, where it began. */
  point: ChainPoint;
  /** The entry it found broken, or null; NaN if it does not say which. */
  broken: { seq: number } | null;
  /** Where its walk began, and the newest entry its snapshot held as the app wrote it: null in a beat before 0.12. */
  walk: { from: ChainPoint; head: bigint } | null;
};

function said(beat: Awaited<ReturnType<typeof newestHeartbeats>>[number], key: LogKey): Said | undefined {
  if (!verifyEntries([beat], { startSeq: beat.seq, startPrevHash: beat.prevHash, keys: [key] }).ok) return undefined;
  const { verified, broken, from, head } = JSON.parse(beat.metadata) as { verified?: unknown; broken?: { seq?: unknown }; from?: unknown; head?: unknown };
  // One that ran no walk, its database out of reach, says nothing of where to resume: the walk from an older
  // one's point reads its row.
  if (verified === undefined && broken === undefined) return undefined;
  const started = from === undefined ? CHAIN_START : pointIn(from, beat.seq);
  return {
    seq: beat.seq,
    point: pointIn(verified, beat.seq) ?? CHAIN_START,
    broken: broken === undefined ? null : { seq: typeof broken.seq === 'number' && Number.isSafeInteger(broken.seq) ? broken.seq : Number.NaN },
    walk: typeof head === 'number' && Number.isSafeInteger(head) && BigInt(head) < beat.seq && started !== undefined ? { from: started, head: BigInt(head) } : null,
  };
}

/** A point a beat names, before its own row: undefined if it names none it can. */
function pointIn(value: unknown, before: bigint): ChainPoint | undefined {
  const { seq, hash } = (value ?? {}) as { seq?: unknown; hash?: unknown };
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0 || BigInt(seq) >= before) return undefined;
  if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) return undefined;
  return { seq: BigInt(seq), hash: Buffer.from(hash, 'hex') };
}

/**
 * Whether `beat` cleared what `finder` found: a clean walk of its, in a
 * snapshot that held the finder's row, so begun after the finder's, that
 * went over the entry found from before it. A finder that found the entry
 * it began from changed, its hash not the one it verified, is cleared only
 * by a walk that began there and found that hash again. A beat before 0.12,
 * which says neither, clears nothing.
 */
function clears(beat: Said, finder: Said): boolean {
  if (beat.broken !== null || beat.walk === null || beat.walk.head < finder.seq) return false;
  const found = finder.broken!.seq;
  if (!Number.isSafeInteger(found)) return false;
  const { from } = beat.walk;
  if (BigInt(found) === finder.point.seq) return from.seq === finder.point.seq && from.hash.equals(finder.point.hash);
  return from.seq < BigInt(found) && BigInt(found) <= beat.point.seq;
}
