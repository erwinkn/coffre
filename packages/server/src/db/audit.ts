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
 * any broken one after that point began. Read in the snapshot the walk
 * runs in (`writeAuditHeartbeat`, `auditReadiness`), so that every beat
 * row past it is one the walk reads: one hidden, forged or deleted there
 * is an entry it finds changed (formal/Audit.tla, `OneSnapshot`).
 *
 * A beat counts only by its MAC, and only for a point before its own row,
 * which its MAC covers: anyone who writes rows can change one, never make
 * one (`CursorByMac`). A broken one past that point found the chain
 * broken in a walk the newest one's did not see: two beats at once, the one
 * that walked first committing last. Its finding stands until a walk from
 * where it began passes it (`NoResumePastFinding`). One past the point
 * that its MAC does not vouch for is read by the walk, and found changed.
 * Before the first beat that walked, past the hour of them, or past
 * `BEATS_SINCE` since, the first entry.
 */
export async function resumePoint(db: Queryable, chainKey: Buffer): Promise<ChainPoint> {
  const key = appLogKey(chainKey);
  const said = (beat: Awaited<ReturnType<typeof newestHeartbeats>>[number]) => {
    if (!verifyEntries([beat], { startSeq: beat.seq, startPrevHash: beat.prevHash, keys: [key] }).ok) return null;
    const { verified, broken } = JSON.parse(beat.metadata) as { verified?: { seq?: unknown; hash?: unknown }; broken?: unknown };
    // One that ran no walk, its database out of reach, says nothing of where to resume: the walk from an older
    // one's point reads its row.
    if (verified === undefined && broken === undefined) return null;
    const { seq, hash } = verified ?? {};
    const point =
      typeof seq === 'number' && Number.isSafeInteger(seq) && seq >= 0 && BigInt(seq) < beat.seq && typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash)
        ? { seq: BigInt(seq), hash: Buffer.from(hash, 'hex') }
        : CHAIN_START;
    return { point, broken: broken !== undefined };
  };
  let resume: ChainPoint | undefined;
  for (const beat of await newestHeartbeats(db, ATTESTATIONS_BACK)) {
    resume = said(beat)?.point;
    if (resume !== undefined) break;
  }
  if (resume === undefined || resume.seq < 0n) return CHAIN_START;
  const since = await newestHeartbeats(db, BEATS_SINCE, resume.seq);
  if (since.length === BEATS_SINCE) return CHAIN_START;
  for (const beat of since) {
    const it = said(beat);
    if (it?.broken === true && it.point.seq < resume.seq) resume = it.point;
  }
  return resume;
}
