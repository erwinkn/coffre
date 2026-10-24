import { deriveLogKey, GENESIS_HASH, verifyEntries, type ChainVerification, type LogKey, type StoredEntry } from '@coffre/core/audit';
import { tablesOf, type Queryable, type Transaction } from '@coffre/db';
import { appendEntries, MOVES_FROM, type Appended } from '@coffre/db/log';
import { and, eq, inArray, min } from 'drizzle-orm';

import { auditHashAt, auditRange } from './queries.ts';

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
  /** What the entry is about, when no column above says: the key a `key.reseal` or `key.rotate` moves from. */
  subject?: string | null;
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
      subjectPrincipal: entry.subject ?? null,
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

/**
 * The app's keys: `chainKey`, the one it signs with now, and those it
 * replaced, `previousChainKeys`, which only verify (`previousAuditChainKeys`
 * in the configuration).
 */
export type AppKeys = { chainKey: Buffer; previousChainKeys: readonly Buffer[] };

/**
 * What the app's entries are checked with: its keys, and for each it
 * replaced that the log has moved on from, the entry where it did, its
 * first `key.reseal` or `key.rotate` naming it. A key verifies only the
 * entries before that one.
 */
export type AppVerifier = { keys: readonly LogKey[]; movedOn: ReadonlyMap<string, bigint> };

/** The verifier for `keys`, as the log now says where it moved on from each: one indexed read, none without previous keys. */
export async function appVerifier(db: Queryable, keys: AppKeys): Promise<AppVerifier> {
  const previous = keys.previousChainKeys.map(appLogKey);
  const all = [appLogKey(keys.chainKey), ...previous];
  if (previous.length === 0) return { keys: all, movedOn: new Map() };
  const { auditLog } = tablesOf(db);
  const rows = await db
    .select({ keyId: auditLog.subjectPrincipal, seq: min(auditLog.seq) })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), inArray(auditLog.action, [...MOVES_FROM]), inArray(auditLog.subjectPrincipal, previous.map((key) => key.keyId))))
    .groupBy(auditLog.subjectPrincipal);
  return { keys: all, movedOn: new Map(rows.map((row) => [row.keyId!, BigInt(row.seq!)])) };
}

/**
 * A run of entries checked as `verifyEntries` checks it, the app's by its
 * keys and the vault's by their place, and then that no entry of the app's
 * is under a key it had moved on from by then.
 */
export function verifyAppEntries(entries: readonly StoredEntry[], from: { startSeq: bigint; startPrevHash: Buffer }, verifier: AppVerifier): ChainVerification {
  const moved = entries.findIndex((entry) => entry.author === 'app' && entry.seq >= (verifier.movedOn.get(entry.keyId) ?? entry.seq + 1n));
  const result = verifyEntries(moved === -1 ? entries : entries.slice(0, moved), { ...from, keys: verifier.keys, chainOnly: ['vault'] });
  if (!result.ok || moved === -1) return result;
  const entry = entries[moved]!;
  return {
    ok: false,
    failedAtSeq: entry.seq,
    reason: `written under ${entry.keyId} after the app moved on from it, at entry ${verifier.movedOn.get(entry.keyId)}: a key it replaced verifies only what came before`,
  };
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
 * stretch, and its key never leaves it. A key the app replaced verifies
 * only its entries from before the app moved on from it (`appVerifier`).
 * `from` must still be where it was, its entry's hash unchanged: a rewrite
 * chained again from before it changes that. Where it got to, and whether
 * that is as far as it was to go; on a fault, the entry before the faulty
 * one, `through`.
 */
export async function walkChain(
  db: Queryable,
  keys: AppKeys,
  from: ChainPoint,
  { to, limit = CHAIN_WALK }: { to?: bigint; limit?: number } = {},
): Promise<ChainWalk> {
  if (from.seq >= 0n) {
    if ((await auditHashAt(db, from.seq)) !== from.hash.toString('hex')) {
      return { ok: false, failedAtSeq: from.seq, reason: 'changed since the app last verified the log through it', through: from.seq - 1n };
    }
  }
  const verifier = await appVerifier(db, keys);
  let at = from;
  for (let left = limit; ; ) {
    if (to !== undefined && at.seq >= to) return { ok: true, at, done: true };
    // Out of entries to walk, it is done if there are none left to: a walk that ends at its budget's last read one more.
    if (left <= 0) return { ok: true, at, done: !(await auditRange(db, at.seq + 1n, 1)).some((row) => to === undefined || row.seq <= to) };
    let batch = await auditRange(db, at.seq + 1n, Math.min(BATCH, left));
    if (to !== undefined) batch = batch.filter((row) => row.seq <= to);
    if (batch.length === 0) return { ok: true, at, done: to === undefined };
    const result = verifyAppEntries(batch, { startSeq: at.seq + 1n, startPrevHash: at.hash }, verifier);
    if (!result.ok) {
      // Verified through the entry read before the faulty one: with a gap, not the seq before it.
      const failed = batch.findIndex((row) => row.seq === result.failedAtSeq);
      return { ok: false, failedAtSeq: result.failedAtSeq, reason: result.reason, through: failed > 0 ? batch[failed - 1]!.seq : at.seq };
    }
    at = { seq: result.nextSeq - 1n, hash: result.head };
    left -= batch.length;
  }
}
