import { deriveLogKey, GENESIS_HASH, verifyEntries, type LogKey, type StoredEntry } from '@coffre/core/audit';
import type { LogHead, LogVerification } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';

import { entriesFrom, hashAt, vaultEntriesAfter } from './store.ts';
import type { Walk } from './tally.ts';

/**
 * The vault's half of the one audit log: its entries are the ones it
 * writes, `author = 'vault'`, each under its MAC, in the chain the app's
 * entries share (@coffre/core/audit says what an entry covers). The app
 * checks its own entries by its key; this checks the vault's by the vault's,
 * and the app's only for their place in the chain.
 */

/**
 * The vault's log key, derived from its signing key, so that it is one more
 * secret to hold, not one more to keep. Whoever can write the database but
 * does not hold the vault's configuration cannot write an entry it accepts.
 */
export function vaultLogKey(signingKey: Uint8Array): LogKey {
  return deriveLogKey('vault', signingKey);
}

/** Where a walk of the log stands: the last entry it covered, -1 before the first, and that entry's hash. */
export type Position = { seq: bigint; hash: Buffer };

/** Before the first entry. */
export const START: Position = { seq: -1n, hash: GENESIS_HASH };

/** The further of two positions, when two calls walked at once. */
export function further(a: Position, b: Position): Position {
  return b.seq > a.seq ? b : a;
}

/** Entries read at once, at most, and no more than `BATCH_BYTES` of what they say: well within a Worker's memory, and a fifth of the round trips of 1000. */
export const VERIFY_BATCH = 5000;

type Broken = Extract<LogVerification, { ok: false }>;

/**
 * Walk the chain on from `from`, a batch in memory at a time, through `to`
 * or the log's last entry, and no more than `limit` entries: every link and
 * hash recomputed, each of the vault's entries by its MAC, its keys moving
 * only forward, and each fed to `walk`. Where it got to, and whether that
 * is as far as it was to go: a walk cut short by `limit` goes on from there
 * another time.
 *
 * It takes `from` as given: whether the log still holds it is the caller's
 * to check, with the other heads it must hold, in one read.
 */
export async function rehash(
  db: Queryable,
  logKeys: readonly LogKey[],
  from: Position,
  walk: Walk,
  { to, limit = Infinity }: { to?: bigint; limit?: number },
): Promise<{ ok: true; at: Position; done: boolean } | Broken> {
  let at = from;
  for (let left = limit; ; ) {
    if (to !== undefined && at.seq >= to) return { ok: true, at, done: true };
    if (left <= 0) return { ok: true, at, done: false };
    let batch = await entriesFrom(db, at.seq + 1n, Math.min(VERIFY_BATCH, left));
    if (to !== undefined) batch = batch.filter((entry) => entry.seq <= to);
    if (batch.length === 0) return { ok: true, at, done: to === undefined };
    const result = verifyEntries(batch, { keys: logKeys, chainOnly: ['app'], startSeq: at.seq + 1n, startPrevHash: at.hash });
    if (!result.ok) return { ok: false, failedAtSeq: Number(result.failedAtSeq), reason: withCause(result.reason) };
    for (const entry of batch) {
      const moved = entry.author === 'vault' ? walk.add(entry, logKeys[0]!.keyId) : null;
      if (moved !== null) return { ok: false, failedAtSeq: Number(moved.failedAtSeq), reason: moved.reason };
    }
    at = { seq: result.nextSeq - 1n, hash: result.head };
    left -= batch.length;
  }
}

/**
 * The chain again from `from`, through `to` and no more than `limit`
 * entries: each hash recomputed from its entry and each link checked, and
 * nothing else, so a stretch costs a hash an entry. What a checkpoint does
 * in the background to the prefixes signed before (`#scrub` in vault.ts):
 * each entry's MAC was checked when it was signed over, and its hash pins
 * it since, so all that can change behind a signed prefix and keep the
 * chain is an entry edited in place, its stored hash left, which its hash
 * finds.
 */
export async function relink(db: Queryable, from: Position, to: bigint, limit: number): Promise<{ ok: true; at: Position } | Broken> {
  let at = from;
  while (at.seq < to && limit > 0) {
    const batch = (await entriesFrom(db, at.seq + 1n, Math.min(VERIFY_BATCH, limit))).filter((entry) => entry.seq <= to);
    if (batch.length === 0) break;
    const result = verifyEntries(batch, { keys: [], chainOnly: ['app', 'vault'], startSeq: at.seq + 1n, startPrevHash: at.hash });
    if (!result.ok) return { ok: false, failedAtSeq: Number(result.failedAtSeq), reason: result.reason };
    at = { seq: result.nextSeq - 1n, hash: result.head };
    limit -= batch.length;
  }
  return { ok: true, at };
}

/**
 * The vault's own entries after `after`, through `to` or its last, no more
 * than `limit` of them, oldest first: each against its own hash, and by its
 * MAC, over the link it names, its keys moving only forward, each fed to
 * `walk`. The links between entries are the caller's to recompute, as the
 * app does over the same stretch. The last it read, and whether that is as
 * far as it was to go.
 */
export async function ownEntries(
  db: Queryable,
  logKeys: readonly LogKey[],
  after: bigint,
  walk: Walk,
  { to, limit = Infinity }: { to?: bigint; limit?: number },
): Promise<{ ok: true; at: bigint; done: boolean } | Broken> {
  for (let left = limit; ; ) {
    if (left <= 0) return { ok: true, at: after, done: false };
    let batch = await vaultEntriesAfter(db, after, Math.min(VERIFY_BATCH, left));
    if (to !== undefined) batch = batch.filter((entry) => entry.seq <= to);
    if (batch.length === 0) return { ok: true, at: after, done: true };
    for (const entry of batch) {
      const result = verifyEntries([entry], { startSeq: entry.seq, startPrevHash: entry.prevHash, keys: logKeys });
      if (!result.ok) return { ok: false, failedAtSeq: Number(result.failedAtSeq), reason: withCause(result.reason) };
    }
    for (const entry of batch) {
      const moved = walk.add(entry, logKeys[0]!.keyId);
      if (moved !== null) return { ok: false, failedAtSeq: Number(moved.failedAtSeq), reason: moved.reason };
    }
    after = batch[batch.length - 1]!.seq;
    left -= batch.length;
  }
}

/**
 * The vault's keys only move forward. Once its entries move from one key to
 * the next, the one before writes no more; once they reach `current`, the
 * key it writes with now, no other key writes again. So a key it replaced,
 * even one that leaked, verifies what came before the rotation, and nothing
 * after it.
 */
export function forward(
  entries: readonly StoredEntry[],
  keys: readonly string[],
  current: string,
): { keys: readonly string[] } | { failedAtSeq: bigint; reason: string } {
  let moved = keys;
  for (const entry of entries) {
    const last = moved.at(-1);
    if (entry.author !== 'vault' || entry.keyId === last) continue;
    if (last === current || moved.includes(entry.keyId)) {
      return {
        failedAtSeq: entry.seq,
        reason: `written under ${entry.keyId} after the vault moved to ${last}: a key it replaced verifies only what came before`,
      };
    }
    moved = [...moved, entry.keyId];
  }
  return { keys: moved };
}

/**
 * A vault entry under a key the vault does not hold is a forgery, or one
 * written under a key it was configured with then: its keys come from its
 * signing key, or from its KEK when it has none. The second is the one an
 * operator can fix.
 */
export function withCause(reason: string): string {
  if (!/^written under vault:\S+, a key this verifier does not hold$/.test(reason)) return reason;
  return `${reason}: either it is forged, or the vault wrote it under another vault key or signing key, which must stay configured: a vault key that was replaced stays in the vault's config, in previousKeks`;
}

/**
 * Whether the log still holds `head` where it was: not rewritten, nor cut
 * back before it. A head of 64 zeros is before the first entry, which any
 * log holds.
 */
export async function carries(db: Queryable, head: LogHead): Promise<boolean> {
  if (head.hash === GENESIS_HASH.toString('hex')) return true;
  return (await hashAt(db, BigInt(head.seq)))?.toString('hex') === head.hash;
}

/** One of the vault's entries, as its tests read them. */
export type LogEntry = {
  seq: number;
  at: string;
  actor: string;
  action: string;
  outcome: 'allow' | 'refuse';
  code: string | null;
  subject: string | null;
  detail: Record<string, unknown>;
  hash: string;
};

/**
 * An entry as the vault log's readers see it. `subject` is the member an
 * access change is about, or what else the entry names: a secret's path,
 * the audit log, the vault's own.
 */
export function entryView(row: StoredEntry): LogEntry {
  const { subject, ...detail } = JSON.parse(row.metadata) as Record<string, unknown>;
  const ids = {
    projectId: row.projectId,
    environmentId: row.environmentId,
    secretId: row.secretId,
    requestId: row.requestId,
    operationId: row.operationId,
    relatedSeq: row.relatedSeq === null ? null : row.relatedSeq.toString(),
  };
  return {
    seq: Number(row.seq),
    at: new Date(row.occurredAt).toISOString(),
    actor: row.actor,
    action: row.action,
    outcome: row.decision === 'allow' ? 'allow' : 'refuse',
    code: row.code,
    subject: row.subjectPrincipal ?? (typeof subject === 'string' ? subject : null),
    detail: { ...Object.fromEntries(Object.entries(ids).filter(([, value]) => value !== null)), ...detail },
    hash: row.hash.toString('hex'),
  };
}
