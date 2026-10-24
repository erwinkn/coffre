// The audit log's anchor: what the heartbeat last verified, kept where
// whoever writes the database cannot (docs/architecture.md, "The audit
// anchor"). One small record per instance, in a store the deployment
// passes in code: a Durable Object on Workers (cloudflare-anchor.ts), a file
// on a single Node process (anchor-file.ts).
//
// The record is the app's, MACed under a key derived from `auditChainKey`,
// and carries the vault's newest checkpoint, signed under the vault's key:
// a store with weak access control is still tamper-evident, though only
// its own compare-and-set keeps someone who can write it from putting an
// older record back.
import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import type { Checkpoint, LogHead } from '@coffre/core/vault';

/**
 * What a beat found, which stands until the entry it names verifies again:
 * a fault of the app's walk, by its seq, or a checkpoint the vault refused
 * for a broken log, which stands until the vault signs again. `seq` is null
 * when the vault did not say where.
 */
export type AnchorFinding = { seq: number | null; reason: string; by: 'app' | 'vault'; since: number };

export type AuditAnchor = {
  /** The newest checkpoint the vault signed that a beat saw: the log must still hold entry `seq`, by its hash. */
  checkpoint: Checkpoint | null;
  /**
   * How far the app has verified the chain, every link and hash and its own
   * entries' MACs: the checkpoint's prefix once caught up, short of it while
   * a beat at a time walks a backlog (`CHAIN_WALK`). Null before the first
   * entry, where a walk starts.
   */
  verified: LogHead | null;
  /** What a beat found, if anything stands. */
  finding: AnchorFinding | null;
  /** The `audit.heartbeat` entry the beat that wrote it appended: readiness wants the checkpoint to cover it. */
  beat: number | null;
  /**
   * Set while the beats walk the whole log because they found the store
   * empty, the first beat's included: when that began. An empty store is
   * no evidence of tampering, so readiness stays green meanwhile.
   */
  reanchor: { since: number } | null;
  /** Raised by an Owner's acceptance of lost entries, the one write that may move a point back. */
  epoch: number;
  /** When a beat last wrote it, milliseconds since the epoch, by the app's clock. */
  at: number;
  /** The app's MAC over the rest, hex. */
  mac: string;
};

/** An anchor before its MAC. */
export type AnchorFields = Omit<AuditAnchor, 'mac'>;

/**
 * Where the anchor lives. `write` puts `next` in place of `prev` (null for
 * none) only if `prev` is still what is stored, and `next` moves neither
 * point back: false otherwise, and nothing changes. A store that cannot
 * read or write throws, and the beat, or readiness, fails closed.
 */
export type AnchorStore = {
  read(): Promise<AuditAnchor | null>;
  write(prev: AuditAnchor | null, next: AuditAnchor): Promise<boolean>;
};

const keys = new WeakMap<Buffer, Buffer>();

function anchorKey(chainKey: Buffer): Buffer {
  let key = keys.get(chainKey);
  if (key === undefined) keys.set(chainKey, (key = Buffer.from(hkdfSync('sha256', chainKey, new Uint8Array(0), 'coffre.audit.anchor.v1', 32))));
  return key;
}

function macOf(chainKey: Buffer, fields: AnchorFields): Buffer {
  const { checkpoint, verified, finding, beat, reanchor, epoch, at } = fields;
  return createHmac('sha256', anchorKey(chainKey)).update(JSON.stringify([checkpoint, verified, finding, beat, reanchor, epoch, at])).digest();
}

/** `fields`, MACed. */
export function sealAnchor(chainKey: Buffer, fields: AnchorFields): AuditAnchor {
  return { ...fields, mac: macOf(chainKey, fields).toString('hex') };
}

/** Whether the app wrote this record, by its MAC. */
export function anchorIsOwn(chainKey: Buffer, anchor: AuditAnchor): boolean {
  const mac = Buffer.from(typeof anchor.mac === 'string' ? anchor.mac : '', 'hex');
  const expected = macOf(chainKey, anchor);
  return mac.length === expected.length && timingSafeEqual(mac, expected);
}

/**
 * Whether a store may put `next` in place of `stored`, asked as `prev`:
 * the compare-and-set and the monotonic rule every store applies. A point
 * moves back only with a new epoch, an Owner's acceptance of lost entries
 * (`acceptLoss`): no beat raises it.
 */
export function admits(stored: AuditAnchor | null, prev: AuditAnchor | null, next: AuditAnchor): boolean {
  if ((stored?.mac ?? null) !== (prev?.mac ?? null)) return false;
  if (stored === null || next.epoch > stored.epoch) return true;
  return next.epoch === stored.epoch && seqOf(next.checkpoint) >= seqOf(stored.checkpoint) && seqOf(next.verified) >= seqOf(stored.verified);
}

function seqOf(point: { seq: number } | null): number {
  return point === null ? -1 : point.seq;
}

/** An anchor in memory: for tests, and a process whose log goes when it does. */
export function memoryAnchor(): AnchorStore {
  let stored: AuditAnchor | null = null;
  return {
    read: async () => stored,
    write: async (prev, next) => {
      if (!admits(stored, prev, next)) return false;
      stored = next;
      return true;
    },
  };
}
