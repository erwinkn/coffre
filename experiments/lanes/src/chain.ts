import { createHash, createHmac } from 'node:crypto';

/**
 * An entry's MAC and hash, shaped as @coffre/core/audit's: the MAC covers
 * the entry's place in its chain (lane, seq, the hash before it) and what it
 * says; the hash covers the same and the MAC. A prototype's own encoding,
 * with the same cost: one HMAC-SHA-256 and one SHA-256 per entry.
 */
export type Fields = {
  actor: string;
  action: string;
  decision: 'allow' | 'deny';
  subject: string | null;
  environmentId: string | null;
  /** The control lane's head the decision was made under: what orders it after every revocation before it. */
  controlSeq: string | null;
  occurredAt: number;
  metadata: string;
};

export type Sealed = { lane: number; seq: bigint; prevHash: Buffer; mac: Buffer; hash: Buffer; fields: Fields };

export const GENESIS = Buffer.alloc(32);

function encode(lane: number, seq: bigint, fields: Fields): string {
  return JSON.stringify([lane, String(seq), fields.actor, fields.action, fields.decision, fields.subject, fields.environmentId, fields.controlSeq, fields.occurredAt, fields.metadata]);
}

export function seal(key: Buffer, lane: number, seq: bigint, prevHash: Buffer, fields: Fields): Sealed {
  const body = encode(lane, seq, fields);
  const mac = createHmac('sha256', key).update('lanes.mac.v1').update(prevHash).update(body).digest();
  const hash = createHash('sha256').update('lanes.chain.v1').update(prevHash).update(body).update(mac).digest();
  return { lane, seq, prevHash, mac, hash, fields };
}

/** Seal `entries` in order after `head`: what a lane's writer does with a batch. */
export function sealAll(key: Buffer, lane: number, head: { nextSeq: bigint; hash: Buffer }, entries: readonly Fields[]): Sealed[] {
  const sealed: Sealed[] = [];
  let seq = head.nextSeq;
  let prev = head.hash;
  for (const fields of entries) {
    const one = seal(key, lane, seq, prev, fields);
    sealed.push(one);
    prev = one.hash;
    seq += 1n;
  }
  return sealed;
}

/** Whether `entries`, read back in order, chain from `prev` and carry the key's MAC. */
export function verify(key: Buffer, lane: number, prev: Buffer, entries: readonly Sealed[]): { ok: true } | { ok: false; seq: bigint; why: string } {
  for (const entry of entries) {
    if (!entry.prevHash.equals(prev)) return { ok: false, seq: entry.seq, why: 'prev' };
    const again = seal(key, lane, entry.seq, prev, entry.fields);
    if (!again.mac.equals(entry.mac)) return { ok: false, seq: entry.seq, why: 'mac' };
    if (!again.hash.equals(entry.hash)) return { ok: false, seq: entry.seq, why: 'hash' };
    prev = entry.hash;
  }
  return { ok: true };
}
