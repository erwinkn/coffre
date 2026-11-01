import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import { macData, type Cut, type LeafValue, type LogEntry } from '@coffre/core/merkle';

import { logObject } from './inputs.ts';

/**
 * 0.15's entries as the trees seal them (docs/design/audit-tree.md, "A
 * leaf"): a row of `log_changes` or `log_uses` (migration 0022), every
 * column in the table's order but its number, which the leaf holds apart,
 * and its MAC, which comes last. The MAC is the vault's, 16 bytes (R53):
 * the tag of the key that made it, four bytes, then HMAC-SHA256 over the
 * tree and every column but the number and itself (`macData`), cut to
 * twelve (D162). The writer of an entry (the change path, PR 4; the use
 * path, PR 5) computes it with `entryMac`, and the checkpointer checks it
 * with `authentic` before it seals anything. The tag is public and names
 * the key, so that once the vault's signing key rotates (T168), the
 * database can refuse an entry under a key the log moved on from, and a
 * reader knows which key to check it under.
 */

/** A change as `log_changes` holds it, `object` a uuid in lower case. */
export type ChangeRow = {
  number: bigint; at: number; requestId: string; object: string; actor: string; payload: string; seal: Buffer | null; mac: Buffer;
};

/** A use as `log_uses` holds it (the slim row, R53), uuids in lower case. */
export type UseRow = {
  number: bigint; at: number; requestId: bigint; credential: string; secret: string; purpose: number; mac: Buffer; place: string | null;
};

export const MAC_BYTES = 16;
/** The key's tag, the first bytes of every MAC: public, one per key. */
export const TAG_BYTES = 4;

/** The key that MACs log entries, and its tag: both from the vault's signing seed, each under a label of its own. */
export type LogMacKey = { tag: Buffer; key: Buffer };

export function logMacKey(seed: Uint8Array): LogMacKey {
  return {
    tag: Buffer.from(hkdfSync('sha256', seed, new Uint8Array(0), 'coffre.log.tag.v1', TAG_BYTES)),
    key: Buffer.from(hkdfSync('sha256', seed, new Uint8Array(0), 'coffre.log.mac.v1', 32)),
  };
}

/** The MAC of a tree's columns: the key's tag, then the HMAC cut to what is left of 16 bytes. */
const mac = (key: LogMacKey, tree: LogEntry['tree'], columns: readonly LeafValue[]) =>
  Buffer.concat([key.tag, createHmac('sha256', key.key).update(macData(tree, columns)).digest().subarray(0, MAC_BYTES - TAG_BYTES)]);

const changeColumns = (r: Omit<ChangeRow, 'number' | 'mac'>): LeafValue[] => [BigInt(r.at), r.requestId, r.object, r.actor, r.payload, r.seal];
const useColumns = (r: Omit<UseRow, 'number' | 'mac'>): LeafValue[] => [BigInt(r.at), r.requestId, r.credential, r.secret, r.purpose, r.place];

/** An entry's MAC, as its writer stores it. */
export function entryMac(key: LogMacKey, entry: { tree: 'changes'; row: Omit<ChangeRow, 'number' | 'mac'> } | { tree: 'uses'; row: Omit<UseRow, 'number' | 'mac'> }): Buffer {
  return mac(key, entry.tree, entry.tree === 'changes' ? changeColumns(entry.row) : useColumns(entry.row));
}

/** A change's row as the trees take it: every column in the table's order, the MAC last (`log_changes`'s own order puts it there too). */
export function changeEntry(r: ChangeRow): LogEntry {
  return { tree: 'changes', number: r.number, at: r.at, columns: [...changeColumns(r), r.mac] };
}

/** A use's row as the trees take it: its columns in the table's order, the MAC moved last (in `log_uses` it comes before `place`). */
export function useEntry(r: UseRow): LogEntry {
  return { tree: 'uses', number: r.number, at: r.at, columns: [...useColumns(r), r.mac] };
}

/** Whether an entry's MAC holds under `key`, its tag included: the checkpointer's `authentic`. */
export function authentic(key: LogMacKey): (entry: LogEntry) => boolean {
  return (entry) => {
    const stored = entry.columns.at(-1);
    if (!(stored instanceof Uint8Array) || stored.length !== MAC_BYTES) return false;
    return timingSafeEqual(mac(key, entry.tree, entry.columns.slice(0, -1)), stored);
  };
}

/**
 * A retention change (plan PR 7, migration 0027's `log_retention`): an entry
 * of the changes tree, kept for good, that cuts the uses tree. Its object is
 * the log's own, its actor the system's, and its payload names the day it
 * drops and the cut: the pair at or past the day's end, by its upto, its time
 * and its uses head, which the kept tiles at the cut give a verifier.
 */
export const RETENTION_OBJECT = logObject('log', 'retention');
export const RETENTION_ACTOR = 'system:retention';

/** The log's own object for the cutover's change from 0.14 (plan PR 9; cutover.ts), its marker: one, ever. */
export const CUTOVER_OBJECT = logObject('log', 'cutover');

/** Who makes the cutover's changes. */
export const CUTOVER_ACTOR = 'system:vault';

export function retentionPayload(day: string, cut: Cut): string {
  return JSON.stringify({ op: 'retention', day, cut: { upto: String(cut.upto), at: cut.at, uses: cut.uses.size, root: cut.uses.root.toString('hex') } });
}

/** The cut a retention change names, from its entry; null for any other entry, or one whose payload is not a retention's. */
export function retentionCut(entry: LogEntry): Cut | null {
  if (entry.tree !== 'changes' || entry.columns[2] !== RETENTION_OBJECT || typeof entry.columns[4] !== 'string') return null;
  let payload: unknown;
  try {
    payload = JSON.parse(entry.columns[4]);
  } catch {
    return null;
  }
  const c = (payload as { op?: unknown; cut?: { upto?: unknown; at?: unknown; uses?: unknown; root?: unknown } } | null);
  const cut = c?.op === 'retention' ? c.cut : undefined;
  if (typeof cut?.upto !== 'string' || !/^\d{1,19}$/.test(cut.upto) || !Number.isSafeInteger(cut.at) || !Number.isSafeInteger(cut.uses) || (cut.uses as number) < 0
    || typeof cut.root !== 'string' || !/^[0-9a-f]{64}$/.test(cut.root)) {
    return null;
  }
  return { upto: BigInt(cut.upto), at: cut.at as number, uses: { size: cut.uses as number, root: Buffer.from(cut.root, 'hex') } };
}
