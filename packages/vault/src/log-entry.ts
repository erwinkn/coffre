import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import { macData, type Cut, type LeafValue, type LogEntry } from '@coffre/core/merkle';

import { logObject } from './inputs.ts';

/**
 * 0.15's entries as the trees seal them (docs/design/audit-tree.md, "A
 * leaf"): a row of `log_changes` or `log_uses` (migration 0022), every
 * column in the table's order but its number, which the leaf holds apart,
 * and its MAC, which comes last. The MAC is the vault's, over the tree and
 * every column but the number and itself (`macData`), cut to 16 bytes
 * (R53): the writer of an entry (the change path, PR 4; the use path,
 * PR 5) computes it with `entryMac`, and the checkpointer checks it with
 * `authentic` before it seals anything.
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

/** The key that MACs log entries, from the vault's signing seed. */
export function logMacKey(seed: Uint8Array): Buffer {
  return Buffer.from(hkdfSync('sha256', seed, new Uint8Array(0), 'coffre.log.mac.v1', 32));
}

const changeColumns = (r: Omit<ChangeRow, 'number' | 'mac'>): LeafValue[] => [BigInt(r.at), r.requestId, r.object, r.actor, r.payload, r.seal];
const useColumns = (r: Omit<UseRow, 'number' | 'mac'>): LeafValue[] => [BigInt(r.at), r.requestId, r.credential, r.secret, r.purpose, r.place];

/** An entry's MAC, as its writer stores it. */
export function entryMac(key: Buffer, entry: { tree: 'changes'; row: Omit<ChangeRow, 'number' | 'mac'> } | { tree: 'uses'; row: Omit<UseRow, 'number' | 'mac'> }): Buffer {
  const columns = entry.tree === 'changes' ? changeColumns(entry.row) : useColumns(entry.row);
  return createHmac('sha256', key).update(macData(entry.tree, columns)).digest().subarray(0, MAC_BYTES);
}

/** A change's row as the trees take it: every column in the table's order, the MAC last (`log_changes`'s own order puts it there too). */
export function changeEntry(r: ChangeRow): LogEntry {
  return { tree: 'changes', number: r.number, at: r.at, columns: [...changeColumns(r), r.mac] };
}

/** A use's row as the trees take it: its columns in the table's order, the MAC moved last (in `log_uses` it comes before `place`). */
export function useEntry(r: UseRow): LogEntry {
  return { tree: 'uses', number: r.number, at: r.at, columns: [...useColumns(r), r.mac] };
}

/** Whether an entry's MAC holds under `key`: the checkpointer's `authentic`. */
export function authentic(key: Buffer): (entry: LogEntry) => boolean {
  return (entry) => {
    const mac = entry.columns.at(-1);
    if (!(mac instanceof Uint8Array) || mac.length !== MAC_BYTES) return false;
    const expected = createHmac('sha256', key).update(macData(entry.tree, entry.columns.slice(0, -1))).digest().subarray(0, MAC_BYTES);
    return timingSafeEqual(expected, mac);
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
