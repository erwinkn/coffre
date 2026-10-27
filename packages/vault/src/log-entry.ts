import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import { macData, type LeafValue, type LogEntry } from '@coffre/core/merkle';

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
