import { createHmac } from 'node:crypto';

import {
  pairSigners,
  pairVerifiers,
  type LogEntry,
  type PairNotes,
  type PairSigners,
  type PairVerifiers,
  type StoredPair,
  type Tile,
  type TileKey,
  type TreeName,
} from '@coffre/core/merkle';

import type { CheckpointStore, Memory, Sealed, SealThrough } from '../src/checkpointer.ts';

/**
 * The checkpointer's database, in memory, with a writer's powers for the
 * attacks: entries, rows and tiles may be deleted, replaced or forged.
 * Every append commits at once, so the barrier's `upto` is the last number.
 */
export class MemoryStore implements CheckpointStore {
  log: LogEntry[] = [];
  rows = new Map<bigint, PairNotes>();
  tileStore: Record<TreeName, Map<string, Buffer>> = { changes: new Map(), uses: new Map() };
  next = 1n;
  writes = 0;
  /** Runs before a write lands; throw to make it fail. */
  beforeWrite: (() => void) | null = null;
  /** Runs after a write lands; throw to make it fail all the same (a reply lost after the commit). */
  afterWrite: (() => void) | null = null;

  private macKey: Buffer;

  constructor(macKey: Buffer) {
    this.macKey = macKey;
  }

  /** An honest entry: columns at, request id, payload, MAC over everything but the number. Returns its number. */
  append(tree: TreeName, requestId: string, payload = '{}', at = Date.now()): bigint {
    const number = this.next;
    this.next += 1n;
    this.log.push(entry(this.macKey, tree, number, requestId, payload, at));
    return number;
  }

  /** A number handed out and never used: an aborted append. */
  skip(): void {
    this.next += 1n;
  }

  /** The floor of `at`, as the fence's row holds it: raised by each barrier, lowered only by a writer. */
  floor = 0;

  /** The floors the signer asked windows to be read from, each tick's in turn. */
  froms: number[] = [];

  async close(after: bigint, from: number) {
    this.froms.push(from);
    const upto = this.next - 1n;
    const found = this.floor;
    this.floor = Math.max(this.floor, Date.now() - 3000);
    // Changes by number; uses by `at` from the floor the signer holds, as 6b's store reads them through their index.
    const entries = this.between(after, upto).filter((e) => e.tree === 'changes' || e.at >= from);
    return { upto, newest: await this.newest(), entries, floor: { found, set: this.floor } };
  }

  async newest(): Promise<StoredPair | null> {
    const upto = this.newestUpto();
    return upto === null ? null : { upto, notes: this.rows.get(upto)! };
  }

  async pairs(after: bigint, limit: number): Promise<StoredPair[]> {
    return [...this.rows].filter(([upto]) => upto > after).sort(([a], [b]) => (a < b ? -1 : 1)).slice(0, limit).map(([upto, notes]) => ({ upto, notes }));
  }

  async pair(upto: bigint): Promise<StoredPair | null> {
    const notes = this.rows.get(upto);
    return notes === undefined ? null : { upto, notes };
  }

  async entries(after: bigint, upto: bigint, options: { limit?: number } = {}): Promise<LogEntry[]> {
    return this.between(after, upto).slice(0, options.limit);
  }

  async tiles(tree: TreeName, keys: readonly TileKey[]): Promise<Tile[]> {
    return keys.flatMap((k) => {
      const hashes = this.tileStore[tree].get(`${k.level}/${k.index}`);
      return hashes === undefined ? [] : [{ ...k, hashes: Buffer.from(hashes) }];
    });
  }

  async write(row: StoredPair, tiles: Record<TreeName, Tile[]>): Promise<void> {
    this.beforeWrite?.();
    for (const tree of ['changes', 'uses'] as const) for (const t of tiles[tree]) this.tileStore[tree].set(`${t.level}/${t.index}`, Buffer.from(t.hashes));
    this.rows.set(row.upto, row.notes);
    this.writes += 1;
    this.afterWrite?.();
  }

  async locate(number: bigint): Promise<{ entry: LogEntry; index: number } | null> {
    const entry = this.log.find((e) => e.number === number);
    if (entry === undefined) return null;
    return { entry, index: this.log.filter((e) => e.tree === entry.tree && e.number < number).length };
  }

  /** The writer's powers. */
  deleteEntry(number: bigint): void {
    this.log = this.log.filter((e) => e.number !== number);
  }

  /** Every row above `upto`, and every entry after it: a consistent, shorter log. */
  rollBack(upto: bigint): void {
    for (const key of [...this.rows.keys()]) if (key > upto) this.rows.delete(key);
    this.log = this.log.filter((e) => e.number <= upto);
  }

  private newestUpto(): bigint | null {
    let newest: bigint | null = null;
    for (const upto of this.rows.keys()) if (newest === null || upto > newest) newest = upto;
    return newest;
  }

  private between(after: bigint, upto: bigint): LogEntry[] {
    return this.log.filter((e) => e.number > after && e.number <= upto).sort((a, b) => (a.number < b.number ? -1 : 1));
  }
}

export function entry(macKey: Buffer, tree: TreeName, number: bigint, requestId: string, payload: string, at: number): LogEntry {
  return { tree, number, at, columns: [BigInt(at), requestId, payload, mac(macKey, tree, at, requestId, payload)] };
}

function mac(key: Buffer, tree: TreeName, at: number, requestId: string, payload: string): Buffer {
  return createHmac('sha256', key).update(JSON.stringify([tree, at, requestId, payload])).digest().subarray(0, 16);
}

/** The vault's MAC check over a stored entry. */
export const authentic = (key: Buffer) => (e: LogEntry): boolean => {
  const [at, requestId, payload, tag] = e.columns;
  return typeof requestId === 'string' && typeof payload === 'string' && tag instanceof Uint8Array
    && Buffer.from(tag).equals(mac(key, e.tree, Number(at), requestId, payload)) && Number(at) === e.at;
};

/** A memory in a variable, with a switch to make the next `remember` fail. */
export function variableMemory(): Memory & { record: string | null; failNext: boolean } {
  return {
    record: null,
    failNext: false,
    async last() {
      return this.record;
    },
    async remember(record) {
      if (this.failNext) {
        this.failNext = false;
        throw new Error('storage unavailable');
      }
      this.record = record;
    },
  };
}

export type Keys = { macKey: Buffer; signers: PairSigners; verifiers: PairVerifiers };

export async function keys(seed = 1): Promise<Keys> {
  const signers = await pairSigners('coffre.test/audit', Buffer.alloc(32, seed));
  return { macKey: Buffer.alloc(32, seed + 100), signers, verifiers: await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey }) };
}

/**
 * A stand-in for the checkpointer, for the change path's tests (plan PR 4):
 * each change it is asked to seal is recorded, and answered as `answer`
 * says: a `Sealed` (witnessed, unwitnessed, or with no witness), or an
 * error, as a change refused because its entry was lost.
 */
export function sealThroughDouble(answer: (number: bigint) => Sealed | Error | Promise<Sealed | Error>): SealThrough & { asked: bigint[] } {
  const asked: bigint[] = [];
  const seal = async (number: bigint) => {
    asked.push(number);
    const a = await answer(number);
    if (a instanceof Error) throw a;
    return a;
  };
  return Object.assign(seal, { asked });
}
