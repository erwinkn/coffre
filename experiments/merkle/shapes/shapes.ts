import { createHash, randomBytes } from 'node:crypto';

import { Edge, edgeOf, WIDTH, type Tile } from '../src/tiles.ts';
import { HASH_SIZE, nodeHash, type Hash } from '../src/tree.ts';

/**
 * W212: the tree shapes the 0.15 audit log could take, each reduced to what a
 * checkpoint does to it: the leaves one tick seals go in, and out come the rows
 * to write and the heads to sign. Every shape is built from #365's own RFC 9162
 * tree and tiles (`../src/tree.ts`, `../src/tiles.ts`), so what differs is the
 * shape alone. `bench.ts` writes what they return to Postgres; `proofs.ts`
 * measures their proofs and walks.
 *
 *   one       one growing tree of every entry (#365, as CT, Go's sumdb, Rekor v2)
 *   one-0     the same, its leaf-level (level 0) tiles not stored: derived from the entries when read
 *   split     one growing tree per retention class: changes (kept forever) and uses (dropped by day)
 *   day       a tree per `at` day; each closed day's root a leaf of a top tree
 *   tick      a tree per tick; each tick's root a leaf of a top tree
 *   chain     a tree per tick; each checkpoint names the previous one's hash
 *   mmr       a Merkle Mountain Range: every node stored in append order, the root its peaks bagged
 */
export type Leaf = { hash: Hash; change: boolean; day: number };

/** A row to write: a tile (or, for the MMR, a chunk of its node array) of tree `tree`. */
export type Row = { tree: number; level: number; index: number; hashes: Buffer };

/** What one tick leaves: rows to write, and the checkpoints to sign (one signature each). */
export type Sealed = { rows: Row[]; heads: Head[] };
export type Head = { tree: number; size: number; root: Hash; extra?: string };

export interface Shape {
  readonly name: string;
  seal(leaves: readonly Leaf[]): Sealed;
}

export const SHAPES = ['one', 'one-0', 'split', 'day', 'tick', 'chain', 'mmr'] as const;
export type ShapeName = (typeof SHAPES)[number];

/** Trees within a shape: changes and uses apart for `split`, the top tree for `day` and `tick`. */
const USES = 0;
const CHANGES = 1;
const TOP = -1;

/**
 * A shape as a log that already holds `start` leaves, with random hashes where
 * its state would be: the right edge of each tree, the MMR's peaks. A
 * checkpoint's cost depends on that state alone, so a year's log can be
 * benched without writing a year of tiles. `changeRate` is the share of
 * changes; `dayLeaves` a day's length in leaves; `dayOffset`, for `day`, how far
 * into the open day the log is (by default, where `start` falls).
 */
export function shapeAt(name: ShapeName, start: number, opts: { changeRate: number; dayLeaves: number; tickLeaves: number; dayOffset?: number }): Shape {
  const { changeRate, dayLeaves, tickLeaves } = opts;
  switch (name) {
    case 'one':
    case 'one-0': {
      const edge = randomEdge(start);
      return {
        name,
        seal(leaves) {
          const tiles = edge.append(leaves.map((l) => l.hash));
          const rows = tiles.filter((t) => name === 'one' || t.level > 0).map((t) => row(USES, t));
          return { rows, heads: [{ tree: USES, size: edge.size, root: edge.root() }] };
        },
      };
    }
    case 'split': {
      const changes = Math.round(start * changeRate);
      const edges = [randomEdge(start - changes), randomEdge(changes)];
      return {
        name,
        seal(leaves) {
          const rows: Row[] = [];
          for (const tree of [USES, CHANGES]) {
            const mine = leaves.filter((l) => l.change === (tree === CHANGES)).map((l) => l.hash);
            if (mine.length > 0) rows.push(...edges[tree]!.append(mine).map((t) => row(tree, t)));
          }
          // Two logs, two standard checkpoints, both every tick: each one's `upto` says every number up to it is final.
          return { rows, heads: [USES, CHANGES].map((tree) => ({ tree, size: edges[tree]!.size, root: edges[tree]!.root() })) };
        },
      };
    }
    case 'day': {
      // The open day's tree, at its place in the day; the top tree holds one root per closed day.
      let day = Math.floor(start / dayLeaves);
      let today = randomEdge(opts.dayOffset ?? start % dayLeaves);
      const top = randomEdge(day);
      return {
        name,
        seal(leaves) {
          const rows: Row[] = [];
          for (let i = 0, j = 0; i < leaves.length; i = j) {
            const d = leaves[i]!.day;
            while (j < leaves.length && leaves[j]!.day === d) j += 1;
            if (d > day) {
              // The day closes: its root becomes the top tree's next leaf, its own tree is done.
              rows.push(...top.append([today.root()]).map((t) => row(TOP, t)));
              day = d;
              today = Edge.empty();
            }
            rows.push(...today.append(leaves.slice(i, j).map((l) => l.hash)).map((t) => row(day, t)));
          }
          const extra = `day ${day} ${today.size} ${today.root().toString('base64')}`;
          return { rows, heads: [{ tree: TOP, size: top.size, root: top.root(), extra }] };
        },
      };
    }
    case 'tick':
    case 'chain': {
      // A tick's tree is rebuilt from its entries when a proof needs it, so nothing of it is stored but its root.
      const top = name === 'tick' ? randomEdge(Math.floor(start / tickLeaves)) : null;
      let previous: Hash = randomBytes(HASH_SIZE);
      let size = start;
      return {
        name,
        seal(leaves) {
          const batch = Edge.empty();
          batch.append(leaves.map((l) => l.hash));
          const root = batch.root();
          size += leaves.length;
          if (top !== null) {
            const rows = top.append([root]).map((t) => row(TOP, t));
            return { rows, heads: [{ tree: TOP, size: top.size, root: top.root(), extra: `batch ${leaves.length} ${root.toString('base64')}` }] };
          }
          previous = link(previous, root, leaves.length, size);
          return { rows: [], heads: [{ tree: TOP, size, root: previous, extra: `batch ${leaves.length} ${root.toString('base64')}` }] };
        },
      };
    }
    case 'mmr': {
      const mmr = Mmr.random(start);
      return {
        name,
        seal(leaves) {
          const rows = mmr.append(leaves.map((l) => l.hash)).map((c) => ({ tree: USES, level: 0, index: c.index, hashes: c.hashes }));
          return { rows, heads: [{ tree: USES, size: mmr.leaves, root: mmr.root() }] };
        },
      };
    }
  }
}

/** A chain link: the previous checkpoint's hash, this tick's root, its size and the log's. */
export function link(previous: Hash, root: Hash, batch: number, size: number): Hash {
  const sizes = Buffer.alloc(16);
  sizes.writeBigUInt64BE(BigInt(batch));
  sizes.writeBigUInt64BE(BigInt(size), 8);
  return createHash('sha256').update(previous).update(root).update(sizes).digest();
}

/** What a link carries on the wire: previous hash, root, two sizes, a time (88 bytes). */
export const LINK_BYTES = 32 + 32 + 8 + 8 + 8;

const row = (tree: number, t: Tile): Row => ({ tree, level: t.level, index: t.index, hashes: t.hashes });

/** A tree of `size` leaves whose right edge (all appending needs) holds random hashes. */
export function randomEdge(size: number): Edge {
  const tiles = new Map<string, Buffer>();
  for (const { level, index, width } of edgeOf(size)) tiles.set(`${level}/${index}`, randomBytes(width * HASH_SIZE));
  return Edge.load(size, tiles);
}

/**
 * A Merkle Mountain Range (Peter Todd's, as Grin and OpenTimestamps keep one):
 * every node is appended to one array in post-order as it forms, and the root
 * is the peaks bagged right to left. Hashed as RFC 9162 hashes (no position in
 * the node hash, unlike Grin), its root is RFC 9162's head of the same leaves
 * (shapes.test.ts): the RFC tree is a mountain range. What differs is storage:
 * every node, not one level in eight. Stored as chunks of 256 hashes, as tiles.
 */
export class Mmr {
  leaves: number;
  private nodes: number;
  private peaks: { height: number; hash: Hash }[];
  private chunk: Hash[];

  private constructor(leaves: number, peaks: { height: number; hash: Hash }[], chunk: Hash[]) {
    this.leaves = leaves;
    this.nodes = 2 * leaves - popcount(leaves);
    this.peaks = peaks;
    this.chunk = chunk;
  }

  static empty(): Mmr {
    return new Mmr(0, [], []);
  }

  /** An MMR of `leaves` leaves with random peaks and a random partial chunk. */
  static random(leaves: number): Mmr {
    const peaks = [];
    for (let h = 52; h >= 0; h -= 1) if (Math.floor(leaves / 2 ** h) % 2 === 1) peaks.push({ height: h, hash: randomBytes(HASH_SIZE) });
    const nodes = 2 * leaves - popcount(leaves);
    return new Mmr(leaves, peaks, Array.from({ length: nodes % WIDTH }, () => randomBytes(HASH_SIZE)));
  }

  /** Appends leaves; returns every chunk of the node array that filled or grew. */
  append(hashes: readonly Hash[]): { index: number; hashes: Buffer }[] {
    const changed = new Map<number, Buffer>();
    const push = (h: Hash) => {
      this.chunk.push(h);
      this.nodes += 1;
      if (this.chunk.length === WIDTH) {
        changed.set((this.nodes - 1 - ((this.nodes - 1) % WIDTH)) / WIDTH, Buffer.concat(this.chunk));
        this.chunk = [];
      }
    };
    for (const leaf of hashes) {
      push(leaf);
      let peak = { height: 0, hash: leaf };
      while (this.peaks.length > 0 && this.peaks.at(-1)!.height === peak.height) {
        const left = this.peaks.pop()!;
        peak = { height: peak.height + 1, hash: nodeHash(left.hash, peak.hash) };
        push(peak.hash);
      }
      this.peaks.push(peak);
      this.leaves += 1;
    }
    if (this.chunk.length > 0) changed.set(Math.floor(this.nodes / WIDTH), Buffer.concat(this.chunk));
    return [...changed].map(([index, hashes]) => ({ index, hashes }));
  }

  /** The peaks bagged right to left: H(p1, H(p2, … H(pk-1, pk))). */
  root(): Hash {
    if (this.peaks.length === 0) return createHash('sha256').digest();
    let r = this.peaks.at(-1)!.hash;
    for (let i = this.peaks.length - 2; i >= 0; i -= 1) r = nodeHash(this.peaks[i]!.hash, r);
    return r;
  }

  get stored(): number {
    return this.nodes;
  }
}

export function popcount(n: number): number {
  let c = 0;
  for (let x = n; x > 0; x = Math.floor(x / 2)) c += x % 2;
  return c;
}
