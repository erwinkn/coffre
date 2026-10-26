import { HASH_SIZE, nodeHash, treeHash, type Hash, type Nodes } from './tree.ts';

/**
 * The tree's storage: tiles, as Go's sumdb and C2SP tlog-tiles lay them out,
 * of height 8. The tile at (level t, index i) holds up to 256 hashes: the
 * nodes at tree level 8t numbered i·256 onwards, concatenated. A level-0 tile
 * holds leaf hashes; a level-1 tile, the roots of 256-leaf subtrees; and so
 * on. Any perfect subtree's hash is in one tile or is at most 127 hashes away
 * from one, so a proof reads one tile per 8 levels: 4 tiles at 2^32 leaves.
 *
 * A tile's hashes never change once written, only grow (the partial tile at
 * the tree's right edge), so a row is read for any older tree size by taking
 * its prefix.
 */
export const HEIGHT = 8;
export const WIDTH = 1 << HEIGHT;

export type TileKey = { level: number; index: number };
export type Tile = TileKey & { hashes: Buffer };

const key = (level: number, index: number) => `${level}/${index}`;
const pow = (e: number) => 2 ** e;

/** Which tile, and where in it, holds what node (level, index) is computed from. */
export function tileOf(level: number, index: number): { tile: TileKey; offset: number; count: number } {
  const t = Math.floor(level / HEIGHT);
  const count = pow(level - t * HEIGHT);
  const first = index * count;
  return { tile: { level: t, index: Math.floor(first / WIDTH) }, offset: first % WIDTH, count };
}

/** A `Nodes` over a set of tiles: each node from the hashes of its tile. */
export function nodesFrom(tiles: ReadonlyMap<string, Buffer>): Nodes {
  return (level, index) => {
    const { tile, offset, count } = tileOf(level, index);
    const hashes = tiles.get(key(tile.level, tile.index));
    if (hashes === undefined || hashes.length < (offset + count) * HASH_SIZE) {
      throw new Error(`tile ${tile.level}/${tile.index} lacks node ${level}/${index}`);
    }
    const layer: Hash[] = [];
    for (let i = 0; i < count; i += 1) layer.push(hashes.subarray((offset + i) * HASH_SIZE, (offset + i + 1) * HASH_SIZE));
    return hashUp(layer);
  };
}

/** The root of a perfect subtree from its 2^k bottom hashes. */
function hashUp(hashes: readonly Hash[]): Hash {
  let layer = hashes;
  while (layer.length > 1) {
    const up: Hash[] = [];
    for (let i = 0; i < layer.length; i += 2) up.push(nodeHash(layer[i]!, layer[i + 1]!));
    layer = up;
  }
  return Buffer.from(layer[0]!);
}

/** The tiles a computation over `Nodes` reads: run it once against a recorder, then fetch them all in one query. */
export function tilesFor<T>(compute: (nodes: Nodes) => T): TileKey[] {
  const seen = new Map<string, TileKey>();
  compute((level, index) => {
    const { tile } = tileOf(level, index);
    seen.set(key(tile.level, tile.index), tile);
    return Buffer.alloc(HASH_SIZE);
  });
  return [...seen.values()];
}

export function tileMap(tiles: readonly Tile[]): Map<string, Buffer> {
  return new Map(tiles.map((t) => [key(t.level, t.index), t.hashes]));
}

/** The tiles at the right edge of a tree of `size` leaves, one per level, with their widths: all the state appending needs. */
export function edgeOf(size: number): (TileKey & { width: number })[] {
  const edge: (TileKey & { width: number })[] = [];
  for (let t = 0; pow(t * HEIGHT) <= size || t === 0; t += 1) {
    const below = Math.floor(size / pow(t * HEIGHT));
    edge.push({ level: t, index: Math.floor(below / WIDTH), width: below % WIDTH });
    if (below < WIDTH) break;
  }
  return edge;
}

/**
 * The tree's growing edge, in memory: the partial tile at each level. Appending
 * leaves fills level 0; each tile that fills up pushes its root into the level
 * above. What changed is returned as tiles to write: every tile filled, and
 * every partial edge tile that grew.
 */
export class Edge {
  size: number;
  private tiles: Buffer[][];

  private constructor(size: number, tiles: Buffer[][]) {
    this.size = size;
    this.tiles = tiles;
  }

  static empty(): Edge {
    return new Edge(0, [[]]);
  }

  /** From the stored edge tiles of a tree of `size` leaves (`edgeOf(size)`), each cut to its width. */
  static load(size: number, stored: ReadonlyMap<string, Buffer>): Edge {
    const tiles = edgeOf(size).map(({ level, index, width }) => {
      if (width === 0) return [];
      const hashes = stored.get(key(level, index));
      if (hashes === undefined || hashes.length < width * HASH_SIZE) throw new Error(`edge tile ${level}/${index} missing or short`);
      return Array.from({ length: width }, (_, i) => Buffer.from(hashes.subarray(i * HASH_SIZE, (i + 1) * HASH_SIZE)));
    });
    return new Edge(size, tiles);
  }

  append(leaves: readonly Hash[]): Tile[] {
    const changed = new Map<string, Tile>();
    for (const leaf of leaves) {
      let hash = leaf;
      for (let t = 0; ; t += 1) {
        const tile = (this.tiles[t] ??= []);
        tile.push(hash);
        const index = Math.floor(this.size / pow((t + 1) * HEIGHT));
        if (tile.length < WIDTH) {
          changed.set(key(t, index), { level: t, index, hashes: Buffer.alloc(0) });
          break;
        }
        changed.set(key(t, index), { level: t, index, hashes: Buffer.concat(tile) });
        hash = hashUp(tile);
        this.tiles[t] = [];
      }
      this.size += 1;
    }
    // Partial tiles are written as they stand once every leaf is in.
    for (const [k, tile] of changed) {
      if (tile.hashes.length > 0) continue;
      const hashes = this.tiles[tile.level]!;
      if (hashes.length === 0) changed.delete(k);
      else tile.hashes = Buffer.concat(hashes);
    }
    return [...changed.values()];
  }

  /** The tree head now. */
  root(): Hash {
    const tiles = new Map<string, Buffer>();
    for (const { level, index } of edgeOf(this.size)) tiles.set(key(level, index), Buffer.concat(this.tiles[level] ?? []));
    return treeHash(nodesFrom(tiles), this.size);
  }
}

/** Go's tile path, `tile/8/<L>/<N>[.p/<W>]`, N in groups of three digits (x001/x234/067). */
export function tilePath(t: TileKey, width: number): string {
  let n = String(t.index);
  const groups: string[] = [];
  while (n.length > 3) {
    groups.unshift(n.slice(-3));
    n = n.slice(0, -3);
  }
  const parts = [n.padStart(3, '0'), ...groups].map((g, i, all) => (i < all.length - 1 ? `x${g}` : g));
  return `tile/${HEIGHT}/${t.level}/${parts.join('/')}${width < WIDTH ? `.p/${width}` : ''}`;
}

export function parseTilePath(path: string): (TileKey & { width: number }) | null {
  const m = /^tile\/8\/(\d+)\/((?:x\d{3}\/)*\d{3})(?:\.p\/(\d+))?$/.exec(path);
  if (m === null) return null;
  return { level: Number(m[1]), index: Number(m[2]!.replaceAll('x', '').replaceAll('/', '')), width: m[3] === undefined ? WIDTH : Number(m[3]) };
}
