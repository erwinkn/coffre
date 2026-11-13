import { HASH_SIZE, nodeHash, treeHash, type Hash, type Nodes } from './tree.ts';

/**
 * The tree's storage (docs/design/0.16.md, `log_tiles`): tiles, as Go's sumdb
 * and C2SP tlog-tiles lay them out, of height 8. The tile at (level t, index
 * i) holds up to 256 hashes: the nodes at tree level 8t numbered i·256
 * onwards, concatenated. A level-0 tile holds leaf hashes; a level-1 tile,
 * the roots of 256-leaf subtrees; and so on. Any perfect subtree's hash is in
 * one tile or is at most 128 hashes away from one, so a proof reads one tile
 * per 8 levels: 4 tiles at 2^32 leaves.
 *
 * A tile's hashes never change once written, only grow (the partial tile at
 * the tree's right edge), so a tile is read for any older tree size by taking
 * its prefix.
 *
 * Pruning a tree deletes level-0 tiles from its start, whole, with the 256
 * entries each stands for. The level-1 tile above keeps each one's root, so
 * the head still covers the pruned entries, and every entry that is kept
 * proves from tiles that are kept.
 */
export const HEIGHT = 8;
export const WIDTH = 256;

export type TileKey = { level: number; index: number };
export type Tile = TileKey & { hashes: Buffer };

export const tileKey = (level: number, index: number) => `${level}/${index}`;

/** Which tile, and where in it, holds what node (level, index) is computed from. */
export function tileOf(level: number, index: number): { tile: TileKey; offset: number; count: number } {
  const t = Math.floor(level / HEIGHT);
  const count = 2 ** (level - t * HEIGHT);
  const first = index * count;
  return { tile: { level: t, index: Math.floor(first / WIDTH) }, offset: first % WIDTH, count };
}

/** A `Nodes` over a set of tiles, keyed by `tileKey`: each node from the hashes of its tile. */
export function nodesFrom(tiles: ReadonlyMap<string, Buffer>): Nodes {
  return (level, index) => {
    const { tile, offset, count } = tileOf(level, index);
    const hashes = tiles.get(tileKey(tile.level, tile.index));
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
export function tilesFor(compute: (nodes: Nodes) => unknown): TileKey[] {
  const seen = new Map<string, TileKey>();
  compute((level, index) => {
    const { tile } = tileOf(level, index);
    seen.set(tileKey(tile.level, tile.index), tile);
    return Buffer.alloc(HASH_SIZE);
  });
  return [...seen.values()];
}

export function tileMap(tiles: readonly Tile[]): Map<string, Buffer> {
  return new Map(tiles.map((t) => [tileKey(t.level, t.index), t.hashes]));
}

/** The tiles at the right edge of a tree of `size` leaves, one per level, with their widths: all the state appending needs. */
export function edgeOf(size: number): (TileKey & { width: number })[] {
  const edge: (TileKey & { width: number })[] = [];
  for (let t = 0; ; t += 1) {
    const below = Math.floor(size / 2 ** (t * HEIGHT));
    edge.push({ level: t, index: Math.floor(below / WIDTH), width: below % WIDTH });
    if (below < WIDTH) return edge;
  }
}

/**
 * The tree's growing edge, in memory: the partial tile at each level.
 * Appending leaves fills level 0; each tile that fills up pushes its root into
 * the level above. What changed comes back as tiles to write: every tile
 * filled, and every partial edge tile that grew.
 */
export class Edge {
  size: number;
  private tiles: Hash[][];

  private constructor(size: number, tiles: Hash[][]) {
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
      const hashes = stored.get(tileKey(level, index));
      if (hashes === undefined || hashes.length < width * HASH_SIZE) throw new Error(`edge tile ${level}/${index} missing or short`);
      return Array.from({ length: width }, (_, i) => Buffer.from(hashes.subarray(i * HASH_SIZE, (i + 1) * HASH_SIZE)));
    });
    return new Edge(size, tiles);
  }

  /** A copy to append to, so a failed write leaves this edge at the head it was. */
  clone(): Edge {
    return new Edge(this.size, this.tiles.map((t) => [...t]));
  }

  append(leaves: readonly Hash[]): Tile[] {
    const changed: Tile[] = [];
    // Levels whose partial tile grew: written as they stand once every leaf is in.
    const grew = new Set<number>();
    for (const leaf of leaves) {
      let hash = leaf;
      for (let t = 0; ; t += 1) {
        const tile = (this.tiles[t] ??= []);
        tile.push(hash);
        if (tile.length < WIDTH) {
          grew.add(t);
          break;
        }
        // A full tile is written now and never again; its root goes up a level.
        changed.push({ level: t, index: Math.floor(this.size / 2 ** ((t + 1) * HEIGHT)), hashes: Buffer.concat(tile) });
        grew.delete(t);
        hash = hashUp(tile);
        this.tiles[t] = [];
      }
      this.size += 1;
    }
    for (const t of grew) changed.push({ level: t, index: Math.floor(this.size / 2 ** ((t + 1) * HEIGHT)), hashes: Buffer.concat(this.tiles[t]!) });
    return changed;
  }

  /** The tree head now. */
  root(): Hash {
    return treeHash(nodesFrom(tileMap(this.edgeTiles())), this.size);
  }

  /**
   * The tile at the right edge of each level, as it stands. With the tiles an append filled, they hold every node a
   * proof of a leaf that append added reads: the tile of the leaf's ancestor at each level is one of them, and so is
   * every tile to its right.
   */
  edgeTiles(): Tile[] {
    return edgeOf(this.size).map(({ level, index }) => ({ level, index, hashes: Buffer.concat(this.tiles[level] ?? []) }));
  }
}
