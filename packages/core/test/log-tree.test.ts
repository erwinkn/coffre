// The tree against RFC 9162's recursion, the tiles against the tree, and
// both against what Go's sumdb/tlog computed from the same leaves (the
// vectors below), which shares no code with this.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  consistencyProof,
  Edge,
  edgeOf,
  EMPTY_ROOT,
  inclusionProof,
  leafHash,
  nodeHash,
  nodesFrom,
  tileKey,
  tilesFor,
  treeHash,
  verifyConsistency,
  verifyInclusion,
  WIDTH,
  type Hash,
  type Nodes,
} from '@coffre/core/log';

const leaves = (n: number, from = 0) => Array.from({ length: n - from }, (_, i) => leafHash(Buffer.from(`entry ${from + i}`)));

/** MTH over every leaf hash, by the RFC's recursion: the reference the tiles must match. */
function reference(hashes: readonly Hash[]): Hash {
  if (hashes.length === 0) return EMPTY_ROOT;
  if (hashes.length === 1) return hashes[0]!;
  let k = 1;
  while (k * 2 < hashes.length) k *= 2;
  return nodeHash(reference(hashes.slice(0, k)), reference(hashes.slice(k)));
}

/** A tree grown to each size in turn, every tile ever written kept (its newest version). */
function grow(sizes: readonly number[]): { tiles: Map<string, Buffer>; edge: Edge; all: Hash[] } {
  const tiles = new Map<string, Buffer>();
  const edge = Edge.empty();
  const all: Hash[] = [];
  for (const size of sizes) {
    const batch = leaves(size, all.length);
    all.push(...batch);
    for (const t of edge.append(batch)) tiles.set(tileKey(t.level, t.index), t.hashes);
  }
  return { tiles, edge, all };
}

/** Nodes computed once each: the exhaustive checks below ask for the same ones many times. */
function memo(nodes: Nodes): Nodes {
  const seen = new Map<string, Hash>();
  return (level, index) => {
    const key = `${level}/${index}`;
    let hash = seen.get(key);
    if (hash === undefined) seen.set(key, (hash = nodes(level, index)));
    return hash;
  };
}

test('the empty tree hashes to SHA-256 of nothing', () => {
  assert.equal(treeHash(() => assert.fail('no node'), 0).toString('hex'), createHash('sha256').digest('hex'));
});

test('tiles give the reference head at every size, appended in uneven batches', () => {
  const sizes = [1, 2, 3, 7, 8, 255, 256, 257, 511, 512, 600, 65535, 65536, 65537, 70001];
  const { tiles, all } = grow(sizes);
  const nodes = nodesFrom(tiles);
  for (const size of [...sizes, 4, 5, 100, 1000, 4097, 65000]) {
    assert.ok(treeHash(nodes, size).equals(reference(all.slice(0, size))), `size ${size}`);
  }
});

test('the edge computes the head itself, reloads from the edge tiles alone, and a clone leaves it as it was', () => {
  for (const size of [1, 255, 256, 257, 65536, 65537, 70001]) {
    const { tiles, edge, all } = grow([size]);
    assert.ok(edge.root().equals(reference(all)), `root ${size}`);
    const again = Edge.load(size, new Map(edgeOf(size).map((e) => [tileKey(e.level, e.index), tiles.get(tileKey(e.level, e.index)) ?? Buffer.alloc(0)])));
    const copy = edge.clone();
    const more = leaves(size + 300, size);
    copy.append(more);
    again.append(more);
    assert.ok(again.root().equals(copy.root()), `reloaded ${size}`);
    assert.equal(edge.size, size);
    assert.ok(edge.root().equals(reference(all)), `clone ${size}`);
  }
});

test('inclusion and consistency proofs verify, and fail when anything is off', () => {
  const { tiles, all } = grow([70001]);
  const nodes = nodesFrom(tiles);
  const root5 = () => treeHash(nodes, 5);
  for (const n of [1, 2, 3, 5, 8, 255, 256, 257, 1000, 65536, 70001]) {
    const root = treeHash(nodes, n);
    for (const m of [0, 1, n >> 1, n - 2, n - 1].filter((m) => m >= 0 && m < n)) {
      const proof = inclusionProof(nodes, m, n);
      assert.ok(verifyInclusion(all[m]!, m, n, proof, root), `inclusion ${m} of ${n}`);
      if (n > 1) assert.ok(!verifyInclusion(all[(m + 1) % n]!, m, n, proof, root), `wrong leaf ${m} of ${n}`);
      if (proof.length > 0) assert.ok(!verifyInclusion(all[m]!, m, n, proof.slice(1), root), `short proof ${m} of ${n}`);
    }
    for (const m of [1, 2, 3, n >> 1, n - 1].filter((m) => m > 0 && m < n)) {
      const proof = consistencyProof(nodes, m, n);
      assert.ok(verifyConsistency(m, n, treeHash(nodes, m), root, proof), `consistency ${m} to ${n}`);
      assert.ok(m === n - 1 || !verifyConsistency(m, n, treeHash(nodes, m), treeHash(nodes, n - 1), proof), `wrong head ${m} to ${n}`);
    }
  }
  assert.ok(!verifyInclusion(all[0]!, -1, 5, [], EMPTY_ROOT));
  assert.ok(!verifyConsistency(5, 3, EMPTY_ROOT, EMPTY_ROOT, []));
  assert.ok(verifyConsistency(0, 5, EMPTY_ROOT, root5(), []) && !verifyConsistency(0, 5, all[0]!, root5(), []), 'the empty tree has one head');
  assert.ok(!verifyConsistency(0, 0, all[0]!, all[0]!, []) && verifyConsistency(0, 0, EMPTY_ROOT, EMPTY_ROOT, []), 'nor at size 0');
});

test('a proof of one entry among 70,001 reads at most 4 tiles', () => {
  // Leaf 12,345 of 70,001: its own level-0 tile, then level 1, level 2, and the partial tile at the right edge.
  const keys = tilesFor((nodes) => inclusionProof(nodes, 12345, 70001));
  assert.ok(keys.length <= 4, `${keys.length} tiles`);
});

test('a tree past 2^32 leaves splits as the RFC says: no 32-bit arithmetic', () => {
  // `n & (n - 1)` is 32-bit in JavaScript: 2^32 + 1 read as a power of two, and 2^32 + 2^31 split at the wrong place.
  const asked: string[] = [];
  const nodes = (level: number, index: number) => {
    asked.push(`${level}/${index}`);
    return Buffer.alloc(32);
  };
  treeHash(nodes, 2 ** 32 + 1);
  assert.deepEqual(asked, ['32/0', '0/4294967296']);
  asked.length = 0;
  treeHash(nodes, 2 ** 33 + 2 ** 32);
  assert.deepEqual(asked, ['33/0', '32/2']);
  // A consistency proof from 2^32 + 1 leaves is not one from a power of two, made or checked.
  assert.equal(consistencyProof(() => Buffer.alloc(32), 2 ** 32 + 1, 2 ** 32 + 2).length, 3);
  // Checked against heads of a tree whose leaves are all one hash, so that any subtree's hash depends on its level
  // alone and a tree of 2^33 leaves costs 33 hashes: a wrong split point shows.
  const levels: Hash[] = [leafHash(Buffer.from('x'))];
  const same: Nodes = (level) => {
    while (levels.length <= level) levels.push(nodeHash(levels.at(-1)!, levels.at(-1)!));
    return levels[level]!;
  };
  for (const [m, n] of [[2 ** 32 + 1, 2 ** 32 + 500], [2 ** 32, 2 ** 33 + 3], [2 ** 32 + 2 ** 31, 2 ** 34], [5, 2 ** 32 + 1]] as const) {
    assert.ok(verifyConsistency(m, n, treeHash(same, m), treeHash(same, n), consistencyProof(same, m, n)), `${m} to ${n}`);
  }
  for (const [m, n] of [[2 ** 32 + 7, 2 ** 33 + 1], [2 ** 32, 2 ** 32 + 1], [3, 2 ** 32 + 2 ** 31]] as const) {
    assert.ok(verifyInclusion(same(0, m), m, n, inclusionProof(same, m, n), treeHash(same, n)), `${m} of ${n}`);
  }
});

/** The tiles left once the entries below `cut`, a multiple of 256, are pruned: every level-0 tile below it is gone, and nothing else. */
function prune(tiles: ReadonlyMap<string, Buffer>, cut: number): Map<string, Buffer> {
  return new Map([...tiles].filter(([key]) => {
    const [level, index] = key.split('/').map(Number) as [number, number];
    return level > 0 || index >= cut / WIDTH;
  }));
}

test('a tree pruned from its start keeps its head, proves every entry it kept, and grows as before', () => {
  // `nodesFrom` throws on a missing tile, so whatever verifies below read none of the pruned ones: the head, the proof
  // of every kept entry, and consistency from every size at or past the cut. Then the signer's next run: the edge
  // loaded from what is kept, and appended to. Exhaustive on small trees, one of them a whole number of level-1
  // tiles and pruned to its last block and to nothing; sampled on one that goes past a level-1 tile.
  const check = (n: number, cuts: readonly number[], stride: number) => {
    const { tiles, edge, all } = grow(Array.from({ length: Math.ceil(n / 997) }, (_, i) => Math.min(n, (i + 1) * 997)));
    const whole = memo(nodesFrom(tiles));
    const more = leaves(n + 300, n);
    const grown = edge.clone();
    grown.append(more);
    for (const cut of cuts) {
      const kept = prune(tiles, cut);
      const nodes = memo(nodesFrom(kept));
      const head = treeHash(nodes, n);
      assert.ok(head.equals(edge.root()), `cut ${cut}: the head`);
      for (let m = cut; m < n; m += stride) assert.ok(verifyInclusion(all[m]!, m, n, inclusionProof(nodes, m, n), head), `cut ${cut}, entry ${m}`);
      for (let from = cut; from <= n; from += stride) {
        const before = treeHash(nodes, from);
        assert.ok(before.equals(treeHash(whole, from)), `cut ${cut}: the head at ${from}`);
        assert.ok(verifyConsistency(from, n, before, head, consistencyProof(nodes, from, n)), `cut ${cut}, from ${from}`);
      }
      assert.throws(() => inclusionProof(nodes, cut - 1, n), /lacks node/, 'a pruned entry proves no more');
      const again = Edge.load(n, kept);
      again.append(more);
      assert.ok(again.root().equals(grown.root()), `cut ${cut}: 300 more entries`);
    }
  };
  check(1500, [256, 512, 768, 1024, 1280], 1);
  check(65_536, [65_280, 65_536], 1);
  check(300_000, [65_536, 200_192], 1013);
});

test('a full verify of a pruned tree starts from the edge at the cut, and an edited entry moves the head', () => {
  const [n, cut] = [1536, 1280];
  const { tiles, edge, all } = grow([n]);
  const kept = prune(tiles, cut);
  // The edge at the cut holds the pruned blocks' hashes, as stored, and nothing of the kept entries.
  const verify = (entries: readonly Hash[]) => {
    const from = Edge.load(cut, kept);
    from.append(entries);
    return from.root();
  };
  assert.ok(verify(all.slice(cut)).equals(edge.root()));
  const edited = all.slice(cut);
  edited[3] = leafHash(Buffer.from('edited'));
  assert.ok(!verify(edited).equals(edge.root()), 'an edited entry');
  assert.ok(!verify(all.slice(cut, -1)).equals(edge.root()), 'a missing one');
  // What a verify must not do: fill in the block's tile and ask `nodesFrom`, which answers from the tile above.
  const filled = new Map(kept).set(tileKey(0, cut / WIDTH), Buffer.concat(edited));
  assert.ok(treeHash(nodesFrom(filled), n).equals(edge.root()), 'nodesFrom never read the edited block');
});

type Vectors = {
  sizes: number[];
  heads: Record<string, string>;
  inclusion: { index: number; size: number; proof: string[] }[];
  consistency: { from: number; to: number; proof: string[] }[];
  tiles: Record<string, string>;
};

/** Go's tile path, `tile/8/<level>/<index>[.p/<width>]`, the index in groups of three digits (x001/x234/067). */
function parseTilePath(path: string): { level: number; index: number; width: number } {
  const m = /^tile\/8\/(\d+)\/((?:x\d{3}\/)*\d{3})(?:\.p\/(\d+))?$/.exec(path);
  assert.ok(m, path);
  return { level: Number(m[1]), index: Number(m[2]!.replaceAll('x', '').replaceAll('/', '')), width: m[3] === undefined ? WIDTH : Number(m[3]) };
}

test("Go's tlog computes the same heads, proofs and tiles", () => {
  const go = JSON.parse(readFileSync(new URL('./vectors/log-tree-go.json', import.meta.url), 'utf8')) as Vectors;
  const max = Math.max(...go.sizes);
  const { tiles } = grow(go.sizes);
  const nodes = nodesFrom(tiles);
  for (const size of go.sizes) assert.equal(treeHash(nodes, size).toString('base64'), go.heads[size], `head ${size}`);
  assert.ok(go.inclusion.length > 0 && go.consistency.length > 0);
  for (const p of go.inclusion) assert.deepEqual(inclusionProof(nodes, p.index, p.size).map((h) => h.toString('base64')), p.proof, `inclusion ${p.index} of ${p.size}`);
  for (const p of go.consistency) assert.deepEqual(consistencyProof(nodes, p.from, p.to).map((h) => h.toString('base64')), p.proof, `consistency ${p.from} to ${p.to}`);
  for (const [path, digest] of Object.entries(go.tiles)) {
    const t = parseTilePath(path);
    const hashes = tiles.get(tileKey(t.level, t.index))!.subarray(0, t.width * 32);
    assert.equal(createHash('sha256').update(hashes).digest('hex'), digest, path);
  }
  assert.equal(Object.keys(go.tiles).length, edgeOf(max).length + Math.floor(max / 256) + Math.floor(max / 65536), 'every tile');
});
