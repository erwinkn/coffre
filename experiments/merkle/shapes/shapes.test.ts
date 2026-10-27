// W212: the shapes against #365's tree. A mountain range hashed as RFC 9162
// hashes is the RFC 9162 tree; each shape's heads are what its trees say.
//
//   node --test experiments/merkle/shapes/shapes.test.ts
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Edge, HEIGHT, nodesFrom } from '../src/tiles.ts';
import { consistencyProof, inclusionProof, leafHash, referenceHash, treeHash, verifyConsistency, verifyInclusion } from '../src/tree.ts';
import { link, Mmr, shapeAt, type Leaf } from './shapes.ts';
import { inclusionRoot, sparseConsistency, sparseInclusion } from './sparse.ts';

const leaves = (n: number, from = 0) => Array.from({ length: n }, (_, i) => leafHash(Buffer.from(`entry ${from + i}`)));

test('a mountain range bagged right to left has the RFC 9162 head of the same leaves, at every size', () => {
  const mmr = Mmr.empty();
  const all = leaves(1100);
  for (let n = 0; n < all.length; n += 1) {
    mmr.append([all[n]!]);
    assert.ok(mmr.root().equals(referenceHash(all.slice(0, n + 1))), `size ${n + 1}`);
  }
  // Every node stored: 2n - popcount(n) of them.
  assert.equal(mmr.stored, 2 * 1100 - 4);
});

test('the mountain range in batches stores what it does leaf by leaf', () => {
  const a = Mmr.empty();
  const b = Mmr.empty();
  const all = leaves(3000);
  const chunksA = new Map<number, string>();
  const chunksB = new Map<number, string>();
  for (const x of all) for (const c of a.append([x])) chunksA.set(c.index, c.hashes.toString('hex'));
  for (let i = 0; i < all.length; i += 487) for (const c of b.append(all.slice(i, i + 487))) chunksB.set(c.index, c.hashes.toString('hex'));
  assert.deepEqual(chunksB, chunksA);
  assert.ok(a.root().equals(b.root()));
});

test('split: two trees, each the RFC 9162 head of its kind', () => {
  const shape = shapeAt('split', 0, { changeRate: 0, dayLeaves: 1e9, tickLeaves: 500 });
  const all = leaves(2000);
  const marked: Leaf[] = all.map((hash, i) => ({ hash, change: i % 7 === 0, day: 0 }));
  let heads;
  for (let i = 0; i < marked.length; i += 500) heads = shape.seal(marked.slice(i, i + 500)).heads;
  assert.ok(heads![0]!.root.equals(referenceHash(marked.filter((l) => !l.change).map((l) => l.hash))));
  assert.ok(heads![1]!.root.equals(referenceHash(marked.filter((l) => l.change).map((l) => l.hash))));
});

test('day: a top tree of closed days, the open day beside it', () => {
  const shape = shapeAt('day', 0, { changeRate: 0, dayLeaves: 700, tickLeaves: 500 });
  const all = leaves(2000);
  const marked: Leaf[] = all.map((hash, i) => ({ hash, change: false, day: Math.floor(i / 700) }));
  let heads;
  for (let i = 0; i < marked.length; i += 500) heads = shape.seal(marked.slice(i, i + 500)).heads;
  const days = [0, 1].map((d) => referenceHash(all.slice(d * 700, (d + 1) * 700)));
  assert.ok(heads![0]!.root.equals(referenceHash(days)));
  assert.equal(heads![0]!.extra, `day 2 600 ${referenceHash(all.slice(1400)).toString('base64')}`);
});

test('tick and chain: a top tree of tick roots, or a chain of them', () => {
  const all = leaves(1500);
  const marked: Leaf[] = all.map((hash) => ({ hash, change: false, day: 0 }));
  const tick = shapeAt('tick', 0, { changeRate: 0, dayLeaves: 1e9, tickLeaves: 500 });
  const roots = [0, 500, 1000].map((i) => referenceHash(all.slice(i, i + 500)));
  let heads;
  for (let i = 0; i < 1500; i += 500) heads = tick.seal(marked.slice(i, i + 500)).heads;
  // `tick` starts from a random top of 0 leaves, which is the empty tree.
  assert.ok(heads![0]!.root.equals(referenceHash(roots)));
  const edge = Edge.empty();
  edge.append(all.slice(1000));
  assert.ok(edge.root().equals(roots[2]!));
  assert.equal(typeof link, 'function');
});

test('a sparse inclusion proof verifies against the root it implies, and fails with one hash changed', () => {
  for (const [m, n] of [[0, 1], [5, 6], [12345, 1e6], [31_535_940_000, 31_536_000_000], [3, 31_536_000_000]] as const) {
    const { leaf, proof } = sparseInclusion(m, n);
    const root = inclusionRoot(leaf, m, n, proof);
    assert.ok(verifyInclusion(leaf, m, n, proof, root), `${m} of ${n}`);
    if (proof.length > 0) {
      const bad = proof.map((p, i) => (i === proof.length - 1 ? Buffer.alloc(32, 7) : p));
      assert.ok(!verifyInclusion(leaf, m, n, bad, root));
    }
  }
  // And the sparse proof is as long as the real one.
  const real = leaves(1000);
  const tree = (level: number, index: number) => referenceHash(real.slice(index * 2 ** level, (index + 1) * 2 ** level));
  for (const m of [0, 17, 511, 999]) assert.equal(sparseInclusion(m, 1000).proof.length, inclusionProof(tree, m, 1000).length);
});

test('a sparse consistency proof verifies against the heads it implies, and is as long as the real one', () => {
  for (const [m, n] of [[1, 2], [4, 9], [500, 1000], [2 ** 32, 2 ** 32 + 500], [2 ** 32 + 1, 2 ** 32 + 500], [31_449_600_000, 31_536_000_000], [500, 31_536_000_000]] as const) {
    const { first, second, proof } = sparseConsistency(m, n);
    assert.ok(verifyConsistency(m, n, first, second, proof), `${m} to ${n}`);
    assert.ok(!verifyConsistency(m, n, first, Buffer.alloc(32, 7), proof));
  }
  const real = leaves(1000);
  const tree = (level: number, index: number) => referenceHash(real.slice(index * 2 ** level, (index + 1) * 2 ** level));
  for (const [m, n] of [[1, 1000], [256, 1000], [999, 1000], [300, 700]] as const) assert.equal(sparseConsistency(m, n).proof.length, consistencyProof(tree, m, n).length);
});

test('below a retention cut, one tile per level is all that proofs above it read', () => {
  // Every tile wholly below the cut goes, at every level, but the tile that holds the cut at each level. Then every
  // leaf above the cut is proved, and consistency checked from every size above it, exhaustively, for cuts on and
  // around tile edges (nodesFrom throws on a missing hash). A larger tree, sampled, crosses level 2.
  const check = (n: number, cuts: number[], stride: number) => {
    const all = leaves(n);
    const edge = Edge.empty();
    const tiles = new Map<string, Buffer>();
    for (let i = 0; i < n; i += 997) for (const t of edge.append(all.slice(i, i + 997))) tiles.set(`${t.level}/${t.index}`, t.hashes);
    const full = nodesFrom(tiles);
    for (const cut of cuts) {
      const kept = new Map([...tiles].filter(([key]) => {
        const [level, index] = key.split('/').map(Number) as [number, number];
        return (index + 1) * 2 ** (HEIGHT * (level + 1)) > cut;
      }));
      const nodes = nodesFrom(kept);
      const head = treeHash(nodes, n);
      assert.ok(head.equals(edge.root()));
      for (let m = cut; m < n; m += stride) assert.ok(verifyInclusion(all[m]!, m, n, inclusionProof(nodes, m, n), head), `cut ${cut}, leaf ${m}`);
      for (let from = Math.max(1, cut); from <= n; from += stride) {
        assert.ok(verifyConsistency(from, n, treeHash(full, from), head, consistencyProof(nodes, from, n)), `cut ${cut}, from ${from}`);
      }
    }
  };
  check(1500, [1, 255, 256, 257, 700, 1024, 1499], 1);
  check(300_000, [65_535, 65_536, 200_003], 1013);
});
