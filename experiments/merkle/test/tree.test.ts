// The tree against RFC 9162's recursion, the tiles against the tree, and the
// signed note round trip. Go checks the same bytes independently (go/).
//
//   node --test experiments/merkle/test/tree.test.ts
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import { checkpointBody, openNote, parseCheckpoint, signerFrom, signNote, verifierFrom } from '../src/note.ts';
import { sparseConsistency } from '../shapes/sparse.ts';
import { Edge, edgeOf, nodesFrom, parseTilePath, tileMap, tilePath, tilesFor, type Tile } from '../src/tiles.ts';
import { consistencyProof, inclusionProof, leafHash, referenceHash, treeHash, verifyConsistency, verifyInclusion } from '../src/tree.ts';

const leaves = (n: number) => Array.from({ length: n }, (_, i) => leafHash(Buffer.from(`entry ${i}`)));

/** Every tile ever written, latest version of each. */
function grow(sizes: number[]): { tiles: Map<string, Buffer>; edge: Edge; all: Buffer[] } {
  const tiles = new Map<string, Buffer>();
  const edge = Edge.empty();
  const all: Buffer[] = [];
  let at = 0;
  for (const size of sizes) {
    const batch = leaves(size).slice(at);
    all.push(...batch);
    for (const t of edge.append(batch)) tiles.set(`${t.level}/${t.index}`, t.hashes);
    at = size;
  }
  return { tiles, edge, all };
}

test('the empty tree hashes to SHA-256 of nothing', () => {
  assert.equal(treeHash(() => { throw new Error('no node'); }, 0).toString('hex'), createHash('sha256').digest('hex'));
});

test('tiles give the reference head at every size, appended in uneven batches', () => {
  const sizes = [1, 2, 3, 7, 8, 255, 256, 257, 511, 512, 600, 65535, 65536, 65537, 70001];
  const { tiles, all } = grow(sizes);
  const nodes = nodesFrom(tiles);
  for (const size of [...sizes, 4, 5, 100, 1000, 4097, 65000]) {
    assert.ok(treeHash(nodes, size).equals(referenceHash(all.slice(0, size))), `size ${size}`);
  }
});

test('the edge computes the head itself, and reloads from the edge tiles alone', () => {
  for (const size of [1, 255, 256, 257, 65536, 65537, 70001]) {
    const { tiles, edge, all } = grow([size]);
    assert.ok(edge.root().equals(referenceHash(all)), `root ${size}`);
    const stored = new Map(edgeOf(size).map((e) => [`${e.level}/${e.index}`, tiles.get(`${e.level}/${e.index}`) ?? Buffer.alloc(0)]));
    const again = Edge.load(size, stored);
    const more = leaves(size + 300).slice(size);
    edge.append(more);
    again.append(more);
    assert.ok(again.root().equals(edge.root()), `reloaded ${size}`);
  }
});

test('inclusion and consistency proofs verify, and fail when anything is off', () => {
  const { tiles, all } = grow([70001]);
  const nodes = nodesFrom(tiles);
  for (const n of [1, 2, 3, 5, 8, 255, 256, 257, 1000, 65536, 70001]) {
    const root = treeHash(nodes, n);
    for (const m of [0, 1, n >> 1, n - 2, n - 1].filter((m) => m >= 0 && m < n)) {
      const proof = inclusionProof(nodes, m, n);
      assert.ok(verifyInclusion(all[m]!, m, n, proof, root), `inclusion ${m} of ${n}`);
      if (n > 1) assert.ok(!verifyInclusion(all[(m + 1) % n]!, m, n, proof, root), `wrong leaf ${m} of ${n}`);
    }
    for (const m of [1, 2, 3, n >> 1, n - 1].filter((m) => m > 0 && m < n)) {
      const proof = consistencyProof(nodes, m, n);
      assert.ok(verifyConsistency(m, n, treeHash(nodes, m), root, proof), `consistency ${m} to ${n}`);
      assert.ok(!verifyConsistency(m, n, treeHash(nodes, m), treeHash(nodes, n - 1), proof) || m === n - 1, `wrong head ${m} to ${n}`);
    }
  }
});

test('a proof reads one tile per 8 levels', () => {
  const { tiles } = grow([70001]);
  const keys = tilesFor((nodes) => inclusionProof(nodes, 12345, 70001));
  assert.ok(keys.length <= 4, `${keys.length} tiles`);
  assert.ok(tileMap(keys.map((k) => ({ ...k, hashes: tiles.get(`${k.level}/${k.index}`)! }) as Tile)).size === keys.length);
});

test("tile paths are Go's", () => {
  assert.equal(tilePath({ level: 0, index: 1234067 }, 256), 'tile/8/0/x001/x234/067');
  assert.equal(tilePath({ level: 2, index: 5 }, 17), 'tile/8/2/005.p/17');
  assert.deepEqual(parseTilePath('tile/8/0/x001/x234/067'), { level: 0, index: 1234067, width: 256 });
});

test('a signed checkpoint opens with its key and no other', async () => {
  const signer = await signerFrom('coffre.example/audit', Buffer.alloc(32, 7));
  const other = await signerFrom('coffre.example/audit', Buffer.alloc(32, 8));
  const body = checkpointBody({ origin: 'coffre.example/audit', size: 3, root: Buffer.alloc(32, 1), upto: '42', at: 1 });
  const note = await signNote(body, [signer]);
  assert.equal(await openNote(note, await verifierFrom(signer.verifierKey)), body);
  assert.equal(await openNote(note, await verifierFrom(other.verifierKey)), null);
  assert.equal(await openNote(note.replace('\n3\n', '\n4\n'), await verifierFrom(signer.verifierKey)), null);
  assert.equal(parseCheckpoint(body).upto, '42');
});

test('a tree past 2^32 leaves splits as the RFC says (no 32-bit arithmetic)', () => {
  const asked: string[] = [];
  const nodes = (level: number, index: number) => {
    asked.push(`${level}/${index}`);
    return Buffer.alloc(32);
  };
  // 2^32 + 1 leaves: the perfect tree of the first 2^32, then the last leaf alone.
  treeHash(nodes, 2 ** 32 + 1);
  assert.deepEqual(asked, ['32/0', '0/4294967296']);
  asked.length = 0;
  treeHash(nodes, 2 ** 33 + 2 ** 32);
  assert.deepEqual(asked, ['33/0', '32/2']);
  // A consistency proof from 2^32 + 1 leaves is not treated as one from a power of two, made or checked.
  assert.equal(consistencyProof(() => Buffer.alloc(32), 2 ** 32 + 1, 2 ** 32 + 2).length, 3);
  const { first, second, proof } = sparseConsistency(2 ** 32 + 1, 2 ** 32 + 500);
  assert.ok(verifyConsistency(2 ** 32 + 1, 2 ** 32 + 500, first, second, proof));
});
