// The tree against RFC 9162's recursion, the tiles against the tree, the
// signed notes and the pair, the leaf encoding, and the witness's rule. Go's
// sumdb/tlog checks the same bytes independently (test/go, vectors below).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  checkpointBody,
  consistencyProof,
  decodePair,
  Edge,
  edgeOf,
  EMPTY_ROOT,
  encodePair,
  HEIGHT,
  inclusionProof,
  keptAbove,
  leafData,
  leafHash,
  nodeHash,
  nodesFrom,
  noteSigner,
  noteVerifier,
  openCheckpoint,
  openNote,
  openPair,
  pairSigners,
  pairVerifiers,
  parseCheckpoint,
  parseTilePath,
  signNote,
  signPair,
  tilePath,
  tilesFor,
  treeHash,
  verifyConsistency,
  verifyInclusion,
  witnessPair,
  type Hash,
  type Nodes,
} from '@coffre/core/merkle';

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
    for (const t of edge.append(batch)) tiles.set(`${t.level}/${t.index}`, t.hashes);
  }
  return { tiles, edge, all };
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
    const again = Edge.load(size, new Map(edgeOf(size).map((e) => [`${e.level}/${e.index}`, tiles.get(`${e.level}/${e.index}`) ?? Buffer.alloc(0)])));
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
});

test('a proof reads about one tile per 8 levels', () => {
  // Leaf 12,345 of 70,001: its own level-0 tile, then level 1, level 2, and the partial tile at the right edge.
  const keys = tilesFor((nodes) => inclusionProof(nodes, 12345, 70001));
  assert.ok(keys.length <= 4, `${keys.length} tiles`);
});

test('a tree past 2^32 leaves splits as the RFC says: no 32-bit arithmetic (W212)', () => {
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
  // alone and a tree of 2^33 leaves costs 33 hashes: the split points are what the old code got wrong.
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

test('below a retention cut, one tile per level is all that proofs above it read (W212)', () => {
  // Every tile wholly below the cut goes, at every level, but the one holding the cut at each level. Then every leaf
  // above the cut is proved, and consistency checked from every size above it, exhaustively on a small tree for cuts
  // on and around tile edges (nodesFrom throws on a missing tile), and sampled on one that crosses level 2.
  const check = (n: number, cuts: number[], stride: number) => {
    const { tiles, edge, all } = grow(Array.from({ length: Math.ceil(n / 997) }, (_, i) => Math.min(n, (i + 1) * 997)));
    const full = memo(nodesFrom(tiles));
    for (const cut of cuts) {
      const kept = new Map([...tiles].filter(([key]) => {
        const [level, index] = key.split('/').map(Number) as [number, number];
        return keptAbove({ level, index }, cut);
      }));
      const below = [...kept.keys()].filter((key) => {
        const [level, index] = key.split('/').map(Number) as [number, number];
        return index * 2 ** (HEIGHT * (level + 1)) < cut;
      });
      assert.ok(below.length <= edgeOf(n).length, `cut ${cut}: ${below.length} tiles kept below it, one a level at most`);
      const nodes = memo(nodesFrom(kept));
      const head = treeHash(nodes, n);
      assert.ok(head.equals(edge.root()));
      for (let m = cut; m < n; m += stride) assert.ok(verifyInclusion(all[m]!, m, n, inclusionProof(nodes, m, n), head), `cut ${cut}, leaf ${m}`);
      for (let from = Math.max(1, cut); from <= n; from += stride) {
        assert.ok(verifyConsistency(from, n, treeHash(full, from), head, consistencyProof(nodes, from, n)), `cut ${cut}, from ${from}`);
      }
      if (cut > 256) assert.throws(() => inclusionProof(nodes, 0, n), /lacks node/, 'a leaf wholly below the cut is gone');
    }
  };
  check(1500, [1, 255, 256, 257, 700, 1024, 1499], 1);
  check(300_000, [65_535, 65_536, 200_003], 1013);
});

test("tile paths are Go's", () => {
  assert.equal(tilePath({ level: 0, index: 1234067 }, 256), 'tile/8/0/x001/x234/067');
  assert.equal(tilePath({ level: 2, index: 5 }, 17), 'tile/8/2/005.p/17');
  assert.deepEqual(parseTilePath('tile/8/0/x001/x234/067'), { level: 0, index: 1234067, width: 256 });
  assert.deepEqual(parseTilePath('tile/8/2/005.p/17'), { level: 2, index: 5, width: 17 });
  for (const bad of ['tile/8/0/005.p/0', 'tile/8/0/005.p/256', 'tile/4/0/005', 'tile/8/0/5', 'tile/8/0/x5/005']) assert.equal(parseTilePath(bad), null, bad);
});

test('a signed checkpoint opens with its key and no other, and nothing but a checkpoint parses', async () => {
  const signer = await noteSigner('coffre.example/audit/uses', Buffer.alloc(32, 7));
  const other = await noteSigner('coffre.example/audit/uses', Buffer.alloc(32, 8));
  const body = checkpointBody({ origin: 'coffre.example/audit/uses', size: 3, root: Buffer.alloc(32, 1), upto: 42n, at: 1 });
  const note = await signNote(body, [signer]);
  const verifier = await noteVerifier(signer.verifierKey);
  assert.equal(await openNote(note, verifier), body);
  assert.equal(await openNote(note, await noteVerifier(other.verifierKey)), null);
  assert.equal(await openNote(note.replace('\n3\n', '\n4\n'), verifier), null);
  assert.equal((await openCheckpoint(note, verifier))?.upto, 42n);
  // Another origin under the same name's key does not open as this log's checkpoint.
  const elsewhere = await signNote(body.replace('coffre.example/audit/uses', 'coffre.example/audit/changes'), [signer]);
  assert.equal(await openCheckpoint(elsewhere, verifier), null);
  for (const text of [
    body.replace('upto 42', 'upto 042'),
    body.replace('upto 42', 'upto 9223372036854775808'),
    body.replace('\n3\n', '\n-3\n'),
    `${body}extra\n`,
    body.slice(0, -1),
    body.replace(/^.*\n/, 'has space\n'),
  ]) assert.throws(() => parseCheckpoint(text), /not a checkpoint/, text);
  assert.equal(await openNote('garbage', verifier), null);
  await assert.rejects(noteVerifier('name+00000000+AQ=='), /Ed25519/);
});

test('a pair is two notes at one upto and one at, each under its own origin and key', async () => {
  const signers = await pairSigners('coffre.example/audit', Buffer.alloc(32, 3));
  const verifiers = await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey });
  assert.equal(signers.changes.name, 'coffre.example/audit/changes');
  assert.ok(!signers.changes.publicKey.equals(signers.uses.publicKey));
  const heads = { changes: { size: 1, root: Buffer.alloc(32, 1) }, uses: { size: 2, root: Buffer.alloc(32, 2) } };
  const { pair, notes } = await signPair(signers, 10n, 1000, heads);
  assert.deepEqual(await openPair(notes, verifiers), pair);
  assert.deepEqual(decodePair(encodePair(notes)), notes);
  for (const record of ['{}', '[]', 'null', '{"changes":"a","uses":"b","x":1}', '{"changes":1,"uses":"b"}', 'not json']) assert.equal(decodePair(record), null, record);
  // Notes from two ticks are not a pair, nor are the trees' notes swapped.
  const later = await signPair(signers, 11n, 1500, heads);
  assert.equal(await openPair({ changes: notes.changes, uses: later.notes.uses }, verifiers), null);
  const sameUpto = await signPair(signers, 10n, 1001, heads);
  assert.equal(await openPair({ changes: notes.changes, uses: sameUpto.notes.uses }, verifiers), null);
  assert.equal(await openPair({ changes: notes.uses, uses: notes.changes }, verifiers), null);
});

const vectors = JSON.parse(readFileSync(new URL('./vectors/audit-tree.json', import.meta.url), 'utf8')) as {
  format: string;
  leaves: { tree: 'changes' | 'uses'; number: string; columns: ({ bytes: string } | { text: string } | { integer: string } | null)[]; data: string; hash: string }[];
  pair: { origin: string; seed: string; keys: { changes: string; uses: string } };
  go: { sizes: number[]; heads: Record<string, string>; inclusion: { index: number; size: number; proof: string[] }[]; consistency: { from: number; to: number; proof: string[] }[]; tiles: Record<string, string> };
};

test('the test vectors still hold: leaf bytes, pair keys, and Go tlog heads, proofs and tiles', async () => {
  assert.equal(vectors.format, 'coffre.audit.leaf.v1');
  for (const v of vectors.leaves) {
    const columns = v.columns.map((c) => (c === null ? null : 'bytes' in c ? Buffer.from(c.bytes, 'hex') : 'text' in c ? c.text : BigInt(c.integer)));
    const data = leafData(v.tree, BigInt(v.number), columns);
    assert.equal(data.toString('hex'), v.data);
    assert.equal(leafHash(data).toString('hex'), v.hash);
  }
  const signers = await pairSigners(vectors.pair.origin, Buffer.from(vectors.pair.seed, 'hex'));
  assert.deepEqual({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey }, vectors.pair.keys);
  // The tree Go's tlog built from the same leaves (`go run ./test/go vectors`): heads, proofs and tile bytes.
  const max = Math.max(...vectors.go.sizes);
  const { tiles } = grow(vectors.go.sizes);
  const nodes = nodesFrom(tiles);
  for (const size of vectors.go.sizes) assert.equal(treeHash(nodes, size).toString('base64'), vectors.go.heads[size], `head ${size}`);
  for (const p of vectors.go.inclusion) assert.deepEqual(inclusionProof(nodes, p.index, p.size).map((h) => h.toString('base64')), p.proof, `inclusion ${p.index} of ${p.size}`);
  for (const p of vectors.go.consistency) assert.deepEqual(consistencyProof(nodes, p.from, p.to).map((h) => h.toString('base64')), p.proof, `consistency ${p.from} to ${p.to}`);
  for (const [path, digest] of Object.entries(vectors.go.tiles)) {
    const t = parseTilePath(path)!;
    const hashes = tiles.get(`${t.level}/${t.index}`)!.subarray(0, t.width * 32);
    assert.equal(createHash('sha256').update(hashes).digest('hex'), digest, path);
  }
  assert.equal(Object.keys(vectors.go.tiles).length, edgeOf(max).length + Math.floor(max / 256) + Math.floor(max / 65536), 'every tile');
});

test('leaves are injective: a column moved, retyped or split is another leaf, and so is the tree', () => {
  const base = leafData('uses', 7n, [1n, 'ab', null, Buffer.from('c')]);
  for (const other of [
    leafData('changes', 7n, [1n, 'ab', null, Buffer.from('c')]),
    leafData('uses', 8n, [1n, 'ab', null, Buffer.from('c')]),
    leafData('uses', 7n, ['1', 'ab', null, Buffer.from('c')]),
    leafData('uses', 7n, [1n, 'a', 'b', null, Buffer.from('c')]),
    leafData('uses', 7n, [1n, 'ab', '', Buffer.from('c')]),
    leafData('uses', 7n, [1n, 'ab', null, 'c']),
  ]) assert.ok(!base.equals(other));
  assert.throws(() => leafData('uses', -1n, []), /out of range/);
  assert.throws(() => leafData('uses', 1n, [1.5]), /whole number/);
  assert.throws(() => leafData('uses', 1n, ['\uD800']), /Unicode/);
});

test('a witness cosigns a pair only if both trees extend the pair it holds', async () => {
  const signers = await pairSigners('coffre.example/audit', Buffer.alloc(32, 3));
  const log = await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey });
  const self = await noteSigner('witness.example', Buffer.alloc(32, 9));
  const changes = nodesFrom(grow([5]).tiles);
  const uses = nodesFrom(grow([800]).tiles);
  // A second history of the uses tree: its first 500 leaves, then others.
  const other = Edge.empty();
  const otherTiles = new Map<string, Buffer>();
  for (const batch of [leaves(500), leaves(800, 500).map((h) => nodeHash(h, h))]) for (const t of other.append(batch)) otherTiles.set(`${t.level}/${t.index}`, t.hashes);
  const forked = nodesFrom(otherTiles);
  const heads = (c: number, u: number, tree = uses) => ({ changes: { size: c, root: treeHash(changes, c) }, uses: { size: u, root: treeHash(tree, u) } });
  const proofs = (from: [number, number], to: [number, number], tree = uses) => ({
    changes: consistencyProof(changes, from[0], to[0]),
    uses: consistencyProof(tree, from[1], to[1]),
  });

  const first = await signPair(signers, 10n, 1, heads(3, 300));
  const held = await witnessPair(null, first.notes, proofs([0, 0], [0, 0]), log, self);
  assert.ok(held.answer.ok);
  const second = await signPair(signers, 20n, 2, heads(4, 700));
  const next = await witnessPair(held.state, second.notes, proofs([3, 300], [4, 700]), log, self);
  assert.ok(next.answer.ok);
  assert.ok((await openNote(next.answer.cosigned.uses, await noteVerifier(self.verifierKey))) !== null, 'cosigned');
  assert.ok((await witnessPair(next.state, second.notes, proofs([4, 700], [4, 700]), log, self)).answer.ok, 'the same pair again');

  // The changes head extends, the uses head is another history: refused whole, and the pair held stays.
  const fork = await signPair(signers, 30n, 3, { changes: heads(5, 0).changes, uses: { size: 800, root: treeHash(forked, 800) } });
  const refused = await witnessPair(next.state, fork.notes, proofs([4, 700], [5, 800], forked), log, self);
  assert.ok(!refused.answer.ok && /split view: uses/.test(refused.answer.reason), JSON.stringify(refused.answer));
  assert.equal(refused.state, next.state);
  // A second pair at the same place, however consistent; an older pair; and notes that are not one pair.
  const sameUpto = await signPair(signers, 20n, 2, heads(5, 800));
  assert.ok(!(await witnessPair(next.state, sameUpto.notes, proofs([4, 700], [5, 800]), log, self)).answer.ok);
  assert.ok(!(await witnessPair(next.state, first.notes, proofs([0, 0], [0, 0]), log, self)).answer.ok);
  assert.ok(!(await witnessPair(next.state, { changes: second.notes.changes, uses: first.notes.uses }, proofs([4, 700], [4, 700]), log, self)).answer.ok);
  const later = await signPair(signers, 40n, 4, heads(5, 800));
  assert.ok((await witnessPair(next.state, later.notes, proofs([4, 700], [5, 800]), log, self)).answer.ok, 'the honest next pair');
});
