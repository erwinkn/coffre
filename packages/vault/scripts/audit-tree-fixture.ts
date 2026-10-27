// A split log for Go's sumdb/tlog to check (packages/core/test/go,
// scripts/audit-tree-go.sh): the checkpointer seals about 70,000 uses and 400
// changes, a tick of about 500 entries at a time, into the in-memory store.
// Written out: every pair, each tree's tiles as stored, sampled inclusion and
// consistency proofs, and uses-tree cuts keeping only the tiles that reach past
// them, with proofs computed from those tiles alone.
//
//   node --conditions=coffre:source packages/vault/scripts/audit-tree-fixture.ts <out.json>
import { writeFileSync } from 'node:fs';

import { consistencyProof, inclusionProof, keptAbove, leafData, nodesFrom, openPair, TREES, type TreeName } from '@coffre/core/merkle';

import { Checkpointer } from '../src/checkpointer.ts';
import { authentic, keys, MemoryStore, variableMemory } from '../test/audit-tree.ts';

const out = process.argv[2];
if (out === undefined) throw new Error('usage: audit-tree-fixture.ts <out.json>');

const k = await keys(7);
const store = new MemoryStore(k.macKey);
const cp = await Checkpointer.open(store, k.signers, { memory: variableMemory(), authentic: authentic(k.macKey) });
let at = Date.now();
for (let tick = 0; tick < 140; tick += 1) {
  for (let i = 0; i < 500; i += 1) {
    if (i % 170 === 0) store.append('changes', `c-${tick}-${i}`, `{"action":"member.revoke","tick":${tick}}`, at);
    store.append('uses', `u-${tick}-${i}`, '{}', at);
    if (i % 97 === 0) store.skip();
  }
  // A last tick that seals the remainder: sizes that are neither tile edges nor round.
  if (tick === 139) for (let i = 0; i < 3; i += 1) store.append('uses', `tail-${i}`, '{}', at);
  at += 500;
  const t = await cp.tick();
  if (!t.signed) throw new Error(t.failures.join('; '));
}

const pairs = await Promise.all([...store.rows.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([, notes]) => notes));
const heads = await Promise.all(pairs.map((notes) => openPair(notes, k.verifiers)));
const b64 = (hashes: Buffer[]) => hashes.map((h) => h.toString('base64'));
const trees: Record<string, unknown> = {};
for (const tree of TREES) {
  const tiles = store.tileStore[tree];
  const nodes = nodesFrom(tiles);
  const size = cp.pair.pair[tree].size;
  const entries = store.log.filter((e) => e.tree === tree);
  const sample = (from: number, count: number) => [...new Set([from, from + 1, size - 1, ...Array.from({ length: count }, (_, i) => from + Math.floor(((size - from) * i) / count))])].filter((i) => i >= from && i < size);
  const record = (index: number, n = nodes) => ({ index, size, data: leafData(tree, entries[index]!.number, entries[index]!.columns).toString('base64'), proof: b64(inclusionProof(n, index, size)) });
  const sizes = [...new Set(heads.map((h) => h![tree].size))].filter((s) => s > 0 && s < size);
  const consistency = [
    ...sizes.map((from) => ({ from, to: size, proof: b64(consistencyProof(nodes, from, size)) })),
    ...sizes.slice(0, -1).map((from, i) => ({ from, to: sizes[i + 1]!, proof: b64(consistencyProof(nodes, from, sizes[i + 1]!)) })),
  ];
  const cuts = tree === 'changes' ? [] : [40_000, 65_536, 65_537, size - 1].map((cut) => {
    const kept = [...tiles.keys()].filter((key) => {
      const [level, index] = key.split('/').map(Number) as [number, number];
      return keptAbove({ level, index }, cut);
    });
    const only = nodesFrom(new Map(kept.map((key) => [key, tiles.get(key)!])));
    return {
      cut,
      kept,
      records: sample(cut, 40).map((index) => record(index, only)),
      consistency: [...new Set([cut, cut + 1, ...sizes.filter((s) => s >= cut)])].filter((from) => from > 0 && from < size).map((from) => ({ from, to: size, proof: b64(consistencyProof(only, from, size)) })),
    };
  });
  trees[tree] = {
    tiles: Object.fromEntries([...tiles].map(([key, hashes]) => [key, hashes.toString('base64')])),
    records: sample(0, 100).map((index) => record(index)),
    consistency,
    cuts,
  };
}
const sizes = (tree: TreeName) => cp.pair.pair[tree].size;
writeFileSync(out, JSON.stringify({ keys: { changes: k.signers.changes.verifierKey, uses: k.signers.uses.verifierKey }, pairs, trees }));
console.log(`fixture: ${pairs.length} pairs, ${sizes('changes')} changes, ${sizes('uses')} uses -> ${out}`);
