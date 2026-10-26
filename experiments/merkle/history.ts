// R48 (W209): what a checkpoint and a proof cost once the tree is large. Seeds a
// log whose tree already has `--leaves` leaves (random leaf hashes, written as
// tiles, under a signed checkpoint), then times proofs at random places, each
// reading its tiles in one statement. bench.ts then runs against the same
// database to time checkpoints on top of it.
//
//   node experiments/merkle/history.ts --url postgresql://… [--leaves 10000000] [--proofs 200]
import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { createLog, keysFrom, readTiles } from './src/log.ts';
import { checkpointBody, signNote } from './src/note.ts';
import { Edge, nodesFrom, tileMap, tilesFor, type Tile } from './src/tiles.ts';
import { consistencyProof, inclusionProof, treeHash, verifyConsistency, verifyInclusion } from './src/tree.ts';

const { values } = parseArgs({ options: { url: { type: 'string' }, leaves: { type: 'string', default: '10000000' }, proofs: { type: 'string', default: '200' }, seed: { type: 'boolean', default: true } } });
const pool = new pg.Pool({ connectionString: values.url, max: 4 });
const keys = await keysFrom('w209-synthetic');
const N = Number(values.leaves);
if (values.seed) {
  await createLog(pool);
  const edge = Edge.empty();
  const started = performance.now();
  let pending = new Map<string, Tile>();
  const flush = async () => {
    const tiles = [...pending.values()];
    pending = new Map();
    await pool.query('INSERT INTO audit_tiles (level, idx, hashes) SELECT * FROM unnest($1::smallint[], $2::bigint[], $3::bytea[]) ON CONFLICT (level, idx) DO UPDATE SET hashes = excluded.hashes',
      [tiles.map((t) => t.level), tiles.map((t) => t.index), tiles.map((t) => t.hashes)]);
  };
  for (let done = 0; done < N;) {
    const batch = Math.min(65_536, N - done);
    const raw = randomBytes(batch * 32);
    const leaves = Array.from({ length: batch }, (_, i) => raw.subarray(i * 32, (i + 1) * 32));
    for (const t of edge.append(leaves)) pending.set(`${t.level}/${t.index}`, t);
    done += batch;
    if (pending.size > 2000 || done === N) await flush();
  }
  const head = { origin: keys.origin, size: N, root: edge.root(), upto: String(N), at: Date.now() };
  const note = await signNote(checkpointBody(head), [keys.signer]);
  await pool.query('INSERT INTO checkpoints (upto, size, root, note) VALUES ($1, $2, $3, $4)', [head.upto, N, head.root, note]);
  await pool.query("SELECT setval('audit_number', $1)", [N]);
  await pool.query('ANALYZE audit_tiles');
  const { rows: [size] } = await pool.query("SELECT count(*)::int AS n, pg_size_pretty(pg_total_relation_size('audit_tiles')) AS bytes FROM audit_tiles");
  console.log(`seeded a tree of ${N} leaves in ${((performance.now() - started) / 1000).toFixed(0)} s: ${size.n} tiles, ${size.bytes}`);
}
const { rows: [c] } = await pool.query('SELECT size::int, root FROM checkpoints ORDER BY upto DESC LIMIT 1');
const times: number[] = [];
const counts: number[] = [];
let bytes = 0;
for (let i = 0; i < Number(values.proofs); i += 1) {
  const m = Math.floor(Math.random() * c.size);
  const t0 = performance.now();
  const keysNeeded = tilesFor((n) => inclusionProof(n, m, c.size));
  const nodes = nodesFrom(tileMap(await readTiles(pool, keysNeeded)));
  const proof = inclusionProof(nodes, m, c.size);
  times.push(performance.now() - t0);
  counts.push(keysNeeded.length);
  bytes = proof.length * 32;
  // The leaf itself, from its tile, to check the proof against the signed head.
  if (!verifyInclusion(nodes(0, m), m, c.size, proof, c.root)) throw new Error(`proof of ${m} failed`);
}
const old = Math.floor(c.size / 3);
const cons = consistencyProof(nodesFrom(tileMap(await readTiles(pool, tilesFor((n) => consistencyProof(n, old, c.size))))), old, c.size);
const oldRoot = treeHash(nodesFrom(tileMap(await readTiles(pool, tilesFor((n) => treeHash(n, old))))), old);
if (!verifyConsistency(old, c.size, oldRoot, c.root, cons)) throw new Error('consistency failed');
times.sort((a, b) => a - b);
console.log(`tree of ${c.size}: inclusion proof ${bytes} bytes (${bytes / 32} hashes), ${Math.max(...counts)} tiles read in one statement, p50 ${times[Math.floor(times.length / 2)]!.toFixed(2)} ms p99 ${times[Math.floor(times.length * 0.99)]!.toFixed(2)} ms (read + compute, local); consistency proof from ${old}: ${cons.length} hashes, verified`);
await pool.end();
