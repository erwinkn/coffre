// W212: what retention costs each shape, on the tiles bench.ts left for a log
// of `--leaves` leaves (`--label storage-10M`), and what serving a proof from
// entries costs the shapes that store no leaf-level tiles. Runs after bench.ts,
// on the same database.
//
//   node experiments/merkle/shapes/retain.ts --url postgresql://… [--entries 1000000]
import { createHmac, randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { leafData, leafOf, type Entry } from '../src/log.ts';
import { Edge } from '../src/tiles.ts';

const { values } = parseArgs({ options: { url: { type: 'string' }, entries: { type: 'string', default: '1000000' }, leaves: { type: 'string', default: '10000000' } } });
const db = new pg.Client({ connectionString: values.url });
await db.connect();
const LEAVES = Number(values.leaves);
const lsn = async () => (await db.query('SELECT pg_current_wal_insert_lsn()::text AS l')).rows[0].l as string;
async function measured(sql: string): Promise<{ ms: number; walBytes: number; rows: number }> {
  await db.query('CHECKPOINT');
  const a = await lsn();
  const t0 = performance.now();
  const r = await db.query(sql);
  const ms = performance.now() - t0;
  const { rows: [d] } = await db.query('SELECT pg_wal_lsn_diff($2, $1)::bigint AS d', [a, await lsn()]);
  return { ms, walBytes: Number(d.d), rows: r.rowCount ?? 0 };
}
const bytes = async (where: string, table: string) => Number((await db.query(`SELECT coalesce(sum(octet_length(hashes)), 0) AS b, count(*) AS n FROM ${table} WHERE ${where}`)).rows[0].b);

const out: Record<string, unknown> = {};
const pct = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.ceil((p / 100) * xs.length) - 1)]!;
// A proof's leaf-level read, for the shapes that store it: one tile, by key.
const tileTimes: number[] = [];
const { rows: [maxIdx] } = await db.query('SELECT max(idx)::int AS m FROM w212_tiles_one WHERE level = 0');
for (let i = 0; i < 300; i += 1) {
  const idx = Math.floor(Math.random() * maxIdx.m);
  const t0 = performance.now();
  await db.query({ name: 'tile', text: 'SELECT hashes FROM w212_tiles_one WHERE tree = 0 AND level = 0 AND idx = $1', values: [idx] });
  tileTimes.push(performance.now() - t0);
}
out.oneTileRead = { p50: pct(tileTimes, 50), p99: pct(tileTimes, 99) };
// What a day's retention may delete, and what it must keep, per shape (cut at the log's end: every leaf droppable).
for (const [shape, droppable, kept] of [
  // #365: level 0 goes; every higher level stays, as proofs above the cut read them.
  ['one', 'level = 0', 'level > 0'],
  // Every level of the uses tree goes (but its edge at the cut); the changes tree stays whole.
  ['split', 'tree = 0', 'tree = 1'],
  // The day's tree goes whole; its root is one leaf of the top tree.
  ['day', 'tree >= 0', 'tree < 0'],
  // Every chunk of the node array goes but the last (the peaks are kept apart, a few hashes).
  ['mmr', `idx < (SELECT max(idx) FROM w212_tiles_mmr)`, `idx = (SELECT max(idx) FROM w212_tiles_mmr)`],
  // No leaf-level storage; the top tree's tiles (one hash per tick) are what is left.
  ['tick', 'false', 'true'],
] as const) {
  const table = `w212_tiles_${shape}`;
  const keptBytes = await bytes(kept, table);
  const dropped = await measured(`DELETE FROM ${table} WHERE ${droppable}`);
  out[shape] = { keptBytesPerLeaf: keptBytes / LEAVES, delete: { ...dropped, msPerMillionLeaves: (dropped.ms / LEAVES) * 1e6, walPerLeaf: dropped.walBytes / LEAVES } };
}
// A day's tiles in a table of their own (`day`, partitioned by tree): the drop is one statement, whatever its size.
await db.query('DROP TABLE IF EXISTS w212_day_copy');
await db.query('CREATE TABLE w212_day_copy AS SELECT * FROM w212_tiles_one');
out.dayDropTable = await measured('DROP TABLE w212_day_copy');

// Entries, shaped as #365's (`audit_uses`), to time what reads them: serving a proof without leaf-level tiles,
// and #365's retention check, which rebuilds the day below the cut from its entries before dropping it.
const N = Number(values.entries);
await db.query('DROP TABLE IF EXISTS w212_entries');
await db.query(`CREATE TABLE w212_entries (number bigint PRIMARY KEY, at bigint NOT NULL, principal text NOT NULL, credential text, kind text NOT NULL,
  request_id text NOT NULL, payload text NOT NULL, seal bytea, mac bytea NOT NULL)`);
const mac = randomBytes(32);
await db.query(`INSERT INTO w212_entries SELECT n, 1793048700000 + n, 'svc-' || (n % 100), 'cred-' || (n % 100), 'use', 'load-' || n,
  '{"secret":"DFNS_KEY","environment":"production","decision":"allow"}', NULL, $2 FROM generate_series(1, $1) n`, [N, mac]);
await db.query('VACUUM ANALYZE w212_entries');
const { rows: [entrySize] } = await db.query("SELECT pg_total_relation_size('w212_entries') AS b");
out.entryBytes = Number(entrySize.b) / N;
const toEntry = (r: any): Entry => ({ number: r.number, at: Number(r.at), principal: r.principal, credential: r.credential, kind: r.kind, requestId: r.request_id, payload: r.payload, seal: r.seal, mac: r.mac });
const SELECT = 'SELECT number::text, at::text, principal, credential, kind, request_id, payload, seal, mac FROM w212_entries';

for (const width of [256, 500]) {
  const times: number[] = [];
  for (let i = 0; i < 300; i += 1) {
    const from = 1 + Math.floor(Math.random() * (N - width));
    const t0 = performance.now();
    const { rows } = await db.query({ name: `range${width}`, text: `${SELECT} WHERE number >= $1 AND number < $2 ORDER BY number`, values: [from, from + width] });
    const e = Edge.empty();
    e.append(rows.map((r) => leafOf(toEntry(r))));
    e.root();
    times.push(performance.now() - t0);
  }
  out[`leavesFromEntries${width}`] = { p50: pct(times, 50), p99: pct(times, 99) };
}

// #365's retention check: every entry below the cut, read in chunks, hashed into the tree.
const t0 = performance.now();
const edge = Edge.empty();
for (let from = 1; from <= N; from += 50_000) {
  const { rows } = await db.query(`${SELECT} WHERE number >= $1 AND number < $2 ORDER BY number`, [from, from + 50_000]);
  edge.append(rows.map((r) => leafOf(toEntry(r))));
}
edge.root();
const usPerEntry = ((performance.now() - t0) * 1000) / N;
out.rebuildFromEntries = { usPerEntry, secondsPerDay: (usPerEntry * 86_400_000) / 1e6 };
// The MAC a full verification also checks (#365's verifier, with the MAC key).
out.leafBytes = leafData(toEntry((await db.query(`${SELECT} LIMIT 1`)).rows[0])).length;
out.hmacUs = (() => {
  const t = performance.now();
  for (let i = 0; i < 100_000; i += 1) createHmac('sha256', mac).update('x'.repeat(200)).digest();
  return ((performance.now() - t) * 1000) / 100_000;
})();
await db.query('DROP TABLE w212_entries');
console.log(JSON.stringify(out, null, 1));
await db.end();
