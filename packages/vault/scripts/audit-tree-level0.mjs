// Level-0 tiles for the uses tree: what dropping them would save, and what it
// would cost (docs/design/audit-tree.md, "Level-0 tiles"). On a scratch
// Postgres 16 of your own, never the shared one: it drops and makes the
// tables `uses` and `tiles` in the database the URL names.
//
//   node packages/vault/scripts/audit-tree-level0.mjs postgres://user:password@127.0.0.1:<port>/<database>
import pg from 'pg';
import { randomBytes, randomUUID } from 'node:crypto';
if (process.argv[2] === undefined) throw new Error('usage: audit-tree-level0.mjs <postgres url>');
const db = new pg.Client({ connectionString: process.argv[2] });
await db.connect();
const q = (t, v) => db.query(t, v);
const lsn = async () => (await q('SELECT pg_current_wal_lsn() AS l')).rows[0].l;
const walSince = async (from) => Number((await q('SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), $1) AS d', [from])).rows[0].d);
await q('DROP TABLE IF EXISTS uses, tiles');
await q(`CREATE TABLE uses (number bigint NOT NULL, at bigint NOT NULL, request_id bigint NOT NULL, credential uuid NOT NULL, secret uuid NOT NULL, mac bytea NOT NULL)`);
await q('CREATE UNIQUE INDEX uses_request ON uses (at, request_id)');
const N = 1_000_000;
const t0 = Date.now() * 1;
// 1M uses at 1,000 a second, numbers with a gap now and then.
await q(`INSERT INTO uses SELECT g + g / 97, $1::bigint + g, (random() * 9e18)::bigint, gen_random_uuid(), gen_random_uuid(), substr(sha256(g::text::bytea), 1, 16) FROM generate_series(1, $2) g`, [t0, N]);
await q('VACUUM ANALYZE uses');
const size = async (rel) => Number((await q('SELECT pg_relation_size($1) AS s', [rel])).rows[0].s);
const heap = await size('uses'), idx = await size('uses_request');
console.log(`uses, 1M rows: heap ${(heap / N).toFixed(1)} B, (at, request_id) index ${(idx / N).toFixed(1)} B per use`);
await q('CREATE INDEX uses_number ON uses (number)');
console.log(`a number index adds ${((await size('uses_number')) / N).toFixed(1)} B per use (built at once; grows ~10% more appended)`);
// WAL per use appended, one per transaction, with and without the number index.
for (const withIndex of [false, true]) {
  if (!withIndex) await q('DROP INDEX uses_number'); else await q('CREATE INDEX uses_number ON uses (number)');
  await q('CHECKPOINT');
  // Warm: past the first full-page images after the checkpoint.
  let number = 2_000_000, at = t0 + 2_000_000;
  const ins = (n) => q('INSERT INTO uses VALUES ($1, $2, $3, $4, $5, $6)', [n, at++, BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()).toString(), randomUUID(), randomUUID(), randomBytes(16)]);
  for (let i = 0; i < 5000; i += 1) await ins(number++);
  const from = await lsn();
  for (let i = 0; i < 20000; i += 1) await ins(number++);
  console.log(`WAL per use appended, ${withIndex ? 'with' : 'without'} a number index: ${((await walSince(from)) / 20000).toFixed(0)} B`);
}
// The tree's level-0 tiles: 256 hashes a row, the partial one rewritten each tick.
await q('CREATE TABLE tiles (level smallint NOT NULL, idx bigint NOT NULL, hashes bytea NOT NULL, PRIMARY KEY (level, idx))');
for (const level0 of [true, false]) {
  await q('TRUNCATE tiles');
  await q('CHECKPOINT');
  let leaves = 0;
  const level = [[], [], []];
  const from = await lsn();
  const ticks = 400;
  for (let t = 0; t < ticks; t += 1) {
    const changed = new Map();
    for (let i = 0; i < 495; i += 1) {
      let h = randomBytes(32), l = 0;
      for (;;) {
        level[l].push(h);
        const index = Math.floor(leaves / 256 ** (l + 1));
        changed.set(`${l}/${index}`, [l, index]);
        if (level[l].length < 256) break;
        changed.set(`${l}/${index}`, [l, index, Buffer.concat(level[l])]);
        h = randomBytes(32); level[l] = []; l += 1;
      }
      leaves += 1;
    }
    const rows = [...changed.values()].map(([l, index, full]) => [l, index, full ?? Buffer.concat(level[l])]).filter(([l, , b]) => b.length > 0 && (level0 || l > 0));
    if (rows.length > 0) await q(`INSERT INTO tiles SELECT * FROM unnest($1::smallint[], $2::bigint[], $3::bytea[]) ON CONFLICT (level, idx) DO UPDATE SET hashes = excluded.hashes`, [rows.map((r) => r[0]), rows.map((r) => r[1]), rows.map((r) => r[2])]);
    if (t % 300 === 299) await q('CHECKPOINT');
  }
  await q('VACUUM tiles');
  const total = Number((await q("SELECT pg_total_relation_size('tiles') AS s")).rows[0].s);
  console.log(`uses tree ${level0 ? 'with' : 'without'} level-0 tiles: WAL ${((await walSince(from)) / ticks / 1024).toFixed(1)} KB a tick of 495 uses; ${(total / leaves).toFixed(1)} B per use on disk`);
}
// A proof's leaf level: one tile, or the 256 uses it stands for, found by number (index) or by `at` (no number index).
await q('DROP TABLE tiles');
await q('CREATE TABLE tiles (level smallint NOT NULL, idx bigint NOT NULL, hashes bytea NOT NULL, PRIMARY KEY (level, idx))');
await q(`INSERT INTO tiles SELECT 0, g, decode(repeat(md5(g::text), 256), 'hex') || decode(repeat(md5(g::text), 256), 'hex') FROM generate_series(0, $1) g`, [Math.floor(N / 256)]);
await q('VACUUM ANALYZE tiles');
await q('VACUUM ANALYZE uses');
const time = async (name, sql, args) => {
  const ts = [];
  for (let i = 0; i < 300; i += 1) {
    const a = args();
    const s = performance.now();
    await q(sql, a);
    ts.push(performance.now() - s);
  }
  ts.sort((x, y) => x - y);
  console.log(`${name}: p50 ${ts[150].toFixed(2)} ms, p99 ${ts[296].toFixed(2)} ms`);
};
const pick = () => Math.floor(Math.random() * (N / 256 - 2));
await time('leaf level from one tile', 'SELECT hashes FROM tiles WHERE level = 0 AND idx = $1', () => [pick()]);
await time('leaf level from 256 uses, by number (with the number index)', 'SELECT * FROM uses WHERE number >= $1 ORDER BY number LIMIT 256', () => [pick() * 256]);
await q('DROP INDEX uses_number');
// Without it: the window's `at` range (a checkpoint row would give it), then the numbers kept.
await time('leaf level from 256 uses, by the window\'s at range (no number index)', 'SELECT * FROM uses WHERE at BETWEEN $1 AND $2 ORDER BY number', () => { const s = t0 + pick() * 256; return [s, s + 300]; });
await db.end();
